use std::{
    future::Future,
    io,
    marker::PhantomData,
    mem,
    pin::Pin,
    str::Utf8Error,
    task::{ready, Context, Poll},
};

use tls_parser::{nom::Err as TlsParseErr, SNIType, TlsExtension, TlsMessage, TlsMessageHandshake};
use tokio::io::{AsyncRead, ReadBuf};
use tracing::{debug, trace};

/// This should be ample to hold a single client hello.
const BUFFER_SIZE: usize = 4096;

/// Wire size of a TLS record header.
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Byte indicating a TLS handshake message.
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;

#[derive(Debug)]
pub struct Sniffer<'a, T> {
    /// buf to store read bytes so they can later be retrieved.
    buf: [u8; BUFFER_SIZE],
    /// Location in the buffer until which we have filled already.
    buf_idx: usize,
    /// Connection to sniff.
    conn: T,

    // TODO: This is only here so we can tie the reference lifetime of the &'a str from the AsyncRead
    // to the struct lifetime. GAT's should be able to fix this
    _marker: PhantomData<&'a T>,
}

#[derive(Debug)]
pub enum SnifferError {
    /// The buffer was filled and no complete `Host` header was found.
    BufferFull,
    /// There was an error reading from the connection.
    ReadError(io::Error),
    /// An error encountered when parsing the SNI value.
    SNIParseError(Utf8Error),
    /// The data in the buffer is a valid client hello, but there is no SNI content.
    MissingSNI,
    /// The data in the buffer is not a valid TLS message.
    InvalidTlsMessage,
    /// The data in the buffer is a handshake message, but not a client hello.
    UnexpectedHandshakeMessage,
    /// The data in the buffer is not a TLS handshake message.
    UnexpectedTlsMessage,
    /// Extension data is corrupt or could otherwise not be parsed.
    InvalidExtensionData,
}

impl<'a, T> Sniffer<'a, T> {
    /// Create a new Sniffer ready for use.
    pub const fn new(conn: T) -> Self {
        Self {
            buf: [0; BUFFER_SIZE],
            buf_idx: 0,
            conn,
            _marker: PhantomData,
        }
    }

    /// Gets the raw parts of the sniffer. This constitutes the buffer used to save sniffed data,
    /// the amount of actual bytes in the buffer, and the connection it is sniffing from.
    pub fn into_parts(self) -> ([u8; BUFFER_SIZE], usize, T) {
        (self.buf, self.buf_idx, self.conn)
    }
}

// FIXME: return error if no host header is present (double newline character to end headers)
impl<'a, T> Future for Sniffer<'a, T>
where
    T: AsyncRead + Unpin,
{
    type Output = Result<&'a str, SnifferError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        loop {
            // Deconstruct self, to avoid borrow check issues.
            let Sniffer {
                buf,
                buf_idx,
                conn,
                _marker,
            } = &mut *self;

            let mut read_buf = ReadBuf::new(&mut buf[*buf_idx..]);
            if let Err(e) = ready!(Pin::new(conn).poll_read(cx, &mut read_buf)) {
                return Poll::Ready(Err(SnifferError::ReadError(e)));
            }
            let remainder = read_buf.remaining();
            *buf_idx += buf.len() - remainder;

            // Attempted TLS parse. Since the first message is always a Client Hello, we don't need
            // to maintain any state.
            // Also, manually parse the TLS header and make sure it is of a proper type here.
            // TODO: we don't really care about most of the message, so we could get rid of the tls
            // parser by manually advancing a pointer until we reach the extension with the sni.
            // This would also avoid some allocations we don't actually use anyway.
            if *buf_idx < TLS_RECORD_HEADER_SIZE {
                continue;
            }
            if buf[0] != TLS_RECORD_TYPE_HANDSHAKE {
                return Poll::Ready(Err(SnifferError::UnexpectedTlsMessage));
            }
            // 2 bytes message version (which is different from the TLS version). Purely technically
            //   we don't care for this, since at this stage all TLS client hello's seem to be
            //   compatible, and all we care for is finding a possible SNI extension.
            // 2 byte length, this does not matter as the decoder can figure out if sufficient data
            //   is present (it is also part of the client hello).

            match tls_parser::parse_tls_message_handshake(&buf[TLS_RECORD_HEADER_SIZE..*buf_idx]) {
                Ok((_, record)) => {
                    match record {
                        TlsMessage::Handshake(msg) => match msg {
                            TlsMessageHandshake::ClientHello(client_hello) => {
                                if let Some(extension_data) = client_hello.ext {
                                    match tls_parser::parse_tls_client_hello_extensions(
                                        extension_data,
                                    ) {
                                        Ok((_, extensions)) => {
                                            for extension in extensions {
                                                // We only care about the SNI extension here.
                                                if let TlsExtension::SNI(sni_extension) = extension
                                                {
                                                    for (sni_type, sni_value) in sni_extension {
                                                        if sni_type == SNIType::HostName {
                                                            match std::str::from_utf8(sni_value) {
                                                                Ok(host) => {
                                                                    return Poll::Ready(Ok(
                                                                        // SAFETY: [`mem::transmute`] is used to change the lifetime of the returned &str from
                                                                        // '1 (the anonymous lifetime introduced by Pin<&'1 Self>) to the lifetime of the
                                                                        // pinned data 'a. It is a bit unfortunate we have to do this here, and we should
                                                                        // probably look for a better way. Regardless, we _know_ the underlying buffer is valid
                                                                        // for at least 'a, therefore this reference is as well.
                                                                        unsafe {
                                                                            mem::transmute(host)
                                                                        },
                                                                    ));
                                                                }
                                                                Err(e) => {
                                                                    return Poll::Ready(Err(
                                                                        SnifferError::SNIParseError(
                                                                            e,
                                                                        ),
                                                                    ));
                                                                }
                                                            }
                                                        }
                                                    }

                                                    return Poll::Ready(Err(
                                                        SnifferError::MissingSNI,
                                                    ));
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            return Poll::Ready(Err(
                                                SnifferError::InvalidExtensionData,
                                            ))
                                        }
                                    }
                                } else {
                                    return Poll::Ready(Err(SnifferError::MissingSNI));
                                }
                            }
                            _ => {
                                return Poll::Ready(Err(SnifferError::UnexpectedHandshakeMessage));
                            }
                        },
                        _ => {
                            return Poll::Ready(Err(SnifferError::UnexpectedTlsMessage));
                        }
                    }
                }
                Err(TlsParseErr::Incomplete(_)) => {
                    trace!("Insufficient data to decode TLS client hello, got {} bytes, need more bytes", buf_idx);
                }
                Err(e) => {
                    debug!("Failed to parse TLS client hello: {}", e);
                    return Poll::Ready(Err(SnifferError::InvalidTlsMessage));
                }
            };

            if *buf_idx >= buf.len() - 1 {
                return Poll::Ready(Err(SnifferError::BufferFull));
            }
        }
    }
}

impl std::fmt::Display for SnifferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnifferError::BufferFull => {
                f.pad("buffer is full and there is no client hello with SNI extension yet")
            }
            SnifferError::ReadError(ref e) => {
                f.pad(&format!("error reading from the connection: {}", e))
            }
            SnifferError::SNIParseError(ref e) => {
                f.pad(&format!("SNI value is invalid UTF-8: {}", e))
            }
            SnifferError::InvalidExtensionData => f.pad("client hello extension data is corrupt"),
            SnifferError::MissingSNI => f.pad("client hello does not contain an SNI extension"),
            SnifferError::InvalidTlsMessage => f.pad("data is not a valid TLS message"),
            SnifferError::UnexpectedHandshakeMessage => {
                f.pad("data is a TLS handshake message, but not a client hello which is expected")
            }
            SnifferError::UnexpectedTlsMessage => {
                f.pad("data is a TLS message, but not a handshake message whic his expected")
            }
        }
    }
}

impl std::error::Error for SnifferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnifferError::SNIParseError(ref e) => Some(e),
            SnifferError::ReadError(ref e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_client_hello() {
        const TLS_PACKET: [u8; 517] = [
            22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 43, 177, 105, 97, 39, 177, 163, 215, 99, 197, 34,
            151, 213, 136, 4, 67, 100, 102, 17, 239, 238, 178, 98, 111, 126, 235, 93, 33, 117, 197,
            158, 172, 32, 35, 68, 185, 200, 181, 234, 144, 118, 239, 136, 10, 196, 98, 83, 145, 58,
            79, 208, 87, 117, 25, 240, 110, 6, 172, 215, 84, 0, 181, 171, 142, 121, 0, 62, 19, 2,
            19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204, 170, 192, 43, 192, 47,
            0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192, 10, 192, 20, 0, 57,
            192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47, 0, 255, 1, 0, 1,
            117, 0, 0, 0, 20, 0, 18, 0, 0, 15, 119, 119, 119, 46, 101, 120, 97, 109, 112, 108, 101,
            46, 99, 111, 109, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0,
            25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116,
            116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 42, 0, 40,
            4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
            3, 3, 3, 1, 3, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 9, 8, 3, 4, 3, 3, 3, 2, 3, 1, 0, 45, 0,
            2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 234, 51, 230, 4, 12, 227, 34, 105, 46, 27,
            82, 196, 34, 153, 98, 191, 9, 33, 51, 108, 100, 168, 99, 201, 29, 79, 165, 152, 52,
            201, 150, 4, 0, 21, 0, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let cursor = io::Cursor::new(TLS_PACKET.clone());
        let mut sniffer = Sniffer::new(cursor);
        let host = (&mut sniffer).await.expect("can't parse SNI extension");
        assert_eq!(host, "www.example.com");
        let (buf, idx, cursor) = sniffer.into_parts();
        assert!(idx <= TLS_PACKET.len());
        let mut fb = buf[..idx].to_vec();
        let cursor_pos = cursor.position();
        fb.extend(&cursor.into_inner()[cursor_pos as usize..]);
        assert_eq!(fb, TLS_PACKET[..]);
    }
}
