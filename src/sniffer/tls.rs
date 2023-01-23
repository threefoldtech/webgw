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

/// Technically, a very large cookie could be sent by the client causing all headers to not fit in
/// this buffer. In practice, we will assume it does.
const BUFFER_SIZE: usize = 4096;

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
            match tls_parser::parse_tls_message_handshake(&buf[..]) {
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
            SnifferError::BufferFull => f.pad("buffer is full and there is no 'host' header yet"),
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
