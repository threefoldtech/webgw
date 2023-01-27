use std::{
    future::Future,
    io,
    marker::PhantomData,
    mem,
    pin::Pin,
    str::Utf8Error,
    task::{ready, Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};
use tracing::trace;

/// This should be ample to hold a single client hello.
const BUFFER_SIZE: usize = 1024;

/// Maximum sid len allowed.
const MAX_SID_LEN: u8 = 32;

/// Wire size of a TLS record header.
const TLS_RECORD_HEADER_SIZE: usize = 5;
/// Wire size of a TLS  handshake header.
const TLS_HANDSHAKE_HEADER_SIZE: usize = 4;

/// Byte indicating a TLS handshake message.
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
/// Byte indicating a handshake client hello message.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Extension type for SNI extension.
const EXTENSION_TYPE_SNI: u16 = 0x0000;
/// SNI type for DNS names.
const NAME_TYPE_DNS_NAME: u8 = 0x00;

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

/// Collection of things which could go wrong when sniffing.
#[derive(Debug)]
pub enum SnifferError {
    /// The buffer was filled and no complete `Host` header was found.
    BufferFull,
    /// There was an error reading from the connection.
    ReadError(io::Error),
    /// An error encountered when parsing the SNI value.
    SNIParseError(Utf8Error),
    /// An error encountered when parsing the SNI value.
    /// We don't have an SNI yet, but there is also not enough data to determine it is not present.
    /// It might still be added.
    InsufficientData,
    /// The data in the buffer is not a valid client hello handshake message.
    CorruptClientHello,
    /// The data in the buffer is a valid client hello, but there is no SNI content.
    MissingSNI,
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
            match extract_sni(&buf[..*buf_idx]) {
                // SAFETY: [`mem::transmute`] is used to change the lifetime of the returned &str from
                // '1 (the anonymous lifetime introduced by Pin<&'1 Self>) to the lifetime of the
                // pinned data 'a. It is a bit unfortunate we have to do this here. Regardless, we
                // _know_ the underlying buffer is valid for at least 'a, therefore this reference is as well.
                Ok(host) => return Poll::Ready(Ok(unsafe { mem::transmute(host) })),
                Err(SnifferError::InsufficientData) => {
                    trace!("TLS data is still valid, but we currently have insuffcient data to extract an SNI header")
                }
                Err(e) => return Poll::Ready(Err(e)),
            };

            if *buf_idx >= buf.len() - 1 {
                return Poll::Ready(Err(SnifferError::BufferFull));
            }
        }
    }
}

macro_rules! size {
    ($slice:ident, $size:expr) => {
        if $slice.len() < $size {
            return Err(SnifferError::InsufficientData);
        }
    };
}

/// Attempt to extract an SNI packet from a TLS client hello packet inside a TLS Handshake message.
/// The input must be (the start of) a valid TLS record, containing a handshake message,
/// containing a client hello message.
pub fn extract_sni(input: &[u8]) -> Result<&str, SnifferError> {
    size!(input, TLS_RECORD_HEADER_SIZE);
    if input[0] != TLS_RECORD_TYPE_HANDSHAKE {
        return Err(SnifferError::CorruptClientHello);
    }

    // 2 bytes message version (which is different from the TLS version). Purely technically
    //   we don't care for this, since at this stage all TLS client hello's seem to be
    //   compatible, and all we care for is finding a possible SNI extension.
    // 2 byte length, this does not matter as the decoder can figure out if sufficient data
    //   is present (it is also part of the client hello).

    // Header processed, move on to client hello
    size!(input, TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE);
    let handshake_type = u8::from_be_bytes(
        input[TLS_RECORD_HEADER_SIZE..TLS_RECORD_HEADER_SIZE + 1]
            .try_into()
            .expect("handshake type is valid size"),
    );
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SnifferError::CorruptClientHello);
    }
    // 3 bytes of version, we skip this implicitly

    // 2 byte version
    // 4 byte time
    // 28 bytes random data
    // 1 byte sidlen, max 32
    size!(
        input,
        TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + 34 + 1
    );

    let sid_len = u8::from_be_bytes(
        input[TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + 34
            ..TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + 34 + 1]
            .try_into()
            .expect("sid len is valid size"),
    );

    if sid_len > MAX_SID_LEN {
        return Err(SnifferError::CorruptClientHello);
    }

    let mut offset = TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + 34 + 1 + sid_len as usize;

    // skip cipher suites
    size!(input, offset + 2);
    let cipher_suites_length = u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("cipher suite length is valid size"),
    ) as usize;
    offset += 2 + cipher_suites_length;

    // skip compression algorithms
    size!(input, offset + 1);
    let compression_length = u8::from_be_bytes(
        input[offset..offset + 1]
            .try_into()
            .expect("compression algorithm length is valid"),
    ) as usize;
    offset += 1 + compression_length;
    size!(input, offset + 2);
    let total_extension_length = u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("total extension lenght is valid size"),
    );
    offset += 2;

    let extension_end = offset + total_extension_length as usize;

    while offset < extension_end {
        size!(input, offset + 4);
        let ext_type = u16::from_be_bytes(
            input[offset..offset + 2]
                .try_into()
                .expect("extension type is valid size"),
        );
        let ext_len = u16::from_be_bytes(
            input[offset + 2..offset + 4]
                .try_into()
                .expect("extension lenght is valid size"),
        );
        if ext_type == EXTENSION_TYPE_SNI {
            // Technically this is a list of SNI values, however we unconditionally extract the
            // firsts SNI value here.
            // TODO: check if there is a valid reason to process the whole list.
            size!(input, offset + 4 + 3);
            let name_type = u8::from_be_bytes(
                input[offset + 4 + 2..offset + 4 + 3]
                    .try_into()
                    .expect("name type  is valid size"),
            );
            if name_type == NAME_TYPE_DNS_NAME {
                size!(input, offset + 4 + 3 + 2);
                let name_length = u16::from_be_bytes(
                    input[offset + 4 + 3..offset + 4 + 3 + 2]
                        .try_into()
                        .expect("name lenght is valid size"),
                ) as usize;
                size!(input, offset + 4 + 3 + 2 + name_length);
                return std::str::from_utf8(
                    &input[offset + 4 + 3 + 2..offset + 4 + 3 + 2 + name_length],
                )
                .map_err(SnifferError::SNIParseError);
            }
        }
        offset += 4 + ext_len as usize;
    }

    Err(SnifferError::MissingSNI)
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
            SnifferError::InsufficientData => f.pad("incomplete client hello"),
            SnifferError::MissingSNI => f.pad("found a valid client hello without SNI extension"),
            SnifferError::CorruptClientHello => {
                f.pad("the buffer does not contain a valid client hello message")
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

    #[test]
    fn extract_sni() {
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

        let res = super::extract_sni(&TLS_PACKET).expect("can extract SNI value");
        assert_eq!(res, "www.example.com");
    }

    /// Test to see if we can properly stream, and our length checks are always valid (we don't get
    /// out of bound access).
    #[test]
    fn streaming_sni_extract() {
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

        let mut success = false;

        for i in 0..TLS_PACKET.len() {
            let res = super::extract_sni(&TLS_PACKET[..i]);
            if !success {
                if res.is_err() {
                    match res.unwrap_err() {
                        SnifferError::InsufficientData => continue,
                        _ => panic!("unexpected error while decoding valid packet"),
                    }
                } else {
                    // found a value, from now on we should always find the same value.
                    success = true;
                }
            }
            // use separate block to avoid having to explicitly add the check for the iteration we
            // find a value for the first time.
            if success {
                assert_eq!(res.unwrap(), "www.example.com");
            }
        }
    }
}
