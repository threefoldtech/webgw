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

/// Technically, a very large cookie could be sent by the client causing all headers to not fit in
/// this buffer. In practice, we will assume it does.
const BUFFER_SIZE: usize = 4096;

/// Host header lenght in bytes, this includes the ':' field.
const HOST_HEADER_PREFIX_SIZE: usize = 5;

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
    /// An error encountered when parsing a header.
    HeaderParseError(Utf8Error),
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
        let (start, end) = 'outer: loop {
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

            // Parse HTTP headers
            // TODO: if we do multiple read calls we will parse the same header. This can be fixed
            // by keeping track of the starting position of the last header we did not fully parse.
            let haystack = &buf[..*buf_idx];
            let mut offset = 0;
            for possible_header in haystack.split(|&c| c == b'\n') {
                if host_header_start(possible_header) {
                    break 'outer (
                        offset + HOST_HEADER_PREFIX_SIZE,
                        offset + possible_header.len(),
                    );
                }
                // NOTE: we need to add an additional byte to the offset as the '\n' byte is
                // removed by the split function, but is still present in the underlying buffer.
                offset += possible_header.len() + 1;
            }

            if *buf_idx >= buf.len() - 1 {
                return Poll::Ready(Err(SnifferError::BufferFull));
            }
        };
        match std::str::from_utf8(&self.buf[start..end]) {
            // SAFETY: [`mem::transmute`] is used to change the lifetime of the returned &str from
            // '1 (the anonymous lifetime introduced by Pin<&'1 Self>) to the lifetime of the
            // pinned data 'a. It is a bit unfortunate we have to do this here, and we should
            // probably look for a better way. Regardless, we _know_ the underlying buffer is valid
            // for at least 'a, therefore this reference is as well.
            Ok(header) => Poll::Ready(Ok(unsafe { mem::transmute(header.trim()) })),
            Err(e) => Poll::Ready(Err(SnifferError::HeaderParseError(e))),
        }
    }
}

// Checks if a byte slice starts with 'host:' in a case insensitive search.
const fn host_header_start(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    (data[0] == b'h' || data[0] == b'H')
        && (data[1] == b'o' || data[1] == b'O')
        && (data[2] == b's' || data[2] == b'S')
        && (data[3] == b't' || data[3] == b'T')
        && data[4] == b':'
}

impl std::fmt::Display for SnifferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnifferError::BufferFull => f.pad("buffer is full and there is no 'host' header yet"),
            SnifferError::ReadError(ref e) => {
                f.pad(&format!("error reading from the connection: {}", e))
            }
            SnifferError::HeaderParseError(ref e) => {
                f.pad(&format!("host header value is invalid UTF-8: {}", e))
            }
        }
    }
}

impl std::error::Error for SnifferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnifferError::HeaderParseError(ref e) => Some(e),
            SnifferError::ReadError(ref e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sniff_valid_header() {
        let http_packet = br#"GET / HTTP/1.1
User-Agent: curl/7.64.1
Host: www.example.com
Accept-Language: en, mi
"#;
        let cursor = io::Cursor::new(http_packet.clone());
        let mut sniffer = Sniffer::new(cursor);
        let host = (&mut sniffer).await.expect("can't parse host header");
        assert_eq!(host, "www.example.com");
        let (buf, idx, cursor) = sniffer.into_parts();
        assert!(idx <= http_packet.len());
        let mut fb = buf[..idx].to_vec();
        let cursor_pos = cursor.position();
        fb.extend(&cursor.into_inner()[cursor_pos as usize..]);
        assert_eq!(fb, http_packet[..]);
    }
}
