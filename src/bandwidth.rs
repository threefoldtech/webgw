use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

/// A connection which measures bytes written and read.
#[derive(Debug)]
pub struct MeasuredConnection<T> {
    /// Measurement of used bandwidth, wrapped in an Arc so there can be multiple handles to the
    /// measurements (useful for e.g. io::copy workloads, to get a handle before starting the copy
    /// and read bandwidth during the copy).
    bandwidth: Arc<Bandwidth>,
    con: T,
}

impl<T> MeasuredConnection<T> {
    /// Wraps an existing connection to allow bandwidth measurements.
    pub fn new(con: T) -> Self {
        Self {
            bandwidth: Arc::new(Bandwidth::new()),
            con,
        }
    }

    /// Wraps an existing connection, and use existing bandwidth measurements.
    pub fn with_bandwidth(con: T, bandwidth: Arc<Bandwidth>) -> Self {
        Self { bandwidth, con }
    }

    /// Get a reference to the active bandwidth measurement of the connection.
    pub fn bandwidth(&self) -> Arc<Bandwidth> {
        Arc::clone(&self.bandwidth)
    }
}

/// Bandwidth counters.
#[derive(Debug)]
pub struct Bandwidth {
    /// Amount of bytes read.
    read: AtomicU64,
    /// Amount of bytes written.
    written: AtomicU64,
}

impl Bandwidth {
    /// Create a new Bandwidth structure.
    pub fn new() -> Self {
        Self {
            read: AtomicU64::new(0),
            written: AtomicU64::new(0),
        }
    }

    /// Returns the amount of bytes read.
    pub fn read(&self) -> u64 {
        self.read.load(Ordering::Acquire)
    }

    /// Returns the amount of bytes written.
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Acquire)
    }
}

impl Default for Bandwidth {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AsyncRead for MeasuredConnection<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let start = buf.filled().len();
        let res = ready!(Pin::new(&mut self.con).poll_read(cx, buf));
        self.bandwidth
            .read
            .fetch_add((buf.filled().len() - start) as u64, Ordering::Relaxed);
        Poll::Ready(res)
    }
}

impl<T> AsyncWrite for MeasuredConnection<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let written = ready!(Pin::new(&mut self.con).poll_write(cx, buf));
        if let Ok(amt) = written {
            self.bandwidth
                .written
                .fetch_add(amt as u64, Ordering::Relaxed);
        };
        Poll::Ready(written)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.con).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.con).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn count_read_bytes() {
        const BUF_SIZE: usize = 64;
        let (reader, mut writer) = duplex(BUF_SIZE);
        let data = [0; BUF_SIZE];
        writer
            .write_all(&data)
            .await
            .expect("can write all data to buffered duplex");
        let mut measured_reader = MeasuredConnection::new(reader);
        let measurements = measured_reader.bandwidth();
        assert_eq!(measurements.read(), 0);
        assert_eq!(measurements.written(), 0);
        let mut out = [0; BUF_SIZE];
        measured_reader
            .read_exact(&mut out)
            .await
            .expect("can read from wrapped cursor");
        assert_eq!(measurements.read(), BUF_SIZE as u64);
        assert_eq!(measurements.written(), 0);
    }

    #[tokio::test]
    async fn count_written_bytes() {
        const BUF_SIZE: usize = 64;
        // reader need to stay in scope or the write will error with BrokenPipe
        let (_reader, writer) = duplex(BUF_SIZE);
        let data = [0; BUF_SIZE];
        let mut measured_writer = MeasuredConnection::new(writer);
        let measurements = measured_writer.bandwidth();
        assert_eq!(measurements.read(), 0);
        assert_eq!(measurements.written(), 0);
        measured_writer
            .write_all(&data)
            .await
            .expect("can write to wrapped cursor");
        assert_eq!(measurements.read(), 0);
        assert_eq!(measurements.written(), BUF_SIZE as u64);
    }
}
