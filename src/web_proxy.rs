use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::{
    io::{self, AsyncWriteExt},
    select,
};
use tracing::{debug, trace};

use crate::bandwidth::{Bandwidth, MeasuredConnection};
use crate::sniffer::{HTTPSniffer, HTTPSnifferError};

/// Hash of the secret is a blake2b-32 digest.
pub type SecretHash = [u8; 32];

/// Default port to listen on for HTTP connections.
const HTTP_PORT: u16 = 80;

/// A generic TCP proxy, extended with sniffers for incoming traffic.
#[derive(Debug)]
pub struct Proxy {
    /// Host names for which a client is connected
    connected_hosts: RwLock<HashMap<String, (ConnectedRemote, Arc<Bandwidth>)>>,
    /// All hosts registered in the proxy, mapped to the secret required by clients for
    /// authentication.
    registered_hosts: RwLock<HashMap<String, SecretHash>>,
}

// TODO: This should be part of the core
#[derive(Debug)]
pub struct ConnectedRemote {
    // TODO
}

impl ConnectedRemote {
    pub async fn request_connection(&self) -> Result<TcpStream, Box<dyn std::error::Error>> {
        todo!();
    }
}

impl Proxy {
    /// Create a new Proxy
    pub fn new() -> Self {
        Self {
            connected_hosts: RwLock::new(HashMap::new()),
            registered_hosts: RwLock::new(HashMap::new()),
        }
    }

    /// Listen for incoming HTTP connections, attempt to identify them, and if successful, attempt
    /// to proxy them to a connected client, if any. If not client is connected for the host, or
    /// the host is not known, the connection is closed.
    pub async fn listen_http(&self) -> Result<(), io::Error> {
        let listener = TcpListener::bind(("[::]", HTTP_PORT)).await?;
        loop {
            let (frontend_con, remote) = listener.accept().await?;
            debug!("Accepted new connection from {}", remote);
            // Get the target host.
            let mut sniffer = HTTPSniffer::new(frontend_con);
            let host = match (&mut sniffer).await {
                Ok(host) => host,
                Err(se) => {
                    debug!("Could not extract HTTP host from connection: {}", se);
                    continue;
                }
            };

            // Deconstruct the sniffer
            let (buffer, buf_size, mut frontend_con) = sniffer.into_parts();
            // Check if we know this host. Note that we don't check the registered hosts, but only
            // the ones for which a client is connected, as a known host without connected client
            // will have the same result as an unknown host, i.e. a closed connection.
            let connected_hosts = self.connected_hosts.read().await;
            if let Some((remote, bandwidth)) = connected_hosts.get(host) {
                match remote.request_connection().await {
                    Ok(mut backend_con) => {
                        trace!(
                            "Got new proxy ready connection for {}, dumping {} byte sniffer buffer",
                            host,
                            buf_size
                        );
                        if let Err(e) = backend_con.write_all(&buffer[..buf_size]).await {
                            // If there is an error, move on to the next connection.
                            debug!("Writing sniffer buffer failed: {}", e);
                            continue;
                        }
                        // Notice that we don't flush here. That's because we don't really care
                        // that this data reaches the remote _now_, we only care that it is queued
                        // before adding the other data of the connection. Besides, there is no
                        // guarantee that the remote will be able to do anything useful with what
                        // is in the buffer at this point in time anyway.

                        // Don't forget to increment the written counter.
                        bandwidth.add_written(buf_size as u64);

                        // Get a new handle, as there existing handle is a reference, which can't
                        // go into the task.
                        let bandwidth = Arc::clone(bandwidth);
                        tokio::spawn(async move {
                            // Split the tcp streams as copy bidirectional seems to have some
                            // issues. Use `split` and then a select instead of `into_split`
                            // so we only spawn 1 task, and avoid a heap allocation for the split.
                            let (backend_reader, backend_writer) = backend_con.split();
                            let (mut fronted_reader, mut frontend_writer) = frontend_con.split();
                            // Measure bandwidth on the backend.
                            let mut backend_reader = MeasuredConnection::with_bandwidth(
                                backend_reader,
                                Arc::clone(&bandwidth),
                            );
                            let mut backend_writer =
                                MeasuredConnection::with_bandwidth(backend_writer, bandwidth);

                            // TODO: Verify graceful shutdown
                            select! {
                                _ = io::copy(&mut fronted_reader, &mut backend_writer) => {}
                                _ = io::copy(&mut backend_reader, &mut frontend_writer) => {}
                            }
                        });
                    }
                    Err(e) => {
                        debug!("Failed to get connection from remote: {}", e);
                        continue;
                    }
                }
            };
        }
    }

    /// Register a new host name with the Proxy, with the given secret hash. This function will
    /// error in case the host is already registered with a __different__ secret hash.
    pub async fn register_host(
        &self,
        host: String,
        secret_hash: SecretHash,
    ) -> Result<(), DuplicateHostRegistration> {
        let mut registered_hosts = self.registered_hosts.write().await;
        if let Some(known_secret) = registered_hosts.get(&host) {
            if known_secret != &secret_hash {
                return Err(DuplicateHostRegistration {
                    host,
                    secret_hash,
                    old_secret_hash: *known_secret,
                });
            }
        }
        // It is technically possible that the host is already registered, but then the secret is
        // the same (we checked for a __different__ secret above), so we will silently ignore that
        // and allow this as a NOOP.
        registered_hosts.insert(host, secret_hash);
        Ok(())
    }

    /// Unregister a host from the Proxy. If the host is known, the secret hash associated is
    /// returned. This can be used for debugging from the call site.
    pub async fn unregister_host(&self, host: &str) -> Option<SecretHash> {
        let mut registered_hosts = self.registered_hosts.write().await;
        registered_hosts.remove(host)
    }
}

/// Error type returned in case [`Proxy::register_host`] fails because the host is already
/// registered with a different secret.
#[derive(Debug)]
pub struct DuplicateHostRegistration {
    /// The hostname which was registered twice.
    pub host: String,
    /// The secret hash of the duplicate registration.
    pub secret_hash: SecretHash,
    /// The secret hash of the existing hostname registration in the proxy.
    pub old_secret_hash: SecretHash,
}

impl std::fmt::Display for DuplicateHostRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("can't register already known hostname ")?;
        f.write_str(&self.host)
    }
}

impl std::error::Error for DuplicateHostRegistration {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_host() {
        const HASH: SecretHash = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ];
        let host = String::from("example.com");
        let proxy = Proxy::new();
        let res = proxy.register_host(host, HASH).await;
        assert!(res.is_ok());
        // Can't panic because of the above assertion
        let res = res.unwrap();
        assert_eq!(res, ())
    }

    #[tokio::test]
    async fn register_duplicate_host_with_same_secret() {
        const HASH: SecretHash = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ];
        let host = String::from("example.com");
        let proxy = Proxy::new();
        let res = proxy.register_host(host.clone(), HASH).await;
        assert!(res.is_ok());
        // Can't panic because of the above assertion
        let res = res.unwrap();
        assert_eq!(res, ());

        let res2 = proxy.register_host(host, HASH).await;
        assert!(res2.is_ok());
        // Can't panic because of the above assertion
        let res2 = res2.unwrap();
        assert_eq!(res2, ())
    }

    #[tokio::test]
    async fn register_duplicate_host_with_different_secret() {
        const HASH: SecretHash = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ];
        const HASH2: SecretHash = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];
        let host = String::from("example.com");
        let proxy = Proxy::new();
        let res = proxy.register_host(host.clone(), HASH).await;
        assert!(res.is_ok());
        // Can't panic because of the above assertion
        let res = res.unwrap();
        assert_eq!(res, ());

        let res2 = proxy.register_host(host.clone(), HASH2).await;
        assert!(res2.is_err());
        // Can't panic because of the above assertion
        let res2 = res2.unwrap_err();
        assert_eq!(res2.host, host);
        assert_eq!(res2.secret_hash, HASH2);
        assert_eq!(res2.old_secret_hash, HASH);
    }

    #[tokio::test]
    async fn unregister_known_host() {
        const HASH: SecretHash = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ];
        let host = String::from("example.com");
        let proxy = Proxy::new();
        let _ = proxy.register_host(host.clone(), HASH).await;
        let possible_secret = proxy.unregister_host(&host).await;
        assert_eq!(possible_secret, Some(HASH))
    }

    #[tokio::test]
    async fn unregister_unknown_host() {
        const HASH: SecretHash = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1,
        ];
        let host = String::from("example.com");
        let proxy = Proxy::new();
        let possible_secret = proxy.unregister_host(&host).await;
        assert_eq!(possible_secret, None)
    }
}
