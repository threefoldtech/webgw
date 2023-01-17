use std::fmt::Display;
use std::sync::Arc;
use std::{collections::HashMap, time::Duration};

use blake2::{digest::typenum::U32, Blake2b, Digest};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::RwLock,
    time::timeout,
};
use tracing::{debug, error, trace, warn};

use crate::bandwidth::{Bandwidth, MeasuredConnection};
use crate::sniffer::{HTTPSniffer, HTTPSnifferError};

/// Hash of the secret is a blake2b-32 digest.
pub type SecretHash = [u8; 32];

/// Type of a connection secret, which is used to identify connections made from clients to the
/// proxy to actually proxy a frontend connection.
pub type ConnectionSecret = [u8; CONNECTION_SECRET_SIZE];

/// Blake2b hasher with 32 byte digest.
type Hasher = Blake2b<U32>;

/// Default port to listen on for HTTP connections.
const HTTP_PORT: u16 = 80;
/// Default port to listen for client connections.
const BACKEND_PORT: u16 = 4658;

/// Amount of bytes used for a ConnectionSecret.
pub const CONNECTION_SECRET_SIZE: usize = 32;

/// A generic TCP proxy, extended with sniffers for incoming traffic.
#[derive(Debug)]
pub struct Proxy {
    /// Host names for which a client is connected
    connected_hosts: RwLock<HashMap<String, (ConnectedRemote, Arc<Bandwidth>)>>,
    /// All hosts registered in the proxy, mapped to the secret required by clients for
    /// authentication.
    registered_hosts: RwLock<HashMap<String, SecretHash>>,
    /// Pending backend connections.
    pending_proxy_connections: Arc<Mutex<HashMap<ConnectionSecret, oneshot::Sender<TcpStream>>>>,
    /// The maximum amount of time to sniff the destination from a new frontend connection.
    sniffer_timeout: Duration,
    /// The amount of time to wait for a client to create a connection to the proxy when a new
    /// connection for its host has been identified.
    backend_connection_timeout: Duration,
    /// The amount of time a client connection has to send the connection identification secret,
    /// after the initial connection. This should be shorter than `backend_connection_timeout`.
    backend_identification_timeout: Duration,
}

// TODO: This should be part of the core
#[derive(Debug)]
pub struct ConnectedRemote {
    // TODO: Add a lvl of indirection by replacing this with an mpsc::Sender and spawning a task,
    // or implementing a newtype which implements futures::Sink and making this generic. This would
    // greatly improve testability.
    remote: jsonrpsee::SubscriptionSink,
}

impl ConnectedRemote {
    /// Create a new ConnectedRemote from the given SubscriptionSink.
    pub fn new(remote: jsonrpsee::SubscriptionSink) -> Self {
        Self { remote }
    }

    /// Request a new connection from the remote
    pub async fn request_connection(
        &self,
        _secret: ConnectionSecret,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!();
    }
}

impl Proxy {
    /// Create a new Proxy
    pub fn new() -> Self {
        Self {
            connected_hosts: RwLock::new(HashMap::new()),
            registered_hosts: RwLock::new(HashMap::new()),
            pending_proxy_connections: Arc::new(Mutex::new(HashMap::new())),
            sniffer_timeout: Duration::from_secs(10),
            backend_connection_timeout: Duration::from_secs(5),
            backend_identification_timeout: Duration::from_secs(3),
        }
    }

    /// Listen for incoming TCP connections from clients. These connections are the result of
    /// requesting a new connection to be opened from the client by the proxy, in repsonse to a new
    /// frontend connection coming in, and being identified as being hosted by said client. This
    /// function blocks until the listener fails to accept a connection.
    pub async fn listen_backend_connection(&self) -> Result<(), io::Error> {
        let listener = TcpListener::bind(("[::]", BACKEND_PORT)).await?;
        loop {
            let (mut client_con, remote) = listener.accept().await?;
            debug!("Accepted new backend connection from {}", remote);
            let backend_identification_timeout = self.backend_identification_timeout;
            let pending_proxy_connections = Arc::clone(&self.pending_proxy_connections);
            tokio::spawn(async move {
                let mut secret = [0; CONNECTION_SECRET_SIZE];
                match timeout(
                    backend_identification_timeout,
                    client_con.read_exact(&mut secret),
                )
                .await
                {
                    Ok(Ok(read)) => {
                        if read != secret.len() {
                            warn!(
                            "Secret read is not the correct lenght, expected {} bytes got {} bytes",
                            secret.len(),
                            read
                        );
                            return;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("Failed to read secret from client connection: {}", e);
                        return;
                    }
                    Err(_) => {
                        debug!("Timeout while reading client connection secret");
                        return;
                    }
                }
                // Now we have the secret, match it
                let mut pending_proxy_connections = pending_proxy_connections.lock().await;
                // We actually `remove` here, because we want to take ownership of the value, and also
                // want to clean it up already.
                if let Some(tx) = pending_proxy_connections.remove(&secret) {
                    // If send fails we get back the connection, but the receiver is gone already
                    // anyhow in that case so we can't really do anything meaningful.
                    if tx.send(client_con).is_err() {
                        debug!("Could not process client connection, probably took too long to process it");
                    };
                }
            });
        }
    }

    /// Listen for incoming HTTP connections, attempt to identify them, and if successful, attempt
    /// to proxy them to a connected client, if any. If not client is connected for the host, or
    /// the host is not known, the connection is closed. This function blocks until the listener
    /// fails to accept a connection.
    pub async fn listen_http(&self) -> Result<(), io::Error> {
        let listener = TcpListener::bind(("[::]", HTTP_PORT)).await?;
        loop {
            let (frontend_con, remote) = listener.accept().await?;
            debug!("Accepted new presumed HTTP connection from {}", remote);
            // Get the target host.
            let mut sniffer = HTTPSniffer::new(frontend_con);
            let host = match timeout(self.sniffer_timeout, &mut sniffer).await {
                Ok(Ok(host)) => host,
                Ok(Err(se)) => {
                    debug!("Could not extract HTTP host from connection: {}", se);
                    continue;
                }
                Err(_) => {
                    debug!("Incoming connection did not send host header in time");
                    continue;
                }
            };

            // Deconstruct the sniffer
            let (buffer, buf_size, mut frontend_con) = sniffer.into_parts();

            match self.request_connection(host).await {
                Ok((mut backend_con, bandwidth)) => {
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
    /// returned. This can be used for debugging from the call site. This also removes a
    /// connected client, if any.
    pub async fn unregister_host(&self, host: &str) -> Option<SecretHash> {
        let mut registered_hosts = self.registered_hosts.write().await;
        let mut connected_hosts = self.connected_hosts.write().await;
        connected_hosts.remove(host);
        registered_hosts.remove(host)
    }

    /// Register a new client for a given host. The secret is hashed, and if the resulting value
    /// matches the configured secret hash, the client is accepted.
    pub async fn register_client<'a>(
        &self,
        host: &'a str,
        secret: &[u8],
        remote: ConnectedRemote,
    ) -> Result<(), ProxyClientError<'a>> {
        let secret_hash = Hasher::digest(secret);
        let registered_hosts = self.registered_hosts.read().await;
        let registered_secret_hash = match registered_hosts.get(host) {
            Some(secret) => secret,
            None => return Err(ProxyClientError::UnknownHost { host }),
        };
        if secret_hash.as_slice() != registered_secret_hash {
            return Err(ProxyClientError::WrongSecret);
        }
        // Aquire a write lock on connected_remotes to insert the new connection. Note we still
        // need to hold the read lock on registered hosts, as otherwise there is a potential race
        // condition where `host` is unregsitered before the new data is inserted in connected
        // hosts. We only grab this lock after the above checks to avoid contention here as much as
        // possible, as this map is also used whenever a new frontend connection is identified.
        let mut connected_remotes = self.connected_hosts.write().await;
        // Extract existing measurements, in case we already have a live client for this host. The
        // client will be replaced regardless. We use remove for this, as we will end up replacing
        // the data anyway, and by removing we take ownership of the data, avoiding making a copy
        // of the Arc and bumping its refcount. This is ever so slightly more performant.
        let bandwidth = if let Some((_, bandwidth)) = connected_remotes.remove(host) {
            bandwidth
        } else {
            Arc::new(Bandwidth::new())
        };
        connected_remotes.insert(host.to_string(), (remote, bandwidth));

        Ok(())
    }

    /// Unregisters a client for a host. This returns the current bandwidth counters for the host.
    pub async fn unregister_client<'a>(&self, host: &str) -> Option<Arc<Bandwidth>> {
        let mut connected_hosts = self.connected_hosts.write().await;
        connected_hosts.remove(host).map(|(_, bandwidth)| bandwidth)
    }

    pub fn register_client_blocking<'a>(
        &self,
        host: &'a str,
        secret: &[u8],
        remote: ConnectedRemote,
    ) -> Result<(), ProxyClientError<'a>> {
        let secret_hash = Hasher::digest(secret);
        let registered_hosts = self.registered_hosts.blocking_read();
        let registered_secret_hash = match registered_hosts.get(host) {
            Some(secret) => secret,
            None => return Err(ProxyClientError::UnknownHost { host }),
        };
        if secret_hash.as_slice() != registered_secret_hash {
            return Err(ProxyClientError::WrongSecret);
        }
        // Aquire a write lock on connected_remotes to insert the new connection. Note we still
        // need to hold the read lock on registered hosts, as otherwise there is a potential race
        // condition where `host` is unregsitered before the new data is inserted in connected
        // hosts. We only grab this lock after the above checks to avoid contention here as much as
        // possible, as this map is also used whenever a new frontend connection is identified.
        let mut connected_remotes = self.connected_hosts.blocking_write();
        // Extract existing measurements, in case we already have a live client for this host. The
        // client will be replaced regardless. We use remove for this, as we will end up replacing
        // the data anyway, and by removing we take ownership of the data, avoiding making a copy
        // of the Arc and bumping its refcount. This is ever so slightly more performant.
        let bandwidth = if let Some((_, bandwidth)) = connected_remotes.remove(host) {
            bandwidth
        } else {
            Arc::new(Bandwidth::new())
        };
        connected_remotes.insert(host.to_string(), (remote, bandwidth));

        Ok(())
    }

    /// Request a new connection for a given host. This function will request a connected client
    /// for the host to open a new connection. If no client is connected, or the host is otherwise
    /// unknown to the proxy, an error is returned.
    async fn request_connection<'a>(
        &self,
        host: &'a str,
    ) -> Result<(TcpStream, Arc<Bandwidth>), ProxyError<'a>> {
        let connected_hosts = self.connected_hosts.read().await;
        // Check if we know this host. Note that we don't check the registered hosts, but only
        // the ones for which a client is connected, as a known host without connected client
        // will have the same result as an unknown host, i.e. a closed connection.
        if let Some((remote, bandwidth)) = connected_hosts.get(host) {
            // Generate secret
            let secret: [u8; 32] = rand::thread_rng().gen();
            // Insert secret in map with pending connections, with value oneshot channel to return
            // the stream.
            let (tx, mut rx) = oneshot::channel();
            {
                let mut pending_connections = self.pending_proxy_connections.lock().await;
                pending_connections.insert(secret, tx);
            } // drop the MutexGuard on pending connections.
              // TODO: return a proper eror here.
            remote.request_connection(secret).await.expect("TODO");
            match timeout(self.backend_connection_timeout, &mut rx).await {
                // The pending connection map should be cleaned up in the code handling the
                // incoming connection.
                Ok(Ok(con)) => Ok((con, Arc::clone(&bandwidth))),
                Ok(Err(_)) => {
                    error!("Oneshot channel closed without sending value, this should not happen!");
                    unreachable!();
                }
                Err(_) => {
                    debug!("Client did not open a new connection in time");
                    // Clean up the pending connections
                    let mut pending_connections = self.pending_proxy_connections.lock().await;
                    // There is a possible race condition here: the timeout fires, while the client is
                    // already connected and sending the secret. The pending connection mutex is
                    // locked, and the connection is sent on the channel. Then this code tries to clean
                    // up the channel (even though it is already gone). The result is the connection is
                    // established and in the channel. So if tx is gone, we try one more time to see if
                    // a connection is on the channel, and if so we still accept it.
                    if pending_connections.remove(&secret).is_none() {
                        if let Ok(con) = rx.try_recv() {
                            return Ok((con, Arc::clone(bandwidth)));
                        }
                    }
                    Err(ProxyError::ClientTimeout)
                }
            }
        } else {
            Err(ProxyError::ClientNotConnected { host })
        }
    }
}

/// Request to a client to open a new proxy connection. It contains all the required information
/// for the client to set up the connection both to the server and the remote service.
// TODO: Check if we can replace the `String`s here with &'a str.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyConnectionRequest {
    /// Hex encoded connection secret.
    secret: String,
    /// Host we are connecting to. This might be needed in case multiple hosts are connected from
    /// the same client, but could be ignored for now.
    host: String,
    /// The port the initial connection came in on.
    port: u16,
    /// The port the server is listening on for client connections.
    server_listening_port: u16,
}

#[derive(Debug)]
pub enum ProxyError<'a> {
    /// No client connected for the given host.
    ClientNotConnected { host: &'a str },
    /// Timeout waiting for the client to open a new proxy connection.
    ClientTimeout,
}

impl<'a> Display for ProxyError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientNotConnected { host } => {
                f.write_str("there is no connected client for host ")?;
                f.write_str(host)
            }
            Self::ClientTimeout => f.write_str("client did not open a new connection in time"),
        }
    }
}

impl<'a> std::error::Error for ProxyError<'a> {}

#[derive(Debug)]
pub enum ProxyClientError<'a> {
    UnknownHost { host: &'a str },
    WrongSecret,
}

impl<'a> Display for ProxyClientError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownHost { host } => {
                f.write_str("unknown host ")?;
                f.write_str(host)
            }
            Self::WrongSecret => f.write_str("wrong secret used to authenticate client"),
        }
    }
}

impl<'a> std::error::Error for ProxyClientError<'a> {}

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

impl Display for DuplicateHostRegistration {
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
