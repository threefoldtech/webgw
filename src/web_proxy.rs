use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;
use std::{collections::HashMap, time::Duration};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::select;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex, RwLock},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::bandwidth::{Bandwidth, MeasuredConnection};
use crate::sniffer::{HTTPSniffer, TLSSniffer};

/// Hash of the secret is a SHA256 digest.
pub type SecretHash = [u8; 32];

/// Type of a connection secret, which is used to identify connections made from clients to the
/// proxy to actually proxy a frontend connection.
pub type ConnectionSecret = [u8; CONNECTION_SECRET_SIZE];

/// SHA256 hasher (32 byte digest).
type Hasher = Sha256;

/// Default port to listen on for HTTP connections.
const HTTP_PORT: u16 = 80;
/// Default port to listen on for TLS connections.
const TLS_PORT: u16 = 443;
/// Default port to listen for client connections.
const DEFAULT_CLIENT_PORT: u16 = 4658;

/// Amount of bytes used for a ConnectionSecret.
pub const CONNECTION_SECRET_SIZE: usize = 32;

/// A generic TCP proxy, extended with sniffers for incoming traffic.
#[derive(Debug)]
pub struct Proxy {
    /// Host names for which a client is connected
    connected_hosts: RwLock<HashMap<String, ConnectedRemote>>,
    /// All hosts registered in the proxy, with associated info
    registered_hosts: RwLock<HashMap<String, HostInfo>>,
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
    /// The port the server is listening on for client connection.
    server_client_port: u16,
}

/// Required info for a connected host
#[derive(Debug)]
struct HostInfo {
    secret_hash: SecretHash,
    bandwidth: Arc<Bandwidth>,
    cancellation_token: CancellationToken,
}

/// Client implementation for the [`Proxy`].
#[derive(Debug)]
pub struct ProxyClient {
    /// Map ports on the proxy to local ports.
    port_map: HashMap<u16, u16>,
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
            server_client_port: DEFAULT_CLIENT_PORT,
        }
    }

    /// Listen for incoming TCP connections from clients. These connections are the result of
    /// requesting a new connection to be opened from the client by the proxy, in repsonse to a new
    /// frontend connection coming in, and being identified as being hosted by said client. This
    /// function blocks until the listener fails to accept a connection.
    pub async fn listen_backend_connection(&self) -> Result<(), io::Error> {
        info!(
            "Binding TCP listener on port {} for backend connections",
            self.server_client_port
        );
        let listener = TcpListener::bind(("::", self.server_client_port)).await?;
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
        info!(
            "Binding TCP listener on port {} for HTTP connections",
            HTTP_PORT
        );
        let listener = TcpListener::bind(("::", HTTP_PORT)).await?;
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

            // Scope this, so we drop the read lock on registered hosts early.
            let (bandwidth, token) = {
                let registered_hosts = self.registered_hosts.read().await;
                if let Some(info) = registered_hosts.get(host) {
                    (Arc::clone(&info.bandwidth), info.cancellation_token.clone())
                } else {
                    debug!("Can't get bandwith meters for unknown host {}", host);
                    continue;
                }
            };

            match self.request_connection(host, HTTP_PORT).await {
                Ok(backend_con) => {
                    trace!(
                        "Got new proxy ready connection for {}, dumping {} byte sniffer buffer",
                        host,
                        buf_size
                    );
                    // Add bandwidth counters to backend connection.
                    let mut backend_con =
                        MeasuredConnection::with_bandwidth(backend_con, bandwidth);
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

                    tokio::spawn(async move {
                        select! {
                            biased;
                            _ = token.cancelled() => {
                                trace!("Cancelling proxy as token is cancelled");
                            }
                            res = io::copy_bidirectional(&mut frontend_con, &mut backend_con) => {
                                if let Err(e) = res {
                                    debug!(
                                        "Error while proxying data between frontend and backend: {}",
                                        e
                                    );
                                }
                            }
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

    /// Listen for incoming TLS connections, attempt to identify them, and if successful, attempt
    /// to proxy them to a connected client, if any. If not client is connected for the host, or
    /// the host is not known, the connection is closed. This function blocks until the listener
    /// fails to accept a connection.
    pub async fn listen_tls(&self) -> Result<(), io::Error> {
        info!(
            "Binding TCP listener on port {} for TLS connections",
            TLS_PORT,
        );
        let listener = TcpListener::bind(("::", TLS_PORT)).await?;
        loop {
            let (frontend_con, remote) = listener.accept().await?;
            debug!("Accepted new presumed TLS connection from {}", remote);
            // Get the target host.
            let mut sniffer = TLSSniffer::new(frontend_con);
            let host = match timeout(self.sniffer_timeout, &mut sniffer).await {
                Ok(Ok(host)) => host,
                Ok(Err(se)) => {
                    debug!("Could not extract TLS SNI header from connection: {}", se);
                    continue;
                }
                Err(_) => {
                    debug!("Incoming connection did not send TLS SNI header in time");
                    continue;
                }
            };

            // Deconstruct the sniffer
            let (buffer, buf_size, mut frontend_con) = sniffer.into_parts();

            // Scope this, so we drop the read lock on registered hosts early.
            let (bandwidth, token) = {
                let registered_hosts = self.registered_hosts.read().await;
                if let Some(info) = registered_hosts.get(host) {
                    (Arc::clone(&info.bandwidth), info.cancellation_token.clone())
                } else {
                    debug!("Can't get bandwith meters for unknown host {}", host);
                    continue;
                }
            };

            match self.request_connection(host, HTTP_PORT).await {
                Ok(backend_con) => {
                    trace!(
                        "Got new proxy ready connection for {}, dumping {} byte sniffer buffer",
                        host,
                        buf_size
                    );
                    // Add bandwidth counters to backend connection.
                    let mut backend_con =
                        MeasuredConnection::with_bandwidth(backend_con, bandwidth);
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

                    tokio::spawn(async move {
                        select! {
                            biased;
                            _ = token.cancelled() => {
                                trace!("Cancelling proxy as token is cancelled");
                            }
                            res = io::copy_bidirectional(&mut frontend_con, &mut backend_con) => {
                                if let Err(e) = res {
                                    debug!(
                                        "Error while proxying data between frontend and backend: {}",
                                        e
                                    );
                                }
                            }
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
        if let Some(info) = registered_hosts.get(&host) {
            if info.secret_hash != secret_hash {
                return Err(DuplicateHostRegistration {
                    host,
                    secret_hash,
                    old_secret_hash: info.secret_hash,
                });
            }
        }
        // It is technically possible that the host is already registered, but then the secret is
        // the same (we checked for a __different__ secret above), so we will silently ignore that
        // and allow this as a NOOP.
        registered_hosts.insert(
            host,
            HostInfo {
                secret_hash,
                bandwidth: Arc::new(Bandwidth::new()),
                cancellation_token: CancellationToken::new(),
            },
        );
        Ok(())
    }

    /// Unregister a host from the Proxy. If the host is known, the secret hash associated is
    /// returned. This can be used for debugging from the call site. This also removes a
    /// connected client, if any. This also returns a copy of the bandwidth measurements, allowing
    /// the caller to get a final count of the stats.
    pub async fn unregister_host(&self, host: &str) -> Option<(SecretHash, Arc<Bandwidth>)> {
        let mut registered_hosts = self.registered_hosts.write().await;
        let mut connected_hosts = self.connected_hosts.write().await;
        connected_hosts.remove(host);
        if let Some(host_info) = registered_hosts.remove(host) {
            host_info.cancellation_token.cancel();
            Some((host_info.secret_hash, host_info.bandwidth))
        } else {
            None
        }
    }

    /// List all currently known hosts on the server allong with their secrets and bandwidth stats.
    pub async fn list_hosts(&self) -> Vec<(String, SecretHash, Arc<Bandwidth>)> {
        let registered_hosts = self.registered_hosts.read().await;
        registered_hosts
            .iter()
            .map(|(host, host_info)| {
                (
                    host.clone(),
                    host_info.secret_hash,
                    Arc::clone(&host_info.bandwidth),
                )
            })
            .collect()
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
        let host_info = match registered_hosts.get(host) {
            Some(value) => value,
            None => return Err(ProxyClientError::UnknownHost { host }),
        };
        if secret_hash.as_slice() != host_info.secret_hash {
            return Err(ProxyClientError::WrongSecret);
        }
        // Aquire a write lock on connected_remotes to insert the new connection. Note we still
        // need to hold the read lock on registered hosts, as otherwise there is a potential race
        // condition where `host` is unregsitered before the new data is inserted in connected
        // hosts. We only grab this lock after the above checks to avoid contention here as much as
        // possible, as this map is also used whenever a new frontend connection is identified.
        let mut connected_remotes = self.connected_hosts.write().await;
        connected_remotes.insert(host.to_string(), remote);

        Ok(())
    }

    /// Unregisters a client for a host. This returns wether a client was present or not.
    pub async fn unregister_client<'a>(&self, host: &str) -> bool {
        let mut connected_hosts = self.connected_hosts.write().await;
        connected_hosts.remove(host).is_some()
    }

    /// Register a client, blocking until the operation completes.
    pub fn register_client_blocking<'a>(
        &self,
        host: &'a str,
        secret: &[u8],
        remote: ConnectedRemote,
    ) -> Result<(), ProxyClientError<'a>> {
        let secret_hash = Hasher::digest(secret);
        let registered_hosts = self.registered_hosts.blocking_read();
        let host_info = match registered_hosts.get(host) {
            Some(value) => value,
            None => return Err(ProxyClientError::UnknownHost { host }),
        };
        if secret_hash.as_slice() != host_info.secret_hash {
            return Err(ProxyClientError::WrongSecret);
        }
        // Aquire a write lock on connected_remotes to insert the new connection. Note we still
        // need to hold the read lock on registered hosts, as otherwise there is a potential race
        // condition where `host` is unregsitered before the new data is inserted in connected
        // hosts. We only grab this lock after the above checks to avoid contention here as much as
        // possible, as this map is also used whenever a new frontend connection is identified.
        let mut connected_remotes = self.connected_hosts.blocking_write();
        connected_remotes.insert(host.to_string(), remote);

        Ok(())
    }

    /// Request a new connection for a given host. This function will request a connected client
    /// for the host to open a new connection. If no client is connected, or the host is otherwise
    /// unknown to the proxy, an error is returned.
    async fn request_connection<'a>(
        &self,
        host: &'a str,
        port: u16,
    ) -> Result<TcpStream, ProxyError<'a>> {
        let connected_hosts = self.connected_hosts.read().await;
        // Check if we know this host. Note that we don't check the registered hosts, but only
        // the ones for which a client is connected, as a known host without connected client
        // will have the same result as an unknown host, i.e. a closed connection.
        if let Some(remote) = connected_hosts.get(host) {
            // Generate secret
            let secret: [u8; 32] = rand::thread_rng().gen();
            // Insert secret in map with pending connections, with value oneshot channel to return
            // the stream.
            let (tx, mut rx) = oneshot::channel();
            {
                let mut pending_connections = self.pending_proxy_connections.lock().await;
                pending_connections.insert(secret, tx);
            } // drop the MutexGuard on pending connections.
            if remote
                .request_connection(secret, port, self.server_client_port)
                .await
                .is_err()
            {
                // Client disconnected
                debug!("Couldn't rquest connection from client, client disconnected");
                return Err(ProxyError::ClientNotConnected { host });
            };
            match timeout(self.backend_connection_timeout, &mut rx).await {
                // The pending connection map should be cleaned up in the code handling the
                // incoming connection.
                Ok(Ok(con)) => Ok(con),
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
                            return Ok(con);
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

impl Default for Proxy {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyClient {
    /// Creates a new ProyClient with the given port mappings.
    pub fn new(port_map: HashMap<u16, u16>) -> Self {
        Self { port_map }
    }

    /// Handle a request to open a new connection to a [`Proxy`]. If this is succesfull, it also
    /// connects to the local process which is being proxied.
    pub async fn proxy_connection_request(
        &self,
        remote: IpAddr,
        request: ProxyConnectionRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut raw_secret = [0; CONNECTION_SECRET_SIZE];
        faster_hex::hex_decode(request.secret.as_bytes(), &mut raw_secret[..])?;

        trace!("Opening new connection to proxy");
        let mut frontend_con = TcpStream::connect((remote, request.server_listening_port)).await?;

        trace!("Writing connection secret");
        frontend_con.write_all(&raw_secret).await?;
        frontend_con.flush().await?;

        // Check if we have a local port override.
        let target_port = if let Some(port) = self.port_map.get(&request.port) {
            *port
        } else {
            request.port
        };
        trace!("Connecting to local server on port {}", target_port);
        let mut backend_con = TcpStream::connect(("localhost", target_port)).await?;

        tokio::spawn(async move {
            if let Err(e) = io::copy_bidirectional(&mut frontend_con, &mut backend_con).await {
                debug!("Error while copying data on proxy connection: {}", e)
            }
        });

        Ok(())
    }
}

/// An abstraction over a connection to a peer. This allows proxy specific communication with the
/// peer.
#[derive(Debug)]
pub struct ConnectedRemote {
    remote: mpsc::Sender<ProxyConnectionRequest>,
}

impl ConnectedRemote {
    /// Create a new ConnectedRemote.
    pub fn new(remote: mpsc::Sender<ProxyConnectionRequest>) -> Self {
        Self { remote }
    }

    /// Request a new connection from the remote
    pub async fn request_connection(
        &self,
        raw_secret: ConnectionSecret,
        port: u16,
        server_listening_port: u16,
    ) -> Result<(), ProxyClientDisconnected> {
        self.remote
            .send(ProxyConnectionRequest {
                secret: faster_hex::hex_string(&raw_secret[..]),
                port,
                server_listening_port,
            })
            .await
            .map_err(|_| ProxyClientDisconnected)
    }
}

/// Request to a client to open a new proxy connection. It contains all the required information
/// for the client to set up the connection both to the server and the remote service.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConnectionRequest {
    /// Hex encoded connection secret.
    secret: String,
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
pub struct ProxyClientDisconnected;

impl Display for ProxyClientDisconnected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to request proxy connection from client, client disconnected")
    }
}

impl std::error::Error for ProxyClientDisconnected {}

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
        let possible_secret = proxy.unregister_host(&host).await.map(|(s, _)| s);
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
        let possible_secret = proxy.unregister_host(&host).await.map(|(s, _)| s);
        assert_eq!(possible_secret, None)
    }

    // This test is here to test compliance with an external tool.
    #[test]
    fn validate_sha256() {
        let output = Hasher::digest([b'V']);
        let hex_output = faster_hex::hex_string(&output);
        assert_eq!(
            hex_output,
            "de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc"
        );
    }
}
