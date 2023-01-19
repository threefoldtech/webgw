use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use crate::web_proxy::{
    ConnectedRemote, Proxy, ProxyClient, ProxyClientError, ProxyConnectionRequest,
};
use jsonrpsee::{
    core::client::IdKind,
    proc_macros::rpc,
    types::{error::ErrorCode, ErrorObjectOwned, SubscriptionEmptyError},
    ws_client::WsClientBuilder,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, time};
use tracing::{debug, error, info, trace, warn};

/// Maximum size for a request body. This should be large enough to fit the maximum amount of data
/// required by a single call, and protocol overhead.
pub const MAX_MESSAGE_BODY_SIZE: u32 = 1024;
/// Maximum size for a respone body. This should be large enough to fit the maximum amount of data
/// required by a single response, and protocol overhead.
pub const MAX_RESPONSE_BODY_SIZE: u32 = 512;

/// Minimum size in bytes of a secret.
pub const SECRET_MINIMUM_SIZE: usize = 32;
/// Maximum size in bytes of a secret;
pub const SECRET_MAXIMUM_SIZE: usize = 256;

/// Amount of seconds between client pings.
const PING_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum amount of time to wait for a request to be processed by the server.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum amount of time to connect to the server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum amount of proxy requests to buffer per client.
const PROXY_CONNECT_BUFFER_SIZE: usize = 1;

#[rpc(client, server)]
pub trait Protocol {
    /// Registers a new client to the webgw server. The host is the domain name to register, the
    /// secret is the hex encoded plain secret. This secret will be decoded and then hashed by the
    /// server. Only if this hashed secret matches the secret hash configured in the server will
    /// the client be accepted.
    #[subscription(name = "webgw_registerClient", unsubscribe = "webgw_unregisterClient", item = ProxyConnectionRequest, param_kind = map)]
    fn subscribe_proxy_connections(&self, host: &str, hex_secret: &str);
}

#[derive(Debug)]
pub struct CoreServer {
    proxy: Arc<Proxy>,
}

#[derive(Debug)]
pub struct CoreClient {
    proxy_client: ProxyClient,
    proxies: Vec<ProxyConnectionConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoreClientConfig {
    proxy: ProxyClientConfig,
}

/// Configuration for the [`ProxyClient`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyClientConfig {
    port_map: Option<HashMap<u16, u16>>,
    proxies: Option<Vec<ProxyConnectionConfig>>,
}

/// Configuration for a single host on a proxy.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyConnectionConfig {
    /// Hostname to proxy.
    host: String,
    /// Secret, hex encoded, for the host on the given proxy.
    hex_secret: String,
    address: SocketAddr,
}

impl CoreClient {
    /// Create a new CoreClient from the given [`CoreClientConfig`].
    pub fn new(config: CoreClientConfig) -> Self {
        Self {
            proxy_client: ProxyClient::new(config.proxy.port_map.unwrap_or_default()),
            proxies: config.proxy.proxies.unwrap_or_default(),
        }
    }

    /// Connect the client to the defined servers in the config. If not servers are defined, this
    /// function will exit immediately.
    ///
    /// This function launches all clients and disjoins them, meaning it will exit as soon as all
    /// clients have spawned. Individual clients will periodically reconnect if the connection
    /// breaks.
    pub async fn connect(self) -> Result<(), Box<dyn std::error::Error>> {
        if self.proxies.is_empty() {
            warn!("No proxies defined in the client, exiting");
            return Ok(());
        }
        debug!("Starting client connections");

        // Gather entries per proxy
        let mut hosts_per_proxy = HashMap::new();
        for entry in self.proxies {
            hosts_per_proxy
                .entry(entry.address)
                .or_insert_with(Vec::new)
                .push((entry.host, entry.hex_secret))
        }

        let proxy_client = Arc::new(self.proxy_client);

        for (remote, host_configs) in hosts_per_proxy {
            let proxy_client = Arc::clone(&proxy_client);
            tokio::spawn(async move {
                loop {
                    let client = match WsClientBuilder::default()
                        .id_format(IdKind::Number)
                        .ping_interval(PING_INTERVAL)
                        .request_timeout(REQUEST_TIMEOUT)
                        .connection_timeout(CONNECT_TIMEOUT)
                        .max_request_body_size(MAX_MESSAGE_BODY_SIZE)
                        .build(&format!("ws://{}", remote))
                        .await
                    {
                        Ok(client) => {
                            trace!("Client connected to {}", remote);
                            Arc::new(client)
                        }
                        Err(e) => {
                            error!("Could not connect to client: {}", e);
                            trace!("Attempting next connection in 60 seconds");
                            time::sleep(Duration::from_secs(60)).await;
                            continue;
                        }
                    };

                    if !client.is_connected() {
                        error!("Client is not connected");
                        continue;
                    }

                    trace!("Client connected to proxy");

                    // Start subscribtions
                    for (host, hex_secret) in host_configs.clone() {
                        let client = Arc::clone(&client);
                        let proxy_client = Arc::clone(&proxy_client);
                        tokio::spawn(async move {
                            'outer: loop {
                                let mut sub = match client
                                    .subscribe_proxy_connections(&host, &hex_secret)
                                    .await
                                {
                                    Ok(sub) => {
                                        trace!(
                                            "Opened subscription for host {} to {}",
                                            host,
                                            remote
                                        );
                                        sub
                                    }
                                    Err(e) => {
                                        error!(
                                            "Could not subscribe for host {} on {}: {}",
                                            host, remote, e
                                        );
                                        time::sleep(Duration::from_secs(60)).await;
                                        continue;
                                    }
                                };

                                while let Some(request) = sub.next().await {
                                    match request {
                                        Ok(request) => {
                                            if let Err(e) = proxy_client
                                                .proxy_connection_request(remote.ip(), request)
                                                .await
                                            {
                                                error!("Could not proxy request: {}", e);
                                                time::sleep(Duration::from_secs(10)).await;
                                                continue 'outer;
                                            }
                                            trace!("Proxy connection established");
                                        }
                                        Err(e) => {
                                            error!("Subscription error {}", e);
                                            time::sleep(Duration::from_secs(10)).await;
                                            continue 'outer;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    // Wait untill the client is disconnected to retry the connection
                    client.on_disconnect().await;
                    time::sleep(Duration::from_secs(5)).await;
                }
            });
        }

        Ok(())
    }
}

impl CoreServer {
    /// Create a new CoreServer from the individual components.
    pub fn new(proxy: Proxy) -> Self {
        let proxy = Arc::new(proxy);
        let p = Arc::clone(&proxy);
        tokio::spawn(async move {
            info!("Spawning proxy backend listener");
            if let Err(e) = p.listen_backend_connection().await {
                error!("Failed to listen for proxy backend connections: {}", e);
            }
        });
        let p = Arc::clone(&proxy);
        tokio::spawn(async move {
            info!("Spawning proxy HTTP listener");
            if let Err(e) = p.listen_http().await {
                error!("Failed to listen for proxy HTTP connections: {}", e);
            }
        });
        Self { proxy }
    }

    /// Get a handle to the [`Proxy`].
    pub fn proxy(&self) -> Arc<Proxy> {
        Arc::clone(&self.proxy)
    }
}

impl ProtocolServer for CoreServer {
    // TODO: See if it is better to avoid the block_in_place call by spawning a task with an mpsc,
    // and only sending the received items here to the task which would then be properly async.
    fn subscribe_proxy_connections(
        &self,
        mut subscription_sink: jsonrpsee::SubscriptionSink,
        host: &str,
        hex_secret: &str,
    ) -> jsonrpsee::types::SubscriptionResult {
        debug!("Attempting to accept new client subscription for {}", host);
        if hex_secret.len() > SECRET_MAXIMUM_SIZE * 2 || hex_secret.len() < SECRET_MINIMUM_SIZE * 2
        {
            debug!(
                "Client connection for host {} failed, secret size is invalid",
                host
            );
            // Error here is fine since it means the client is gone anyway.
            let _ = subscription_sink.reject(ErrorCode::InvalidParams);
            return Err(SubscriptionEmptyError);
        }
        // Decode secret
        let mut secret = [0; SECRET_MAXIMUM_SIZE];
        // hex_secret.len() might be odd here, which is invalid hex and will be caught by the actual
        // decoding function.
        let secret_size = hex_secret.len() / 2;
        if let Err(e) = faster_hex::hex_decode(hex_secret.as_bytes(), &mut secret[..secret_size]) {
            debug!("Client connection for host {} failed: {}", host, e);
            // Error here is fine since it means the client is gone anyway.
            let _ = subscription_sink.reject(ErrorCode::InvalidParams);
            return Err(SubscriptionEmptyError);
        };

        let (tx, mut rx) = mpsc::channel(PROXY_CONNECT_BUFFER_SIZE);
        let result = tokio::task::block_in_place(|| {
            self.proxy.register_client_blocking(
                host,
                &secret[..secret_size],
                ConnectedRemote::new(tx),
            )
        });

        match result {
            Err(e) => {
                debug!("Failed to register client for host {host}: {e}");
                let _ = subscription_sink.reject(e);
                Err(SubscriptionEmptyError)
            }
            Ok(()) => {
                if let Err(e) = subscription_sink.accept() {
                    debug!("Failed to accept client subscription: remote hung up");
                    return Err(e.into());
                }
                tokio::spawn(async move {
                    loop {
                        while let Some(request) = rx.recv().await {
                            match subscription_sink.send(&request) {
                                Ok(true) => {
                                    trace!("Requested new connection from remote");
                                }
                                Ok(false) => {
                                    // We explicitly accepted the subscription already, so this
                                    // must mean the remote is gone.
                                    debug!("Could not request proxy connection: remote hung up");
                                    return;
                                }
                                Err(e) => {
                                    error!("Couldn't serialize message: {}", e);
                                    // All messages have the same structure so this is a terminal
                                    // condition.
                                    subscription_sink.close(ErrorCode::InternalError);
                                    return;
                                }
                            }
                        }
                    }
                });
                Ok(())
            }
        }
    }
}

impl CoreClient {}

impl<'a> From<ProxyClientError<'a>> for ErrorObjectOwned {
    fn from(value: ProxyClientError<'a>) -> Self {
        match value {
            ProxyClientError::UnknownHost { host } => Self::owned(
                UNKNOWN_HOST_ERROR_CODE,
                UNKNOWN_HOST_MSG,
                Some(format!("Host {host} is not currently known on the server")),
            ),
            ProxyClientError::WrongSecret => Self::owned(
                WRONG_SECRET_ERROR_CODE,
                WRONG_SECRET_MSG,
                Some("Provided secret does not match the configured secret for the host"),
            ),
        }
    }
}

/// Unknown host error code.
const UNKNOWN_HOST_ERROR_CODE: i32 = -20_000;
/// Wrong secret error code.
const WRONG_SECRET_ERROR_CODE: i32 = -20_001;

/// Unknown host error message
const UNKNOWN_HOST_MSG: &str = "Unknown host";
/// Unknown host error message
const WRONG_SECRET_MSG: &str = "Wrong secret";
