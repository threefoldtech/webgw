use std::sync::Arc;

use crate::web_proxy::{ConnectedRemote, Proxy, ProxyClientError, ProxyConnectionRequest};
use jsonrpsee::{
    proc_macros::rpc,
    types::{error::ErrorCode, ErrorObjectOwned, SubscriptionEmptyError},
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

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
}

impl ProtocolServer for CoreServer {
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
        let result = self.proxy.register_client_blocking(
            host,
            &secret[..secret_size],
            ConnectedRemote::new(tx),
        );

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
