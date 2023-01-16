use crate::web_proxy::{ConnectedRemote, Proxy, ProxyClientError, ProxyConnectionRequest};
use jsonrpsee::{
    proc_macros::rpc,
    types::{error::ErrorCode, ErrorObjectOwned, SubscriptionEmptyError},
};
use tracing::debug;

/// Minimum size in bytes of a secret.
pub const SECRET_MINIMUM_SIZE: usize = 32;
/// Maximum size in bytes of a secret;
pub const SECRET_MAXIMUM_SIZE: usize = 256;

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
    proxy: Proxy,
}

impl CoreServer {}

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
        }
        // Decode secret
        let mut secret = [0; SECRET_MAXIMUM_SIZE];
        // secret.len() might be odd here, which is invalid hex and will be caught by the actual
        // decoding function.
        let secret_size = secret.len() / 2;
        if let Err(e) = faster_hex::hex_decode(hex_secret.as_bytes(), &mut secret[..secret_size]) {
            debug!("Client connection for host {} failed: {}", host, e);
            // Error here is fine since it means the client is gone anyway.
            let _ = subscription_sink.reject(ErrorCode::InvalidParams);
        };
        let result = self.proxy.register_client_blocking(
            host,
            &secret[..secret_size],
            ConnectedRemote::new(subscription_sink),
        );

        match result {
            Err(e) => {
                debug!("Failed to register client for host {host}: {e}");
                Err(SubscriptionEmptyError)
            }
            Ok(()) => Ok(()),
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
