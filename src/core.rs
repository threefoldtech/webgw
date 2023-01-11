use async_trait::async_trait;
use jsonrpsee::async_client::ClientBuilder;
use jsonrpsee::core::{client::Subscription, Error};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, SubscriptionSink};
use jsonrpsee::types::SubscriptionResult;
use jsonrpsee::ws_client::WsClientBuilder;
use serde::{Deserialize, Serialize};

#[rpc(server, client, namespace = "core")]
pub trait Rpc {
    /// Create a new subscription for incoming connections on the tcp proxy. Whenever a new
    /// connection comes in, a notificiation is sent to the client, which will request to open a
    /// new plain tcp connection to the server. A secret will also be included which must be sent
    /// first on the connection, to identify the target.
    #[subscription(name = "tcpProxy_register" => "tcpProxy_proxyOpen", unsubscribe = "tcpProxy_unsubscribe", item = ProxyRequest, param_kind = map)]
    fn register_web_proxy(&self, name: String, secret: String);
}

#[async_trait]
impl RpcServer for Core {
    fn register_web_proxy(
        &self,
        mut sink: SubscriptionSink,
        name: String,
        secret: String,
    ) -> SubscriptionResult {
        todo!();
        Ok(sink.accept()?)
    }
}

pub struct Core {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyRequest {}
