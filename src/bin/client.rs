use std::time::Duration;

use jsonrpsee::{core::client::IdKind, ws_client::WsClientBuilder};
use tokio::select;
use tracing::{error, info, Level};
use webgw::core::{ProtocolClient, MAX_MESSAGE_BODY_SIZE};

/// Amount of seconds between client pings.
const PING_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum amount of time to wait for a request to be processed by the server.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum amount of time to connect to the server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Temporary testing.
const SERVER_URL: &str = "ws://localhost:9080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(true)
        .with_target(true)
        .init();

    let client = WsClientBuilder::default()
        .id_format(IdKind::Number)
        .ping_interval(PING_INTERVAL)
        .request_timeout(REQUEST_TIMEOUT)
        .connection_timeout(CONNECT_TIMEOUT)
        .max_request_body_size(MAX_MESSAGE_BODY_SIZE)
        .build(SERVER_URL)
        .await?;

    if !client.is_connected() {
        error!("Client is not connected");
        panic!("Client not connected");
    }

    let mut sub = client
        .subscribe_proxy_connections(
            "www.example.com",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .await?;

    select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = client.on_disconnect() => {},
        Some(Ok(_notif)) = sub.next() => {
            info!("Got a new subscription, should probably open a connection at this point");
        }
    }

    Ok(())
}
