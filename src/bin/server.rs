use std::time::Duration;

use tracing::{info, Level};
use webgw::{
    core::{CoreServer, ProtocolServer, MAX_MESSAGE_BODY_SIZE, MAX_RESPONSE_BODY_SIZE},
    web_proxy::Proxy,
};

/// Amount of seconds between server pings.
const PING_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum amount of connections the server accepts.
const SERVER_MAX_CONNECTIONS: u32 = 10_000;

/// Temporary constant server address.
const SERVER_ADDRESS: (&str, u16) = ("::", 9080);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(true)
        .with_target(true)
        .init();

    let proxy = Proxy::new();
    let core = CoreServer::new(proxy);

    let handle = jsonrpsee::server::ServerBuilder::new()
        .ws_only()
        .ping_interval(PING_INTERVAL)
        .max_connections(SERVER_MAX_CONNECTIONS)
        .set_id_provider(jsonrpsee::server::RandomIntegerIdProvider)
        .max_request_body_size(MAX_MESSAGE_BODY_SIZE)
        .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
        .build(SERVER_ADDRESS)
        .await?
        .start(core.into_rpc())?;

    // Wait for Ctrl-c
    tokio::signal::ctrl_c().await?;
    info!("Received SIGINT, exiting");
    handle.stop()?;

    Ok(())
}
