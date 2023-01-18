use std::{net::IpAddr, time::Duration};

use clap::Parser;
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

/// The default server rpc port. This is the only port we need to know to operate with a server.
const DEFAULT_SERVER_RPC_PORT: u16 = 9080;

/// Web gateway client
///
/// Command line options for the client.
// TODO: This will be replaced mostly by a config file.
#[derive(Parser)]
struct Opts {
    /// IP used by the server. This is IP must be reachable from this host.
    #[arg(long)]
    server_ip: IpAddr,
    /// Port used by the server for the jsonrpc p2p communication. This is the we will connect on.
    #[arg(long)]
    server_rpc_port: Option<u16>,
    /// Enable debug logging.
    #[arg(short, long)]
    debug: bool,
    /// Enable trace logging. This is very verbose.
    #[arg(short, long)]
    trace: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Opts::parse();

    let level = if args.trace {
        Level::TRACE
    } else if args.debug {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(true)
        .with_target(true)
        .init();

    let server_rpc_port = if let Some(port) = args.server_rpc_port {
        port
    } else {
        DEFAULT_SERVER_RPC_PORT
    };

    let client = WsClientBuilder::default()
        .id_format(IdKind::Number)
        .ping_interval(PING_INTERVAL)
        .request_timeout(REQUEST_TIMEOUT)
        .connection_timeout(CONNECT_TIMEOUT)
        .max_request_body_size(MAX_MESSAGE_BODY_SIZE)
        .build(&format!("ws://{}:{}", args.server_ip, server_rpc_port))
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
