use std::{
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

use clap::Parser;
use tracing::{info, Level};
use webgw::{
    core::{CoreServer, ProtocolServer, MAX_MESSAGE_BODY_SIZE, MAX_RESPONSE_BODY_SIZE},
    web_proxy::Proxy,
};

/// Amount of seconds between server pings.
const PING_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum amount of connections the server accepts.
const SERVER_MAX_CONNECTIONS: u32 = 10_000;
/// Default IP address to bind the JSONRPC socket to, used for p2p communications.
const DEFALT_RPC_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
/// Default port for the JSONRPC socket, used for p2p communications.
const DEFAULT_SERVER_RPC_PORT: u16 = 9080;

/// Web gateway server
///
/// Command line options for the server.
#[derive(Parser)]
struct Opts {
    /// IP used for the jsonrpc p2p communication. This is IP must be reachable for clients.
    #[arg(long)]
    rpc_ip: Option<IpAddr>,
    /// Port used for the jsonrpc p2p communication. This is the port clients will connect on.
    #[arg(long)]
    rpc_port: Option<u16>,
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

    let rpc_server_ip = if let Some(ip) = args.rpc_ip {
        ip
    } else {
        DEFALT_RPC_IP
    };
    let rpc_server_port = if let Some(port) = args.rpc_port {
        port
    } else {
        DEFAULT_SERVER_RPC_PORT
    };

    let proxy = Proxy::new();
    let core = CoreServer::new(proxy);

    let handle = jsonrpsee::server::ServerBuilder::new()
        .ws_only()
        .ping_interval(PING_INTERVAL)
        .max_connections(SERVER_MAX_CONNECTIONS)
        .set_id_provider(jsonrpsee::server::RandomIntegerIdProvider)
        .max_request_body_size(MAX_MESSAGE_BODY_SIZE)
        .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
        .build((rpc_server_ip, rpc_server_port))
        .await?
        .start(core.into_rpc())?;

    // Wait for Ctrl-c
    tokio::signal::ctrl_c().await?;
    info!("Received SIGINT, exiting");
    handle.stop()?;

    Ok(())
}
