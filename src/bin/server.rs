use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{self, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn, Level};
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
/// Default port for the HTTP API.
const DEFAULT_SERVER_API_PORT: u16 = 8080;

/// Web gateway server
///
/// Command line options for the server.
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Opts {
    /// IP used for the jsonrpc p2p communication. This is IP must be reachable for clients.
    #[arg(long, default_value_t = DEFALT_RPC_IP)]
    rpc_ip: IpAddr,
    /// Port used for the jsonrpc p2p communication. This is the port clients will connect on.
    #[arg(long, default_value_t = DEFAULT_SERVER_RPC_PORT)]
    rpc_port: u16,
    /// Port used for the HTTP API.
    #[arg(long, default_value_t = DEFAULT_SERVER_API_PORT)]
    api_port: u16,
    /// Enable debug logging.
    #[arg(short, long)]
    debug: bool,
    /// Enable trace logging. This is very verbose (implies --debug).
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

    let proxy = Proxy::new();
    let core = CoreServer::new(proxy);

    // Get a reference to the state for the command server.
    let server_state = core.proxy();

    tokio::spawn(async move {
        let proxy_router = Router::new()
            .route("/", get(list_hosts))
            .route("/", post(add_host))
            .route("/:host", delete(remove_host))
            .with_state(server_state);

        let api_router_v1 = Router::new().nest("/proxy", proxy_router);

        let app = Router::new().nest("/api/v1", api_router_v1);

        let api_server_address: SocketAddr =
            (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), args.api_port).into();

        info!("Starting HTTP API server on {}", api_server_address);

        match axum::Server::bind(&api_server_address)
            .serve(app.into_make_service())
            .await
        {
            Ok(()) => info!("HTTP API server exited normally"),
            Err(e) => error!("HTTP API server terminated with error {}", e),
        };
    });

    let handle = jsonrpsee::server::ServerBuilder::new()
        .ws_only()
        .ping_interval(PING_INTERVAL)
        .max_connections(SERVER_MAX_CONNECTIONS)
        .set_id_provider(jsonrpsee::server::RandomIntegerIdProvider)
        .max_request_body_size(MAX_MESSAGE_BODY_SIZE)
        .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
        .build((args.rpc_ip, args.rpc_port))
        .await?
        .start(core.into_rpc())?;

    // Wait for Ctrl-c
    tokio::signal::ctrl_c().await?;
    info!("Received SIGINT, exiting");
    handle.stop()?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddHost {
    host: String,
    hex_secret_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostInfo {
    host: String,
    hex_secret_hash: String,
    read: u64,
    written: u64,
}

/// Add a new host to the server with the configured secret, after which the server can accept
/// subscriptions for this host.
async fn add_host(
    State(state): State<Arc<Proxy>>,
    extract::Json(data): extract::Json<AddHost>,
) -> impl IntoResponse {
    let mut secret = [0; 32];
    if let Err(e) = faster_hex::hex_decode(data.hex_secret_hash.as_bytes(), &mut secret) {
        warn!(
            "Could not decode hex value {} to 32 byte hash secret: {}",
            data.hex_secret_hash, e
        );
        return StatusCode::BAD_REQUEST;
    }

    match state.register_host(data.host, secret).await {
        Ok(()) => {
            info!("Registered new host");
            StatusCode::OK
        }
        Err(_) => {
            warn!("Trying to register new host with a different secret");
            StatusCode::CONFLICT
        }
    }
}

/// Delete a host from the server. No new connections can be established to the backend through
/// this server.
async fn remove_host(
    State(state): State<Arc<Proxy>>,
    Path(host): Path<String>,
) -> impl IntoResponse {
    if let Some((secret_hash, bandwidth)) = state.unregister_host(&host).await {
        info!(
            "Removed host {} from proxy with registered secret hash {}, read {} bytes, wrote {} bytes",
            host,
            faster_hex::hex_string(&secret_hash),
            bandwidth.read(),
            bandwidth.written(),

        );
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    }
}

/// Lists all hosts currently configured on the server.
async fn list_hosts(State(state): State<Arc<Proxy>>) -> (StatusCode, Json<Vec<HostInfo>>) {
    let data = state
        .list_hosts()
        .await
        .into_iter()
        .map(|(host, secret_hash, bandwidth)| HostInfo {
            host,
            hex_secret_hash: faster_hex::hex_string(&secret_hash),
            read: bandwidth.read(),
            written: bandwidth.written(),
        })
        .collect();
    (StatusCode::OK, Json(data))
}
