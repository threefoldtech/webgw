use std::path::PathBuf;

use clap::Parser;
use tokio::fs;
use tracing::{info, Level};
use webgw::core::CoreClient;

/// Web gateway client
///
/// Command line options for the client.
// TODO: This will be replaced mostly by a config file.
#[derive(Parser)]
struct Opts {
    /// Path to the configuration file.
    #[arg(short, long)]
    config: PathBuf,
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

    info!("Loading config from {}", args.config.display());

    let config = toml::from_str(&fs::read_to_string(args.config).await?)?;

    let client = CoreClient::new(config);

    client.connect().await?;

    tokio::signal::ctrl_c().await?;

    info!("Got SIGINT, shutting down");

    Ok(())
}
