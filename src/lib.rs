/// Wrappers for metered connections.
pub mod bandwidth;
/// Protocol definitions for p2p behavior.
pub mod core;
/// Sniffers for network protocols.
pub mod sniffer;
/// Generic L4 (tcp) proxy, using sniffers to identify web traffic and proxy it to a registered
/// client.
pub mod web_proxy;

#[cfg(test)]
mod tests {}
