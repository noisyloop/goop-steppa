//! Seam for per-application attribution (which process made a query).
//!
//! Out of scope for v1. A future implementation (e.g. eBPF tracing of `connect`/`sendto`
//! on port 53, correlated by source port) can implement [`ProcessAttributor`] and be
//! plugged into the handler without touching the rest of the pipeline.

use std::net::SocketAddr;

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
}

pub trait ProcessAttributor: Send + Sync + 'static {
    /// Look up the process that sent a query from `client`. `None` = unknown.
    fn attribute(&self, client: SocketAddr) -> Option<ProcessInfo>;
}

/// Default: no attribution.
pub struct NoAttribution;

impl ProcessAttributor for NoAttribution {
    fn attribute(&self, _client: SocketAddr) -> Option<ProcessInfo> {
        None
    }
}
