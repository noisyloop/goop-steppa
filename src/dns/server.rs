//! The local DNS server: receives queries, decides, forwards or sinkholes.

use super::attribution::{NoAttribution, ProcessAttributor};
use super::upstream::Upstream;
use crate::category::{Action, Verdict};
use crate::config::ServerConfig;
use anyhow::{Context, Result};
use hickory_proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use hickory_server::Server;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

/// Decides what to do with a domain. Stage 2 plugs the real filter engine in here.
pub type Decider = Arc<dyn Fn(&str) -> Verdict + Send + Sync>;

const BLOCK_TTL: u32 = 60;

pub struct Handler {
    upstream: Upstream,
    decide: Decider,
    #[allow(dead_code)] // seam for per-process attribution (post-v1)
    attributor: Arc<dyn ProcessAttributor>,
}

impl Handler {
    pub fn new(upstream: Upstream, decide: Decider) -> Self {
        Self { upstream, decide, attributor: Arc::new(NoAttribution) }
    }
}

/// Lowercased, no trailing dot.
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut meta = Metadata::response_from_request(&request.metadata);
        meta.recursion_available = true;

        let info = match request.request_info() {
            Ok(i) => i,
            Err(_) => {
                let r = builder.error_msg(&request.metadata, ResponseCode::FormErr);
                return response_handle.send_response(r).await.unwrap_or_else(|_| servfail(request));
            }
        };
        let qname = info.query.original().name.clone();
        let qtype = info.query.query_type();
        let domain = normalize(&qname.to_string());
        let verdict = (self.decide)(&domain);
        tracing::debug!(%domain, ?qtype, action = verdict.action.as_str(), category = %verdict.category, "query");

        let result = if verdict.action == Action::Blocked {
            let rec: Option<Record> = match qtype {
                RecordType::A => Some(Record::from_rdata(qname, BLOCK_TTL, RData::A(A(Ipv4Addr::UNSPECIFIED)))),
                RecordType::AAAA => Some(Record::from_rdata(qname, BLOCK_TTL, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)))),
                _ => None, // other types: NOERROR with empty answer
            };
            let answers: Vec<Record> = rec.into_iter().collect();
            let r = builder.build(meta, answers.iter(), [], [], []);
            response_handle.send_response(r).await
        } else {
            match self.upstream.lookup(qname, qtype).await {
                Ok(lookup) => {
                    let msg = lookup.message();
                    let r = builder.build(
                        meta,
                        msg.answers.iter(),
                        msg.authorities.iter(),
                        [],
                        [],
                    );
                    response_handle.send_response(r).await
                }
                Err(e) => {
                    meta.response_code = if e.is_nx_domain() {
                        ResponseCode::NXDomain
                    } else if e.is_no_records_found() {
                        ResponseCode::NoError
                    } else {
                        tracing::warn!(%domain, error = %e, "upstream failure");
                        ResponseCode::ServFail
                    };
                    let r = builder.build_no_records(meta);
                    response_handle.send_response(r).await
                }
            }
        };
        match result {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(error = %e, "failed to send response");
                servfail(request)
            }
        }
    }
}

fn servfail(request: &Request) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header { metadata, counts: HeaderCounts::default() })
}

/// Bind UDP+TCP and serve until `shutdown` resolves.
pub async fn serve(cfg: &ServerConfig, handler: Handler, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
    let addr = SocketAddr::new(cfg.listen, cfg.port);
    let udp = UdpSocket::bind(addr).await.map_err(|e| bind_err(e, addr))?;
    let tcp = TcpListener::bind(addr).await.map_err(|e| bind_err(e, addr))?;
    let mut server = Server::new(handler);
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(5), 4096);
    tracing::info!("DNS listening on {addr} (udp+tcp)");
    tokio::select! {
        r = server.block_until_done() => { r.context("DNS server stopped")?; }
        _ = shutdown => {
            tracing::info!("shutting down");
            let _ = server.shutdown_gracefully().await;
        }
    }
    Ok(())
}

fn bind_err(e: std::io::Error, addr: SocketAddr) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "cannot bind {addr}: permission denied.\n  \
             Use an unprivileged port (--port 5353), or grant the capability:\n  \
             sudo setcap 'cap_net_bind_service=+ep' $(command -v goop-steppa)"
        )
    } else if e.kind() == std::io::ErrorKind::AddrInUse {
        anyhow::anyhow!(
            "cannot bind {addr}: address in use (systemd-resolved's stub listener owns 127.0.0.53:53; \
             something else owns {addr}). Try --port 5353."
        )
    } else {
        anyhow::Error::new(e).context(format!("binding {addr}"))
    }
}
