//! Encrypted upstream forwarding via hickory-resolver.

use crate::config::{UpstreamConfig, UpstreamProtocol};
use anyhow::{bail, Context, Result};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolveHosts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::Resolver;
use std::sync::Arc;

pub type Upstream = Resolver<TokioRuntimeProvider>;

pub fn build(cfg: &UpstreamConfig) -> Result<Upstream> {
    if cfg.servers.is_empty() {
        bail!("upstream.servers is empty");
    }
    let tls_name: Arc<str> = Arc::from(cfg.tls_name.as_str());
    let path: Arc<str> = Arc::from(cfg.doh_path.as_str());
    let servers: Vec<NameServerConfig> = cfg
        .servers
        .iter()
        .map(|ip| match cfg.protocol {
            UpstreamProtocol::Doh => NameServerConfig::https(*ip, tls_name.clone(), Some(path.clone())),
            UpstreamProtocol::Dot => NameServerConfig::tls(*ip, tls_name.clone()),
            UpstreamProtocol::Udp => NameServerConfig::udp_and_tcp(*ip),
        })
        .collect();

    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    );
    // Pure forwarder: never consult /etc/hosts or search domains.
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.build().context("building upstream resolver")
}
