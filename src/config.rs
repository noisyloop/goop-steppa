//! TOML configuration and filesystem locations.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: IpAddr,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { listen: IpAddr::from([127, 0, 0, 1]), port: 53 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Doh,
    Dot,
    /// Plain DNS over UDP+TCP. Insecure; for testing only.
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub protocol: UpstreamProtocol,
    pub servers: Vec<IpAddr>,
    pub tls_name: String,
    pub doh_path: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            protocol: UpstreamProtocol::Doh,
            servers: vec![IpAddr::from([9, 9, 9, 9]), IpAddr::from([149, 112, 112, 112])],
            tls_name: "dns.quad9.net".into(),
            doh_path: "/dns-query".into(),
        }
    }
}

/// Where config/data live (XDG).
pub fn config_dir() -> Result<PathBuf> {
    let d = directories::ProjectDirs::from("", "", "goop-steppa")
        .context("cannot determine home directory")?;
    Ok(d.config_dir().to_path_buf())
}

pub fn default_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

impl Config {
    /// Load from `path`, or from the default location. If the default file does not
    /// exist yet, write the shipped default so the user has something to edit.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let (p, explicit) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (default_config_path()?, false),
        };
        if !p.exists() {
            if explicit {
                anyhow::bail!("config file {} not found", p.display());
            }
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, DEFAULT_CONFIG)
                .with_context(|| format!("writing default config to {}", p.display()))?;
            tracing::info!("wrote default config to {}", p.display());
        }
        let text = std::fs::read_to_string(&p)
            .with_context(|| format!("reading {}", p.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", p.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_default_parses_and_matches_defaults() {
        let c: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(c.server.port, 53);
        assert_eq!(c.upstream.protocol, UpstreamProtocol::Doh);
        assert_eq!(c.upstream.servers.len(), 2);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.upstream.tls_name, "dns.quad9.net");
    }
}
