//! TOML configuration and filesystem locations.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use crate::category::Category;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");
/// Shipped starter list; written to `<config dir>/lists/` (only if missing) so the user can edit it.
pub const LINUX_TELEMETRY_LIST: &str = include_str!("../config/lists/linux-telemetry.txt");
pub const LINUX_TELEMETRY_FILE: &str = "lists/linux-telemetry.txt";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub filter: FilterConfig,
    pub storage: StorageConfig,
    pub web: WebConfig,
    pub lists: Vec<ListConfig>,
}

/// The dashboard always binds to 127.0.0.1; only the port is configurable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    pub enabled: bool,
    pub port: u16,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self { enabled: true, port: 8053 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// SQLite history file (default: ~/.local/share/goop-steppa/history.db)
    pub path: Option<PathBuf>,
    /// Delete history older than this many days on startup. 0 keeps everything.
    pub retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { path: None, retention_days: 30 }
    }
}

impl StorageConfig {
    pub fn db_path(&self) -> Result<PathBuf> {
        match &self.path {
            Some(p) => Ok(p.clone()),
            None => Ok(data_dir()?.join("history.db")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    /// Refresh URL lists this often while running. 0 disables scheduled refresh.
    pub refresh_hours: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self { refresh_hours: 24 }
    }
}

/// A blocklist: either a `url` (downloaded and cached) or a local `path`.
/// Hosts, adblock (`||domain^`) and plain-domain formats are auto-detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListConfig {
    pub name: String,
    pub url: Option<String>,
    pub path: Option<std::path::PathBuf>,
    pub category: Category,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
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

pub fn data_dir() -> Result<PathBuf> {
    let d = directories::ProjectDirs::from("", "", "goop-steppa")
        .context("cannot determine home directory")?;
    Ok(d.data_dir().to_path_buf())
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
        if !explicit {
            // Never overwrite: the user may have edited it.
            if let Some(dir) = p.parent() {
                let list = dir.join(LINUX_TELEMETRY_FILE);
                if !list.exists() {
                    if let Some(lp) = list.parent() {
                        std::fs::create_dir_all(lp)?;
                    }
                    std::fs::write(&list, LINUX_TELEMETRY_LIST).with_context(|| format!("writing {}", list.display()))?;
                }
            }
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
        assert!(c.lists.len() >= 4, "default config should ship lists");
        assert!(c.lists.iter().any(|l| l.url.is_some()));
        let local: Vec<_> = c.lists.iter().filter(|l| l.path.is_some()).collect();
        assert_eq!(local.len(), 1, "exactly the Linux starter list is local");
        assert_eq!(local[0].path.as_deref(), Some(std::path::Path::new(LINUX_TELEMETRY_FILE)));
    }

    #[test]
    fn shipped_linux_list_is_usable() {
        let d = crate::filter::parse::parse_list(LINUX_TELEMETRY_LIST);
        assert!(d.len() >= 8, "{d:?}");
        assert!(d.contains(&"motd.ubuntu.com".to_string()) && d.contains(&"popcon.debian.org".to_string()));
        assert!(d.iter().all(|x| !x.contains(' ') && x.contains('.')), "comments must not leak in as domains: {d:?}");
    }

    #[test]
    fn empty_config_uses_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.upstream.tls_name, "dns.quad9.net");
    }
}
