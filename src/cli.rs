use crate::category::Category;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "goop-steppa", version, about = "Local DNS privacy monitor")]
pub struct Cli {
    /// Path to config file (default: ~/.config/goop-steppa/config.toml)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the DNS resolver
    Run {
        /// Override listen port
        #[arg(long)]
        port: Option<u16>,
    },
    /// Add a domain (and its subdomains) to your blocklist
    Block {
        /// Domain or URL
        domain: String,
        /// malware | telemetry | ads
        #[arg(long, short, default_value = "ads")]
        category: Category,
    },
    /// Add a domain (and its subdomains) to your allowlist. The allowlist always wins.
    Allow {
        /// Domain or URL
        domain: String,
    },
    /// Remove a domain from both of your lists
    Forget {
        /// Domain or URL
        domain: String,
    },
    /// Manage blocklists
    Lists {
        #[command(subcommand)]
        action: ListsAction,
    },
    /// Check domains against the current lists (no network)
    Check {
        domains: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ListsAction {
    /// Download/refresh all configured lists now
    Update,
    /// Show configured lists and how many domains each contributes
    Show,
}
