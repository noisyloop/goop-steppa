use crate::category::Category;
use crate::theme::ColorMode;
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
        /// Show the live color-coded terminal view while running (logs go to a file)
        #[arg(long)]
        tui: bool,
        /// Do not start the web dashboard
        #[arg(long)]
        no_web: bool,
    },
    /// Live terminal view of a running instance (tails the query history)
    Tui,
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
    /// Show a color-coded summary of what your DNS queries looked like
    Report {
        /// Time window: 30m, 24h, 7d, all
        #[arg(long, default_value = "24h")]
        since: String,
        /// Rows in each "top domains" table
        #[arg(long, default_value_t = 8)]
        top: usize,
        /// Also list this many most recent queries
        #[arg(long, default_value_t = 0)]
        recent: usize,
        /// Only show this category (malware | telemetry | ads | allowed | clean | unknown)
        #[arg(long, short)]
        category: Option<Category>,
        #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
        color: ColorMode,
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
