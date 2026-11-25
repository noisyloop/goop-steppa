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
}
