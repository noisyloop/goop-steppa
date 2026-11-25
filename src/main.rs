mod category;
mod cli;
mod config;
mod dns;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let mut cfg = config::Config::load(cli.config.as_deref())?;
    match cli.command {
        Command::Run { port } => {
            if let Some(p) = port {
                cfg.server.port = p;
            }
            run(cfg).await
        }
    }
}

async fn run(cfg: config::Config) -> Result<()> {
    let upstream = dns::upstream::build(&cfg.upstream)?;
    let decide: dns::server::Decider =
        std::sync::Arc::new(|_d| category::Verdict::pass(category::Category::Unknown));
    let handler = dns::server::Handler::new(upstream, decide);
    dns::server::serve(&cfg.server, handler, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
