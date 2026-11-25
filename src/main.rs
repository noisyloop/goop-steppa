mod category;
mod cli;
mod config;
mod dns;
mod filter;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, ListsAction};
use filter::{parse::domain_from_input, Filter};
use std::sync::Arc;
use std::time::Duration;

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
        Command::Block { domain, category } => {
            let d = parse_domain(&domain)?;
            Filter::new(&cfg)?.block(&d, category)?;
            println!("blocked {d} ({category}) - subdomains included. A running instance picks this up within seconds.");
            Ok(())
        }
        Command::Allow { domain } => {
            let d = parse_domain(&domain)?;
            Filter::new(&cfg)?.allow(&d)?;
            println!("allowed {d} - subdomains included. The allowlist always wins.");
            Ok(())
        }
        Command::Forget { domain } => {
            let d = parse_domain(&domain)?;
            Filter::new(&cfg)?.forget(&d)?;
            println!("removed {d} from your block and allow lists");
            Ok(())
        }
        Command::Lists { action: ListsAction::Update } => {
            let f = Filter::new(&cfg)?;
            let mut failed = 0;
            for r in f.update_lists().await {
                match r.result {
                    Ok(n) => println!("  ok    {:<32} {n} domains", r.name),
                    Err(e) => {
                        failed += 1;
                        println!("  FAIL  {:<32} {e}", r.name);
                    }
                }
            }
            if failed > 0 {
                println!("{failed} list(s) failed; previous cached copies (if any) are still in use.");
            }
            Ok(())
        }
        Command::Lists { action: ListsAction::Show } => {
            let f = Filter::new(&cfg)?;
            let (stats, (ub, ua)) = f.stats();
            for s in stats {
                println!("  {:<32} {:<10} {} domains", s.name, s.category, s.domains);
            }
            println!("  {:<32} {:<10} {ub} blocked, {ua} allowed", "your lists", "user");
            Ok(())
        }
        Command::Check { domains } => {
            let f = Filter::new(&cfg)?;
            for d in domains {
                let d = parse_domain(&d)?;
                let v = f.check(&d);
                println!("{d}: {} / {} ({})", v.action.as_str(), v.category, v.source.as_deref().unwrap_or("-"));
            }
            Ok(())
        }
    }
}

fn parse_domain(s: &str) -> Result<String> {
    domain_from_input(s).ok_or_else(|| anyhow::anyhow!("'{s}' is not a valid domain"))
}

async fn run(cfg: config::Config) -> Result<()> {
    let upstream = dns::upstream::build(&cfg.upstream)?;
    let filter = Arc::new(Filter::new(&cfg)?);

    // Background: refresh lists on a schedule (and once now if stale/missing), and watch user files.
    let refresh = Duration::from_secs(cfg.filter.refresh_hours * 3600);
    {
        let f = filter.clone();
        tokio::spawn(async move {
            loop {
                if refresh.is_zero() {
                    // scheduled refresh disabled; still fetch once if nothing is cached yet
                    if f.needs_update(Duration::MAX) {
                        log_reports(f.update_lists().await);
                    }
                    return;
                }
                if f.needs_update(refresh) {
                    log_reports(f.update_lists().await);
                }
                tokio::time::sleep(Duration::from_secs(3600).min(refresh)).await;
            }
        });
        let f = filter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                f.poll_user_files();
            }
        });
    }

    let f = filter.clone();
    let decide: dns::server::Decider = Arc::new(move |d| f.check(d));
    let handler = dns::server::Handler::new(upstream, decide);
    dns::server::serve(&cfg.server, handler, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

fn log_reports(reports: Vec<filter::UpdateReport>) {
    for r in reports {
        match r.result {
            Ok(n) => tracing::info!(list = %r.name, domains = n, "list updated"),
            Err(e) => tracing::warn!(list = %r.name, "list update failed: {e}"),
        }
    }
}
