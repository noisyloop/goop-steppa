mod category;
mod cli;
mod config;
mod dns;
mod event;
mod filter;
mod report;
mod store;
mod theme;
mod tui;
mod web;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, ListsAction};
use filter::{parse::domain_from_input, Filter};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(matches!(cli.command, Command::Run { tui: true, .. } | Command::Tui));
    let mut cfg = config::Config::load(cli.config.as_deref())?;
    match cli.command {
        Command::Run { port, tui, no_web } => {
            if let Some(p) = port {
                cfg.server.port = p;
            }
            if no_web {
                cfg.web.enabled = false;
            }
            if tui {
                run_with_tui(cfg).await
            } else {
                run(cfg).await
            }
        }
        Command::Tui => {
            let store = store::Store::open(&cfg.storage.db_path()?)?;
            let files = filter::UserFiles::new()?;
            tokio::task::spawn_blocking(move || tui::run(&store, &files)).await?
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
        Command::Report { since, top, recent, category, color } => {
            let store = store::Store::open(&cfg.storage.db_path()?)?;
            let window = report::parse_window(&since)?;
            let opts = report::Options {
                since_ms: report::since_ms(window, chrono::Utc::now().timestamp_millis()),
                window_label: if since == "all" { "all time".into() } else { since.clone() },
                top,
                recent,
                category,
            };
            let data = report::gather(&store, &opts)?;
            print!("{}", report::render(&data, color.enabled()));
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

/// Logs go to stderr normally; when a TUI owns the terminal they go to a file instead.
fn init_tracing(tui: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if tui {
        let file = config::data_dir().ok().and_then(|d| {
            std::fs::create_dir_all(&d).ok()?;
            std::fs::OpenOptions::new().create(true).append(true).open(d.join("goop-steppa.log")).ok()
        });
        if let Some(f) = file {
            tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(std::sync::Mutex::new(f)).init();
            return;
        }
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::sink).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Server in the background, TUI in the foreground. Startup errors (e.g. port in use) are shown
/// on the normal screen before the TUI takes over.
async fn run_with_tui(cfg: config::Config) -> Result<()> {
    let db = cfg.storage.db_path()?;
    let mut server = tokio::spawn(run(cfg));
    tokio::select! {
        r = &mut server => {
            return match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(e.into()),
            };
        }
        _ = tokio::time::sleep(Duration::from_millis(700)) => {}
    }
    let store = store::Store::open(&db)?;
    let files = filter::UserFiles::new()?;
    let res = tokio::task::spawn_blocking(move || tui::run(&store, &files)).await?;
    server.abort();
    res
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

    // History: every query event is written to SQLite; domains seen before stay green, new ones turn grey.
    let store = Arc::new(store::Store::open(&cfg.storage.db_path()?)?);
    if cfg.storage.retention_days > 0 {
        let cutoff = chrono::Utc::now().timestamp_millis() - cfg.storage.retention_days as i64 * 86_400_000;
        let n = store.prune_older_than(cutoff)?;
        if n > 0 {
            tracing::info!("pruned {n} history rows older than {} days", cfg.storage.retention_days);
        }
    }
    let seen = Arc::new(event::Seen::from_domains(store.seen_domains()?));
    let events = event::channel();
    spawn_logger(store.clone(), events.subscribe());

    if cfg.web.enabled {
        let state = Arc::new(web::WebState { store: store.clone(), filter: filter.clone(), events: events.clone(), port: cfg.web.port });
        let port = cfg.web.port;
        // A busy dashboard port must not take DNS down with it: warn and carry on.
        tokio::spawn(async move {
            if let Err(e) = web::serve(port, state, std::future::pending()).await {
                tracing::warn!("dashboard disabled: {e:#}");
            }
        });
    }

    let f = filter.clone();
    let decide: dns::server::Decider = Arc::new(move |d| {
        let v = f.check(d);
        event::apply_first_seen(v, seen.first_time(d))
    });
    let handler = dns::server::Handler::new(upstream, decide, events);
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

/// Batches query events into SQLite so logging never slows down DNS answers.
fn spawn_logger(store: Arc<store::Store>, mut rx: tokio::sync::broadcast::Receiver<event::QueryEvent>) {
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};
    tokio::spawn(async move {
        loop {
            let mut batch = Vec::new();
            match rx.recv().await {
                Ok(e) => batch.push(e),
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("history logger lagged; {n} events dropped");
                    continue;
                }
                Err(RecvError::Closed) => return,
            }
            // Gather whatever else arrived within a short window.
            tokio::time::sleep(Duration::from_millis(200)).await;
            loop {
                match rx.try_recv() {
                    Ok(e) => batch.push(e),
                    Err(TryRecvError::Lagged(n)) => tracing::warn!("history logger lagged; {n} events dropped"),
                    Err(_) => break,
                }
                if batch.len() >= 1000 {
                    break;
                }
            }
            let st = store.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || st.insert_batch(&batch)).await.unwrap_or_else(|e| Err(e.into())) {
                tracing::error!("writing history failed: {e:#}");
            }
        }
    });
}
