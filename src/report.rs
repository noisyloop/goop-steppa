//! The colored `report` command.

use crate::category::{Action, Category};
use crate::store::{Row, Store};
use crate::theme::{bold, dim, label, paint};
use anyhow::{bail, Result};
use chrono::{Local, TimeZone};
use std::collections::HashMap;
use std::fmt::Write;

pub struct Options {
    pub since_ms: i64,
    pub window_label: String,
    pub top: usize,
    pub recent: usize,
    pub category: Option<Category>,
}

pub struct Data {
    pub opts_window: String,
    pub totals: HashMap<Category, (u64, u64)>, // (blocked, allowed)
    pub top: Vec<(Category, Vec<(String, u64)>)>,
    pub sources: Vec<(String, u64)>,
    pub recent: Vec<Row>,
    pub canary_seen: bool,
}

/// Parse `30m`, `24h`, `7d`, `all`. Returns (milliseconds, label).
pub fn parse_window(s: &str) -> Result<i64> {
    let s = s.trim();
    if s == "all" {
        return Ok(i64::MAX);
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num.parse().map_err(|_| anyhow::anyhow!("bad --since '{s}' (use e.g. 30m, 24h, 7d, all)"))?;
    let mult = match unit {
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => bail!("bad --since '{s}' (use e.g. 30m, 24h, 7d, all)"),
    };
    Ok(n * mult)
}

pub fn since_ms(window_ms: i64, now_ms: i64) -> i64 {
    if window_ms == i64::MAX { 0 } else { now_ms - window_ms }
}

pub fn gather(store: &Store, o: &Options) -> Result<Data> {
    let mut totals: HashMap<Category, (u64, u64)> = HashMap::new();
    for (cat, act, n) in store.totals(o.since_ms)? {
        let e = totals.entry(cat).or_default();
        match act {
            Action::Blocked => e.0 += n,
            Action::Allowed => e.1 += n,
        }
    }
    let cats: Vec<Category> = match o.category {
        Some(c) => vec![c],
        None => Category::ALL.to_vec(),
    };
    let mut top = Vec::new();
    for c in cats {
        let rows = store.top_domains(o.since_ms, c, o.top)?;
        if !rows.is_empty() {
            top.push((c, rows));
        }
    }
    Ok(Data {
        opts_window: o.window_label.clone(),
        totals,
        top,
        sources: store.top_sources(o.since_ms, 8)?,
        recent: if o.recent > 0 { store.recent(o.since_ms, o.recent, o.category)? } else { vec![] },
        canary_seen: store.domain_seen_since(crate::filter::engine::FIREFOX_CANARY, o.since_ms)?,
    })
}

fn bar(n: u64, max: u64, width: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let w = ((n as f64 / max as f64) * width as f64).round() as usize;
    "█".repeat(w.max(if n > 0 { 1 } else { 0 }))
}

pub fn render(d: &Data, color: bool) -> String {
    let mut s = String::new();
    let total: u64 = d.totals.values().map(|(b, a)| b + a).sum();
    let blocked: u64 = d.totals.values().map(|(b, _)| b).sum();
    let _ = writeln!(s, "{}  {}", bold("goop-steppa report", color), dim(&format!("(last {})", d.opts_window), color));
    let _ = writeln!(s);
    if total == 0 {
        let _ = writeln!(s, "No queries recorded in this window.");
        let _ = writeln!(s, "{}", dim("Is goop-steppa running, and is your system resolver pointed at it? See `goop-steppa setup --help` / the README.", color));
        return s;
    }
    let pct = blocked as f64 * 100.0 / total as f64;
    let _ = writeln!(s, "{} queries, {} blocked ({:.1}%)", bold(&total.to_string(), color), bold(&blocked.to_string(), color), pct);
    let _ = writeln!(s);

    let max = d.totals.values().map(|(b, a)| b + a).max().unwrap_or(0);
    let _ = writeln!(s, "{}", bold("By category", color));
    for c in Category::ALL {
        let (b, a) = d.totals.get(&c).copied().unwrap_or((0, 0));
        let n = b + a;
        let verdict = if c.is_blockable() { "blocked" } else { "forwarded" };
        let _ = writeln!(
            s,
            "  {} {:>7}  {}  {}",
            paint(&format!("{:<17}", label(c)), c, color),
            n,
            paint(&format!("{:<24}", bar(n, max, 24)), c, color),
            dim(verdict, color)
        );
    }

    for (c, rows) in &d.top {
        let _ = writeln!(s);
        let _ = writeln!(s, "{}", paint(&format!("Top {}", label(*c)), *c, color));
        let w = rows.iter().map(|(d, _)| d.len()).max().unwrap_or(0).min(60);
        for (dom, n) in rows {
            let _ = writeln!(s, "  {}  {:>6}", paint(&format!("{:<w$}", dom, w = w), *c, color), n);
        }
    }

    if !d.sources.is_empty() {
        let _ = writeln!(s);
        let _ = writeln!(s, "{}", bold("Blocked by list", color));
        for (name, n) in &d.sources {
            let _ = writeln!(s, "  {:<36} {:>6}", name, n);
        }
    }

    if !d.recent.is_empty() {
        let _ = writeln!(s);
        let _ = writeln!(s, "{}", bold("Recent queries", color));
        for r in &d.recent {
            let t = Local.timestamp_millis_opt(r.ts_ms).single().map(|t| t.format("%H:%M:%S").to_string()).unwrap_or_default();
            let tag = match r.action {
                Action::Blocked => "BLOCK",
                Action::Allowed => "ok   ",
            };
            let _ = writeln!(
                s,
                "  {} {} {:<6} {}",
                dim(&t, color),
                paint(tag, r.category, color),
                r.qtype,
                paint(&r.domain, r.category, color)
            );
        }
    }

    let _ = writeln!(s);
    let _ = writeln!(s, "{}", bold("Notes", color));
    if d.canary_seen {
        let _ = writeln!(s, "  - Firefox asked for its DoH canary (use-application-dns.net) and was refused, so Firefox turns its built-in DoH off.");
    } else {
        let _ = writeln!(s, "  - Firefox canary (use-application-dns.net) is blocked, which makes Firefox disable its built-in DoH.");
    }
    let _ = writeln!(s, "  - Chrome / Brave / Edge may bypass local DNS with their own \"Secure DNS\" (DoH). Turn it off in the browser");
    let _ = writeln!(s, "    (Settings -> Privacy and security -> Security -> Use secure DNS) or their lookups will not appear here.");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Verdict;
    use crate::event::QueryEvent;

    #[test]
    fn window_parsing() {
        assert_eq!(parse_window("30m").unwrap(), 1_800_000);
        assert_eq!(parse_window("24h").unwrap(), 86_400_000);
        assert_eq!(parse_window("7d").unwrap(), 7 * 86_400_000);
        assert_eq!(parse_window("all").unwrap(), i64::MAX);
        assert!(parse_window("zz").is_err());
        assert!(parse_window("5x").is_err());
        assert_eq!(since_ms(i64::MAX, 1000), 0);
    }

    fn sample() -> Data {
        let s = Store::open_memory().unwrap();
        let mk = |d: &str, a: Action, c: Category, src: Option<&str>| {
            QueryEvent::new(d, "A", &Verdict { action: a, category: c, source: src.map(String::from) }, "127.0.0.1".parse().unwrap())
        };
        s.insert_batch(&[
            mk("evil.com", Action::Blocked, Category::Malware, Some("URLhaus")),
            mk("track.io", Action::Blocked, Category::Ads, Some("EasyPrivacy")),
            mk("track.io", Action::Blocked, Category::Ads, Some("EasyPrivacy")),
            mk("good.org", Action::Allowed, Category::Clean, None),
            mk("new.net", Action::Allowed, Category::Unknown, None),
            mk("use-application-dns.net", Action::Blocked, Category::Telemetry, Some("builtin")),
        ])
        .unwrap();
        gather(&s, &Options { since_ms: 0, window_label: "all time".into(), top: 5, recent: 3, category: None }).unwrap()
    }

    #[test]
    fn plain_report_has_all_sections_and_no_escapes() {
        let out = render(&sample(), false);
        assert!(!out.contains('\x1b'));
        for needle in ["6 queries, 4 blocked", "malware/phishing", "Top ads/trackers", "track.io", "evil.com", "EasyPrivacy", "Recent queries", "Secure DNS", "canary"] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
    }

    #[test]
    fn colored_report_uses_category_colors() {
        let out = render(&sample(), true);
        assert!(out.contains("\x1b[38;5;9m"), "red for malware: {out:?}");
        assert!(out.contains("\x1b[38;5;208m"), "orange for telemetry");
        assert!(out.contains("\x1b[38;5;245m"), "grey for unknown");
    }

    #[test]
    fn empty_report_explains() {
        let s = Store::open_memory().unwrap();
        let d = gather(&s, &Options { since_ms: 0, window_label: "x".into(), top: 5, recent: 0, category: None }).unwrap();
        assert!(render(&d, false).contains("No queries recorded"));
    }
}
