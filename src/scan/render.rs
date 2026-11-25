//! Colored scan report (same palette as `report`, TUI and dashboard).

use super::ScanResult;
use crate::category::{Action, Category};
use crate::theme::{bold, dim, label, paint};
use std::fmt::Write;

pub struct RenderOpts {
    pub color: bool,
    /// Only blocked categories.
    pub flagged_only: bool,
    /// Show every unflagged domain instead of the first few.
    pub all: bool,
}

const UNFLAGGED_PREVIEW: usize = 25;

pub fn render(r: &ScanResult, o: &RenderOpts) -> String {
    let c = o.color;
    let mut s = String::new();
    let _ = writeln!(s, "{}  {}", bold("goop-steppa scan", c), dim(&format!("{}  ({}, {})", r.path, r.kind.as_str(), human(r.size)), c));
    let _ = writeln!(s);

    let mut counts = [0usize; 6];
    for f in &r.findings {
        counts[Category::ALL.iter().position(|x| *x == f.category).unwrap_or(5)] += 1;
    }
    let flagged = r.findings.iter().filter(|f| f.action == Action::Blocked).count();
    let _ = writeln!(s, "{} domains found, {} flagged", bold(&r.findings.len().to_string(), c), bold(&flagged.to_string(), c));
    let chips: Vec<String> = Category::ALL.iter().enumerate().map(|(i, cat)| paint(&format!("{} {}", counts[i], label(*cat)), *cat, c)).collect();
    let _ = writeln!(s, "{}", chips.join("   "));
    let _ = writeln!(s);

    if r.findings.is_empty() {
        let _ = writeln!(s, "No domains or URLs found.");
    }

    let mut shown_unflagged = 0;
    let mut hidden = 0;
    let width = r.findings.iter().map(|f| f.domain.len()).max().unwrap_or(0).min(60);
    for f in &r.findings {
        let is_flagged = f.action == Action::Blocked;
        if !is_flagged {
            if o.flagged_only {
                hidden += 1;
                continue;
            }
            if !o.all && shown_unflagged >= UNFLAGGED_PREVIEW {
                hidden += 1;
                continue;
            }
            shown_unflagged += 1;
        }
        let tag = if is_flagged { "BLOCK" } else { "ok   " };
        let _ = writeln!(
            s,
            "  {} {} {}  {:>4}  {}",
            paint(tag, f.category, c),
            paint(&format!("{:<17}", label(f.category)), f.category, c),
            paint(&format!("{:<w$}", f.domain, w = width), f.category, c),
            f.count,
            dim(f.source.as_deref().unwrap_or(""), c)
        );
        if is_flagged {
            for ex in &f.examples {
                let _ = writeln!(s, "        {}", dim(ex, c));
            }
        }
    }
    if hidden > 0 {
        let why = if o.flagged_only { "unflagged, hidden by --flagged" } else { "more unflagged; use --all to list them" };
        let _ = writeln!(s, "  {}", dim(&format!("... {hidden} {why}"), c));
    }

    if !r.ips.is_empty() {
        let _ = writeln!(s);
        let _ = writeln!(s, "{}", bold("IP addresses in URLs (not judged: DNS lists cannot score raw IPs)", c));
        for ip in r.ips.iter().take(30) {
            let _ = writeln!(s, "  {ip}");
        }
        if r.ips.len() > 30 {
            let _ = writeln!(s, "  ... {} more", r.ips.len() - 30);
        }
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "{}", dim("Nothing was opened or executed; the file was only read as bytes. Green = seen in your DNS history; grey = no list opinion and new to you.", c));
    for n in &r.notes {
        let _ = writeln!(s, "{}", dim(&format!("note: {n}"), c));
    }
    s
}

fn human(n: u64) -> String {
    match n {
        0..=1023 => format!("{n} B"),
        1024..=1_048_575 => format!("{:.1} KiB", n as f64 / 1024.0),
        _ => format!("{:.1} MiB", n as f64 / 1_048_576.0),
    }
}
