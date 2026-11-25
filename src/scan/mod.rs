//! `scan <file>`: pull every URL/domain out of a file and check it against the lists.
//!
//! Safety: this only ever *reads bytes*. Nothing is opened by another program, executed, parsed by a
//! complex format library, or followed over the network. Extraction is plain byte/string handling
//! (plus bounded zlib decompression for PDF streams).

pub mod extract;
pub mod render;

use crate::category::{Action, Category};
use crate::filter::Filter;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    Text,
    Html,
    Pdf,
    Binary,
}

impl FileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::Text => "text",
            FileKind::Html => "HTML",
            FileKind::Pdf => "PDF",
            FileKind::Binary => "binary",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub domain: String,
    pub count: usize,
    pub action: Action,
    pub category: Category,
    pub source: Option<String>,
    /// A few URLs that mentioned this domain.
    pub examples: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub findings: Vec<Finding>,
    /// IP-literal hosts found in URLs. DNS lists can't judge these, so they are listed, not scored.
    pub ips: Vec<String>,
    pub notes: Vec<String>,
}

/// Read a file (only regular files; no devices/FIFOs that could block or never end) with a size cap.
pub fn read_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > max_bytes {
        bail!("{} is {} MiB; larger than the {} MiB limit (raise it with --max-size)", path.display(), meta.len() >> 20, max_bytes >> 20);
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(path)?.take(max_bytes + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Extract and judge. `seen` = domains already present in the DNS history (read-only): a domain
/// with no list opinion is green if you have seen it before, grey if it is new to you.
pub fn scan_bytes(path: &str, bytes: &[u8], filter: &Filter, seen: &HashSet<String>) -> ScanResult {
    let ex = extract::extract(bytes);
    let mut findings: Vec<Finding> = ex
        .domains
        .into_iter()
        .map(|(domain, info)| {
            let mut v = filter.check(&domain);
            if v.category == Category::Clean && !seen.contains(&domain) {
                v.category = Category::Unknown;
            }
            Finding { domain, count: info.count, action: v.action, category: v.category, source: v.source, examples: info.examples }
        })
        .collect();
    findings.sort_by(|a, b| {
        rank(b.category).cmp(&rank(a.category)).then(b.count.cmp(&a.count)).then(a.domain.cmp(&b.domain))
    });
    ScanResult {
        path: path.to_string(),
        kind: ex.kind,
        size: bytes.len() as u64,
        findings,
        ips: ex.ips.into_iter().collect(),
        notes: ex.notes,
    }
}

/// Display order: bad things first.
fn rank(c: Category) -> u8 {
    match c {
        Category::Malware => 5,
        Category::Telemetry => 4,
        Category::Ads => 3,
        Category::Allowed => 2,
        Category::Unknown => 1,
        Category::Clean => 0,
    }
}

#[cfg(test)]
mod tests;
