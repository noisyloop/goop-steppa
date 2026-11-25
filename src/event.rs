//! The query event: produced by the DNS handler, consumed by the logger (and later the TUI and web UI).

use crate::category::{Action, Category, Verdict};
use serde::Serialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize)]
pub struct QueryEvent {
    /// Milliseconds since the Unix epoch.
    pub ts_ms: i64,
    pub domain: String,
    pub qtype: String,
    pub action: Action,
    pub category: Category,
    /// List name or "user" that caused the verdict.
    pub source: Option<String>,
    pub client: IpAddr,
}

impl QueryEvent {
    pub fn new(domain: &str, qtype: &str, v: &Verdict, client: IpAddr) -> Self {
        QueryEvent {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            domain: domain.to_string(),
            qtype: qtype.to_string(),
            action: v.action,
            category: v.category,
            source: v.source.clone(),
            client,
        }
    }
}

pub type EventTx = broadcast::Sender<QueryEvent>;

pub fn channel() -> EventTx {
    broadcast::channel(8192).0
}

/// Remembers which domains we've seen before, so a clean domain seen for the first time
/// is shown grey ("unknown") instead of green.
#[derive(Default)]
pub struct Seen(Mutex<HashSet<String>>);

impl Seen {
    pub fn from_domains(it: impl IntoIterator<Item = String>) -> Self {
        Seen(Mutex::new(it.into_iter().collect()))
    }

    /// Records `domain`; true if this is the first time it was seen.
    pub fn first_time(&self, domain: &str) -> bool {
        let mut s = self.0.lock().unwrap();
        if s.contains(domain) {
            false
        } else {
            s.insert(domain.to_string());
            true
        }
    }
}

/// Applies the "first time seen" rule: only domains with no list opinion turn grey.
pub fn apply_first_seen(mut v: Verdict, first: bool) -> Verdict {
    if first && v.category == Category::Clean {
        v.category = Category::Unknown;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_seen_turns_clean_grey_once() {
        let seen = Seen::default();
        let v = apply_first_seen(Verdict::pass(Category::Clean), seen.first_time("a.com"));
        assert_eq!(v.category, Category::Unknown);
        let v = apply_first_seen(Verdict::pass(Category::Clean), seen.first_time("a.com"));
        assert_eq!(v.category, Category::Clean);
    }

    #[test]
    fn first_seen_never_touches_listed_domains() {
        let blocked = Verdict { action: Action::Blocked, category: Category::Malware, source: None };
        assert_eq!(apply_first_seen(blocked, true).category, Category::Malware);
        let allowed = Verdict { action: Action::Allowed, category: Category::Allowed, source: None };
        assert_eq!(apply_first_seen(allowed, true).category, Category::Allowed);
    }

    #[test]
    fn preloaded_seen() {
        let seen = Seen::from_domains(["x.org".to_string()]);
        assert!(!seen.first_time("x.org"));
    }
}
