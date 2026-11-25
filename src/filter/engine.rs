//! The matching engine: suffix matching, categories and precedence.
//!
//! Precedence, highest first:
//!   1. user allowlist (any parent domain matching allows the whole subtree)
//!   2. most specific blocklist match (user blocklist beats lists at the same level)
//!   3. within one list level, the most severe category wins (malware > telemetry > ads)
//!   4. otherwise clean

use crate::category::{Action, Category, Verdict};
use std::collections::{HashMap, HashSet};

/// Firefox checks this name; if it fails to resolve, Firefox disables its built-in DoH.
pub const FIREFOX_CANARY: &str = "use-application-dns.net";

#[derive(Debug, Clone, Copy)]
struct Entry {
    category: Category,
    source: u16,
}

#[derive(Default)]
pub struct Engine {
    sources: Vec<String>,
    block: HashMap<String, Entry>,
    user_block: HashMap<String, Category>,
    user_allow: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListStat {
    pub name: String,
    pub category: Category,
    pub domains: usize,
}

impl Engine {
    pub fn new() -> Self {
        let mut e = Engine::default();
        e.add_list("builtin", Category::Telemetry, [FIREFOX_CANARY.to_string()]);
        e
    }

    /// Add a list's domains. Returns how many were added/kept as the winner.
    pub fn add_list(&mut self, name: &str, category: Category, domains: impl IntoIterator<Item = String>) -> usize {
        let idx = self.sources.len() as u16;
        self.sources.push(name.to_string());
        let mut n = 0;
        for d in domains {
            match self.block.get(&d) {
                Some(old) if old.category.severity() >= category.severity() => {}
                _ => {
                    self.block.insert(d, Entry { category, source: idx });
                    n += 1;
                }
            }
        }
        n
    }

    pub fn set_user(&mut self, block: impl IntoIterator<Item = (String, Category)>, allow: impl IntoIterator<Item = String>) {
        self.user_block = block.into_iter().collect();
        self.user_allow = allow.into_iter().collect();
    }

    pub fn check(&self, domain: &str) -> Verdict {
        let domain = domain.trim_end_matches('.');
        // 1. allowlist
        for s in suffixes(domain) {
            if self.user_allow.contains(s) {
                return Verdict { action: Action::Allowed, category: Category::Allowed, source: Some("user".into()) };
            }
        }
        // 2. most specific block
        for s in suffixes(domain) {
            if let Some(c) = self.user_block.get(s) {
                return Verdict { action: Action::Blocked, category: *c, source: Some("user".into()) };
            }
            if let Some(e) = self.block.get(s) {
                return Verdict {
                    action: Action::Blocked,
                    category: e.category,
                    source: Some(self.sources[e.source as usize].clone()),
                };
            }
        }
        Verdict::pass(Category::Clean)
    }

    pub fn stats(&self) -> Vec<ListStat> {
        let mut counts = vec![0usize; self.sources.len()];
        for e in self.block.values() {
            counts[e.source as usize] += 1;
        }
        let mut cats: HashMap<u16, Category> = HashMap::new();
        for e in self.block.values() {
            cats.entry(e.source).or_insert(e.category);
        }
        self.sources
            .iter()
            .enumerate()
            .map(|(i, n)| ListStat {
                name: n.clone(),
                category: cats.get(&(i as u16)).copied().unwrap_or(Category::Clean),
                domains: counts[i],
            })
            .collect()
    }

    pub fn user_counts(&self) -> (usize, usize) {
        (self.user_block.len(), self.user_allow.len())
    }
}

/// `a.b.example.com` → `a.b.example.com`, `b.example.com`, `example.com`, `com`.
fn suffixes(domain: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(domain);
    std::iter::from_fn(move || {
        let cur = rest?;
        rest = cur.split_once('.').map(|(_, r)| r);
        Some(cur)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eng() -> Engine {
        let mut e = Engine::new();
        e.add_list("ads", Category::Ads, ["example.com".to_string(), "both.net".to_string()]);
        e.add_list("mal", Category::Malware, ["both.net".to_string(), "evil.org".to_string()]);
        e
    }

    #[test]
    fn suffix_iteration() {
        assert_eq!(suffixes("a.b.c").collect::<Vec<_>>(), vec!["a.b.c", "b.c", "c"]);
    }

    #[test]
    fn matches_domain_and_subdomains() {
        let e = eng();
        assert_eq!(e.check("example.com").category, Category::Ads);
        assert_eq!(e.check("a.b.example.com").action, Action::Blocked);
        assert_eq!(e.check("example.com.").action, Action::Blocked, "trailing dot");
    }

    #[test]
    fn does_not_match_lookalikes() {
        let e = eng();
        assert_eq!(e.check("notexample.com").action, Action::Allowed);
        assert_eq!(e.check("example.com.evil-site.io").action, Action::Allowed);
        assert_eq!(e.check("example.com").source.as_deref(), Some("ads"));
        assert_eq!(e.check("other.org").category, Category::Clean);
    }

    #[test]
    fn most_severe_category_wins_regardless_of_order() {
        let e = eng();
        assert_eq!(e.check("both.net").category, Category::Malware);
        let mut e2 = Engine::new();
        e2.add_list("mal", Category::Malware, ["both.net".to_string()]);
        e2.add_list("ads", Category::Ads, ["both.net".to_string()]);
        assert_eq!(e2.check("both.net").category, Category::Malware);
        assert_eq!(e2.check("both.net").source.as_deref(), Some("mal"));
    }

    #[test]
    fn allowlist_always_wins() {
        let mut e = eng();
        e.set_user([("evil.org".to_string(), Category::Malware)], ["evil.org".to_string()]);
        let v = e.check("evil.org");
        assert_eq!((v.action, v.category), (Action::Allowed, Category::Allowed));
        // allowing a parent allows the whole subtree, even specific blocks beneath it
        e.set_user([("x.evil.org".to_string(), Category::Ads)], ["evil.org".to_string()]);
        assert_eq!(e.check("x.evil.org").action, Action::Allowed);
    }

    #[test]
    fn allowing_subdomain_leaves_siblings_blocked() {
        let mut e = eng();
        e.set_user([], ["ok.example.com".to_string()]);
        assert_eq!(e.check("ok.example.com").action, Action::Allowed);
        assert_eq!(e.check("deep.ok.example.com").action, Action::Allowed);
        assert_eq!(e.check("bad.example.com").action, Action::Blocked);
        assert_eq!(e.check("example.com").action, Action::Blocked);
    }

    #[test]
    fn user_block_beats_list_at_same_level_and_most_specific_wins() {
        let mut e = eng();
        e.set_user([("example.com".to_string(), Category::Telemetry)], []);
        let v = e.check("example.com");
        assert_eq!((v.category, v.source.as_deref()), (Category::Telemetry, Some("user")));
        // a more specific list entry beats a less specific user entry
        e.add_list("mal2", Category::Malware, ["sub.example.com".to_string()]);
        assert_eq!(e.check("a.sub.example.com").category, Category::Malware);
    }

    #[test]
    fn firefox_canary_blocked_builtin() {
        let e = Engine::new();
        let v = e.check(FIREFOX_CANARY);
        assert_eq!(v.action, Action::Blocked);
        assert_eq!(v.source.as_deref(), Some("builtin"));
    }
}
