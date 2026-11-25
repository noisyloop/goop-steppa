//! SQLite query history.

use crate::category::{Action, Category};
use crate::event::QueryEvent;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub ts_ms: i64,
    pub domain: String,
    pub qtype: String,
    pub action: Action,
    pub category: Category,
    pub source: Option<String>,
}

fn parse_action(s: &str) -> Action {
    if s == "blocked" { Action::Blocked } else { Action::Allowed }
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn open_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                domain TEXT NOT NULL,
                qtype TEXT NOT NULL,
                action TEXT NOT NULL,
                category TEXT NOT NULL,
                source TEXT,
                client TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
             CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);",
        )?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    pub fn insert_batch(&self, events: &[QueryEvent]) -> Result<()> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO queries (ts, domain, qtype, action, category, source, client) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            )?;
            for e in events {
                st.execute(params![
                    e.ts_ms,
                    e.domain,
                    e.qtype,
                    e.action.as_str(),
                    e.category.as_str(),
                    e.source,
                    ip_str(e.client)
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every domain ever logged (to seed the "first time seen" set).
    pub fn seen_domains(&self) -> Result<Vec<String>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT DISTINCT domain FROM queries")?;
        let v = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(v)
    }

    pub fn prune_older_than(&self, cutoff_ms: i64) -> Result<usize> {
        Ok(self.conn.lock().unwrap().execute("DELETE FROM queries WHERE ts < ?1", [cutoff_ms])?)
    }

    /// (category, action, count) since `since_ms`.
    pub fn totals(&self, since_ms: i64) -> Result<Vec<(Category, Action, u64)>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT category, action, COUNT(*) FROM queries WHERE ts >= ?1 GROUP BY category, action")?;
        let rows = st
            .query_map([since_ms], |r| {
                let cat: String = r.get(0)?;
                let act: String = r.get(1)?;
                Ok((cat.parse().unwrap_or(Category::Unknown), parse_action(&act), r.get::<_, i64>(2)? as u64))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn top_domains(&self, since_ms: i64, cat: Category, limit: usize) -> Result<Vec<(String, u64)>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(
            "SELECT domain, COUNT(*) n FROM queries WHERE ts >= ?1 AND category = ?2 GROUP BY domain ORDER BY n DESC, domain LIMIT ?3",
        )?;
        let rows = st
            .query_map(params![since_ms, cat.as_str(), limit as i64], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Which lists did the blocking: (source, count).
    pub fn top_sources(&self, since_ms: i64, limit: usize) -> Result<Vec<(String, u64)>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(
            "SELECT source, COUNT(*) n FROM queries WHERE ts >= ?1 AND action = 'blocked' AND source IS NOT NULL GROUP BY source ORDER BY n DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![since_ms, limit as i64], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Newest first.
    pub fn recent(&self, since_ms: i64, limit: usize, cat: Option<Category>) -> Result<Vec<Row>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(
            "SELECT ts, domain, qtype, action, category, source FROM queries
             WHERE ts >= ?1 AND (?2 IS NULL OR category = ?2) ORDER BY ts DESC, id DESC LIMIT ?3",
        )?;
        let rows = st
            .query_map(params![since_ms, cat.map(|c| c.as_str()), limit as i64], |r| {
                let act: String = r.get(3)?;
                let cat: String = r.get(4)?;
                Ok(Row {
                    ts_ms: r.get(0)?,
                    domain: r.get(1)?,
                    qtype: r.get(2)?,
                    action: parse_action(&act),
                    category: cat.parse().unwrap_or(Category::Unknown),
                    source: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Was `domain` queried since `since_ms`?
    pub fn domain_seen_since(&self, domain: &str, since_ms: i64) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM queries WHERE ts >= ?1 AND domain = ?2", params![since_ms, domain], |r| r.get(0))?;
        Ok(n > 0)
    }

    /// Query counts per time bucket: (bucket_start_ms, blocked, allowed). Used by the web dashboard.
    pub fn timeline(&self, since_ms: i64, bucket_ms: i64) -> Result<Vec<(i64, u64, u64)>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(
            "SELECT (ts / ?2) * ?2 b, SUM(action='blocked'), SUM(action!='blocked') FROM queries WHERE ts >= ?1 GROUP BY b ORDER BY b",
        )?;
        let rows = st
            .query_map(params![since_ms, bucket_ms], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn ip_str(ip: IpAddr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Verdict;

    fn ev(domain: &str, ts: i64, action: Action, cat: Category, src: Option<&str>) -> QueryEvent {
        let mut e = QueryEvent::new(
            domain,
            "A",
            &Verdict { action, category: cat, source: src.map(String::from) },
            "127.0.0.1".parse().unwrap(),
        );
        e.ts_ms = ts;
        e
    }

    fn seeded() -> Store {
        let s = Store::open_memory().unwrap();
        s.insert_batch(&[
            ev("a.com", 1000, Action::Blocked, Category::Ads, Some("L1")),
            ev("a.com", 2000, Action::Blocked, Category::Ads, Some("L1")),
            ev("b.com", 3000, Action::Blocked, Category::Malware, Some("L2")),
            ev("c.com", 4000, Action::Allowed, Category::Clean, None),
            ev("d.com", 5000, Action::Allowed, Category::Unknown, None),
        ])
        .unwrap();
        s
    }

    #[test]
    fn totals_and_windowing() {
        let s = seeded();
        let all: u64 = s.totals(0).unwrap().iter().map(|t| t.2).sum();
        assert_eq!(all, 5);
        let recent: u64 = s.totals(3000).unwrap().iter().map(|t| t.2).sum();
        assert_eq!(recent, 3);
    }

    #[test]
    fn top_domains_and_sources() {
        let s = seeded();
        assert_eq!(s.top_domains(0, Category::Ads, 5).unwrap(), vec![("a.com".to_string(), 2)]);
        assert_eq!(s.top_sources(0, 5).unwrap(), vec![("L1".to_string(), 2), ("L2".to_string(), 1)]);
    }

    #[test]
    fn recent_filtering_and_order() {
        let s = seeded();
        let r = s.recent(0, 2, None).unwrap();
        assert_eq!(r.iter().map(|x| x.domain.as_str()).collect::<Vec<_>>(), vec!["d.com", "c.com"]);
        let m = s.recent(0, 10, Some(Category::Malware)).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].action, Action::Blocked);
    }

    #[test]
    fn seen_prune_timeline() {
        let s = seeded();
        let mut seen = s.seen_domains().unwrap();
        seen.sort();
        assert_eq!(seen, vec!["a.com", "b.com", "c.com", "d.com"]);
        assert!(s.domain_seen_since("d.com", 5000).unwrap());
        assert!(!s.domain_seen_since("a.com", 5000).unwrap());
        let t = s.timeline(0, 2500).unwrap();
        assert_eq!(t, vec![(0, 2, 0), (2500, 1, 1), (5000, 0, 1)]);
        assert_eq!(s.prune_older_than(3000).unwrap(), 2);
        assert_eq!(s.seen_domains().unwrap().len(), 3);
    }
}
