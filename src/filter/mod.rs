//! Filter = engine + list management (fetch, cache, user files, hot reload).

pub mod engine;
pub mod parse;

use crate::category::{Category, Verdict};
use crate::config::{self, Config, ListConfig};
use anyhow::{Context, Result};
use engine::{Engine, ListStat};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime};

pub struct Filter {
    engine: RwLock<Engine>,
    lists: Vec<ListConfig>,
    cache_dir: PathBuf,
    block_path: PathBuf,
    allow_path: PathBuf,
    mtimes: Mutex<(Option<SystemTime>, Option<SystemTime>)>,
}

#[derive(Debug)]
pub struct UpdateReport {
    pub name: String,
    pub result: std::result::Result<usize, String>,
}

impl Filter {
    pub fn new(cfg: &Config) -> Result<Self> {
        let dir = config::config_dir()?;
        Self::with_paths(cfg, config::data_dir()?.join("lists"), dir.join("blocklist.txt"), dir.join("allowlist.txt"))
    }

    pub fn with_paths(cfg: &Config, cache_dir: PathBuf, block_path: PathBuf, allow_path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        let f = Filter {
            engine: RwLock::new(Engine::new()),
            lists: cfg.lists.clone(),
            cache_dir,
            block_path,
            allow_path,
            mtimes: Mutex::new((None, None)),
        };
        f.reload()?;
        Ok(f)
    }

    pub fn check(&self, domain: &str) -> Verdict {
        self.engine.read().unwrap().check(domain)
    }

    pub fn stats(&self) -> (Vec<ListStat>, (usize, usize)) {
        let e = self.engine.read().unwrap();
        (e.stats(), e.user_counts())
    }

    fn cache_file(&self, l: &ListConfig) -> Option<PathBuf> {
        if let Some(p) = &l.path {
            return Some(p.clone());
        }
        l.url.as_ref()?;
        let safe: String = l.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
        Some(self.cache_dir.join(format!("{safe}.txt")))
    }

    /// Rebuild the whole engine from cached/local list files plus user files.
    pub fn reload(&self) -> Result<()> {
        let mut e = Engine::new();
        for l in self.lists.iter().filter(|l| l.enabled) {
            let Some(path) = self.cache_file(l) else { continue };
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let n = e.add_list(&l.name, l.category, parse::parse_list(&text));
                    tracing::info!(list = %l.name, domains = n, "loaded list");
                }
                Err(_) => tracing::warn!(list = %l.name, "no cached copy yet (run `goop-steppa lists update`)"),
            }
        }
        let (b, a) = (read_user_block(&self.block_path), read_user_allow(&self.allow_path));
        e.set_user(b, a);
        *self.mtimes.lock().unwrap() = (mtime(&self.block_path), mtime(&self.allow_path));
        *self.engine.write().unwrap() = e;
        Ok(())
    }

    /// Re-read only the user files (cheap).
    fn refresh_user(&self) {
        let (b, a) = (read_user_block(&self.block_path), read_user_allow(&self.allow_path));
        self.engine.write().unwrap().set_user(b, a);
        *self.mtimes.lock().unwrap() = (mtime(&self.block_path), mtime(&self.allow_path));
    }

    /// Reload user files if they were edited on disk (e.g. by `goop-steppa block` in another process).
    pub fn poll_user_files(&self) {
        let now = (mtime(&self.block_path), mtime(&self.allow_path));
        if *self.mtimes.lock().unwrap() != now {
            tracing::info!("user block/allow list changed on disk; reloading");
            self.refresh_user();
        }
    }

    pub fn block(&self, domain: &str, category: Category) -> Result<()> {
        edit_user_file(&self.allow_path, domain, None)?; // blocking supersedes an earlier allow
        edit_user_file(&self.block_path, domain, Some(Some(category)))?;
        self.refresh_user();
        Ok(())
    }

    pub fn allow(&self, domain: &str) -> Result<()> {
        edit_user_file(&self.allow_path, domain, Some(None))?;
        self.refresh_user();
        Ok(())
    }

    /// Remove from both user lists.
    pub fn forget(&self, domain: &str) -> Result<()> {
        edit_user_file(&self.allow_path, domain, None)?;
        edit_user_file(&self.block_path, domain, None)?;
        self.refresh_user();
        Ok(())
    }

    /// True if any URL list has no cache or one older than `max_age`.
    pub fn needs_update(&self, max_age: Duration) -> bool {
        self.lists.iter().filter(|l| l.enabled && l.url.is_some()).any(|l| {
            match self.cache_file(l).and_then(|p| mtime(&p)) {
                Some(t) => t.elapsed().map(|a| a > max_age).unwrap_or(false),
                None => true,
            }
        })
    }

    /// Download all enabled URL lists (failures are per-list and non-fatal), then reload.
    pub async fn update_lists(&self) -> Vec<UpdateReport> {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("goop-steppa/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return vec![UpdateReport { name: "(http client)".into(), result: Err(e.to_string()) }];
            }
        };
        let mut reports = Vec::new();
        for l in self.lists.iter().filter(|l| l.enabled) {
            let Some(url) = &l.url else { continue };
            let Some(dest) = self.cache_file(l) else { continue };
            let result = fetch_to(&client, url, &dest).await.map_err(|e| format!("{e:#}"));
            reports.push(UpdateReport { name: l.name.clone(), result });
        }
        if let Err(e) = self.reload() {
            tracing::error!("reload failed: {e:#}");
        }
        reports
    }
}

async fn fetch_to(client: &reqwest::Client, url: &str, dest: &Path) -> Result<usize> {
    let resp = client.get(url).send().await.with_context(|| format!("GET {url}"))?.error_for_status()?;
    let body = resp.text().await?;
    let n = parse::parse_list(&body).len();
    if n == 0 {
        anyhow::bail!("downloaded file contained no usable domains; keeping previous copy");
    }
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, dest)?;
    Ok(n)
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// User blocklist lines: `domain [category]`, `#` comments. Default category: ads.
pub fn parse_user_block(text: &str) -> Vec<(String, Category)> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let mut t = l.split_whitespace();
            let d = parse::clean_domain(t.next()?)?;
            let c = t.next().and_then(|c| c.parse().ok()).unwrap_or(Category::Ads);
            Some((d, c))
        })
        .collect()
}

pub fn parse_user_allow(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| parse::clean_domain(l.split('#').next()?.split_whitespace().next()?)).collect()
}

fn read_user_block(p: &Path) -> Vec<(String, Category)> {
    std::fs::read_to_string(p).map(|t| parse_user_block(&t)).unwrap_or_default()
}

fn read_user_allow(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p).map(|t| parse_user_allow(&t)).unwrap_or_default()
}

/// Edit a user file. `add`: `None` = remove the domain; `Some(cat)` = ensure present
/// (a block file entry gets `cat` if `Some(Some(c))`).
fn edit_user_file(path: &Path, domain: &str, add: Option<Option<Category>>) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let is_target = |line: &str| {
        line.split('#').next().and_then(|l| l.split_whitespace().next()).and_then(parse::clean_domain).as_deref() == Some(domain)
    };
    let mut lines: Vec<String> = existing.lines().filter(|l| !is_target(l)).map(str::to_string).collect();
    if let Some(cat) = add {
        lines.push(match cat {
            Some(c) => format!("{domain} {c}"),
            None => domain.to_string(),
        });
    } else if lines.len() == existing.lines().count() && !path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = lines.join("\n");
    out.push('\n');
    std::fs::write(path, out).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Action;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("goop-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn local_list_and_user_files_end_to_end() {
        let d = tmp("e2e");
        std::fs::write(d.join("l.txt"), "0.0.0.0 tracker.example.com\n||ads.example.net^\n").unwrap();
        let cfg: Config = toml::from_str(&format!(
            "[[lists]]\nname='local'\npath='{}'\ncategory='telemetry'\n",
            d.join("l.txt").display()
        ))
        .unwrap();
        let f = Filter::with_paths(&cfg, d.join("cache"), d.join("b.txt"), d.join("a.txt")).unwrap();
        assert_eq!(f.check("x.tracker.example.com").category, Category::Telemetry);
        assert_eq!(f.check("ads.example.net").action, Action::Blocked);
        assert_eq!(f.check("fine.org").category, Category::Clean);

        f.allow("tracker.example.com").unwrap();
        assert_eq!(f.check("x.tracker.example.com").action, Action::Allowed);
        f.block("tracker.example.com", Category::Malware).unwrap(); // block supersedes allow
        assert_eq!(f.check("x.tracker.example.com").category, Category::Malware);
        f.block("new.org", Category::Ads).unwrap();
        assert_eq!(f.check("a.new.org").action, Action::Blocked);
        f.forget("new.org").unwrap();
        assert_eq!(f.check("a.new.org").action, Action::Allowed);
        // survives a reload from disk
        f.reload().unwrap();
        assert_eq!(f.check("x.tracker.example.com").category, Category::Malware);
    }

    #[test]
    fn user_file_parsing() {
        assert_eq!(
            parse_user_block("# c\nfoo.com malware\nbar.org\nbad line here\n"),
            vec![("foo.com".into(), Category::Malware), ("bar.org".into(), Category::Ads)]
        );
        assert_eq!(parse_user_allow("a.com # note\n\nb.org\n"), vec!["a.com", "b.org"]);
    }

    #[test]
    fn external_edit_is_picked_up() {
        let d = tmp("poll");
        let f = Filter::with_paths(&Config::default(), d.join("c"), d.join("b.txt"), d.join("a.txt")).unwrap();
        assert_eq!(f.check("zzz.org").action, Action::Allowed);
        std::fs::write(d.join("b.txt"), "zzz.org\n").unwrap();
        f.poll_user_files();
        assert_eq!(f.check("zzz.org").action, Action::Blocked);
    }
}
