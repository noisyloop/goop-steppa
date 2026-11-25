//! Pointing the Linux system resolver at goop-steppa (systemd-resolved), reversibly.
//!
//! Everything goes through one drop-in file, `/etc/systemd/resolved.conf.d/goop-steppa.conf`.
//! No existing file is modified, so revert = delete that one file and restart systemd-resolved.
//! All filesystem access is relative to `root` and all commands go through a [`Runner`], so the
//! logic is unit-tested without root or systemd.

use crate::store::Store;
use anyhow::{bail, Context, Result};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DROPIN_REL: &str = "etc/systemd/resolved.conf.d/goop-steppa.conf";
pub const MARKER: &str = "# Managed by goop-steppa";
/// `DNS=host:port` needs systemd >= 247.
const MIN_SYSTEMD_FOR_PORT: u32 = 247;

pub struct CmdOutput {
    pub ok: bool,
    pub stdout: String,
}

pub trait Runner {
    fn run(&self, prog: &str, args: &[&str]) -> Result<CmdOutput>;
}

pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, prog: &str, args: &[&str]) -> Result<CmdOutput> {
        let out = std::process::Command::new(prog).args(args).output().with_context(|| format!("running {prog}"))?;
        Ok(CmdOutput { ok: out.status.success(), stdout: String::from_utf8_lossy(&out.stdout).into_owned() })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Detection {
    pub resolved_active: bool,
    pub systemd_version: Option<u32>,
    /// Where /etc/resolv.conf points, if it is a symlink.
    pub resolv_conf_target: Option<String>,
    pub dropin_present: bool,
    pub dropin_ours: bool,
}

pub struct Sys<'a> {
    pub root: PathBuf,
    pub runner: &'a dyn Runner,
}

pub fn dropin_contents(port: u16) -> String {
    let dns = if port == 53 { "127.0.0.1".to_string() } else { format!("127.0.0.1:{port}") };
    format!(
        "{MARKER}. Undo with: sudo goop-steppa setup --revert\n\
         # (or simply delete this file and run: sudo systemctl restart systemd-resolved)\n\
         [Resolve]\n\
         DNS={dns}\n\
         Domains=~.\n\
         DNSOverTLS=no\n"
    )
}

pub fn parse_systemd_version(out: &str) -> Option<u32> {
    out.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

impl<'a> Sys<'a> {
    pub fn new(root: impl Into<PathBuf>, runner: &'a dyn Runner) -> Self {
        Sys { root: root.into(), runner }
    }

    fn dropin_path(&self) -> PathBuf {
        self.root.join(DROPIN_REL)
    }

    pub fn detect(&self) -> Detection {
        let active = self.runner.run("systemctl", &["is-active", "systemd-resolved"]).map(|o| o.ok && o.stdout.trim() == "active").unwrap_or(false);
        let version = self.runner.run("systemctl", &["--version"]).ok().and_then(|o| parse_systemd_version(&o.stdout));
        let target = std::fs::read_link(self.root.join("etc/resolv.conf")).ok().map(|p| p.display().to_string());
        let dp = self.dropin_path();
        let content = std::fs::read_to_string(&dp).ok();
        Detection {
            resolved_active: active,
            systemd_version: version,
            resolv_conf_target: target,
            dropin_present: dp.exists(),
            dropin_ours: content.map(|c| c.contains(MARKER)).unwrap_or(false),
        }
    }

    /// Human-readable plan; changes nothing.
    pub fn plan(&self, port: u16) -> String {
        let d = self.detect();
        let mut s = String::new();
        s.push_str("goop-steppa setup (dry run: nothing has been changed)\n\n");
        s.push_str("Detected\n");
        s.push_str(&format!("  systemd-resolved active : {}\n", yn(d.resolved_active)));
        if let Some(v) = d.systemd_version {
            s.push_str(&format!("  systemd version         : {v}\n"));
        }
        s.push_str(&format!("  /etc/resolv.conf        : {}\n", d.resolv_conf_target.as_deref().unwrap_or("not a symlink")));
        s.push_str(&format!("  goop-steppa configured  : {}\n\n", if d.dropin_ours { "yes (drop-in installed)" } else { "no" }));

        if !d.resolved_active {
            s.push_str("systemd-resolved is not running, so `setup --apply` cannot be used here.\nManual setup:\n");
            s.push_str(&format!(
                "  - Run goop-steppa on port 53 (needs root or: sudo setcap 'cap_net_bind_service=+ep' $(command -v goop-steppa)),\n\
                 \x20   then point your resolver at it, e.g. in NetworkManager set the connection's DNS to 127.0.0.1 and ignore\n\
                 \x20   DHCP-provided DNS, or write `nameserver 127.0.0.1` to /etc/resolv.conf (note: port {port} is configured).\n\
                 - To undo: restore the previous DNS setting / /etc/resolv.conf.\n"
            ));
            return s;
        }
        s.push_str("`goop-steppa setup --apply` will:\n");
        s.push_str(&format!("  1. check that something answers DNS on 127.0.0.1:{port} (refuses otherwise, so you cannot lose DNS by accident)\n"));
        s.push_str(&format!("  2. write ONE new file: /{DROPIN_REL}\n"));
        s.push_str("  3. run: systemctl restart systemd-resolved\n\n");
        s.push_str("That file will contain:\n");
        for l in dropin_contents(port).lines() {
            s.push_str(&format!("    {l}\n"));
        }
        s.push_str("\nTo undo at any time:  sudo goop-steppa setup --revert\n");
        s.push_str(&format!("  (equivalent by hand: sudo rm /{DROPIN_REL} && sudo systemctl restart systemd-resolved)\n\n"));
        s.push_str("Things to know\n");
        s.push_str("  - If goop-steppa is not running, name resolution on this machine fails (it is the only DNS server).\n");
        s.push_str("    Run it as a service (see the README) or revert before stopping it.\n");
        if port != 53 {
            s.push_str(&format!("  - Port {port} is non-standard: this relies on systemd >= {MIN_SYSTEMD_FOR_PORT} (`DNS=host:port`).\n"));
        }
        s.push_str("  - Per-link DNS servers (DHCP/NetworkManager) can still take precedence. After applying, run\n");
        s.push_str("    `goop-steppa setup --verify`; if it reports queries are not reaching goop-steppa, see the README.\n");
        s.push_str("  - Chrome / Brave / Edge may bypass local DNS with their own \"Secure DNS\"; turn it off in the browser.\n");
        s.push_str("    Firefox is handled: goop-steppa blocks its canary (use-application-dns.net), which disables Firefox's built-in DoH.\n");
        s
    }

    /// Install the drop-in and restart systemd-resolved. Returns a log of what was done.
    /// `probe(port)` must return true if something answers DNS there (skipped with `force`).
    pub fn apply(&self, port: u16, probe: &dyn Fn(u16) -> bool, force: bool) -> Result<Vec<String>> {
        let d = self.detect();
        if !d.resolved_active {
            bail!("systemd-resolved is not active; run `goop-steppa setup` (no flags) for manual instructions");
        }
        if port != 53 {
            if let Some(v) = d.systemd_version {
                if v < MIN_SYSTEMD_FOR_PORT {
                    bail!("systemd {v} cannot send DNS to a non-standard port (needs >= {MIN_SYSTEMD_FOR_PORT}). Run goop-steppa on port 53 instead.");
                }
            }
        }
        if d.dropin_present && !d.dropin_ours {
            bail!("/{DROPIN_REL} exists but was not created by goop-steppa; refusing to overwrite it");
        }
        if !force && !probe(port) {
            bail!("nothing answered DNS on 127.0.0.1:{port}. Start goop-steppa first (`goop-steppa run --port {port}`), or use --force.");
        }
        let path = self.dropin_path();
        std::fs::create_dir_all(path.parent().unwrap()).with_context(|| format!("creating {}", path.parent().unwrap().display()))?;
        let previous = std::fs::read(&path).ok();
        write_atomic(&path, dropin_contents(port).as_bytes())?;
        let mut log = vec![format!("wrote /{DROPIN_REL}")];
        let restarted = self.runner.run("systemctl", &["restart", "systemd-resolved"]);
        if !restarted.as_ref().map(|o| o.ok).unwrap_or(false) {
            // Roll back so a failed restart cannot leave a half-applied state behind.
            match previous {
                Some(p) => std::fs::write(&path, p)?,
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            bail!("`systemctl restart systemd-resolved` failed; rolled the change back");
        }
        log.push("restarted systemd-resolved".into());
        Ok(log)
    }

    pub fn revert(&self) -> Result<Vec<String>> {
        let d = self.detect();
        if !d.dropin_present {
            return Ok(vec!["nothing to revert: goop-steppa is not configured as the system resolver".into()]);
        }
        if !d.dropin_ours {
            bail!("/{DROPIN_REL} was not created by goop-steppa; refusing to remove it");
        }
        std::fs::remove_file(self.dropin_path())?;
        let mut log = vec![format!("removed /{DROPIN_REL}")];
        if self.runner.run("systemctl", &["restart", "systemd-resolved"]).map(|o| o.ok).unwrap_or(false) {
            log.push("restarted systemd-resolved: DNS is back to the system defaults".into());
        } else {
            log.push("WARNING: could not restart systemd-resolved; run: sudo systemctl restart systemd-resolved".into());
        }
        Ok(log)
    }

    /// Resolve a unique name through the *system* resolver and check that goop-steppa logged it.
    pub fn verify(&self, store: &Store, wait: Duration) -> Result<bool> {
        // Must be unique per call: a repeated name could be "seen" because of an earlier probe.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let nonce = format!("gs-verify-{:x}-{:x}-{:x}.example.org", std::process::id(), nanos, n);
        let before = chrono::Utc::now().timestamp_millis() - 1000;
        // The result (NXDOMAIN or an answer) does not matter; only that the query reached us.
        let _ = self.runner.run("resolvectl", &["query", &nonce]);
        let end = Instant::now() + wait;
        loop {
            if store.domain_seen_since(&nonce, before)? {
                return Ok(true);
            }
            if Instant::now() >= end {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("writing {} (are you root?)", tmp.display()))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Is a DNS server answering on 127.0.0.1:port? Sends a query for Firefox's canary, which goop-steppa
/// answers locally (NXDOMAIN) without touching the network.
pub fn probe_dns(port: u16) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else { return false };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    let mut q = vec![0x47, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in crate::filter::engine::FIREFOX_CANARY.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    if sock.send_to(&q, ("127.0.0.1", port)).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(sock.recv_from(&mut buf), Ok((n, _)) if n >= 12 && buf[0] == 0x47 && buf[1] == 0x53 && buf[2] & 0x80 != 0)
}

/// Are we root? (No libc dependency: /proc/self is owned by the effective uid.)
pub fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::{Action, Category, Verdict};
    use crate::event::QueryEvent;
    use std::cell::RefCell;
    use std::sync::Arc;

    struct Fake {
        active: bool,
        version: &'static str,
        restart_ok: bool,
        calls: RefCell<Vec<String>>,
        on_query: Option<Box<dyn Fn(&str)>>,
    }

    impl Fake {
        fn new() -> Self {
            Fake { active: true, version: "systemd 255 (255.4)", restart_ok: true, calls: RefCell::new(vec![]), on_query: None }
        }
    }

    impl Runner for Fake {
        fn run(&self, prog: &str, args: &[&str]) -> Result<CmdOutput> {
            self.calls.borrow_mut().push(format!("{prog} {}", args.join(" ")));
            Ok(match (prog, args) {
                ("systemctl", ["is-active", _]) => CmdOutput { ok: self.active, stdout: if self.active { "active\n" } else { "inactive\n" }.into() },
                ("systemctl", ["--version"]) => CmdOutput { ok: true, stdout: format!("{}\n+PAM +AUDIT", self.version) },
                ("systemctl", ["restart", _]) => CmdOutput { ok: self.restart_ok, stdout: String::new() },
                ("resolvectl", ["query", name]) => {
                    if let Some(f) = &self.on_query {
                        f(name);
                    }
                    CmdOutput { ok: false, stdout: String::new() }
                }
                _ => CmdOutput { ok: false, stdout: String::new() },
            })
        }
    }

    fn root(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("goop-sys-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        d
    }

    fn yes(_: u16) -> bool {
        true
    }
    fn no(_: u16) -> bool {
        false
    }

    #[test]
    fn dropin_content_port_handling() {
        let a = dropin_contents(53);
        assert!(a.contains("DNS=127.0.0.1\n") && a.contains("Domains=~.") && a.starts_with(MARKER));
        assert!(dropin_contents(5353).contains("DNS=127.0.0.1:5353\n"));
    }

    #[test]
    fn systemd_version_parsing() {
        assert_eq!(parse_systemd_version("systemd 252 (252.22-1~deb12u1)\n+PAM"), Some(252));
        assert_eq!(parse_systemd_version("garbage"), None);
        assert_eq!(parse_systemd_version(""), None);
    }

    #[test]
    fn plan_changes_nothing_and_explains() {
        let r = root("plan");
        let f = Fake::new();
        let sys = Sys::new(&r, &f);
        let p = sys.plan(5353);
        for n in ["dry run", "goop-steppa.conf", "DNS=127.0.0.1:5353", "--revert", "Secure DNS", "use-application-dns.net", "not running, name resolution"] {
            assert!(p.contains(n), "missing {n:?}\n{p}");
        }
        assert!(!r.join(DROPIN_REL).exists(), "plan must not write anything");
        assert!(f.calls.borrow().iter().all(|c| !c.contains("restart")), "plan must not restart anything");
    }

    #[test]
    fn plan_without_resolved_gives_manual_instructions() {
        let r = root("noresolved");
        let mut f = Fake::new();
        f.active = false;
        let p = Sys::new(&r, &f).plan(53);
        assert!(p.contains("not running") && p.contains("Manual setup") && p.contains("nameserver 127.0.0.1"));
    }

    #[test]
    fn apply_then_revert_roundtrip() {
        let r = root("roundtrip");
        let f = Fake::new();
        let sys = Sys::new(&r, &f);
        let log = sys.apply(5353, &yes, false).unwrap();
        assert!(log.iter().any(|l| l.contains("wrote")) && log.iter().any(|l| l.contains("restarted")));
        let file = std::fs::read_to_string(r.join(DROPIN_REL)).unwrap();
        assert_eq!(file, dropin_contents(5353));
        assert!(sys.detect().dropin_ours);
        // idempotent
        sys.apply(5353, &yes, false).unwrap();
        // revert restores the original state exactly: file gone, no other file touched
        let log = sys.revert().unwrap();
        assert!(log[0].contains("removed"));
        assert!(!r.join(DROPIN_REL).exists());
        assert!(!sys.detect().dropin_present);
        assert_eq!(f.calls.borrow().iter().filter(|c| c.starts_with("systemctl restart")).count(), 3);
        // reverting again is a harmless no-op
        assert!(sys.revert().unwrap()[0].contains("nothing to revert"));
    }

    #[test]
    fn refuses_when_nothing_is_listening() {
        let r = root("nolisten");
        let f = Fake::new();
        let sys = Sys::new(&r, &f);
        let e = sys.apply(5353, &no, false).unwrap_err().to_string();
        assert!(e.contains("nothing answered"), "{e}");
        assert!(!r.join(DROPIN_REL).exists());
        assert!(f.calls.borrow().iter().all(|c| !c.contains("restart")), "must not touch resolved");
        // --force skips the safety check
        sys.apply(5353, &no, true).unwrap();
        assert!(r.join(DROPIN_REL).exists());
    }

    #[test]
    fn refuses_to_clobber_or_remove_foreign_files() {
        let r = root("foreign");
        let p = r.join(DROPIN_REL);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "[Resolve]\nDNS=1.1.1.1\n").unwrap();
        let f = Fake::new();
        let sys = Sys::new(&r, &f);
        assert!(sys.apply(53, &yes, true).unwrap_err().to_string().contains("not created by goop-steppa"));
        assert!(sys.revert().unwrap_err().to_string().contains("not created by goop-steppa"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "[Resolve]\nDNS=1.1.1.1\n", "foreign file untouched");
    }

    #[test]
    fn failed_restart_rolls_back() {
        let r = root("rollback");
        let mut f = Fake::new();
        f.restart_ok = false;
        let sys = Sys::new(&r, &f);
        assert!(sys.apply(53, &yes, false).unwrap_err().to_string().contains("rolled the change back"));
        assert!(!r.join(DROPIN_REL).exists(), "no half-applied state left behind");
        // rollback also restores a previous goop-steppa file
        let ok = Fake::new();
        Sys::new(&r, &ok).apply(5353, &yes, false).unwrap();
        let before = std::fs::read_to_string(r.join(DROPIN_REL)).unwrap();
        assert!(sys.apply(53, &yes, false).is_err());
        assert_eq!(std::fs::read_to_string(r.join(DROPIN_REL)).unwrap(), before);
    }

    #[test]
    fn old_systemd_cannot_use_a_custom_port() {
        let r = root("oldsd");
        let mut f = Fake::new();
        f.version = "systemd 245 (245.4)";
        let sys = Sys::new(&r, &f);
        assert!(sys.apply(5353, &yes, true).unwrap_err().to_string().contains("non-standard port"));
        assert!(sys.apply(53, &yes, true).is_ok(), "port 53 works on any version");
    }

    #[test]
    fn requires_resolved() {
        let r = root("inactive");
        let mut f = Fake::new();
        f.active = false;
        assert!(Sys::new(&r, &f).apply(53, &yes, true).unwrap_err().to_string().contains("not active"));
    }

    #[test]
    fn resolv_conf_symlink_is_reported() {
        let r = root("symlink");
        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", r.join("etc/resolv.conf")).unwrap();
        let d = Sys::new(&r, &Fake::new()).detect();
        assert_eq!(d.resolv_conf_target.as_deref(), Some("../run/systemd/resolve/stub-resolv.conf"));
    }

    #[test]
    fn verify_sees_queries_that_reach_goop_steppa() {
        let store = Arc::new(Store::open_memory().unwrap());
        let r = root("verify");
        let mut f = Fake::new();
        let s2 = store.clone();
        f.on_query = Some(Box::new(move |name| {
            let v = Verdict { action: Action::Allowed, category: Category::Unknown, source: None };
            s2.insert_batch(&[QueryEvent::new(name, "A", &v, "127.0.0.1".parse().unwrap())]).unwrap();
        }));
        assert!(Sys::new(&r, &f).verify(&store, Duration::from_millis(500)).unwrap());
        // a resolver path that bypasses goop-steppa: nothing is logged
        let g = Fake::new();
        assert!(!Sys::new(&r, &g).verify(&store, Duration::from_millis(300)).unwrap());
    }

    #[test]
    fn probe_detects_a_real_dns_responder_and_silence() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let mut b = [0u8; 512];
            let (n, a) = sock.recv_from(&mut b).unwrap();
            let mut resp = b[..n].to_vec();
            resp[2] |= 0x80; // QR
            resp[3] = (resp[3] & 0xf0) | 3; // NXDOMAIN
            sock.send_to(&resp, a).unwrap();
        });
        assert!(probe_dns(port));
        h.join().unwrap();
        // a port with nobody home
        let free = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(!probe_dns(free));
    }
}
