//! Parsers for blocklist formats. Format is detected per line, so mixed or
//! mislabelled files still work:
//!   * hosts:    `0.0.0.0 ads.example.com [more.example.com ...]`
//!   * adblock:  `||ads.example.com^` (optionally with harmless options)
//!   * domains:  `ads.example.com`

use std::net::IpAddr;

/// Normalise and validate a hostname. Returns None for IPs, single labels and junk.
pub fn clean_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return None;
    }
    let s = s.to_ascii_lowercase();
    if s.parse::<IpAddr>().is_ok() {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return None;
        }
    }
    Some(s)
}

const HOSTS_JUNK: &[&str] = &[
    "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
    "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
    "ip6-allhosts", "0.0.0.0",
];

/// Options that don't narrow a rule to something DNS can't express.
const SAFE_OPTIONS: &[&str] = &["third-party", "3p", "important", "all", "popup", "document", "doc"];

fn parse_adblock_line(line: &str) -> Option<String> {
    let rest = line.strip_prefix("||")?;
    let (host_part, opts) = match rest.split_once('$') {
        Some((h, o)) => (h, Some(o)),
        None => (rest, None),
    };
    if let Some(o) = opts {
        if !o.split(',').all(|x| SAFE_OPTIONS.contains(&x.trim().trim_start_matches('~')) && !x.trim().starts_with('~')) {
            return None;
        }
    }
    // Must be exactly `host^` or `host` (end of rule), no paths/wildcards/ports.
    let host = host_part.strip_suffix('^').unwrap_or(host_part);
    if host.contains(['/', '*', '^', ':', '?', '|']) {
        return None;
    }
    clean_domain(host)
}

/// Parse any supported list text into a Vec of domains (not de-duplicated).
pub fn parse_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if line.starts_with("@@") || line.contains("##") || line.contains("#@#") || line.contains("#?#") {
            continue; // exceptions & cosmetic filters: not expressible at DNS level
        }
        if line.starts_with("||") {
            if let Some(d) = parse_adblock_line(line) {
                out.push(d);
            }
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        let mut toks = line.split_whitespace();
        let Some(first) = toks.next() else { continue };
        if first.parse::<IpAddr>().is_ok() {
            for t in toks {
                if HOSTS_JUNK.contains(&t) {
                    continue;
                }
                if let Some(d) = clean_domain(t) {
                    out.push(d);
                }
            }
        } else if toks.next().is_none() {
            if let Some(d) = clean_domain(first) {
                out.push(d);
            }
        }
    }
    out
}

/// Extract a bare host from user input like `https://Foo.com/x?y`, `foo.com`, `*.foo.com`.
pub fn domain_from_input(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit_once('@').map(|(_, h)| h).unwrap_or(s);
    let s = match s.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => s,
    };
    clean_domain(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_format() {
        let t = "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com tracker.example.net # trailing\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n";
        assert_eq!(parse_list(t), vec!["ads.example.com", "tracker.example.net"]);
    }

    #[test]
    fn adblock_format() {
        let t = "[Adblock Plus 2.0]\n! comment\n||Ads.Example.com^\n||t.example.org^$third-party\n||x.example.org^$script\n||path.example.org/banner^\n||wild*.example.org^\n@@||ok.example.com^\nexample.com##.banner\n||evil.example.com^$important\n";
        assert_eq!(parse_list(t), vec!["ads.example.com", "t.example.org", "evil.example.com"]);
    }

    #[test]
    fn plain_domains() {
        let t = "foo.com\n  Bar.Example.ORG  \n*.wild.com\nlocalhost\n1.2.3.4\nnot a domain\n";
        assert_eq!(parse_list(t), vec!["foo.com", "bar.example.org", "wild.com"]);
    }

    #[test]
    fn rejects_bad_domains() {
        assert!(clean_domain("a..b").is_none());
        assert!(clean_domain("-").is_none());
        assert!(clean_domain("com").is_none());
        assert!(clean_domain("exa mple.com").is_none());
        assert!(clean_domain("::1").is_none());
    }

    #[test]
    fn input_extraction() {
        assert_eq!(domain_from_input("https://User@Foo.com:8080/x?y#z").as_deref(), Some("foo.com"));
        assert_eq!(domain_from_input("foo.com").as_deref(), Some("foo.com"));
        assert_eq!(domain_from_input("*.foo.com").as_deref(), Some("foo.com"));
        assert_eq!(domain_from_input("nonsense"), None);
    }
}
