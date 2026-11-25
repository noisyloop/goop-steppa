//! Turning bytes into candidate URLs/domains.

use super::FileKind;
use crate::filter::parse::clean_domain;
use flate2::read::ZlibDecoder;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::sync::OnceLock;

/// Max bytes we will inflate from any one PDF stream (zip-bomb guard), and in total.
const MAX_STREAM_OUT: u64 = 32 * 1024 * 1024;
const MAX_TOTAL_OUT: u64 = 128 * 1024 * 1024;
const MIN_STRING: usize = 4;
const MAX_EXAMPLES: usize = 3;

#[derive(Default)]
pub struct DomainInfo {
    pub count: usize,
    pub examples: Vec<String>,
}

pub struct Extracted {
    pub kind: FileKind,
    pub domains: HashMap<String, DomainInfo>,
    pub ips: BTreeSet<String>,
    pub notes: Vec<String>,
}

fn tlds() -> &'static HashSet<&'static str> {
    static T: OnceLock<HashSet<&'static str>> = OnceLock::new();
    T.get_or_init(|| include_str!("tlds.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()).collect())
}

/// TLDs that are far more often file extensions than domains in the wild (install.sh, run.py, a.zip).
/// A bare `name.<these>` is ignored; inside an explicit URL it is accepted.
const AMBIGUOUS_TLDS: &[&str] = &["sh", "py", "pl", "rs", "so", "md", "zip", "mov", "ps", "pm"];

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)\b(?:https?|ftps?|wss?|sftp)://[^\s"'<>\\^`{}|]+"#).unwrap())
}

fn domain_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}\b").unwrap())
}

pub fn detect(bytes: &[u8]) -> FileKind {
    if bytes.starts_with(b"%PDF-") || bytes[..bytes.len().min(1024)].windows(5).any(|w| w == b"%PDF-") {
        return FileKind::Pdf;
    }
    let head = &bytes[..bytes.len().min(8192)];
    let nonprint = head.iter().filter(|&&b| b == 0 || (b < 9) || (b > 13 && b < 32) || b == 127).count();
    if head.contains(&0) && nonprint > 0 || nonprint * 20 > head.len().max(1) {
        // UTF-16 text is NUL-heavy too; treat it as binary (strings handles both encodings).
        return FileKind::Binary;
    }
    let sample = &bytes[..bytes.len().min(64 * 1024)];
    let lower: Vec<u8> = sample.iter().map(|b| b.to_ascii_lowercase()).collect();
    let has = |n: &[u8]| lower.windows(n.len()).any(|w| w == n);
    if has(b"<html") || has(b"<!doctype html") || has(b"<body") || has(b"<a href") || has(b"<script") {
        return FileKind::Html;
    }
    FileKind::Text
}

fn printable_ratio(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 1.0;
    }
    b.iter().filter(|&&c| (0x20..0x7f).contains(&c) || matches!(c, b'\n' | b'\r' | b'\t')).count() as f64 / b.len() as f64
}

/// Printable-ASCII runs (like `strings -n 4`). Tab counts as printable; newlines end a run, which
/// conveniently gives one candidate "line" per text line.
pub fn ascii_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b) || b == b'\t';
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= MIN_STRING {
                    out.push(String::from_utf8_lossy(&bytes[s..i]).into_owned());
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= MIN_STRING {
            out.push(String::from_utf8_lossy(&bytes[s..]).into_owned());
        }
    }
    out
}

/// Printable-ASCII runs encoded as UTF-16LE (how Windows binaries store most strings).
pub fn utf16le_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for offset in 0..2 {
        let mut cur = String::new();
        let mut i = offset;
        while i + 1 < bytes.len() {
            let (lo, hi) = (bytes[i], bytes[i + 1]);
            if hi == 0 && ((0x20..0x7f).contains(&lo) || lo == b'\t') {
                cur.push(lo as char);
                i += 2;
            } else {
                if cur.len() >= MIN_STRING {
                    out.push(std::mem::take(&mut cur));
                }
                cur.clear();
                i += if hi == 0 { 2 } else { 1 };
            }
        }
        if cur.len() >= MIN_STRING {
            out.push(cur);
        }
    }
    out
}

/// Inflate zlib streams found in a PDF, with hard output caps.
fn pdf_streams(bytes: &[u8], notes: &mut Vec<String>) -> (Vec<Vec<u8>>, Vec<(usize, usize)>) {
    let mut out = Vec::new();
    let mut ranges = Vec::new();
    let mut total = 0u64;
    let mut pos = 0;
    let mut truncated = false;
    while let Some(i) = find(bytes, b"stream", pos) {
        // skip "endstream"
        if i >= 3 && &bytes[i - 3..i] == b"end" {
            pos = i + 6;
            continue;
        }
        let mut s = i + 6;
        if bytes.get(s) == Some(&b'\r') {
            s += 1;
        }
        if bytes.get(s) == Some(&b'\n') {
            s += 1;
        }
        let Some(e) = find(bytes, b"endstream", s) else { break };
        let data = &bytes[s..e];
        pos = e + 9;
        if data.len() < 8 {
            continue;
        }
        let mut dec = Vec::new();
        let mut reader = ZlibDecoder::new(data).take(MAX_STREAM_OUT + 1);
        if reader.read_to_end(&mut dec).is_ok() || !dec.is_empty() {
            if dec.len() as u64 > MAX_STREAM_OUT {
                dec.truncate(MAX_STREAM_OUT as usize);
                truncated = true;
            }
            total += dec.len() as u64;
            if !dec.is_empty() {
                out.push(dec);
                ranges.push((s, e)); // inflated fine: the decoded copy replaces the raw bytes
            }
            if total > MAX_TOTAL_OUT {
                truncated = true;
                break;
            }
        }
    }
    if truncated {
        notes.push("some compressed PDF streams were larger than the safety limit and were only partly scanned".into());
    }
    (out, ranges)
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

/// Pull text out of a PDF content stream: concatenate the `(literal)` strings on each line
/// (so a URL split across `[(http://ex)-3(ample.com)] TJ` comes back whole).
pub fn pdf_text(stream: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < stream.len() {
        match stream[i] {
            b'(' => {
                i += 1;
                let mut depth = 1;
                while i < stream.len() && depth > 0 {
                    match stream[i] {
                        b'\\' => {
                            i += 1;
                            match stream.get(i) {
                                Some(b'n') | Some(b'r') | Some(b't') | Some(b'b') | Some(b'f') => {}
                                Some(c @ b'0'..=b'7') => {
                                    let mut v = (c - b'0') as u32;
                                    for _ in 0..2 {
                                        match stream.get(i + 1) {
                                            Some(d @ b'0'..=b'7') => {
                                                v = v * 8 + (d - b'0') as u32;
                                                i += 1;
                                            }
                                            _ => break,
                                        }
                                    }
                                    cur.push((v & 0xff) as u8);
                                }
                                Some(&c) => cur.push(c),
                                None => {}
                            }
                        }
                        b'(' => {
                            depth += 1;
                            cur.push(b'(');
                        }
                        b')' => {
                            depth -= 1;
                            if depth > 0 {
                                cur.push(b')');
                            }
                        }
                        c => cur.push(c),
                    }
                    i += 1;
                }
            }
            b'\n' | b'\r' => {
                if !cur.is_empty() {
                    lines.push(String::from_utf8_lossy(&std::mem::take(&mut cur)).into_owned());
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    if !cur.is_empty() {
        lines.push(String::from_utf8_lossy(&cur).into_owned());
    }
    lines
}


/// A font's glyph-code -> text map, from a PDF `/ToUnicode` CMap stream.
pub struct CMap {
    /// Bytes per source code (2 for Identity-H style CID fonts, 1 for simple fonts).
    key_bytes: usize,
    pub map: HashMap<u32, String>,
}

const MAX_CMAPS: usize = 64;

fn hex_bytes(h: &str) -> Vec<u8> {
    let digits: Vec<u8> = h.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    digits
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = c.get(1).map(|&x| (x as char).to_digit(16).unwrap_or(0) as u8).unwrap_or(0);
            hi * 16 + lo
        })
        .collect()
}

fn utf16be(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

fn be_u32(b: &[u8]) -> u32 {
    b.iter().take(4).fold(0u32, |a, &x| (a << 8) | x as u32)
}

/// Parse `beginbfchar` / `beginbfrange` sections. Returns None if the stream isn't a CMap.
pub fn parse_cmap(text: &[u8]) -> Option<CMap> {
    if !(find(text, b"beginbfchar", 0).is_some() || find(text, b"beginbfrange", 0).is_some()) {
        return None;
    }
    let t = String::from_utf8_lossy(text);
    let mut map = HashMap::new();
    let mut key_bytes = 0usize;
    let section = |name: &str, end: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut rest: &str = &t;
        while let Some(a) = rest.find(name) {
            let body = &rest[a + name.len()..];
            let Some(b) = body.find(end) else { break };
            out.push(body[..b].to_string());
            rest = &body[b + end.len()..];
        }
        out
    };
    // Tokens: <hex> or [ ... ] groups.
    let hexes = |body: &str| -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        let mut it = body.split('<').skip(1);
        for chunk in &mut it {
            if let Some((h, _)) = chunk.split_once('>') {
                v.push(hex_bytes(h));
            }
        }
        v
    };
    for body in section("beginbfchar", "endbfchar") {
        for pair in hexes(&body).chunks(2) {
            if let [src, dst] = pair {
                if src.is_empty() || src.len() > 4 {
                    continue;
                }
                key_bytes = key_bytes.max(src.len());
                map.insert(be_u32(src), utf16be(dst));
            }
        }
    }
    for body in section("beginbfrange", "endbfrange") {
        // Only the common `<lo> <hi> <dst>` form; the `[<..> <..>]` array form is skipped.
        for line in body.lines() {
            if line.contains('[') {
                continue;
            }
            if let [lo, hi, dst] = hexes(line).as_slice() {
                if lo.is_empty() || lo.len() > 4 || dst.len() < 2 {
                    continue;
                }
                key_bytes = key_bytes.max(lo.len());
                let (lo_v, hi_v) = (be_u32(lo), be_u32(hi));
                if hi_v < lo_v || hi_v - lo_v > 0xffff {
                    continue;
                }
                let base = utf16be(dst);
                let mut chars: Vec<char> = base.chars().collect();
                let Some(last) = chars.pop() else { continue };
                for off in 0..=(hi_v - lo_v) {
                    let mut st: String = chars.iter().collect();
                    if let Some(c) = char::from_u32(last as u32 + off) {
                        st.push(c);
                    }
                    map.insert(lo_v + off, st);
                }
            }
        }
    }
    if map.is_empty() {
        return None;
    }
    Some(CMap { key_bytes: key_bytes.max(1), map })
}

/// Hex strings `<...>` of each `BT .. ET` text block in a content stream (or the whole stream if it
/// has no BT/ET). Literal strings and `<<` dictionaries are skipped.
pub fn hex_text_blocks(stream: &[u8]) -> Vec<Vec<Vec<u8>>> {
    let mut blocks: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut cur: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    let n = stream.len();
    let is_ws = |b: u8| b.is_ascii_whitespace() || b == 0;
    // If the stream has text objects, only hex strings inside BT..ET are text (not dictionary values).
    let has_bt = find(stream, b"BT", 0).is_some();
    let mut in_text = !has_bt;
    while i < n {
        match stream[i] {
            b'(' => {
                let mut depth = 1;
                i += 1;
                while i < n && depth > 0 {
                    match stream[i] {
                        b'\\' => i += 1,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'<' if stream.get(i + 1) == Some(&b'<') => i += 2,
            b'<' => {
                let start = i + 1;
                let mut j = start;
                while j < n && stream[j] != b'>' && (stream[j].is_ascii_hexdigit() || is_ws(stream[j])) {
                    j += 1;
                }
                if in_text && j < n && stream[j] == b'>' && j > start {
                    cur.push(hex_bytes(&String::from_utf8_lossy(&stream[start..j])));
                }
                i = j + 1;
            }
            b'B' if has_bt && stream.get(i + 1) == Some(&b'T') && (i == 0 || is_ws(stream[i - 1])) && stream.get(i + 2).map(|&b| is_ws(b)).unwrap_or(true) => {
                in_text = true;
                i += 2;
            }
            b'E' if stream.get(i + 1) == Some(&b'T') && (i == 0 || is_ws(stream[i - 1])) && stream.get(i + 2).map(|&b| is_ws(b)).unwrap_or(true) => {
                if !cur.is_empty() {
                    blocks.push(std::mem::take(&mut cur));
                }
                in_text = !has_bt;
                i += 2;
            }
            _ => i += 1,
        }
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

/// Decode one text block with a font's CMap. Unmapped codes break the text; if most codes are
/// unmapped this is probably another font's CMap, so decode nothing.
pub fn decode_block(cmap: &CMap, block: &[Vec<u8>]) -> Option<String> {
    let (mut total, mut mapped) = (0usize, 0usize);
    let mut out = String::new();
    for s in block {
        for code in s.chunks(cmap.key_bytes) {
            total += 1;
            match cmap.map.get(&be_u32(code)) {
                Some(t) => {
                    mapped += 1;
                    out.push_str(t);
                }
                None => out.push('\n'),
            }
        }
    }
    if total == 0 || mapped * 10 < total * 6 {
        return None;
    }
    Some(out)
}

/// Undo the usual ways text hides a URL: defanging, HTML entities, percent-encoding.
pub fn variants(s: &str) -> Vec<String> {
    let mut v = vec![s.to_string()];
    let mut t = s.to_string();
    let mut changed = false;
    for (from, to) in [("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[://]", "://"), ("[:]//", "://"), ("[@]", "@"), ("[at]", "@")] {
        if t.contains(from) {
            t = t.replace(from, to);
            changed = true;
        }
    }
    let lower = t.to_ascii_lowercase();
    for (from, to) in [("hxxps", "https"), ("hxxp", "http"), ("fxp", "ftp")] {
        if let Some(p) = lower.find(from) {
            t.replace_range(p..p + from.len(), to);
            changed = true;
        }
    }
    if t.contains('&') {
        let u = html_unescape(&t);
        if u != t {
            t = u;
            changed = true;
        }
    }
    if t.contains('%') {
        let u = percent_decode(&t);
        if u != t {
            t = u;
            changed = true;
        }
    }
    if changed {
        v.push(t);
    }
    v
}

pub fn html_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        // Search the next <=12 *bytes* for ';' (byte search: slicing a &str here could split a char).
        let Some(semi) = rest.as_bytes()[..rest.len().min(12)].iter().position(|&b| b == b';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..semi];
        let rep = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "period" => Some('.'),
            "colon" => Some(':'),
            "sol" => Some('/'),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match rep {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16)) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

enum Host {
    Domain(String),
    Ip(String),
}

/// Host of a URL (userinfo/port/path stripped). Accepts IP literals separately.
fn url_host(url: &str) -> Option<Host> {
    let rest = url.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
    let host = if let Some(stripped) = auth.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => auth,
        }
    };
    let host = host.trim_end_matches('.');
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(Host::Ip(host.to_string()));
    }
    clean_domain(host).map(Host::Domain)
}

fn trim_url(u: &str) -> &str {
    u.trim_end_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '\'' | '"' | '>'))
}

/// Plausible bare domain (not inside a URL): needs a real TLD, and not a file-extension TLD.
fn bare_domain_ok(d: &str) -> bool {
    let tld = d.rsplit('.').next().unwrap_or("");
    tlds().contains(tld) && !AMBIGUOUS_TLDS.contains(&tld)
}

struct Collector<'a> {
    domains: &'a mut HashMap<String, DomainInfo>,
    ips: &'a mut BTreeSet<String>,
    /// Only trust explicit URLs (not bare `name.tld` strings). Set for binary-looking data embedded
    /// in other files (e.g. font programs inside a PDF), where bare matches are mostly noise.
    urls_only: bool,
}

impl Collector<'_> {
    fn add(&mut self, domain: String, example: Option<&str>) {
        let e = self.domains.entry(domain).or_default();
        e.count += 1;
        if let Some(u) = example {
            if e.examples.len() < MAX_EXAMPLES && !e.examples.iter().any(|x| x == u) {
                e.examples.push(u.chars().take(200).collect());
            }
        }
    }

    fn line(&mut self, line: &str) {
        let found = self.scan_line(line);
        self.commit(found);
    }

    fn commit(&mut self, found: HashMap<String, Option<String>>) {
        for (d, ex) in found {
            self.add(d, ex.as_deref());
        }
    }

    /// Each domain counts once per line, however many de-obfuscated variants reveal it.
    fn scan_line(&mut self, line: &str) -> HashMap<String, Option<String>> {
        let mut found: HashMap<String, Option<String>> = HashMap::new();
        for v in variants(line) {
            for m in url_re().find_iter(&v) {
                let url = trim_url(m.as_str());
                match url_host(url) {
                    Some(Host::Domain(d)) => {
                        let slot = found.entry(d).or_insert(None);
                        if slot.is_none() {
                            *slot = Some(url.to_string());
                        }
                    }
                    Some(Host::Ip(ip)) => {
                        self.ips.insert(ip);
                    }
                    None => {}
                }
            }
            if self.urls_only {
                continue;
            }
            for m in domain_re().find_iter(&v) {
                // Skip matches that are part of a URL we already handled or a path/file name.
                let start = m.start();
                let prev = v[..start].chars().next_back();
                if matches!(prev, Some('/') | Some('\\')) && !v[..start].ends_with("//") {
                    continue; // a path segment like /usr/lib/libfoo.com
                }
                if let Some(d) = clean_domain(m.as_str()) {
                    if bare_domain_ok(&d) {
                        found.entry(d).or_insert(None);
                    }
                }
            }
        }
        found
    }
}

pub fn extract(bytes: &[u8]) -> Extracted {
    let kind = detect(bytes);
    let mut domains = HashMap::new();
    let mut ips = BTreeSet::new();
    let mut notes = Vec::new();
    {
        let mut c = Collector { domains: &mut domains, ips: &mut ips, urls_only: false };
        // For PDFs, inflate streams first and blank their compressed bytes out of the raw pass:
        // compressed data is random noise to `strings`, and the decoded copy is scanned below.
        let (streams, ranges) = if kind == FileKind::Pdf { pdf_streams(bytes, &mut notes) } else { (Vec::new(), Vec::new()) };
        let masked: Vec<u8>;
        let raw: &[u8] = if ranges.is_empty() {
            bytes
        } else {
            let mut m = bytes.to_vec();
            for &(a, b) in &ranges {
                m[a..b].fill(0);
            }
            masked = m;
            &masked
        };
        for s in ascii_strings(raw) {
            c.line(&s);
        }
        if kind == FileKind::Binary {
            for s in utf16le_strings(bytes) {
                c.line(&s);
            }
        }
        if kind == FileKind::Pdf {
            let mut text_lines = 0usize;
            let cmaps: Vec<CMap> = streams.iter().filter_map(|st| parse_cmap(st)).take(MAX_CMAPS).collect();
            for st in &streams {
                // Plain strings first; then the reassembled `(text)` runs and hex-glyph text decoded
                // through each font's CMap, adding only what earlier passes could not see.
                let mut already: HashSet<String> = HashSet::new();
                // Binary-looking streams (font programs, images, embedded files) are not content streams:
                // no text-operator parsing, and only explicit URLs count from their strings.
                let texty = printable_ratio(st) >= 0.7;
                c.urls_only = !texty;
                for s in ascii_strings(st) {
                    let found = c.scan_line(&s);
                    already.extend(found.keys().cloned());
                    c.commit(found);
                }
                c.urls_only = false;
                let mut extra: Vec<String> = if texty { pdf_text(st) } else { Vec::new() };
                text_lines += extra.len();
                for block in if texty { hex_text_blocks(st) } else { Vec::new() } {
                    // Simple (1-byte) fonts: the hex bytes are the characters themselves. Skip when the
                    // bytes are not overwhelmingly printable (e.g. 2-byte glyph IDs, which would only
                    // splice junk like "2.cv" out of the IDs).
                    let raw = block.concat();
                    if printable_ratio(&raw) >= 0.95 {
                        extra.push(String::from_utf8_lossy(&raw).into_owned());
                    }
                    for cm in &cmaps {
                        if let Some(t) = decode_block(cm, &block) {
                            text_lines += 1;
                            extra.extend(t.lines().map(str::to_string));
                        }
                    }
                }
                for line in extra {
                    let mut found = c.scan_line(&line);
                    found.retain(|d, _| !already.contains(d));
                    already.extend(found.keys().cloned());
                    c.commit(found);
                }
            }
            if streams.is_empty() || text_lines == 0 {
                notes.push("PDF text extraction is best-effort (literal strings and zlib streams); text stored with embedded font encodings or other filters may not be visible".into());
            }
        }
    }
    Extracted { kind, domains, ips, notes }
}
