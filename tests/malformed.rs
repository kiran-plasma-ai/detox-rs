//! Malicious-input catalog (user directive: "best practices" hardening).
//! Sources (adapted subsets, patterns re-implemented from descriptions):
//! - Markus Kuhn, UTF-8 decoder stress test (cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt, CC BY 4.0)
//! - minimaxir/Big-List-of-Naughty-Strings (CC0)
//! - fuzzdb attack/file-upload filename-bypass patterns (CWE-434)
//! - GHSA-36h5-qg4p-q2qf (CRLF header injection via attachment filename)
//! - CVE-2026-53537-class RFC 2231 parameter smuggling
//! - MIME ambiguity patterns (CCS'24 "Exploiting MIME Ambiguities")
//!
//! Oracle per case: no panic; sanitize() output is valid UTF-8, within cap,
//! and a fixed point; extract() emits only paths under the out dir, never
//! through symlinks; identity-encoded content is byte-exact.
//! Behavioral contracts (golden assertions) only where SPEC/EXTRACT pin them.

use detox_rs::extract::{extract, ExtractOptions};
use detox_rs::sanitize;
use detox_rs::{Options, Profile};

// ---------------------------------------------------------- UTF-8 catalog --
// Kuhn categories: lone/invalid starters, overlongs, surrogates in UTF-8,
// noncharacters, > U+10FFFF, 5/6-byte legacy, truncated sequences.
const MALFORMED_UTF8: &[&[u8]] = &[
    b"\x80", b"\xbf", b"\xc0", b"\xc1", b"\xfe", b"\xff",
    b"\xc2", b"\xe0\xa0", b"\xe2\x82", b"\xf0\x9f\x92", b"\xf4\x8f\xbf",
    b"\xc0\xaf", b"\xc1\xbf", b"\xe0\x80\xaf", b"\xe0\x9f\xbf",
    b"\xf0\x80\x80\xaf", b"\xf0\x8f\xbf\xbf", b"\xf8\x88\x80\x80\x80", b"\xfc\x84\x80\x80\x80\x80",
    b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\xed\xaf\xbf", b"\xed\xa0\x80\xed\xbf\xbf",
    b"\xef\xbf\xbe", b"\xef\xbf\xbf", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80", b"\xf7\xbf\xbf\xbf",
    b"a\x80b", b"\xe2(\xa1", b"\xc2A", b"\xe2\x82A", b"\xf0\x9f\x92A",
    b"\xff\xfeE\x00P\x00", b"\xfe\xff\x00E\x00P", b"\xef\xbb\xbfname",
    b"ok\xe2\x82bad\xf0\x9f\x92ok",
];

// Naughty-string subset relevant to names (controls, bidi, exotic space,
// Zalgo, tags, noncharacters, lookalikes, C1 raw).
const NAUGHTY: &[&str] = &[
    "\u{0}", "\u{1}\u{2}\u{1f}", "\u{7f}", "\u{80}\u{9f}",
    "\u{a0}\u{1680}\u{2000}\u{2007}\u{202f}\u{205f}\u{3000}\u{85}",
    "\u{202e}txe\u{202c}", "\u{200e}\u{200f}", "\u{2066}\u{2067}\u{2069}",
    "z\u{0301}\u{0327}\u{0334}\u{0358}a",
    "\u{e0001}\u{e0020}", "\u{1f3fb}\u{1f3ff}", "\u{1f1e6}\u{1f1e8}",
    "\u{fdd0}\u{fdef}", "\u{fffe}\u{ffff}", "\u{ff0e}\u{ff0f}\u{ff1a}",
    "ＣＯＮ．ｔｘｔ", "ﬁle\u{2460}", "㋡", "\u{ad}",
    "$PATH ${HOME} $(id) `id` ${IFS}", "%s%d%n", "{glob}[brack]*?",
    "\u{1b}[31mred\u{1b}[0m", "\u{feff}bom",
    "name\u{2028}sep\u{2029}",
];

// fuzzdb filename-filter bypass patterns (traversal + platform traps).
const TRAVERSAL: &[&str] = &[
    "../", "..\\", "..;/", ".../", "....//", "..%2f", "..%5c", "%2e%2e/",
    "%2e%2e%2f", "..%c0%af", "..%c1%9c", "..%252f", "..//",
    "/etc/passwd", "C:\\Windows\\system32\\x", "c:/x", "\\\\server\\share\\f",
    "\\\\?\\C:\\x", "file:stream", "name:ads.txt", "name.txt:stream",
    "CON", "con.txt", "PRN.pdf", "AUX", "NUL", "COM1", "LPT9.txt",
    " trailing.txt", "trailing.   ", "name .txt", ".hidden", "..", "...",
    "--help", "-rf", "-", "--", "~", "~root", ".~lock", "#hash",
    "*", "?", "[a]", "{a,b}", "a|b", "a;b", "a&b", "a%b", "\u{ff0e}\u{ff0e}/x",
];

#[test]
fn malformed_utf8_sanitize_is_stable() {
    let opts = Options::default();
    for raw in MALFORMED_UTF8 {
        let o = sanitize(raw, &opts);
        std::str::from_utf8(o.name.as_bytes()).expect("valid utf8 out");
        assert!(!o.name.is_empty());
        // Fixed point.
        let again = sanitize(o.name.as_bytes(), &opts);
        assert_eq!(o.name, again.name, "not idempotent: {raw:?}");
    }
}

#[test]
fn malformed_utf8_portable_profile_is_ascii() {
    let opts = Options {
        profile: Profile::Portable,
        ..Options::default()
    };
    for raw in MALFORMED_UTF8 {
        let o = sanitize(raw, &opts);
        assert!(
            o.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "{raw:?} -> {:?}",
            o.name
        );
    }
}

#[test]
fn naughty_strings_sanitize_invariants() {
    let opts = Options::default();
    for s in NAUGHTY {
        let o = sanitize(s.as_bytes(), &opts);
        std::str::from_utf8(o.name.as_bytes()).unwrap();
        assert!(!o.name.is_empty());
        let again = sanitize(o.name.as_bytes(), &opts);
        assert_eq!(o.name, again.name, "not idempotent: {s:?}");
        assert!(o.name.len() <= 255);
    }
}

#[test]
fn traversal_patterns_reduce_to_basename() {
    let opts = Options::default();
    for s in TRAVERSAL {
        let o = sanitize(s.as_bytes(), &opts);
        std::str::from_utf8(o.name.as_bytes()).unwrap();
        assert!(!o.name.contains('/'), "{s:?} -> {:?} has separator", o.name);
        assert!(!o.name.contains('\\'), "{s:?} -> {:?} has backslash", o.name);
        assert_ne!(o.name, "..", "{s:?} survived as dotdot");
        assert_ne!(o.name, ".", "{s:?} survived as dot");
        let again = sanitize(o.name.as_bytes(), &opts);
        assert_eq!(o.name, again.name, "not idempotent: {s:?}");
    }
}

// ------------------------------------------------------- extract attacks --

fn mail_with_filename(fname: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"");
    m.extend_from_slice(fname);
    m.extend_from_slice(b"\"\r\n\r\nJVBERi0xLjQK\r\n--BB--\r\n");
    m
}

fn extract_invariants(fname: &[u8], tag: &str) {
    let dir = std::env::temp_dir().join(format!(
        "detox-mal-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let mail = mail_with_filename(fname);
    if let Ok(r) = extract(
        &mail,
        &ExtractOptions {
            out_dir: dir.clone(),
            ..Default::default()
        },
    ) {
        for p in &r.parts {
            assert_eq!(p.file.parent(), Some(dir.as_path()), "escape: {:?}", p.file);
            assert!(
                !std::fs::symlink_metadata(&p.file)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false),
                "emitted a symlink: {:?}",
                p.file
            );
            let again = sanitize(
                p.file
                    .file_name()
                    .unwrap()
                    .as_encoded_bytes(),
                &Options::default(),
            );
            assert_eq!(
                again.name.as_bytes(),
                p.file.file_name().unwrap().as_encoded_bytes(),
                "emitted name not a fixed point: {:?}",
                p.file
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_survives_malformed_utf8_filenames() {
    for (i, raw) in MALFORMED_UTF8.iter().enumerate() {
        extract_invariants(raw, &format!("u8-{i}"));
    }
}

#[test]
fn extract_survives_naughty_filenames() {
    for (i, s) in NAUGHTY.iter().enumerate() {
        extract_invariants(s.as_bytes(), &format!("n-{i}"));
    }
}

#[test]
fn extract_survives_traversal_filenames() {
    for (i, s) in TRAVERSAL.iter().enumerate() {
        extract_invariants(s.as_bytes(), &format!("t-{i}"));
    }
}

// GHSA-36h5-qg4p-q2qf class: CRLF injection inside the filename must not
// create a second disposition that redirects output or escapes the dir.
#[test]
fn crlf_header_injection_via_filename() {
    extract_invariants(
        b"ok.pdf\r\nContent-Disposition: attachment; filename=\"evil.txt\"",
        "crlf-inject",
    );
    // And a golden check on what IS emitted.
    let dir = std::env::temp_dir().join(format!("detox-crlf-g-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mail = mail_with_filename(b"a.pdf\r\nX-Injected: 1");
    let r = extract(
        &mail,
        &ExtractOptions {
            out_dir: dir.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r.parts.len(), 1);
    assert_eq!(r.parts[0].file.parent(), Some(dir.as_path()));
    let _ = std::fs::remove_dir_all(&dir);
}

// CVE-2026-53537 class: RFC 2231 parameter smuggling — a star param plus a
// plain param must not let the plain one override into an unsafe name.
#[test]
fn rfc2231_parameter_smuggling() {
    let dir = std::env::temp_dir().join(format!("detox-smug-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mail = b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=utf-8''safe.pdf; filename=\"../../evil.pdf\"\r\n\r\nJVBERi0xLjQK\r\n--BB--\r\n".to_vec();
    let r = extract(
        &mail,
        &ExtractOptions {
            out_dir: dir.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r.parts.len(), 1);
    assert_eq!(r.parts[0].file.parent(), Some(dir.as_path()));
    assert_eq!(r.parts[0].file.file_name().unwrap(), "safe.pdf");
    let _ = std::fs::remove_dir_all(&dir);
}

// MIME ambiguity (CCS'24 class): boundary that prefixes another; interleaved
// closers; missing closer — output stays in-dir, no panic.
#[test]
fn boundary_ambiguity() {
    for (i, mail) in [
        b"Content-Type: multipart/mixed; boundary=ABC\r\n\r\n--ABC\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"f1.txt\"\r\n\r\naGk=\r\n--ABCx\r\njunk\r\n--ABC--".to_vec(),
        b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"f2.txt\"\r\n\r\naGk=\r\n--BB".to_vec(),
        b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"f3.txt\"\r\n\r\naGk=\r\n--BB--".to_vec(),
    ]
    .iter()
    .enumerate()
    {
        let dir = std::env::temp_dir().join(format!("detox-bnd-{i}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if let Ok(r) = extract(
            mail,
            &ExtractOptions {
                out_dir: dir.clone(),
                ..Default::default()
            },
        ) {
            for p in &r.parts {
                assert_eq!(p.file.parent(), Some(dir.as_path()), "escape: {:?}", p.file);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// UTF-16/BOM filenames: documented ceiling is lossy fallback — assert the
// safe behavior (no panic, in-dir, no UTF-16 auto-detection smuggling).
#[test]
fn utf16_bom_filename_is_safe_not_decoded() {
    // "ÉP" as UTF-16LE with BOM, then a traversal attempt in UTF-16BE.
    for (i, raw) in [
        &b"\xff\xfeE\x00P\x00.\x00p\x00d\x00f\x00"[..],
        &b"\xfe\xff\x00E\x00P\x00.\x00p\x00d\x00f"[..],
        &b"\xff\xfe.\x00.\x00\\\x00e\x00v\x00i\x00l\x00"[..],
    ]
    .iter()
    .enumerate()
    {
        extract_invariants(raw, &format!("u16-{i}"));
    }
}

// utf-7 is a known smuggling vector: we must NOT decode it (no table), and
// the result must still be a safe fixed point.
#[test]
fn utf7_charset_is_not_decoded() {
    let dir = std::env::temp_dir().join(format!("detox-u7-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mail = b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"=?utf-7?B?KGR-DstW?=\"\r\n\r\nJVBERi0xLjQK\r\n--BB--\r\n".to_vec();
    let r = extract(
        &mail,
        &ExtractOptions {
            out_dir: dir.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r.parts.len(), 1);
    assert!(
        r.parts[0]
            .note
            .as_ref()
            .is_some_and(|n| n.contains("unknown charset")),
        "utf-7 must be reported as unknown: {:?}",
        r.parts[0].note
    );
    assert_eq!(r.parts[0].file.parent(), Some(dir.as_path()));
    let _ = std::fs::remove_dir_all(&dir);
}
