//! Filename resolution per EXTRACT.md §3 precedence: RFC 2231
//! continuations/star params, then filename= (2047), then Content-Type
//! name= — plus basename reduction and extension-by-type.

use super::decode::charset_decode;
use super::mime::{header_value, parse_params};
use super::rfc2047::decode_rfc2047;

pub(super) fn raw_filename(headers: &[(String, String)]) -> (Option<String>, String, Vec<String>, Option<String>) {
    let cd = header_value(headers, "Content-Disposition");
    let ct = header_value(headers, "Content-Type");

    // RFC 2231 continuations first (filename*0*/filename*0), then filename*,
    // then filename= (all values, EXTRACT §4 EXT-6), then Content-Type name=.
    let cd_params = cd.map(|v| parse_params(v).1).unwrap_or_default();
    let mut cont: Vec<(usize, String)> = Vec::new();
    let mut simple_star: Option<String> = None;
    let mut simples: Vec<String> = Vec::new();
    for (k, v) in &cd_params {
        if let Some(rest) = k.strip_prefix("filename*") {
            let idx_str = rest.strip_suffix('*').unwrap_or(rest);
            if idx_str.is_empty() {
                simple_star = Some(v.trim_matches('"').to_string());
            } else if let Ok(idx) = idx_str.parse::<usize>() {
                cont.push((idx, v.trim_matches('"').to_string()));
            }
        } else if k == "filename" {
            simples.push(v.trim_matches('"').to_string());
        }
    }

    let mut note = None;
    if !cont.is_empty() {
        cont.sort_by_key(|(i, _)| *i);
        let joined: String = cont.iter().map(|(_, v)| v.as_str()).collect();
        if joined.contains('\'') {
            let mut segs = joined.split('\'');
            let charset = segs.next().unwrap_or("utf-8");
            let _lang = segs.next();
            let value: String = segs.collect::<Vec<_>>().join("'");
            let dec = percent_decode(value.as_bytes());
            let (text, known) = charset_decode(&dec, charset);
            if !known {
                note = Some(format!("unknown charset {charset}; lossy fallback"));
            }
            // No second decode pass: percent-encoding CAN produce "=?"
            // (%3D%3F), so a re-decode here would violate MIME-1 (SPEC §8)
            // and let screened senders smuggle encoded-words (sec review F3).
            // A literal "=?..." from a charset-marked 2231 param stays literal.
            return (Some(text), "filename*N* (2231)".into(), vec![], note);
        }
        let (text, known) = decode_rfc2047(&joined);
        if !known && note.is_none() {
            note = Some("unknown charset in encoded-word; lossy fallback".into());
        }
        return (Some(text), "filename*N (2231)".into(), vec![], note);
    }
    if let Some(v) = simple_star {
        if v.contains('\'') {
            let mut segs = v.split('\'');
            let charset = segs.next().unwrap_or("utf-8");
            let _lang = segs.next();
            let value: String = segs.collect::<Vec<_>>().join("'");
            let dec = percent_decode(value.as_bytes());
            let (text, known) = charset_decode(&dec, charset);
            if !known {
                note = Some(format!("unknown charset {charset}; lossy fallback"));
            }
            return (Some(text), "filename* (2231)".into(), vec![], note);
        }
        // charset-less `filename*=` is still a 2231 marker: percent-decode
        // once (charset defaults to utf-8), then stop — MIME-1, no 2047 pass.
        let text = charset_decode(&percent_decode(v.as_bytes()), "utf-8").0;
        return (
            Some(text),
            "filename* (2231)".into(),
            vec![],
            note,
        );
    }
    if !simples.is_empty() {
        let mut it = simples.into_iter();
        let first = it.next().unwrap();
        let extras: Vec<String> = it.collect();
        let (decoded, known) = decode_rfc2047(&first);
        if !known && note.is_none() {
            note = Some("unknown charset in encoded-word; lossy fallback".into());
        }
        let src = if decoded != first { "filename= (2047)" } else { "filename=" };
        return (Some(decoded), src.into(), extras, note);
    }
    if let Some(ct) = ct {
        let (_, params) = parse_params(ct);
        for (k, v) in params {
            if k == "name" {
                let v = v.trim_matches('"');
                let (decoded, known) = decode_rfc2047(v);
                if !known && note.is_none() {
                    note = Some("unknown charset in encoded-word; lossy fallback".into());
                }
                let src = if decoded != v { "name= (2047)" } else { "name=" };
                return (Some(decoded), src.into(), vec![], note);
            }
        }
    }
    (None, "none".into(), vec![], note)
}

fn percent_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' && i + 3 <= data.len() {
            if let Ok(h) = std::str::from_utf8(&data[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(h, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// Reduce any path-ish name to a bare basename: keep only the component
/// after the LAST `/` or `\`. No drive-letter or `..` handling here by
/// design — colons are sanitize's job and `..` is just text once reduced
/// (EXTRACT.md §3).
pub(super) fn basename_reduce(name: &str) -> String {
    // Take the last path component by either separator. Colons are NOT
    // separators and an "X:" prefix is not a drive letter here: sanitize
    // maps ':' to '_' anyway, so dropping two chars from ordinary names
    // like "e:mail.pdf" would be pure data loss with no traversal defense
    // gained.
    let s = match name.rfind(['/', '\\']) {
        Some(i) => &name[i + 1..],
        None => name,
    };
    s.to_string()
}

pub(super) fn ext_for_type(ct: &str) -> Option<&'static str> {
    let main = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    Some(match main.as_str() {
        "image/jpeg" | "image/jpg" => "jpeg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "application/pdf" => "pdf",
        "text/plain" => "txt",
        "text/html" => "html",
        "application/zip" => "zip",
        "application/gzip" => "gz",
        "audio/mpeg" => "mp3",
        "video/mp4" => "mp4",
        _ => return None,
    })
}

