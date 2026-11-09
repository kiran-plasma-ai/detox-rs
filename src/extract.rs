//! `detox-rs extract` — MIME attachment extraction with pipeline-clean names.
//! Contract: docs/SLICES.md slice 6 v1; behavior per SPEC §8 and EXTRACT.md.

use crate::fs;
use crate::{sanitize, CaseMode, Options, Profile, UniqueStyle, Uniquifier};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ExtractOptions {
    pub out_dir: PathBuf,
    pub profile: Profile,
    pub case: CaseMode,
    pub max_bytes: usize,
    pub prefix: String,
    pub name_by_type: bool,
    pub no_nameless: bool,
    pub unique_style: UniqueStyle,
    pub overwrite: bool, // armed only when passed twice by the CLI
    pub headers_file: Option<PathBuf>,
    pub mailbox: bool,
    pub recursion_max: usize,
    pub parts_max: usize,
    pub format_json: bool,
    pub journal_dir: Option<PathBuf>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            out_dir: PathBuf::from("."),
            profile: Profile::Clean,
            case: CaseMode::Preserve,
            max_bytes: 255,
            prefix: "text".into(),
            name_by_type: false,
            no_nameless: false,
            unique_style: UniqueStyle::Infix,
            overwrite: false,
            headers_file: None,
            mailbox: false,
            recursion_max: 20,
            parts_max: 10_000,
            format_json: false,
            journal_dir: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct ExtractReport {
    pub parts: Vec<Extracted>,
    /// Non-fatal batch problems: caps hit (partial extraction) or a journal
    /// write failure. Empty == fully clean.
    pub journal_error: Option<String>,
}

#[derive(Debug)]
pub struct Extracted {
    pub file: PathBuf,
    pub content_type: String,
    pub size: usize,
    pub decoded_from: String,
    pub name_source: String,
    /// Set when a charset fell back to lossy decoding (unknown charset).
    pub note: Option<String>,
    /// EXT-6: this path is a hard link to the named primary file.
    pub hard_link_of: Option<PathBuf>,
}

#[derive(Debug)]
pub struct ExtractError(pub String);

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------- helpers --

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Parse `;`-separated params, honoring quotes. Returns (main-value, params).
fn parse_params(s: &str) -> (String, Vec<(String, String)>) {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                cur.push(c);
            }
            ';' if !in_q => {
                parts.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    parts.push(cur.trim().to_string());
    let main = parts.first().cloned().unwrap_or_default();
    let mut params = Vec::new();
    for p in parts.iter().skip(1) {
        if let Some((k, v)) = p.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            params.push((k.trim().to_ascii_lowercase(), v));
        }
    }
    (main, params)
}

/// Decode an RFC 2047 encoded-word (charset?B?..?= / ?Q?..?=).
fn decode_rfc2047_word(w: &str) -> Option<(String, bool)> {
    let inner = w.strip_prefix("=?")?.strip_suffix("?=")?;
    let mut it = inner.splitn(3, '?');
    let charset = it.next()?;
    let encoding = it.next()?;
    let payload = it.next()?;
    let bytes = if encoding.eq_ignore_ascii_case("b") {
        base64_decode(payload.as_bytes())?
    } else if encoding.eq_ignore_ascii_case("q") {
        let mut out = Vec::new();
        let mut cs = payload.chars();
        while let Some(c) = cs.next() {
            if c == '_' {
                out.push(b' ');
            } else if c == '=' {
                let h: String = cs.by_ref().take(2).collect();
                out.push(u8::from_str_radix(&h, 16).ok()?);
            } else {
                out.push(c as u8);
            }
        }
        out
    } else {
        return None;
    };
    let (text, known) = charset_decode(&bytes, charset);
    Some((text, known))
}

/// Replace encoded-words (incl. adjacent runs) in a header fragment.
/// Returns the text and whether every decoded word used a known charset.
fn decode_rfc2047(s: &str) -> (String, bool) {
    let mut out = String::new();
    let mut rest = s;
    let mut all_known = true;
    while let Some(start) = rest.find("=?") {
        let after = &rest[start + 2..];
        // Encoded-word shape: =?charset?enc?payload?= — the terminator "?="
        // can only occur after the third '?'; a naive find("?=") matches the
        // "?Q?=" separator itself and truncates the word.
        let end = (|| -> Option<usize> {
            let q1 = after.find('?')?;
            let q2 = after[q1 + 1..].find('?')? + q1 + 1;
            let rel = after[q2 + 1..].find("?=")?;
            Some(q2 + 1 + rel)
        })();
        if let Some(end) = end {
            let cand = &rest[start..start + 2 + end + 2];
            if let Some((dec, known)) = decode_rfc2047_word(cand) {
                out.push_str(&rest[..start]);
                out.push_str(&dec);
                all_known &= known;
                rest = &rest[start + 2 + end + 2..];
                // RFC 2047 §6.2: whitespace BETWEEN adjacent encoded-words is
                // ignored — skip it when another encoded-word follows.
                if rest.starts_with([' ', '\t']) && rest[1..].starts_with("=?") {
                    rest = &rest[1..];
                    while rest.starts_with([' ', '\t']) {
                        rest = &rest[1..];
                    }
                }
                continue;
            }
        }
        out.push_str(&rest[..start + 2]);
        rest = &rest[start + 2..];
    }
    out.push_str(rest);
    (out, all_known)
}

/// Minimal charset coverage (SPEC slice-6 contract): utf-8, us-ascii,
/// iso-8859-1/latin1, windows-1252/cp1252. Anything else: lossy UTF-8,
/// reported via the `false` return.
fn charset_decode(bytes: &[u8], charset: &str) -> (String, bool) {
    let cs = charset.trim().to_ascii_lowercase();
    match cs.as_str() {
        "utf-8" | "utf8" => (String::from_utf8_lossy(bytes).into_owned(), true),
        "us-ascii" | "us_ascii" | "ascii" => {
            // Strictly 7-bit: higher bytes have no mapping. Lossy U+FFFD per
            // byte AND report lossiness (matches Python email's
            // errors=replace behavior; found via differential fuzzing —
            // previously this arm shared the latin-1 mapping).
            let mut out = String::with_capacity(bytes.len());
            let mut clean = true;
            for &b in bytes {
                if b < 0x80 {
                    out.push(char::from(b));
                } else {
                    out.push('\u{FFFD}');
                    clean = false;
                }
            }
            (out, clean)
        }
        "iso-8859-1" | "iso_8859-1" | "latin1" | "latin-1" => {
            (bytes.iter().map(|&b| char::from(b)).collect(), true)
        }
        "windows-1252" | "cp1252" => {
            const T: [char; 32] = [
                '\u{20ac}', '\u{81}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}',
                '\u{2021}', '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8d}',
                '\u{17d}', '\u{8f}', '\u{90}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}',
                '\u{2022}', '\u{2013}', '\u{2014}', '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}',
                '\u{153}', '\u{9d}', '\u{17e}', '\u{178}',
            ];
            (
                bytes
                    .iter()
                    .map(|&b| {
                        if (0x80..0xa0).contains(&b) {
                            T[(b - 0x80) as usize]
                        } else {
                            char::from(b)
                        }
                    })
                    .collect(),
                true,
            )
        }
        "iso-8859-2" | "iso_8859-2" | "latin2" | "latin-2" => {
            const T: [char; 128] = [
                '\u{0080}', '\u{0081}', '\u{0082}', '\u{0083}', '\u{0084}', '\u{0085}', '\u{0086}', '\u{0087}',
                '\u{0088}', '\u{0089}', '\u{008A}', '\u{008B}', '\u{008C}', '\u{008D}', '\u{008E}', '\u{008F}',
                '\u{0090}', '\u{0091}', '\u{0092}', '\u{0093}', '\u{0094}', '\u{0095}', '\u{0096}', '\u{0097}',
                '\u{0098}', '\u{0099}', '\u{009A}', '\u{009B}', '\u{009C}', '\u{009D}', '\u{009E}', '\u{009F}',
                '\u{00A0}', '\u{0104}', '\u{02D8}', '\u{0141}', '\u{00A4}', '\u{013D}', '\u{015A}', '\u{00A7}',
                '\u{00A8}', '\u{0160}', '\u{015E}', '\u{0164}', '\u{0179}', '\u{00AD}', '\u{017D}', '\u{017B}',
                '\u{00B0}', '\u{0105}', '\u{02DB}', '\u{0142}', '\u{00B4}', '\u{013E}', '\u{015B}', '\u{02C7}',
                '\u{00B8}', '\u{0161}', '\u{015F}', '\u{0165}', '\u{017A}', '\u{02DD}', '\u{017E}', '\u{017C}',
                '\u{0154}', '\u{00C1}', '\u{00C2}', '\u{0102}', '\u{00C4}', '\u{0139}', '\u{0106}', '\u{00C7}',
                '\u{010C}', '\u{00C9}', '\u{0118}', '\u{00CB}', '\u{011A}', '\u{00CD}', '\u{00CE}', '\u{010E}',
                '\u{0110}', '\u{0143}', '\u{0147}', '\u{00D3}', '\u{00D4}', '\u{0150}', '\u{00D6}', '\u{00D7}',
                '\u{0158}', '\u{016E}', '\u{00DA}', '\u{0170}', '\u{00DC}', '\u{00DD}', '\u{0162}', '\u{00DF}',
                '\u{0155}', '\u{00E1}', '\u{00E2}', '\u{0103}', '\u{00E4}', '\u{013A}', '\u{0107}', '\u{00E7}',
                '\u{010D}', '\u{00E9}', '\u{0119}', '\u{00EB}', '\u{011B}', '\u{00ED}', '\u{00EE}', '\u{010F}',
                '\u{0111}', '\u{0144}', '\u{0148}', '\u{00F3}', '\u{00F4}', '\u{0151}', '\u{00F6}', '\u{00F7}',
                '\u{0159}', '\u{016F}', '\u{00FA}', '\u{0171}', '\u{00FC}', '\u{00FD}', '\u{0163}', '\u{02D9}',
            ];
            (
                bytes
                    .iter()
                    .map(|&b| if b >= 0x80 { T[(b - 0x80) as usize] } else { char::from(b) })
                    .collect(),
                true,
            )
        }
        "windows-1250" | "cp1250" => {
            const T: [char; 128] = [
                '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{FFFD}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
                '\u{FFFD}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{015A}', '\u{0164}', '\u{017D}', '\u{0179}',
                '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
                '\u{FFFD}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{015B}', '\u{0165}', '\u{017E}', '\u{017A}',
                '\u{00A0}', '\u{02C7}', '\u{02D8}', '\u{0141}', '\u{00A4}', '\u{0104}', '\u{00A6}', '\u{00A7}',
                '\u{00A8}', '\u{00A9}', '\u{015E}', '\u{00AB}', '\u{00AC}', '\u{00AD}', '\u{00AE}', '\u{017B}',
                '\u{00B0}', '\u{00B1}', '\u{02DB}', '\u{0142}', '\u{00B4}', '\u{00B5}', '\u{00B6}', '\u{00B7}',
                '\u{00B8}', '\u{0105}', '\u{015F}', '\u{00BB}', '\u{013D}', '\u{02DD}', '\u{013E}', '\u{017C}',
                '\u{0154}', '\u{00C1}', '\u{00C2}', '\u{0102}', '\u{00C4}', '\u{0139}', '\u{0106}', '\u{00C7}',
                '\u{010C}', '\u{00C9}', '\u{0118}', '\u{00CB}', '\u{011A}', '\u{00CD}', '\u{00CE}', '\u{010E}',
                '\u{0110}', '\u{0143}', '\u{0147}', '\u{00D3}', '\u{00D4}', '\u{0150}', '\u{00D6}', '\u{00D7}',
                '\u{0158}', '\u{016E}', '\u{00DA}', '\u{0170}', '\u{00DC}', '\u{00DD}', '\u{0162}', '\u{00DF}',
                '\u{0155}', '\u{00E1}', '\u{00E2}', '\u{0103}', '\u{00E4}', '\u{013A}', '\u{0107}', '\u{00E7}',
                '\u{010D}', '\u{00E9}', '\u{0119}', '\u{00EB}', '\u{011B}', '\u{00ED}', '\u{00EE}', '\u{010F}',
                '\u{0111}', '\u{0144}', '\u{0148}', '\u{00F3}', '\u{00F4}', '\u{0151}', '\u{00F6}', '\u{00F7}',
                '\u{0159}', '\u{016F}', '\u{00FA}', '\u{0171}', '\u{00FC}', '\u{00FD}', '\u{0163}', '\u{02D9}',
            ];
            (
                bytes
                    .iter()
                    .map(|&b| if b >= 0x80 { T[(b - 0x80) as usize] } else { char::from(b) })
                    .collect(),
                true,
            )
        }
        _ => (
            String::from_utf8_lossy(bytes).into_owned(),
            false,
        ),
    }
}

fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    // Ignore non-alphabet bytes (whitespace, per RFC 2045).
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &b in data {
        let v = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b'\t' | b' ' => continue,
            _ => continue,
        };
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

fn qp_decode(data: &[u8]) -> Vec<u8> {
    // Byte-for-byte port of CPython 3.14 binascii.a2b_qp(header=False), the
    // decoder behind Python's email module — the ecosystem reference for
    // QP edge semantics (differential fuzzing found 3 divergences here):
    //   '=':
    //     EOF after it            -> dropped
    //     '\n'                    -> soft break
    //     '\r' [junk] '\n'        -> soft break over the whole line tail
    //     '='                     -> literal '=', second '=' consumed
    //                              ("broken case from broken python qp")
    //     hexdigit hexdigit       -> byte (requires both to exist)
    //     anything else           -> literal '=', rest re-examined as data
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'=' {
            out.push(data[i]);
            i += 1;
            continue;
        }
        i += 1; // consume '='
        if i >= data.len() {
            break; // dangling '=' at EOF
        }
        let c = data[i];
        if c == b'\n' {
            i += 1;
        } else if c == b'\r' {
            while i < data.len() && data[i] != b'\n' {
                i += 1;
            }
            if i < data.len() {
                i += 1; // consume '\n'
            }
        } else if c == b'=' {
            out.push(b'=');
            i += 1;
        } else if i + 1 < data.len() && c.is_ascii_hexdigit() && data[i + 1].is_ascii_hexdigit() {
            out.push((hexval(c) << 4) | hexval(data[i + 1]));
            i += 2;
        } else {
            out.push(b'=');
        }
    }
    out
}

fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// --------------------------------------------------------- MIME structure --

/// Split header block from body at the first blank line.
fn split_head_body(data: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let sep = find_seq(data, b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| find_seq(data, b"\n\n").map(|i| (i, 2)));
    let Some((i, len)) = sep else {
        return (vec![], data);
    };
    let raw = &data[..i];
    let body = &data[i + len..];
    let text = String::from_utf8_lossy(raw);
    let mut headers = Vec::new();
    let mut cur: Option<(String, String)> = None;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = cur.as_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            if let Some(prev) = cur.take() {
                headers.push(prev);
            }
            cur = Some((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if let Some(prev) = cur.take() {
        headers.push(prev);
    }
    (headers, body)
}

fn find_seq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Find a boundary delimiter that starts at a line boundary and is followed
/// by EOL or `--` — avoids prefix false positives (`--abc2` vs `--abc`) and
/// mid-line mentions inside text bodies.
fn find_delim(body: &[u8], delim: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(i) = find_seq(&body[at..], delim) {
        let i = at + i;
        let at_line_start = i == 0 || body[i - 1] == b'\n';
        let after = i + delim.len();
        // Trailing SP/HT after a delimiter ("--x \n") appears from broken
        // MUAs; Python email accepts it, and rejecting it silently dropped
        // the WHOLE multipart (review P3.2).
        let ok_end = after >= body.len()
            || matches!(body[after], b'\r' | b'\n' | b'-' | b' ' | b'\t');
        if at_line_start && ok_end {
            return Some(i);
        }
        at = i + 1;
    }
    None
}

/// Split a multipart body on its boundary, returning inner part bodies
/// (each including their own header block).
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let mut delim = Vec::new();
    delim.extend_from_slice(b"--");
    delim.extend_from_slice(boundary.as_bytes());
    let mut parts = Vec::new();
    let Some(first) = find_delim(body, &delim, 0) else {
        return parts;
    };
    let mut pos = first + delim.len();
    loop {
        let line_end = find_seq(&body[pos..], b"\n").map(|i| pos + i + 1).unwrap_or(body.len());
        if body[pos..line_end].starts_with(b"--") {
            break; // closing boundary
        }
        let Some(next) = find_delim(body, &delim, pos) else {
            break;
        };
        let mut end = next;
        if end >= 1 && body[end - 1] == b'\n' {
            end -= 1;
            if end >= 1 && body[end - 1] == b'\r' {
                end -= 1;
            }
        }
        parts.push(&body[pos..end]);
        pos = next + delim.len();
    }
    parts
}

// ------------------------------------------------- filename resolution -----

/// Resolve the raw filename for a part per EXTRACT.md §3 precedence.
/// Returns (primary, source, extra-filenames-in-order, note).
fn raw_filename(headers: &[(String, String)]) -> (Option<String>, String, Vec<String>, Option<String>) {
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
fn basename_reduce(name: &str) -> String {
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

fn ext_for_type(ct: &str) -> Option<&'static str> {
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

// ---------------------------------------------------------------- extract --

pub fn extract(input: &[u8], opts: &ExtractOptions) -> Result<ExtractReport, ExtractError> {
    std::fs::create_dir_all(&opts.out_dir)
        .map_err(|e| ExtractError(format!("out dir: {e}")))?;

    let mut messages: Vec<&[u8]> = vec![];
    if opts.mailbox {
        // mbox: split on "\nFrom " boundaries; the first message may start at
        // offset 0 without a leading blank line.
        let mut start = 0usize;
        let mut i = 0usize;
        while i + 6 <= input.len() {
            let Some(rel) = find_seq(&input[i..], b"\nFrom ") else {
                break;
            };
            let abs = i + rel;
            // Require an envelope-ish line (address with '@') to avoid
            // splitting on an unescaped "From " inside a part body.
            let line_end = find_seq(&input[abs + 1..], b"\n")
                .map(|e| abs + 1 + e)
                .unwrap_or(input.len())
                .min(input.len());
            let line = &input[abs + 1..line_end.min(abs + 201).min(input.len())];
            if line.contains(&b'@') {
                messages.push(&input[start..abs]);
                start = abs + 1;
            }
            i = abs + 1;
        }
        messages.push(&input[start..]);
        messages.retain(|m| !m.trim_ascii().is_empty());
    } else {
        messages.push(input);
    }

    if let Some(hf) = &opts.headers_file {
        let mut hdr = String::new();
        if let Some(m) = messages.first() {
            let (headers, _) = split_head_body(m);
            for (k, v) in headers {
                hdr.push_str(&format!("{k}: {v}\n"));
            }
        }
        std::fs::write(hf, hdr).map_err(|e| ExtractError(format!("headers file: {e}")))?;
    }

    let mut out = Vec::new();
    let mut uniq = Uniquifier::new(opts.unique_style, opts.max_bytes);
    // Seed the collision domain with names already in DIR (EXTRACT §6: UNQ
    // applies to pre-existing files, never follow) — unless --overwrite is
    // double-armed, in which case the file at the requested name IS the
    // intended target and must not be uniquified away (review P1: seeding
    // unconditionally made the documented overwrite arm unreachable).
    if !opts.overwrite {
        if let Ok(rd) = std::fs::read_dir(&opts.out_dir) {
            for e in rd.flatten() {
                if let Some(n) = e.file_name().to_str() {
                    let _ = uniq.apply(n.to_string());
                }
            }
        }
    }
    let mut journal_error = None;
    for msg in messages {
        let mut parts_seen = 0usize;
        let mut cap_hit = false;
        let (headers, body) = split_head_body(msg);
        let r = walk_part(&headers, body, opts, 0, &mut out, &mut uniq, &mut parts_seen, &mut cap_hit);
        if let Err(e) = r {
            // Journal whatever was written so undo can reach it (EXTRACT §6).
            journal_error = journal_error.or(Some(e.to_string()));
            break;
        }
        if cap_hit {
            journal_error = journal_error
                .or(Some("recursion-max or parts cap hit; partial extraction".into()));
        }
    }

    // Journal created files so `undo` can remove them (EXTRACT.md).
    let jerr = write_extract_journal(&opts.journal_dir, &out);
    if journal_error.is_none() {
        journal_error = jerr;
    }
    Ok(ExtractReport {
        parts: out,
        journal_error,
    })
}

fn write_extract_journal(
    journal_dir: &Option<PathBuf>,
    out: &[Extracted],
) -> Option<String> {
    let (Some(jdir), true) = (journal_dir, !out.is_empty()) else {
        return None;
    };
    let mut created = Vec::with_capacity(out.len());
    for e in out {
        // Hard-link aliases are journaled too (sec review F5): undo's
        // dev+inode check makes remove_file delete exactly one name, so
        // both the primary and its aliases must be journaled for undo to
        // restore pre-extraction state fully.
        if let Ok(md) = std::fs::symlink_metadata(&e.file) {
            let (d, i) = fs::file_identity(&e.file, &md);
            created.push((e.file.clone(), d, i));
        }
    }
    if created.is_empty() {
        return None;
    }
    fs::write_create_journal(jdir, &run_id(), &created)
        .err()
        .map(|e| format!("journal write: {e}"))
}

fn run_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(nanos);
    h.write_u32(std::process::id());
    format!("{:016x}", h.finish())
}

#[allow(clippy::too_many_arguments)]
fn walk_part(
    headers: &[(String, String)],
    body: &[u8],
    opts: &ExtractOptions,
    depth: usize,
    out: &mut Vec<Extracted>,
    uniq: &mut Uniquifier,
    parts_seen: &mut usize,
    cap_hit: &mut bool,
) -> Result<(), ExtractError> {
    *parts_seen += 1;
    if *parts_seen > opts.parts_max {
        *cap_hit = true;
        return Ok(()); // cap: skip the rest of this message
    }
    let ct = header_value(headers, "Content-Type")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "text/plain".into());
    let (main, params) = parse_params(&ct);
    let main_l = main.to_ascii_lowercase();

    if main_l.starts_with("multipart/") {
        // F2 (security review): RFC 2046 bounds boundaries at 70 chars; an
        // uncapped attacker-controlled needle makes the delimiter scan
        // O(body x boundary). Oversized boundary -> treat as opaque part.
        const BOUNDARY_MAX: usize = 200;
        let boundary = params
            .iter()
            .find(|(k, _)| k == "boundary")
            .map(|(_, v)| v.trim_matches('"').to_string())
            .ok_or_else(|| ExtractError("multipart without boundary".into()))?;
        if boundary.len() > BOUNDARY_MAX {
            *cap_hit = true;
            return Ok(());
        }
        // F1 (security review): nesting depth is capped for message/rfc822
        // but multipart recursion passed `depth` unchanged — ~10k nested
        // shells blew the 8 MB main-thread stack (SIGABRT, not a panic, so
        // the fuzz oracles stayed green). Same guard for both.
        if depth + 1 > opts.recursion_max {
            *cap_hit = true;
            return Ok(());
        }
        for sub in split_multipart(body, &boundary) {
            let (sh, sb) = split_head_body(sub);
            walk_part(&sh, sb, opts, depth + 1, out, uniq, parts_seen, cap_hit)?;
        }
        return Ok(());
    }

    if main_l == "message/rfc822" {
        if depth + 1 > opts.recursion_max {
            *cap_hit = true; // partial: caller records it (EXTRACT §7 T-EX-011)
            return Ok(());
        }
        let (sh, sb) = split_head_body(body);
        return walk_part(&sh, sb, opts, depth + 1, out, uniq, parts_seen, cap_hit);
    }

    // Leaf part: decode content.
    let cte = header_value(headers, "Content-Transfer-Encoding")
        .unwrap_or("7bit")
        .to_ascii_lowercase();
    let decoded = match cte.as_str() {
        "base64" => base64_decode(body).ok_or_else(|| ExtractError("bad base64".into()))?,
        "quoted-printable" => qp_decode(body),
        _ => body.to_vec(), // 7bit/8bit/binary/unknown: byte-exact
    };
    let decoded_from = if cte == "base64" || cte == "quoted-printable" {
        cte.clone()
    } else {
        "identity".into()
    };

    // Name resolution.
    let (raw_name, name_source, extras, note) = raw_filename(headers);
    let name = match raw_name {
        Some(raw) if !raw.trim().is_empty() => {
            let base = basename_reduce(raw.trim().trim_matches('"'));
            let o = sanitize(base.as_bytes(), &Options {
                profile: opts.profile,
                case: opts.case,
                max_bytes: opts.max_bytes,
            });
            o.name
        }
        _ => {
            if opts.no_nameless {
                return Ok(());
            }
            // Generate a candidate, THEN run it through the pipeline — a
            // forged Content-Type must not inject separators (review finding).
            let candidate = if opts.name_by_type {
                main.split('/').map(|s| s.trim()).collect::<Vec<_>>().join("_")
            } else {
                match ext_for_type(&main) {
                    Some(ext) => format!("{}.{}", opts.prefix, ext),
                    None => opts.prefix.clone(),
                }
            };
            sanitize(candidate.as_bytes(), &Options {
                profile: opts.profile,
                case: opts.case,
                max_bytes: opts.max_bytes,
            })
            .name
        }
    };

    let name = match uniq.apply(name) {
        Ok((n, _)) => n,
        Err(_) => return Err(ExtractError("cannot uniquify within max-length".into())),
    };
    let path = opts.out_dir.join(&name);
    // Provably under out_dir: name came from sanitize (no separators) or
    // name_by_type (alnum+underscore), and join() with a relative name cannot
    // escape; belt-and-suspenders: verify parent == out_dir.
    if path.parent() != Some(opts.out_dir.as_path()) {
        return Err(ExtractError(format!("path escape rejected: {name}")));
    }
    // No-clobber: a symlink (even dangling) is an occupied slot — never
    // follow it (EXTRACT §6). create_new unless double-armed --overwrite.
    if std::fs::symlink_metadata(&path).is_ok() && !opts.overwrite {
        return Err(ExtractError(format!("refusing to overwrite {name}")));
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true);
    if opts.overwrite {
        // Overwrite REGULAR files only; symlinks refused above, and the
        // open itself gets O_NOFOLLOW so a swap between the check and the
        // open cannot redirect the write through a planted link (sec F7).
        if let Ok(md) = std::fs::symlink_metadata(&path) {
            if md.file_type().is_symlink() {
                return Err(ExtractError(format!("refusing to overwrite {name}")));
            }
        }
        open.truncate(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            // FILE_FLAG_OPEN_REPARSE_POINT: don't resolve a swapped-in
            // symlink at open time (O_NOFOLLOW equivalent on Windows).
            use std::os::windows::fs::OpenOptionsExt;
            open.custom_flags(0x0020_0000);
        }
    } else {
        open.create_new(true);
    }
    open.open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &decoded))
        .map_err(|e| ExtractError(format!("write {name}: {e}")))?;
    out.push(Extracted {
        file: path.clone(),
        content_type: main.clone(),
        size: decoded.len(),
        decoded_from: decoded_from.clone(),
        name_source: name_source.clone(),
        note: note.clone(),
        hard_link_of: None,
    });

    // EXT-6: hard link per additional filename param (same content).
    for extra in extras {
        let base = basename_reduce(extra.trim().trim_matches('"'));
        let o = sanitize(base.as_bytes(), &Options {
            profile: opts.profile,
            case: opts.case,
            max_bytes: opts.max_bytes,
        });
        let en = match uniq.apply(o.name) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };
        let epath = opts.out_dir.join(&en);
        if epath.parent() != Some(opts.out_dir.as_path())
            || std::fs::symlink_metadata(&epath).is_ok()
        {
            continue;
        }
        if std::fs::hard_link(&path, &epath).is_ok() {
            out.push(Extracted {
                file: epath,
                content_type: main.clone(),
                size: decoded.len(),
                decoded_from: decoded_from.clone(),
                name_source: "filename= (hard link)".into(),
                note: note.clone(),
                hard_link_of: Some(path.clone()),
            });
        }
    }
    Ok(())
}
