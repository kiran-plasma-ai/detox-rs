//! MIME structure parsing: header block split, `;`-parameter parsing
//! (quote-aware), line-anchored boundary delimiter scan, multipart split.
//! No decoding here — see decode.rs / rfc2047.rs.


pub(super) fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Parse `;`-separated params, honoring quotes. Returns (main-value, params).
pub(super) fn parse_params(s: &str) -> (String, Vec<(String, String)>) {
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

pub(super) fn split_head_body(data: &[u8]) -> (Vec<(String, String)>, &[u8]) {
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

pub(super) fn find_seq(hay: &[u8], needle: &[u8]) -> Option<usize> {
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
pub(super) fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
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

