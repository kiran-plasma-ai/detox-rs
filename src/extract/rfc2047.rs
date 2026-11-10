//! RFC 2047 encoded-word decoding: single-decode-pass invariant (MIME-1,
//! SPEC §8) lives here — never add a second decode pass over 2231 output.

use super::decode::{base64_decode, charset_decode};

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
pub(super) fn decode_rfc2047(s: &str) -> (String, bool) {
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
