//! Shared report helpers: run ids, stage display gloss, one NDJSON writer.
//!
//! Stage codes (`nrm`, `trl`, ...) are *produced* by `lib.rs::sanitize` and
//! flow through as strings; [`stage_detail`] is a display-time view over
//! them, not a second definition — the codes themselves must not be
//! re-pinned here.

use std::io::Write;

use detox_rs::json_escape;

use super::write_line;

/// uuid-v4-shaped run id from hashed time+pid entropy (no external RNG dep).
pub fn run_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let block = |salt: u64| {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(nanos);
        h.write_u32(std::process::id());
        h.write_u64(salt);
        h.finish()
    };
    let (a, b) = (block(0), block(1));
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        a as u32,
        (a >> 32) as u16,
        0x4000 | (b as u16 & 0x0fff),
        0x8000 | ((b >> 16) as u16 & 0x3fff),
        ((b >> 32) << 16 | (a >> 48)) & 0xffffffffffff
    )
}

/// Human gloss for a stage code (appears in NDJSON `reason` fields).
pub fn stage_detail(stage: &str) -> &'static str {
    match stage {
        "nrm" => "nfc",
        "trl" => "translit",
        "cas" => "case",
        "san" => "charset",
        "cln" => "collapse/strip",
        "len" => "byte-cap",
        "unq" => "counter",
        _ => "",
    }
}

/// `"nrm:nfc; san:charset"` reason string shared by all NDJSON records.
pub fn reason(stages: &[&str]) -> String {
    stages
        .iter()
        .map(|s| format!("{s}:{}", stage_detail(s)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One NDJSON field. The order of fields at the call site IS the wire
/// format (golden vectors pin it) — never reorder.
pub enum Field<'a> {
    S(&'a str, &'a str),
    N(&'a str, u64),
}

/// Write one NDJSON record: `{"k":"v","n":42}` with values escaped.
pub fn json_line(out: &mut impl Write, fields: &[Field]) {
    let body = fields
        .iter()
        .map(|f| match f {
            Field::S(k, v) => format!("\"{k}\":\"{}\"", json_escape(v)),
            Field::N(k, n) => format!("\"{k}\":{n}"),
        })
        .collect::<Vec<_>>()
        .join(",");
    write_line(out, &format!("{{{body}}}"));
}
