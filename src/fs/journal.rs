//! Journal I/O shared by rename-commit and extract: entry type, escape/
//! parse (inverse pair), file naming, and the two writers. The reader
//! (undo) is fs/undo.rs; the schedule writer that calls write_journal is
//! fs/commit.rs.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct JEntry {
    pub(super) old: PathBuf,
    pub(super) new: PathBuf,
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) tmp: bool,
    pub(super) create: bool, // extraction: `new` was created (undo = delete)
}

pub(super) fn jescape(s: &str) -> String {
    crate::json_escape(s)
}

pub(super) fn junescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('u') => {
                    let h: String = chars.by_ref().take(4).collect();
                    if let Ok(n) = u32::from_str_radix(&h, 16) {
                        out.push(char::from_u32(n).unwrap_or('\u{fffd}'));
                    }
                }
                _ => out.push('\u{fffd}'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Minimal parser for our own journal lines (inverse of the writer above).
pub(super) fn jparse(line: &str) -> Option<JEntry> {
    let get_s = |key: &str| -> Option<String> {
        let pat = format!("\"{key}\":\"");
        let start = line.find(&pat)? + pat.len();
        let rest = &line[start..];
        let mut end = 0;
        let mut it = rest.char_indices().peekable();
        while let Some((i, c)) = it.next() {
            if c == '\\' {
                it.next();
                continue;
            }
            if c == '"' {
                end = i;
                break;
            }
        }
        Some(junescape(&rest[..end]))
    };
    let get_n = |key: &str| -> Option<u64> {
        let pat = format!("\"{key}\":");
        let start = line.find(&pat)? + pat.len();
        let rest = &line[start..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    };
    Some(JEntry {
        old: PathBuf::from(get_s("old").unwrap_or_default()),
        new: PathBuf::from(get_s("new")?),
        dev: get_n("dev").unwrap_or(0),
        ino: get_n("ino").unwrap_or(0),
        tmp: line.contains("\"tmp\":true"),
        create: line.contains("\"create\":true"),
    })
}

pub(super) fn journal_path(journal_dir: &Path, run: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    journal_dir.join(format!("{ts}-{run}.jsonl"))
}

pub(super) fn write_journal(path: &Path, run: &str, entries: &[JEntry]) -> io::Result<()> {
    let mut f = fs::File::create(path)?;
    for e in entries {
        let old = e.old.to_string_lossy();
        let new = e.new.to_string_lossy();
        writeln!(
            f,
            "{{\"run\":\"{run}\",\"old\":\"{}\",\"new\":\"{}\",\"dev\":{},\"ino\":{}{}}}",
            jescape(&old),
            jescape(&new),
            e.dev,
            e.ino,
            if e.tmp { ",\"tmp\":true" } else { "" }
        )?;
    }
    f.sync_all()
}

fn default_journal_dir() -> PathBuf {
    if let Ok(d) = std::env::var("DETOX_RS_JOURNAL_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(x) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(x).join("detox-rs/journal");
    }
    if let Ok(h) = std::env::var("HOME") {
        // Same "detox-rs" name as the XDG branch (review P3.1: the old
        // "detox" fallback split one user's journals across two homes).
        return PathBuf::from(h).join(".local/state/detox-rs/journal");
    }
    std::env::temp_dir().join("detox-journal")
}

pub fn journal_dir() -> PathBuf {
    default_journal_dir()
}

/// Write extraction ("create") entries to a journal file. Caller fsyncs.
pub fn write_create_journal(
    journal_dir: &Path,
    run: &str,
    created: &[(PathBuf, u64, u64)],
) -> io::Result<PathBuf> {
    fs::create_dir_all(journal_dir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = journal_dir.join(format!("{ts}-{run}.jsonl"));
    let mut f = fs::File::create(&path)?;
    for (p, dev, ino) in created {
        let n = p.to_string_lossy();
        writeln!(
            f,
            "{{\"run\":\"{run}\",\"new\":\"{}\",\"dev\":{dev},\"ino\":{ino},\"create\":true}}",
            jescape(&n)
        )?;
    }
    f.sync_all()?;
    Ok(path)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn journal_escape_roundtrip() {
        let nasty = "quo\"te\\back\tslash\nnl\u{1f600} 日本 .x";
        let esc = jescape(nasty);
        let quoted = format!("\"old\":\"{esc}\",\"dev\":1");
        let parsed = jparse(&format!(
            "{{\"run\":\"r\",\"old\":\"{esc}\",\"new\":\"n\",\"dev\":1,\"ino\":2}}"
        ))
        .unwrap();
        assert_eq!(parsed.old.to_string_lossy(), nasty);
        assert!(quoted.contains("\\\""));
        assert_eq!(parsed.ino, 2);
        assert!(!parsed.tmp);
    }

    #[test]
    fn journal_parse_tmp_flag() {
        let e = jparse("{\"run\":\"r\",\"old\":\"a\",\"new\":\"b\",\"dev\":0,\"ino\":0,\"tmp\":true}")
            .unwrap();
        assert!(e.tmp);
    }
}
