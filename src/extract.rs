//! `detox-rs extract` — MIME attachment extraction with pipeline-clean names.
//! Contract: docs/SLICES.md slice 6 v1; behavior per SPEC §8 and EXTRACT.md.
//!
//! Module map: [`decode`] byte decoders + charset tables, [`rfc2047`]
//! encoded-words, [`mime`] structure parsing, [`filename`] name resolution
//! (EXTRACT.md §3), [`walk`] the recursive extraction driver.

mod decode;
mod filename;
mod mime;
mod rfc2047;
mod walk;

use crate::{CaseMode, Profile, UniqueStyle, Uniquifier};
use mime::{find_seq, split_head_body};
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
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
        let r = walk::walk_part(&headers, body, opts, 0, &mut out, &mut uniq, &mut parts_seen, &mut cap_hit);
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
    let jerr = walk::write_extract_journal(&opts.journal_dir, &out);
    if journal_error.is_none() {
        journal_error = jerr;
    }
    Ok(ExtractReport {
        parts: out,
        journal_error,
    })
}
