//! Undo: journal selection (last or by run id) and pure reverse replay.
//! Every journal line including temp steps is undone new->old in reverse
//! order; missing/dev+inode mismatches skip with a reason (SPEC §5.3).

use std::fs;
use std::path::{Path, PathBuf};

use super::commit::{file_identity, rename_noreplace};
use super::journal::{jparse, JEntry};

#[derive(Clone, Debug, Default)]
pub enum UndoSel {
    #[default]
    Last,
    Run(String),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SkipReason {
    /// The journaled `new` path no longer exists.
    Missing,
    /// The path exists but dev+inode don't match the journal.
    Mismatch,
    /// The original parent directory no longer exists (never recreated).
    ParentMissing,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SkipReason::Missing => "path missing",
            SkipReason::Mismatch => "dev+inode mismatch (occupied by another file)",
            SkipReason::ParentMissing => "parent directory missing; not recreating",
        })
    }
}

#[derive(Debug, Default)]
pub struct UndoReport {
    pub restored: usize,
    pub skipped: Vec<(PathBuf, SkipReason)>,
}

#[derive(Debug)]
pub struct UndoError(pub String);

impl std::fmt::Display for UndoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn undo(sel: UndoSel, journal_dir: &Path) -> Result<UndoReport, UndoError> {
    let mut files: Vec<PathBuf> = fs::read_dir(journal_dir)
        .map_err(|e| UndoError(format!("journal dir: {e}")))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    let chosen = match sel {
        UndoSel::Last => files.last().cloned(),
        UndoSel::Run(id) => files.iter().rev().find(|f| {
            f.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".jsonl"))
                .and_then(|s| s.split_once('-'))
                .is_some_and(|(_, r)| r == id)
        }).cloned(),
    };
    let Some(jf) = chosen else {
        return Err(UndoError("no matching journal".into()));
    };
    let content =
        fs::read_to_string(&jf).map_err(|e| UndoError(format!("reading journal: {e}")))?;
    let mut entries: Vec<JEntry> = content.lines().filter_map(jparse).collect();
    // Pure reverse replay: every journal line (including both temp steps) is
    // undone new->old in reverse chronological order. Missing/dev+inode
    // mismatches are skip-with-warning (SPEC §5.3); temp steps whose tmp path
    // was already restored via the paired entry simply no longer exist.
    entries.reverse();
    let mut report = UndoReport::default();
    for e in &entries {
        if e.create {
            // Extraction undo: delete the file we created, but only if it is
            // still the same file (dev+inode).
            match fs::symlink_metadata(&e.new) {
                Err(_) => report.skipped.push((e.new.clone(), SkipReason::Missing)),
                Ok(md) => {
                    if file_identity(&e.new, &md) != (e.dev, e.ino) {
                        report.skipped.push((e.new.clone(), SkipReason::Mismatch));
                    } else {
                        match fs::remove_file(&e.new) {
                            Ok(()) => report.restored += 1,
                            Err(_) => report
                                .skipped
                                .push((e.new.clone(), SkipReason::Mismatch)),
                        }
                    }
                }
            }
            continue;
        }
        match restore_one(e) {
            Ok(()) => report.restored += 1,
            Err(reason) => report.skipped.push((e.new.clone(), reason)),
        }
    }
    Ok(report)
}

fn restore_one(e: &JEntry) -> Result<(), SkipReason> {
    // lstat: match the link's own identity, not its target's.
    let md = match fs::symlink_metadata(&e.new) {
        Ok(m) => m,
        Err(_) => return Err(SkipReason::Missing),
    };
    if file_identity(&e.new, &md) != (e.dev, e.ino) {
        return Err(SkipReason::Mismatch);
    }
    if let Some(parent) = e.old.parent() {
        // symlink_metadata (not exists()): a parent swapped for a symlink
        // between runs must not redirect the restore (sec review F6).
        if !parent.as_os_str().is_empty()
            && !fs::symlink_metadata(parent).is_ok_and(|m| m.is_dir())
        {
            return Err(SkipReason::ParentMissing);
        }
    }
    rename_noreplace(&e.new, &e.old).map_err(|_| SkipReason::Mismatch)
}

