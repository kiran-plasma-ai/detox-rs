//! Filesystem walk, plan/commit, journal, undo. Contract: SLICES.md slice 4 v1.
//! Safety model per SPEC §5: journal fsync'd before first rename; renames never
//! overwrite (renameat2 RENAME_NOREPLACE); batch cycles broken via journaled
//! temp names.
//!
//! Module map: this file holds the read-only side (walk + plan).
//! `commit` is the rename engine (schedule + no-replace primitives),
//! `journal` the shared journal I/O, `undo` the reverse replay.

mod commit;
mod journal;
mod undo;

use crate::{sanitize, Options, UniqueStyle, Uniquifier};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub use commit::{commit, file_identity, CommitError, CommitReport};
pub use journal::{journal_dir, write_create_journal};
pub use undo::{undo, SkipReason, UndoError, UndoReport, UndoSel};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum HiddenMode {
    #[default]
    Skip,
    Include,
    Only,
}

#[derive(Clone, Debug)]
pub struct WalkOptions {
    pub recursive: bool,
    pub hidden: HiddenMode,
    pub special: bool,
    pub max_depth: usize, // 0 = unlimited
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            recursive: false,
            hidden: HiddenMode::Skip,
            special: false,
            max_depth: 64,
        }
    }
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('.'))
}

/// Lexical normalization (no fs access): collapses `.`/`..` textually so
/// `./x` and `x` share one per-dir Uniquifier in plan().
fn lex_normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Walk: explicit args always processed; recursion honors hidden/special/
/// max_depth; symlinks never followed. Returns (entries, walk skips with
/// reasons, hidden-dropped paths): files first, dirs post-order; skipped
/// records dropped specials/unreadable dirs. The third channel is reported
/// but never aborts an apply (SPEC §4 UX-2: hidden skips are counted and
/// listed, unlike plan.skipped).
pub type WalkResult = (Vec<PathBuf>, Vec<(PathBuf, String)>, Vec<PathBuf>);

pub fn walk(paths: &[PathBuf], w: &WalkOptions) -> Result<WalkResult, String> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut hidden = Vec::new();
    for p in paths {
        let md = fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let ft = md.file_type();
        if ft.is_symlink() {
            // Never follow; rename the link itself unless it's a dir link.
            out.push(p.clone());
            continue;
        }
        if ft.is_dir() {
            walk_dir(p, w, 1, &mut out, &mut skipped, &mut hidden);
        } else if ft.is_file() || w.special {
            out.push(p.clone());
        } else {
            skipped.push((p.clone(), "special file (use --special)".into()));
        }
    }
    // Overlapping roots ("detox . ./x") would otherwise duplicate entries.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    out.retain(|e| seen.insert(lex_normalize(e)));
    Ok((out, skipped, hidden))
}

fn walk_dir(
    dir: &Path,
    w: &WalkOptions,
    depth: usize,
    out: &mut Vec<PathBuf>,
    skipped: &mut Vec<(PathBuf, String)>,
    hidden: &mut Vec<PathBuf>,
) {
    if w.recursive && (w.max_depth == 0 || depth <= w.max_depth) {
        let mut subdirs = Vec::new();
        match fs::read_dir(dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let p = e.path();
                    let is_hid = is_hidden(&p);
                    match w.hidden {
                        HiddenMode::Skip if is_hid => {
                            hidden.push(p);
                            continue;
                        }
                        HiddenMode::Only if !is_hid => continue,
                        _ => {}
                    }
                    let ft = match e.file_type() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if ft.is_symlink() {
                        out.push(p); // link itself, never followed
                    } else if ft.is_dir() {
                        subdirs.push(p);
                    } else if ft.is_file() || w.special {
                        out.push(p);
                    } else {
                        skipped.push((p, "special file (use --special)".into()));
                    }
                }
            }
            Err(e) => skipped.push((dir.to_path_buf(), format!("unreadable: {e}"))),
        }
        for d in subdirs {
            walk_dir(&d, w, depth + 1, out, skipped, hidden);
        }
    }
    // "." / ".." / "/" are walk roots, not rename candidates.
    if dir.file_name().is_some() {
        out.push(dir.to_path_buf()); // post-order: dir after its contents
    }
}

#[derive(Debug, PartialEq)]
pub struct PlanItem {
    pub old: PathBuf,
    pub new: PathBuf,
    pub stages: Vec<&'static str>,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub items: Vec<PlanItem>,
    pub unchanged: usize,
    pub skipped: Vec<(PathBuf, String)>,
}

fn lstat_exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

/// Plan: pipeline each entry; uniquify against on-disk names. Targets that
/// are olds of *planned* renames are left for commit-time cycle ordering;
/// targets of unchanged batch members are ordinary collisions.
pub fn plan(entries: &[PathBuf], opts: &Options) -> Plan {
    // Pass 1: which olds will actually be renamed?
    let mut pending: HashSet<PathBuf> = HashSet::new();
    for old in entries {
        let Some(name_os) = old.file_name() else { continue };
        let o = sanitize(name_os.as_encoded_bytes(), opts);
        if o.name.as_bytes() != name_os.as_encoded_bytes() {
            pending.insert(old.clone());
        }
    }

    // Pass 2: resolve targets.
    let mut plan = Plan::default();
    let mut per_dir: HashMap<PathBuf, Uniquifier> = HashMap::new();
    for old in entries {
        let Some(name_os) = old.file_name() else {
            plan.skipped.push((old.clone(), "no file name".into()));
            continue;
        };
        let o = sanitize(name_os.as_encoded_bytes(), opts);
        if o.name.as_bytes() == name_os.as_encoded_bytes() {
            plan.unchanged += 1;
            continue;
        }
        let dir = old
            .parent()
            .map(lex_normalize)
            .unwrap_or_default();
        let uniq = per_dir
            .entry(dir)
            .or_insert_with(|| Uniquifier::new(UniqueStyle::Infix, opts.max_bytes));
        let resolved = match uniq.apply(o.name) {
            Ok((n, _)) => old.with_file_name(n),
            Err(_) => {
                plan.skipped
                    .push((old.clone(), "cannot uniquify within max-length".into()));
                continue;
            }
        };
        // On-disk collision with a path NOT being renamed in this batch:
        // counter-advance. Planned targets stay (cycle ordering at commit).
        let mut resolved = resolved;
        let mut guard = 0usize;
        while lstat_exists(&resolved) && !pending.contains(&resolved) {
            guard += 1;
            if guard > 10_000 {
                plan.skipped
                    .push((old.clone(), "collision resolution loop".into()));
                resolved = old.clone();
                break;
            }
            let base = resolved.file_name().unwrap().to_string_lossy().into_owned();
            match uniq.apply(base) {
                Ok((n, _)) => resolved = old.with_file_name(n),
                Err(_) => {
                    // No uniquified variant fits max-length: report and leave
                    // the file untouched. (Without this, `resolved` could
                    // remain an on-disk-existing path here and the plan would
                    // carry a doomed rename; renameat2 NOREPLACE kept it from
                    // ever overwriting, but it belonged in `skipped`.)
                    plan.skipped
                        .push((old.clone(), "cannot uniquify within max-length".into()));
                    resolved = old.clone();
                    break;
                }
            }
        }
        if resolved == *old {
            continue;
        }
        plan.items.push(PlanItem {
            old: old.clone(),
            new: resolved,
            stages: o.stages,
        });
    }
    plan
}
