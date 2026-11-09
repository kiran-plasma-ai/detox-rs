//! Filesystem walk, plan/commit, journal, undo. Contract: SLICES.md slice 4 v1.
//! Safety model per SPEC §5: journal fsync'd before first rename; renames never
//! overwrite (renameat2 RENAME_NOREPLACE); batch cycles broken via journaled
//! temp names.

use crate::{sanitize, Options, UniqueStyle, Uniquifier};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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

#[derive(Debug)]
pub struct CommitReport {
    pub renamed: usize,
    pub errors: Vec<(PathBuf, String)>,
}

#[derive(Debug)]
pub struct CommitError(pub String);

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn dev_ino(p: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    // symlink_metadata: journal the link's own identity, not its target's —
    // undo must match (and restore) the link itself.
    fs::symlink_metadata(p).ok().map(|m| (m.dev(), m.ino()))
}

#[derive(Debug)]
struct JEntry {
    old: PathBuf,
    new: PathBuf,
    dev: u64,
    ino: u64,
    tmp: bool,
    create: bool, // extraction: `new` was created (undo = delete)
}

fn jescape(s: &str) -> String {
    crate::json_escape(s)
}

fn junescape(s: &str) -> String {
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
fn jparse(line: &str) -> Option<JEntry> {
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

fn rename_noreplace(old: &Path, new: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        const RENAME_NOREPLACE: libc::c_int = 1; // linux/fs.h; libc gates the symbol to gnu
        let ob = old.as_os_str().as_bytes();
        let nb = new.as_os_str().as_bytes();
        let mut obuf = Vec::with_capacity(ob.len() + 1);
        obuf.extend_from_slice(ob);
        obuf.push(0);
        let mut nbuf = Vec::with_capacity(nb.len() + 1);
        nbuf.extend_from_slice(nb);
        nbuf.push(0);
        // syscall(2): available on every Linux arch/kernel combo where the
        // wrapper is not (musl), and identical semantics elsewhere.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                obuf.as_ptr(),
                libc::AT_FDCWD,
                nbuf.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if ret == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => {} // fall through to fallback
            _ => return Err(e),
        }
    }
    if lstat_exists(new) {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "target exists"));
    }
    fs::rename(old, new)
}

fn journal_path(journal_dir: &Path, run: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    journal_dir.join(format!("{ts}-{run}.jsonl"))
}

fn write_journal(path: &Path, run: &str, entries: &[JEntry]) -> io::Result<()> {
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

/// Build the execution schedule in dependency-safe order: plain entries as
/// planned; dependency chains reversed (target is a pending old); cycles
/// broken with a temp rename (first element via temp, rest reversed, temp
/// lands last). Precomputing means the journaled sequence IS the executed
/// sequence, so undo is a pure reverse replay.
fn build_exec(items: &[PlanItem], run: &str) -> Vec<(PathBuf, PathBuf)> {
    let olds: HashSet<&Path> = items.iter().map(|i| i.old.as_path()).collect();
    let by_old: HashMap<&Path, &PlanItem> = items.iter().map(|i| (i.old.as_path(), i)).collect();
    let mut done: HashSet<PathBuf> = HashSet::new();
    let mut exec: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut n = 0usize;

    for item in items {
        if done.contains(&item.old) {
            continue;
        }
        let dep = olds.contains(item.new.as_path()) && !done.contains(&item.new);
        if !dep {
            exec.push((item.old.clone(), item.new.clone()));
            done.insert(item.old.clone());
            continue;
        }
        // Walk the dependency chain.
        let mut chain: Vec<&PlanItem> = vec![item];
        let mut is_cycle = false;
        let mut cur = item;
        while let Some(next) = by_old.get(cur.new.as_path()) {
            if chain.first().is_some_and(|f| f.old == next.old) {
                is_cycle = true;
                break;
            }
            if chain.contains(next) || done.contains(&next.old) {
                break;
            }
            chain.push(next);
            cur = next;
        }
        if is_cycle {
            // Temp name carries the run id and is lstat-checked, so a leftover
            // tmp from a crashed run can never deadlock the cycle.
            let mut tmp = chain[0]
                .old
                .with_file_name(format!(".detox-tmp-{run}-{n}"));
            while lstat_exists(&tmp) {
                n += 1;
                tmp = chain[0]
                    .old
                    .with_file_name(format!(".detox-tmp-{run}-{n}"));
            }
            exec.push((chain[0].old.clone(), tmp.clone()));
            done.insert(chain[0].old.clone());
            for link in chain.iter().skip(1).rev() {
                exec.push((link.old.clone(), link.new.clone()));
                done.insert(link.old.clone());
            }
            exec.push((tmp, chain[0].new.clone()));
        } else {
            for link in chain.iter().rev() {
                if done.contains(&link.old) {
                    continue;
                }
                exec.push((link.old.clone(), link.new.clone()));
                done.insert(link.old.clone());
            }
        }
    }
    exec
}

/// Commit: build schedule, journal it (fsync) BEFORE any rename — per SPEC
/// §5.3 the journaled sequence is exactly what executes, so undo is reverse
/// replay and crash recovery is well-defined.
pub fn commit(plan: &Plan, journal_dir: &Path, run: &str) -> Result<CommitReport, CommitError> {
    if plan.items.is_empty() {
        return Ok(CommitReport {
            renamed: 0,
            errors: vec![],
        });
    }
    fs::create_dir_all(journal_dir).map_err(|e| CommitError(format!("journal dir: {e}")))?;

    let exec = build_exec(&plan.items, run);
    // dev/ino captured pre-rename; rename preserves both, so each step's
    // target inherits its source's identity — this resolves steps whose
    // source is a not-yet-existing tmp path (cycles).
    let mut inode_map: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut entries: Vec<JEntry> = Vec::with_capacity(exec.len());
    for (old, new) in &exec {
        let (dev, ino) = dev_ino(old)
            .or_else(|| inode_map.get(old).copied())
            .unwrap_or((0, 0));
        inode_map.insert(new.clone(), (dev, ino));
        entries.push(JEntry {
            old: old.clone(),
            new: new.clone(),
            dev,
            ino,
            tmp: new
                .file_name()
                .is_some_and(|f| f.to_string_lossy().starts_with(".detox-tmp-")),
            create: false,
        });
    }
    let jpath = journal_path(journal_dir, run);
    if let Err(e) = write_journal(&jpath, run, &entries) {
        return Err(CommitError(format!("journal write: {e}"))); // abort before any rename
    }

    let mut report = CommitReport {
        renamed: 0,
        errors: vec![],
    };
    for (old, new) in &exec {
        if let Err(e) = rename_noreplace(old, new) {
            report.errors.push((old.clone(), e.to_string()));
            continue;
        }
        report.renamed += 1;
    }

    // SPEC §5.3 taxonomy: zero committed renames -> leave no journal; partial
    // batches keep the journal with a partial marker.
    if report.renamed == 0 {
        let _ = fs::remove_file(&jpath);
    } else if !report.errors.is_empty() {
        if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&jpath) {
            let _ = writeln!(f, "{{\"run\":\"{run}\",\"partial\":true}}");
        }
    }
    Ok(report)
}

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
                    use std::os::unix::fs::MetadataExt;
                    if (md.dev(), md.ino()) != (e.dev, e.ino) {
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

fn restore_one(e: &JEntry) -> Result<(), SkipReason> {
    // lstat: match the link's own identity, not its target's.
    let md = match fs::symlink_metadata(&e.new) {
        Ok(m) => m,
        Err(_) => return Err(SkipReason::Missing),
    };
    use std::os::unix::fs::MetadataExt;
    if (md.dev(), md.ino()) != (e.dev, e.ino) {
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
