//! The rename engine: execution-schedule builder (dependency chains and
//! cycle-breaking via journaled temp names), the journal-then-rename
//! commit driver, and the atomic no-replace primitives. SPEC §5 safety
//! model lives here: journal fsync'd before the first rename; renames
//! never overwrite (renameat2 NOREPLACE / renamex_np EXCL / checked
//! fallback).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::journal::{journal_path, write_journal, JEntry};
use super::{lstat_exists, Plan, PlanItem};


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

/// Filesystem identity for journal dev+inode checks.
/// Unix: real dev/ino from the metadata. Windows: volume serial + file
/// index via GetFileInformationByHandle (std's accessors are unstable), so
/// the path is re-opened with OPEN_REPARSE to match the link's own
/// identity, like symlink_metadata. Other OSes: (0,0) — the check
/// degenerates to path-only; only shipped targets get a hard identity.
pub fn file_identity(p: &Path, md: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = p;
        (md.dev(), md.ino())
    }
    #[cfg(windows)]
    {
        windows_identity(p).unwrap_or((0, 0))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (p, md);
        (0, 0)
    }
}

#[cfg(windows)]
fn windows_identity(p: &Path) -> Option<(u64, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    // BY_HANDLE_FILE_INFORMATION (winbase.h); FILETIME modeled as two
    // DWORDs to preserve 4-byte packing.
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct ByHandleInfo {
        file_attributes: u32,
        creation: FileTime,
        last_access: FileTime,
        last_write: FileTime,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(h: *mut std::ffi::c_void, i: *mut ByHandleInfo) -> i32;
    }

    // OPEN_REPARSE: identity of the link itself, not its target.
    // BACKUP_SEMANTICS: directories open too. Desired access 0 — a
    // query-only handle is all GetFileInformationByHandle needs.
    let f = std::fs::OpenOptions::new()
        .custom_flags(0x0020_0000 | 0x0200_0000) /* OPEN_REPARSE | BACKUP_SEMANTICS */
        .open(p)
        .ok()?;
    let mut info: ByHandleInfo = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) };
    (ok != 0).then(|| {
        (
            info.volume_serial as u64,
            ((info.index_high as u64) << 32) | info.index_low as u64,
        )
    })
}

fn dev_ino(p: &Path) -> Option<(u64, u64)> {
    // symlink_metadata: journal the link's own identity, not its target's —
    // undo must match (and restore) the link itself.
    fs::symlink_metadata(p)
        .ok()
        .map(|m| file_identity(p, &m))
}

pub(super) fn rename_noreplace(old: &Path, new: &Path) -> io::Result<()> {
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
    // macOS: renamex_np(RENAME_EXCL) is the same atomic no-replace primitive
    // as renameat2(NOREPLACE). Elsewhere the lstat+rename fallback stands;
    // on Windows std rename fails rather than replaces, so the race fails
    // safe there (and is documented on other unixes).
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        const RENAME_EXCL: libc::c_uint = 0x4; // <sys/renamex_np.h>
        let ob = std::ffi::CString::new(old.as_os_str().as_bytes()).unwrap();
        let nb = std::ffi::CString::new(new.as_os_str().as_bytes()).unwrap();
        let ret = unsafe { libc::renamex_np(ob.as_ptr(), nb.as_ptr(), RENAME_EXCL) };
        if ret == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
    if lstat_exists(new) {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "target exists"));
    }
    fs::rename(old, new)
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

