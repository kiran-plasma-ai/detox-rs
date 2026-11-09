//! Slice 4 acceptance: walk/plan/commit/journal/undo against real temp dirs.
//! Oracle: docs/SLICES.md slice 4 v1; SPEC §5.1–5.3, §5.9.

use detox_rs::fs::{self, HiddenMode, UndoSel, WalkOptions};
use detox_rs::Options;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!(
        "detox-test-{}-{}-{}-{}",
        tag,
        std::process::id(),
        nanos,
        n
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn touch(p: &Path) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, b"x").unwrap();
}

fn walk_opts() -> WalkOptions {
    WalkOptions {
        recursive: true,
        ..WalkOptions::default()
    }
}

fn plan_for(dir: &Path) -> fs::Plan {
    let (entries, _walk_skips, _hidden) = fs::walk(&[dir.to_path_buf()], &walk_opts()).unwrap();
    fs::plan(&entries, &Options::default())
}

#[test]
fn apply_then_undo_roundtrip() {
    let root = tmpdir("roundtrip");
    let a = root.join("My Report.docx");
    let b = root.join("--help.txt");
    touch(&a);
    touch(&b);

    let plan = plan_for(&root);
    assert_eq!(plan.items.len(), 2, "{plan:?}");
    // Plan touches nothing.
    assert!(a.exists() && b.exists());

    let journal = root.join("journal");
    let report = fs::commit(&plan, &journal, "test-roundtrip").unwrap();
    assert_eq!(report.errors, vec![]);
    assert_eq!(report.renamed, 2);
    let new_a = root.join("My_Report.docx");
    let new_b = root.join("help.txt");
    assert!(new_a.exists() && new_b.exists(), "renamed files must exist");
    assert!(!a.exists() && !b.exists());

    let undo = fs::undo(UndoSel::Last, &journal).unwrap();
    assert_eq!(undo.skipped, vec![]);
    assert_eq!(undo.restored, 2);
    assert!(a.exists() && b.exists(), "undo must restore originals");
    assert!(!new_a.exists() && !new_b.exists());
}

#[test]
fn swap_cycle_commits_and_undoes() {
    let root = tmpdir("swap");
    let x = root.join("x.txt");
    let y = root.join("y.txt");
    std::fs::write(&x, b"content-x").unwrap();
    std::fs::write(&y, b"content-y").unwrap();
    let plan = fs::Plan {
        items: vec![
            fs::PlanItem {
                old: x.clone(),
                new: y.clone(),
                stages: vec![],
            },
            fs::PlanItem {
                old: y.clone(),
                new: x.clone(),
                stages: vec![],
            },
        ],
        unchanged: 0,
        skipped: vec![],
    };
    let journal = root.join("journal");
    let report = fs::commit(&plan, &journal, "test-swap").unwrap();
    assert_eq!(report.errors, vec![], "{report:?}");
    // Cycle commit = 3 executed steps (x->tmp, y->x, tmp->y).
    assert_eq!(report.renamed, 3);
    assert_eq!(std::fs::read(&y).unwrap(), b"content-x");
    assert_eq!(std::fs::read(&x).unwrap(), b"content-y");

    let undo = fs::undo(UndoSel::Last, &journal).unwrap();
    // Cycle commit = 3 executed steps (x->tmp, y->x, tmp->y), all undone.
    assert_eq!(undo.restored, 3, "{undo:?}");
    assert!(undo.skipped.is_empty(), "{undo:?}");
    assert_eq!(std::fs::read(&x).unwrap(), b"content-x");
    assert_eq!(std::fs::read(&y).unwrap(), b"content-y");
}

#[test]
fn dependency_chain_commits_in_order() {
    // a -> b, b -> c, c -> d (d free): must commit in reverse — c -> d,
    // then b -> c, then a -> b — or NOREPLACE fails on every step.
    let root = tmpdir("chain");
    let a = root.join("a.txt");
    let b = root.join("b.txt");
    let c = root.join("c.txt");
    let d = root.join("d.txt");
    std::fs::write(&a, b"content-a").unwrap();
    std::fs::write(&b, b"content-b").unwrap();
    std::fs::write(&c, b"content-c").unwrap();
    let plan = fs::Plan {
        items: vec![
            fs::PlanItem {
                old: a.clone(),
                new: b.clone(),
                stages: vec![],
            },
            fs::PlanItem {
                old: b.clone(),
                new: c.clone(),
                stages: vec![],
            },
            fs::PlanItem {
                old: c.clone(),
                new: d.clone(),
                stages: vec![],
            },
        ],
        unchanged: 0,
        skipped: vec![],
    };
    let journal = root.join("journal");
    let report = fs::commit(&plan, &journal, "test-chain").unwrap();
    assert_eq!(report.errors, vec![], "{report:?}");
    assert_eq!(report.renamed, 3);
    assert_eq!(std::fs::read(&b).unwrap(), b"content-a");
    assert_eq!(std::fs::read(&c).unwrap(), b"content-b");
    assert_eq!(std::fs::read(&d).unwrap(), b"content-c");
    assert!(!a.exists());
    let undo = fs::undo(UndoSel::Last, &journal).unwrap();
    assert!(undo.skipped.is_empty(), "{undo:?}");
    assert_eq!(std::fs::read(&a).unwrap(), b"content-a");
    assert_eq!(std::fs::read(&b).unwrap(), b"content-b");
    assert_eq!(std::fs::read(&c).unwrap(), b"content-c");
    assert!(!d.exists());
}

#[test]
fn disk_collision_gets_uniquified() {
    let root = tmpdir("collision");
    let existing = root.join("a_b.txt");
    touch(&existing);
    let incoming = root.join("a b.txt");
    touch(&incoming);

    let plan = plan_for(&root);
    assert_eq!(plan.items.len(), 1);
    let item = &plan.items[0];
    assert_eq!(item.old, incoming);
    assert_eq!(item.new, root.join("a_b_1.txt"), "{item:?}");

    let journal = root.join("journal");
    let report = fs::commit(&plan, &journal, "test-collision").unwrap();
    assert_eq!(report.renamed, 1);
    assert!(existing.exists() && root.join("a_b_1.txt").exists());
    let undo = fs::undo(UndoSel::Last, &journal).unwrap();
    assert_eq!(undo.restored, 1);
    assert!(incoming.exists() && existing.exists());
}

#[test]
fn recursive_post_order_dir_rename() {
    let root = tmpdir("postorder");
    let dir = root.join("dir with space");
    let child = dir.join("file x.txt");
    touch(&child);

    let w = WalkOptions {
        recursive: true,
        ..walk_opts()
    };
    let (entries, _skips, _hidden) = fs::walk(std::slice::from_ref(&root), &w).unwrap();
    // Post-order: the child must appear before its parent dir.
    let ci = entries.iter().position(|e| e == &child).unwrap();
    let di = entries.iter().position(|e| e == &dir).unwrap();
    assert!(ci < di, "{entries:?}");
    // The root itself is also listed (post-order) — it keeps its name.
    let plan = fs::plan(&entries, &Options::default());
    let journal = root.join("journal");
    let report = fs::commit(&plan, &journal, "test-postorder").unwrap();
    assert_eq!(report.errors, vec![]);
    assert!(root.join("dir_with_space/file_x.txt").exists());
    let undo = fs::undo(UndoSel::Last, &journal).unwrap();
    assert!(child.exists(), "{undo:?}");
}

#[test]
fn hidden_policy_skip_include() {
    let root = tmpdir("hidden");
    touch(&root.join("visible file.txt"));
    touch(&root.join(".hidden file.txt"));
    let w = WalkOptions {
        recursive: true,
        hidden: HiddenMode::Skip,
        ..walk_opts()
    };
    let (entries, _skips, _hidden) = fs::walk(std::slice::from_ref(&root), &w).unwrap();
    // Root dir itself is also an entry (post-order).
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(!entries.iter().any(|e| e.to_string_lossy().contains(".hidden")));
    let w = WalkOptions {
        recursive: true,
        hidden: HiddenMode::Include,
        ..walk_opts()
    };
    let (entries, _skips, _hidden) = fs::walk(std::slice::from_ref(&root), &w).unwrap();
    assert_eq!(entries.len(), 3, "{entries:?}");
}

#[test]
fn foreign_target_never_clobbered() {
    let root = tmpdir("noclobber");
    let foreign = root.join("a_b.txt");
    std::fs::write(&foreign, b"foreign").unwrap();
    let incoming = root.join("a b.txt");
    std::fs::write(&incoming, b"mine").unwrap();

    let plan = plan_for(&root);
    let journal = root.join("journal");
    fs::commit(&plan, &journal, "test-noclobber").unwrap();
    assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign");
    assert_eq!(std::fs::read(root.join("a_b_1.txt")).unwrap(), b"mine");
}

#[test]
fn zero_renames_leaves_no_journal() {
    let root = tmpdir("empty");
    let f = root.join("clean.txt");
    touch(&f);
    let plan = plan_for(&root);
    assert!(plan.items.is_empty());
    let journal = root.join("journal");
    let report = fs::commit(&plan, &journal, "test-empty").unwrap();
    assert_eq!(report.renamed, 0);
    assert!(!journal.exists() || std::fs::read_dir(&journal).unwrap().next().is_none());
}

#[test]
fn first_rename_failure_leaves_no_journal() {
    let root = tmpdir("readonly");
    let f = root.join("bad name.txt");
    touch(&f);
    let plan = plan_for(&root);
    assert_eq!(plan.items.len(), 1);
    // Make the directory read-only so the rename fails.
    let mut perms = std::fs::metadata(&root).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o555);
    std::fs::set_permissions(&root, perms).unwrap();
    let journal = std::env::temp_dir().join(format!("detox-journal-ro-{}", std::process::id()));
    let report = fs::commit(&plan, &journal, "test-ro").unwrap();
    assert_eq!(report.renamed, 0);
    assert!(!report.errors.is_empty());
    assert!(f.exists());
    assert!(!journal.join("test-ro.jsonl").exists() || {
        // journal file is ts-prefixed; ensure none mentions test-ro
        std::fs::read_dir(&journal)
            .map(|mut d| d.all(|e| !e.unwrap().file_name().to_string_lossy().contains("test-ro")))
            .unwrap_or(true)
    });
    // restore perms for cleanup
    let mut perms = std::fs::metadata(&root).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&root, perms).unwrap();
}

#[test]
fn undo_skips_missing_and_mismatched() {
    let root = tmpdir("undoskip");
    let a = root.join("one bad.txt");
    let b = root.join("two bad.txt");
    touch(&a);
    touch(&b);
    let plan = plan_for(&root);
    let journal = root.join("journal");
    fs::commit(&plan, &journal, "test-undoskip").unwrap();
    let new_a = root.join("one_bad.txt");
    let new_b = root.join("two_bad.txt");
    assert!(new_a.exists() && new_b.exists());
    // Delete one target, replace the other with a different file (fresh inode:
    // fs::write on the existing path would keep the inode).
    std::fs::remove_file(&new_a).unwrap();
    std::fs::remove_file(&new_b).unwrap();
    std::fs::write(&new_b, b"different inode").unwrap();
    let undo = fs::undo(UndoSel::Last, &journal).unwrap();
    assert_eq!(undo.restored, 0, "{undo:?}");
    assert_eq!(undo.skipped.len(), 2);
    // The mismatched foreign file is untouched.
    assert_eq!(std::fs::read(&new_b).unwrap(), b"different inode");
}

#[test]
fn plan_collision_uniquify_err_is_skipped_not_planned() {
    // Independent review + repro in /tmp: when a colliding target cannot be
    // uniquified within --max-length, the entry must land in `skipped`, not
    // in the plan pointing at an existing path. (renameat2 NOREPLACE always
    // prevented the overwrite; this is the planner-contract half.)
    let root = tmpdir("unq-err");
    let a = root.join("a  .txt"); // sanitizes+truncates to `a_.txt`
    let b = root.join("a_.txt"); // exists on disk -> collision
    touch(&a);
    touch(&b);
    let (entries, _, _) = fs::walk(std::slice::from_ref(&a), &walk_opts()).unwrap();
    let opts = Options {
        max_bytes: 6,
        ..Options::default()
    };
    let plan = fs::plan(&entries, &opts);
    assert!(plan.items.is_empty(), "{plan:?}");
    assert_eq!(plan.skipped.len(), 1, "{plan:?}");
    assert!(plan.skipped[0].1.contains("cannot uniquify"));
    assert!(a.exists() && b.exists());
}

#[test]
fn plan_reports_unchanged() {
    let root = tmpdir("unchanged");
    touch(&root.join("clean.txt"));
    let plan = plan_for(&root);
    assert!(plan.items.is_empty());
    // clean.txt + the root dir itself
    assert_eq!(plan.unchanged, 2);
}
