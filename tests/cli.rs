//! CLI-level acceptance: exercises the real binary, its exit codes, and the
//! `check`/`--apply`/`undo` surface (SLICES slice 4, review finding: no CLI
//! tests existed).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> Command {
    // Dashed target names aren't reachable via env!(); cargo sets this at
    // test-runtime for integration tests.
    Command::new(
        std::env::var("CARGO_BIN_EXE_detox-rs").expect("cargo sets CARGO_BIN_EXE_<bin>"),
    )
}

fn tmpdir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!(
        "detox-cli-{}-{}-{}-{}",
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

#[test]
fn hidden_skips_are_listed_and_do_not_abort_apply() {
    // Review P2 (SPEC §4 UX-2): default --hidden skip must COUNT and LIST
    // dotfiles in the report, and an apply must not abort over them.
    let root = tmpdir("hidden");
    touch(&root.join("visible file.txt"));
    touch(&root.join(".dirty name.txt"));
    let out = bin().arg("check").arg("-r").arg(&root).output().unwrap();
    assert!(out.status.code() == Some(1), "status {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("skip") && stdout.contains(".dirty name.txt"),
        "{stdout}"
    );
    // plan output must NOT contain the hidden file as a plan item
    assert!(!stdout.contains("plan\",\"old\":\".dirty"), "{stdout}");

    let out = bin()
        .arg("--apply")
        .arg("-r")
        .arg("--journal-dir")
        .arg(root.join("j"))
        .arg(&root)
        .output()
        .unwrap();
    assert!(out.status.success(), "status {:?}", out.status);
    assert!(root.join("visible_file.txt").exists());
    assert!(root.join(".dirty name.txt").exists(), "hidden untouched");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(".dirty name.txt"), "{stdout}");
}

#[test]
fn extract_double_overwrite_replaces_preexisting_file() {
    // Review P1: with --overwrite double-armed, the file at the requested
    // name is the intended target (seed uniquifier skipped it before).
    let root = tmpdir("ovr");
    touch(&root.join("report.pdf"));
    std::fs::write(root.join("report.pdf"), b"OLD").unwrap();
    let mail = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\n\r\nNEW\r\n--BB--\r\n";
    let mut child = bin()
        .arg("extract")
        .arg("-i")
        .arg("-")
        .arg("-d")
        .arg(&root)
        .arg("--overwrite")
        .arg("--overwrite")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(mail).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "status {:?}", out.status);
    assert_eq!(std::fs::read(root.join("report.pdf")).unwrap(), b"NEW");
}

#[test]
fn boundary_with_trailing_whitespace_is_accepted() {
    // Review P3.2: broken MUAs emit "--x " delimiter lines; rejecting them
    // silently dropped the whole multipart.
    let root = tmpdir("tws");
    let mail = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"bx\"\r\n\r\n--bx \r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"tw.txt\"\r\n\r\nhi\r\n--bx--\r\n";
    let mut child = bin()
        .arg("extract")
        .arg("-i")
        .arg("-")
        .arg("-d")
        .arg(&root)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(mail).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "status {:?}", out.status);
    assert_eq!(std::fs::read(root.join("tw.txt")).unwrap(), b"hi");
}

#[test]
fn check_subcommand_plans_and_exits_1_when_dirty() {
    let root = tmpdir("check");
    touch(&root.join("dirty file.txt"));
    let out = bin().arg("check").arg("-r").arg(&root).output().unwrap();
    assert!(out.status.code() == Some(1), "status {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("plan"), "{stdout}");
    assert!(stdout.contains("dirty_file.txt"), "{stdout}");
    // Plan touches nothing.
    assert!(root.join("dirty file.txt").exists());
}

#[test]
fn check_clean_tree_exits_0() {
    let root = tmpdir("clean");
    touch(&root.join("clean.txt"));
    let out = bin().arg("-r").arg(&root).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn apply_and_undo_roundtrip_cli() {
    let root = tmpdir("apply");
    touch(&root.join("My Report.docx"));
    let journal = root.join("journal");

    let out = bin()
        .args(["-r", "--apply", "--journal-dir"])
        .arg(&journal)
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(root.join("My_Report.docx").exists());

    let out = bin()
        .args(["undo", "--last", "--journal-dir"])
        .arg(&journal)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(root.join("My Report.docx").exists());
}

#[test]
fn usage_errors_exit_3() {
    // --apply with no paths
    let out = bin().arg("--apply").output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    // --ascii conflicts with --profile
    let out = bin()
        .args(["--strings", "--ascii", "--profile", "portable"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    // unknown flag
    let out = bin().arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(3));
}

fn run_with_stdin(args: &[&std::ffi::OsStr], stdin: &str) -> std::process::Output {
    let mut child = bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn strings_mode_exit_codes() {
    let out = run_with_stdin(&[std::ffi::OsStr::new("--strings")], "clean.txt\n");
    assert_eq!(out.status.code(), Some(0));
    let out = run_with_stdin(&[std::ffi::OsStr::new("--strings")], "dirty file.txt\n");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dirty_file.txt"), "{stdout}");
}
