//! CLI dispatch and shared output plumbing.
//!
//! Modes return an exit code (SPEC §4: 0 ok, 1 changes/skips present,
//! 2 error, 3 usage). Modes with a buffered writer terminate through
//! [`flush_exit`], which preserves the broken-pipe-quiet-success
//! convention; mid-stream error paths exit directly exactly as before
//! (a `process::exit` discards the unflushed buffer — that is kept).

pub mod args;
pub mod extract;
pub mod rename;
pub mod report;
pub mod strings;
pub mod undo;

use std::io::Write;

/// Entry point: dispatch on the mode word, in `main`'s old order.
pub fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--strings") {
        return strings::run(&argv);
    }
    if argv.first().is_some_and(|a| a == "undo") {
        return undo::run(&argv[1..]);
    }
    if argv.first().is_some_and(|a| a == "extract") {
        return extract::run(&argv[1..]);
    }
    rename::run(&argv)
}

pub fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  detox-rs [check] [OPTIONS] PATH...   plan renames (default; touches nothing)");
    eprintln!("  detox-rs --apply|run [OPTIONS] PATH...   execute renames");
    eprintln!("  detox-rs undo [--last|--run ID] [--journal-dir D]");
    eprintln!("  detox-rs --strings [--profile P] [--ascii] [--case C] [--max-length N] [--format human|json] [-0]");
    eprintln!("  detox-rs extract -i FILE|- -d DIR [ripMIME-compatible flags]");
    std::process::exit(3);
}

pub fn write_line(out: &mut impl Write, s: &str) {
    if let Err(e) = writeln!(out, "{s}") {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0); // conventional filter: quiet success on pipe close
        }
        eprintln!("detox-rs: writing stdout: {e}");
        std::process::exit(2);
    }
}

/// Flush the buffered writer, then exit with `code`.
pub fn flush_exit(out: &mut impl Write, code: i32) -> ! {
    if let Err(e) = out.flush() {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("detox-rs: writing stdout: {e}");
        std::process::exit(2);
    }
    std::process::exit(code)
}
