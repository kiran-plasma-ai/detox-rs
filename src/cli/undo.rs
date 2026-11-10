//! `undo` mode: restore the last (or a named) journaled run.

use std::path::PathBuf;

use detox_rs::fs::{self, SkipReason, UndoSel};

use super::args::Args;

pub fn run(args: &[String]) -> i32 {
    let mut sel = UndoSel::Last;
    let mut journal_dir = fs::journal_dir();
    let mut a = Args::from_strings(args);
    while let Some(arg) = a.next() {
        match arg.to_str() {
            Some("--last") => sel = UndoSel::Last,
            Some("--run") => {
                sel = UndoSel::Run(a.value("--run").to_string_lossy().into_owned());
            }
            Some("--journal-dir") => {
                journal_dir = PathBuf::from(a.value("--journal-dir"));
            }
            _ => super::usage(),
        }
    }
    match fs::undo(sel, &journal_dir) {
        Ok(r) => {
            let mut conflict = false;
            for (p, why) in &r.skipped {
                eprintln!("undo: skip {}: {why}", p.display());
                if !matches!(why, SkipReason::Missing) {
                    conflict = true;
                }
            }
            if conflict {
                return 2; // SPEC §4: undo conflict
            }
            if !r.skipped.is_empty() {
                return 1; // plain-missing skips
            }
            0
        }
        Err(e) => {
            eprintln!("undo: {e}");
            2
        }
    }
}
