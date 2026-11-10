//! Rename mode (default): walk paths, plan, optionally commit. Implements
//! `check` / `--apply` / `run` / `-n` per CLI.md; plan-with-skips aborts
//! before any change (SPEC §5.1).

use std::collections::HashSet;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use detox_rs::fs::{self, HiddenMode, Plan, WalkOptions};
use detox_rs::{CaseMode, Options, Profile};

use super::args::{self, Args};
use super::report::{self, Field};
use super::{flush_exit, write_line};

struct RenameArgs {
    apply: bool,
    recursive: bool,
    hidden: HiddenMode,
    special: bool,
    max_depth: usize,
    format_json: bool,
    quiet: bool,
    profile: Profile,
    profile_set: bool,
    ascii_flag: bool,
    case_mode: CaseMode,
    max_bytes: usize,
    journal_dir: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

impl RenameArgs {
    fn defaults() -> Self {
        RenameArgs {
            apply: false,
            recursive: false,
            hidden: HiddenMode::Skip,
            special: false,
            max_depth: 64,
            format_json: false,
            quiet: false,
            profile: Profile::Clean,
            profile_set: false,
            ascii_flag: false,
            case_mode: CaseMode::Preserve,
            max_bytes: 255,
            journal_dir: None,
            paths: vec![],
        }
    }
}

pub fn run(argv: &[String]) -> i32 {
    let mut c = RenameArgs::defaults();
    let mut a = Args::from_strings(argv);
    while let Some(arg) = a.next() {
        let cur = arg.to_str().map(str::to_string);
        match cur.as_deref() {
            Some("check") => {}
            Some("--apply") | Some("run") => c.apply = true,
            Some("-n") | Some("--dry-run") => {}
            Some("-r") | Some("--recursive") => c.recursive = true,
            Some("--special") => c.special = true,
            Some("-q") | Some("--quiet") => c.quiet = true,
            Some("--ascii") => {
                c.ascii_flag = true;
                c.profile = Profile::Ascii;
            }
            Some("--profile") => {
                let v = a.value("--profile").to_string_lossy().into_owned();
                c.profile = args::profile_value(&v);
                c.profile_set = true;
            }
            Some("--case") => {
                let v = a.value("--case").to_string_lossy().into_owned();
                c.case_mode = args::case_value(&v);
            }
            Some("--hidden") => {
                let v = a.value("--hidden").to_string_lossy().into_owned();
                c.hidden = match v.as_str() {
                    "skip" => HiddenMode::Skip,
                    "include" => HiddenMode::Include,
                    "only" => HiddenMode::Only,
                    _ => super::usage(),
                };
            }
            Some("--max-depth") => {
                // Unparsable silently falls back to the default (as before).
                let v = a.value("--max-depth").to_string_lossy().into_owned();
                c.max_depth = v.parse().unwrap_or(64);
            }
            Some("--max-length") => {
                let v = a.value("--max-length").to_string_lossy().into_owned();
                c.max_bytes = args::max_length_value(&v);
            }
            Some("--journal-dir") => {
                // Historical leniency: a missing value means "no override",
                // not a usage error.
                c.journal_dir = a.next().map(PathBuf::from);
            }
            Some("--format") => {
                let v = a.value("--format").to_string_lossy().into_owned();
                c.format_json = args::format_value(&v);
            }
            Some("--") => {
                c.paths.extend(a.rest_paths());
                break;
            }
            Some(s) if s.starts_with('-') => {
                eprintln!("detox-rs: unknown option '{s}'");
                super::usage();
            }
            // Non-UTF-8 arguments land here as paths, loss-free.
            _ => c.paths.push(PathBuf::from(arg)),
        }
    }
    if c.ascii_flag && c.profile_set {
        super::usage(); // --ascii conflicts with --profile
    }
    if c.paths.is_empty() {
        super::usage();
    }

    let wopts = WalkOptions {
        recursive: c.recursive,
        hidden: c.hidden,
        special: c.special,
        max_depth: c.max_depth,
    };
    let sopts = Options {
        profile: c.profile,
        case: c.case_mode,
        max_bytes: c.max_bytes,
    };
    let (entries, walk_skips, hidden_skips) = match fs::walk(&c.paths, &wopts) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("detox-rs: {e}");
            std::process::exit(2);
        }
    };
    let mut plan = fs::plan(&entries, &sopts);
    plan.skipped.extend(walk_skips);
    let run = report::run_id();

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    // SPEC §4 UX-2: hidden skips are counted and listed, but unlike
    // plan.skipped they never abort an apply.
    emit_hidden(&mut out, &hidden_skips, &run, c.format_json, c.quiet);

    if !c.apply {
        emit_plan(&mut out, &plan, &run, c.format_json, c.quiet);
        let code = if !plan.skipped.is_empty() {
            2
        } else if plan.items.is_empty() {
            0
        } else {
            1
        };
        flush_exit(&mut out, code);
    }

    // SPEC §5.1: a plan with skipped entries aborts before any change.
    if !plan.skipped.is_empty() {
        for (p, why) in &plan.skipped {
            eprintln!("detox-rs: skip {}: {why}", p.display());
        }
        eprintln!("detox-rs: aborting (plan has skipped entries)");
        std::process::exit(2);
    }

    let journal_dir = c.journal_dir.clone().unwrap_or_else(fs::journal_dir);
    match fs::commit(&plan, &journal_dir, &run) {
        Ok(report) => {
            // Report only renames that actually executed (review P3.4:
            // failed items were printed as "rename" lines before, lying to
            // machine consumers of the NDJSON stream).
            let failed: HashSet<&PathBuf> = report.errors.iter().map(|(o, _)| o).collect();
            for it in &plan.items {
                if failed.contains(&it.old) {
                    continue;
                }
                if c.format_json {
                    report::json_line(
                        &mut out,
                        &[
                            Field::S("run", &run),
                            Field::S("action", "rename"),
                            Field::S("old", &it.old.to_string_lossy()),
                            Field::S("new", &it.new.to_string_lossy()),
                            Field::S("reason", &report::reason(&it.stages)),
                            Field::S("src", "walk"),
                        ],
                    );
                } else if !c.quiet {
                    write_line(
                        &mut out,
                        &format!("rename '{}' -> '{}'", it.old.display(), it.new.display()),
                    );
                }
            }
            for (p, e) in &report.errors {
                eprintln!("detox-rs: {}: {e}", p.display());
            }
            let code = if report.errors.is_empty() { 0 } else { 2 };
            flush_exit(&mut out, code);
        }
        Err(e) => {
            eprintln!("detox-rs: {e}");
            std::process::exit(2);
        }
    }
}

fn emit_hidden(out: &mut impl Write, hidden: &[PathBuf], run: &str, json: bool, quiet: bool) {
    for p in hidden {
        if json {
            report::json_line(
                out,
                &[
                    Field::S("run", run),
                    Field::S("action", "skip"),
                    Field::S("old", &p.to_string_lossy()),
                    Field::S("reason", "hidden"),
                    Field::S("src", "walk"),
                ],
            );
        } else if !quiet {
            write_line(out, &format!("skip '{}' (hidden)", p.display()));
        }
    }
}

fn emit_plan(out: &mut impl Write, plan: &Plan, run: &str, json: bool, quiet: bool) {
    if json {
        for (i, it) in plan.items.iter().enumerate() {
            report::json_line(
                out,
                &[
                    Field::S("run", run),
                    Field::N("seq", i as u64),
                    Field::S("action", "plan"),
                    Field::S("old", &it.old.to_string_lossy()),
                    Field::S("new", &it.new.to_string_lossy()),
                    Field::S("reason", &report::reason(&it.stages)),
                    Field::S("src", "walk"),
                ],
            );
        }
        for (p, why) in &plan.skipped {
            report::json_line(
                out,
                &[
                    Field::S("run", run),
                    Field::S("action", "skip"),
                    Field::S("old", &p.to_string_lossy()),
                    Field::S("reason", why),
                    Field::S("src", "walk"),
                ],
            );
        }
        report::json_line(
            out,
            &[
                Field::S("run", run),
                Field::S("action", "summary"),
                Field::N("planned", plan.items.len() as u64),
                Field::N("unchanged", plan.unchanged as u64),
                Field::N("skipped", plan.skipped.len() as u64),
            ],
        );
    } else if !quiet {
        for it in &plan.items {
            write_line(
                out,
                &format!("plan '{}' -> '{}'", it.old.display(), it.new.display()),
            );
        }
        for (p, why) in &plan.skipped {
            write_line(out, &format!("skip '{}': {why}", p.display()));
        }
        write_line(
            out,
            &format!(
                "summary: {} planned, {} unchanged, {} skipped",
                plan.items.len(),
                plan.unchanged,
                plan.skipped.len()
            ),
        );
        if !plan.items.is_empty() {
            write_line(out, "hint: re-run with --apply to execute");
        }
    }
}
