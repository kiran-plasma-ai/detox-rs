//! detox CLI. Contracts: SLICES.md slices 1–4.
//! Modes: `detox-rs --strings ...` (pure), `detox-rs [check] PATH...` (plan, default),
//! `detox-rs --apply PATH...` / `run`, `detox-rs undo [--last|--run ID]`.

use detox_rs::fs::{self, HiddenMode, Plan, UndoSel, WalkOptions};
use detox_rs::{json_escape, sanitize, CaseMode, Options, Profile, UniqueStyle, Uniquifier};
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead, BufWriter, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  detox-rs [check] [OPTIONS] PATH...   plan renames (default; touches nothing)");
    eprintln!("  detox-rs --apply|run [OPTIONS] PATH...   execute renames");
    eprintln!("  detox-rs undo [--last|--run ID] [--journal-dir D]");
    eprintln!("  detox-rs --strings [--profile P] [--ascii] [--case C] [--max-length N] [--format human|json] [-0]");
    eprintln!("  detox-rs extract -i FILE|- -d DIR [ripMIME-compatible flags]");
    std::process::exit(3);
}

/// Flag-value lookup that names the starving flag instead of dumping usage.
fn need(args: &[String], i: usize) -> &String {
    match args.get(i) {
        Some(v) => v,
        None => {
            let flag = args
                .get(i.wrapping_sub(1))
                .map(String::as_str)
                .unwrap_or("?");
            eprintln!("detox-rs: option {flag} requires a value");
            usage();
        }
    }
}

/// uuid-v4-shaped run id from hashed time+pid entropy (no external RNG dep).
fn run_id() -> String {
    use std::collections::hash_map::RandomState;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let block = |salt: u64| {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(nanos);
        h.write_u32(std::process::id());
        h.write_u64(salt);
        h.finish()
    };
    let (a, b) = (block(0), block(1));
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        a as u32,
        (a >> 32) as u16,
        0x4000 | (b as u16 & 0x0fff),
        0x8000 | ((b >> 16) as u16 & 0x3fff),
        ((b >> 32) << 16 | (a >> 48)) & 0xffffffffffff
    )
}

fn write_line(out: &mut impl Write, s: &str) {
    if let Err(e) = writeln!(out, "{s}") {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0); // conventional filter: quiet success on pipe close
        }
        eprintln!("detox-rs: writing stdout: {e}");
        std::process::exit(2);
    }
}

fn stage_detail(stage: &str) -> &'static str {
    match stage {
        "nrm" => "nfc",
        "trl" => "translit",
        "cas" => "case",
        "san" => "charset",
        "cln" => "collapse/strip",
        "len" => "byte-cap",
        "unq" => "counter",
        _ => "",
    }
}

struct Cli {
    apply: bool,
    recursive: bool,
    hidden: HiddenMode,
    special: bool,
    max_depth: usize,
    format_json: bool,
    quiet: bool,
    profile: Profile,
    ascii_flag: bool,
    case_mode: CaseMode,
    max_bytes: usize,
    journal_dir: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

fn parse_args(args: &[String], strings_mode: bool) -> Cli {
    let mut c = Cli {
        apply: false,
        recursive: false,
        hidden: HiddenMode::Skip,
        special: false,
        max_depth: 64,
        format_json: false,
        quiet: false,
        profile: Profile::Clean,
        ascii_flag: false,
        case_mode: CaseMode::Preserve,
        max_bytes: 255,
        journal_dir: None,
        paths: vec![],
    };
    let mut profile_set = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "check" if !strings_mode => {}
            "--apply" | "run" if !strings_mode => c.apply = true,
            "-n" | "--dry-run" if !strings_mode => {}
            "-r" | "--recursive" if !strings_mode => c.recursive = true,
            "--special" if !strings_mode => c.special = true,
            "-q" | "--quiet" => c.quiet = true,
            // Delimiter is derived from raw flags in strings_mode_fn; nothing
            // to record here (review P3.5: the old \0DELIM push was dead).
            "-0" | "--null" if strings_mode => {}
            "--ascii" => {
                c.ascii_flag = true;
                c.profile = Profile::Ascii;
            }
            "--profile" => {
                i += 1;
                c.profile = match args.get(i).map(String::as_str) {
                    Some("clean") => Profile::Clean,
                    Some("portable") => Profile::Portable,
                    Some("ascii") => Profile::Ascii,
                    _ => usage(),
                };
                profile_set = true;
            }
            "--case" => {
                i += 1;
                c.case_mode = match args.get(i).map(String::as_str) {
                    Some("lower") => CaseMode::Lower,
                    Some("upper") => CaseMode::Upper,
                    Some("preserve") => CaseMode::Preserve,
                    _ => usage(),
                };
            }
            "--hidden" if !strings_mode => {
                i += 1;
                c.hidden = match args.get(i).map(String::as_str) {
                    Some("skip") => HiddenMode::Skip,
                    Some("include") => HiddenMode::Include,
                    Some("only") => HiddenMode::Only,
                    _ => usage(),
                };
            }
            "--max-depth" if !strings_mode => {
                i += 1;
                c.max_depth = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(64);
            }
            "--max-length" => {
                i += 1;
                c.max_bytes = match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(0) => 255,
                    Some(n) => n,
                    None => usage(),
                };
            }
            "--journal-dir" if !strings_mode => {
                i += 1;
                c.journal_dir = args.get(i).map(PathBuf::from);
            }
            "--format" => {
                i += 1;
                c.format_json = match args.get(i).map(String::as_str) {
                    Some("json") => true,
                    Some("human") => false,
                    _ => usage(),
                };
            }
            "--" => {
                c.paths.extend(args[i + 1..].iter().map(PathBuf::from));
                break;
            }
            s if s.starts_with('-') => {
                eprintln!("detox-rs: unknown option '{s}'");
                usage();
            }
            s => c.paths.push(PathBuf::from(s)),
        }
        i += 1;
    }
    if c.ascii_flag && profile_set {
        usage(); // --ascii conflicts with --profile
    }
    c
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--strings") {
        return strings_mode_fn(&argv);
    }
    if argv.first().is_some_and(|a| a == "undo") {
        return undo_mode(&argv[1..]);
    }
    if argv.first().is_some_and(|a| a == "extract") {
        return extract_mode(&argv[1..]);
    }
    walk_mode(&argv);
}

// ---------------------------------------------------------------- strings --

fn strings_mode_fn(argv: &[String]) {
    let flags: Vec<String> = argv
        .iter()
        .filter(|a| *a != "--strings" && *a != "check" && *a != "run")
        .cloned()
        .collect();
    let null_delim = flags.iter().any(|a| a == "-0" || a == "--null");
    let c = parse_args(&flags, true);
    let run = run_id();
    let opts = Options {
        profile: c.profile,
        case: c.case_mode,
        max_bytes: c.max_bytes,
    };
    let profile_name = match opts.profile {
        Profile::Clean => "clean",
        Profile::Portable => "portable",
        Profile::Ascii => "ascii",
    };
    let mut uniq = Uniquifier::new(UniqueStyle::Infix, c.max_bytes);
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut seq = 0u64;
    let mut dirty = 0u64;
    let mut buf = Vec::new();
    let delim = if null_delim { 0u8 } else { b'\n' };

    loop {
        buf.clear();
        match reader.read_until(delim, &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                let line = match buf.last() {
                    Some(&d) if d == delim => &buf[..buf.len() - 1],
                    _ => &buf[..],
                };
                let o = sanitize(line, &opts);
                let (new, unq) = match uniq.apply(o.name) {
                    Ok(pair) => pair,
                    Err(_) => {
                        eprintln!("detox-rs: cannot uniquify within --max-length");
                        std::process::exit(2);
                    }
                };
                if new.as_bytes() != line {
                    dirty += 1;
                }
                if c.format_json {
                    let old = String::from_utf8_lossy(line);
                    let mut stages = o.stages.clone();
                    if unq {
                        stages.push("unq");
                    }
                    let stage = stages.last().copied().unwrap_or("");
                    let reason = stages
                        .iter()
                        .map(|s| format!("{s}:{}", stage_detail(s)))
                        .collect::<Vec<_>>()
                        .join("; ");
                    write_line(
                        &mut out,
                        &format!(
                            "{{\"run\":\"{run}\",\"seq\":{seq},\"action\":\"plan\",\"old\":\"{}\",\"new\":\"{}\",\"reason\":\"{}\",\"stage\":\"{stage}\",\"profile\":\"{profile_name}\",\"src\":\"stdin\"}}",
                            json_escape(&old),
                            json_escape(&new),
                            reason
                        ),
                    );
                } else if !c.quiet {
                    let old = String::from_utf8_lossy(line);
                    write_line(&mut out, &format!("{}\t{}", old, new));
                }
                seq += 1;
            }
            Err(e) => {
                eprintln!("detox-rs: reading stdin: {e}");
                std::process::exit(2);
            }
        }
    }

    if c.format_json {
        write_line(
            &mut out,
            &format!("{{\"run\":\"{run}\",\"action\":\"summary\",\"total\":{seq},\"dirty\":{dirty}}}"),
        );
    }
    flush_exit(&mut out, if dirty > 0 { 1 } else { 0 });
}

fn flush_exit(out: &mut impl Write, code: i32) -> ! {
    if let Err(e) = out.flush() {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("detox-rs: writing stdout: {e}");
        std::process::exit(2);
    }
    std::process::exit(code)
}

// ------------------------------------------------------------------ undo --

fn undo_mode(args: &[String]) {
    let mut sel = UndoSel::Last;
    let mut journal_dir = fs::journal_dir();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--last" => sel = UndoSel::Last,
            "--run" => {
                i += 1;
                sel = UndoSel::Run(need(args, i).to_string());
            }
            "--journal-dir" => {
                i += 1;
                journal_dir = PathBuf::from(need(args, i).as_str());
            }
            _ => usage(),
        }
        i += 1;
    }
    match fs::undo(sel, &journal_dir) {
        Ok(r) => {
            let mut conflict = false;
            for (p, why) in &r.skipped {
                eprintln!("undo: skip {}: {why}", p.display());
                if !matches!(why, fs::SkipReason::Missing) {
                    conflict = true;
                }
            }
            if conflict {
                std::process::exit(2); // SPEC §4: undo conflict
            }
            if !r.skipped.is_empty() {
                std::process::exit(1); // plain-missing skips
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("undo: {e}");
            std::process::exit(2);
        }
    }
}

// --------------------------------------------------------------- extract --

fn extract_mode(args: &[String]) {
    let mut input: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut prefix = "text".to_string();
    let mut name_by_type = false;
    let mut no_nameless = false;
    let mut overwrite_count = 0u8;
    let mut headers_file: Option<PathBuf> = None;
    let mut mailbox = false;
    let mut recursion_max = 20usize;
    let mut format_json = false;
    let mut journal_dir: Option<PathBuf> = None;
    let mut profile: Option<Profile> = None;
    let mut ascii_flag = false;
    let mut case_mode = CaseMode::Preserve;
    let mut max_bytes = 255usize;
    let mut unique_style = UniqueStyle::Infix;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" => {
                i += 1;
                input = Some(PathBuf::from(need(args, i).as_str()));
            }
            "-d" => {
                i += 1;
                out_dir = Some(PathBuf::from(need(args, i).as_str()));
            }
            "-p" => {
                i += 1;
                prefix = need(args, i).to_string();
            }
            "-e" => {
                i += 1;
                headers_file = Some(PathBuf::from(need(args, i).as_str()));
            }
            "--name-by-type" => name_by_type = true,
            "--no-nameless" => no_nameless = true,
            "--mailbox" => mailbox = true,
            "--overwrite" => overwrite_count += 1,
            "--ascii" => ascii_flag = true,
            "--profile" => {
                i += 1;
                profile = Some(match args.get(i).map(String::as_str) {
                    Some("clean") => Profile::Clean,
                    Some("portable") => Profile::Portable,
                    Some("ascii") => Profile::Ascii,
                    _ => usage(),
                });
            }
            "--case" => {
                i += 1;
                case_mode = match args.get(i).map(String::as_str) {
                    Some("lower") => CaseMode::Lower,
                    Some("upper") => CaseMode::Upper,
                    Some("preserve") => CaseMode::Preserve,
                    _ => usage(),
                };
            }
            "--max-length" => {
                i += 1;
                max_bytes = match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(0) => 255,
                    Some(n) => n,
                    None => usage(),
                };
            }
            "--unique-style" => {
                i += 1;
                unique_style = match args.get(i).map(String::as_str) {
                    Some("infix") => UniqueStyle::Infix,
                    Some("prefix") => UniqueStyle::Prefix,
                    Some("postfix") => UniqueStyle::Postfix,
                    _ => usage(),
                };
            }
            "--recursion-max" => {
                i += 1;
                recursion_max = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(20);
            }
            "--journal-dir" => {
                i += 1;
                journal_dir = args.get(i).map(PathBuf::from);
            }
            "--format" => {
                i += 1;
                format_json = matches!(args.get(i).map(String::as_str), Some("json"));
            }
            other => {
                eprintln!("detox-rs: unexpected argument '{other}'");
                usage();
            }
        }
        i += 1;
    }
    let (Some(input), Some(out_dir)) = (input, out_dir) else {
        eprintln!("detox-rs: extract requires -i FILE and -d DIR");
        usage();
    };
    if ascii_flag && profile.is_some() {
        usage();
    }

    let data = if input.as_os_str() == "-" {
        use std::io::Read;
        let mut b = Vec::new();
        std::io::stdin().read_to_end(&mut b).unwrap_or_else(|e| {
            eprintln!("detox-rs: reading stdin: {e}");
            std::process::exit(2);
        });
        b
    } else {
        std::fs::read(&input).unwrap_or_else(|e| {
            eprintln!("detox-rs: {}: {e}", input.display());
            std::process::exit(2);
        })
    };

    let opts = detox_rs::extract::ExtractOptions {
        out_dir,
        profile: if ascii_flag { Profile::Ascii } else { profile.unwrap_or_default() },
        case: case_mode,
        max_bytes,
        prefix,
        name_by_type,
        no_nameless,
        unique_style,
        overwrite: overwrite_count >= 2,
        headers_file,
        mailbox,
        recursion_max,
        parts_max: 10_000,
        format_json,
        journal_dir: journal_dir.or_else(|| Some(fs::journal_dir())),
    };

    match detox_rs::extract::extract(&data, &opts) {
        Ok(report) => {
            let stdout = std::io::stdout();
            let mut out = BufWriter::new(stdout.lock());
            for p in &report.parts {
                if format_json {
                    write_line(
                        &mut out,
                        &format!(
                            "{{\"action\":\"extract\",\"file\":\"{}\",\"content_type\":\"{}\",\"size\":{},\"decoded_from\":\"{}\",\"name_source\":\"{}\"}}",
                            json_escape(&p.file.to_string_lossy()),
                            json_escape(&p.content_type),
                            p.size,
                            p.decoded_from,
                            json_escape(&p.name_source)
                        ),
                    );
                } else {
                    write_line(
                        &mut out,
                        &format!(
                            "extract '{}' ({} {} {} {})",
                            p.file.display(),
                            p.content_type,
                            p.size,
                            p.decoded_from,
                            p.name_source
                        ),
                    );
                }
            }
            if format_json {
                write_line(
                    &mut out,
                    &format!(
                        "{{\"action\":\"summary\",\"total\":{}}}",
                        report.parts.len()
                    ),
                );
            } else {
                write_line(&mut out, &format!("summary: {} extracted", report.parts.len()));
            }
            if let Some(je) = &report.journal_error {
                eprintln!("extract: {je}");
                // Caps hit = partial batch (exit 1, SPEC §4); journal write
                // failure = exit 2 (SPEC §5.3).
                let code = if je.contains("journal") { 2 } else { 1 };
                flush_exit(&mut out, code);
            }
            flush_exit(&mut out, 0);
        }
        Err(e) => {
            eprintln!("extract: {e}");
            std::process::exit(2);
        }
    }
}

// ------------------------------------------------------------------ walk --

fn walk_mode(argv: &[String]) {
    let c = parse_args(argv, false);
    if c.paths.is_empty() {
        usage();
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
    let run = run_id();

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    // SPEC §4 UX-2: hidden skips are counted and listed, but unlike
    // plan.skipped they never abort an apply.
    emit_hidden(&mut out, &hidden_skips, &run, c.format_json, c.quiet);

    if !c.apply {
        emit_plan(&mut out, &plan, &run, c.format_json, c.quiet);
        let code = if !plan.skipped.is_empty() { 2 } else if plan.items.is_empty() { 0 } else { 1 };
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
            let failed: std::collections::HashSet<&PathBuf> =
                report.errors.iter().map(|(o, _)| o).collect();
            for it in &plan.items {
                if failed.contains(&it.old) {
                    continue;
                }
                if c.format_json {
                    let reason = it
                        .stages
                        .iter()
                        .map(|s| format!("{s}:{}", stage_detail(s)))
                        .collect::<Vec<_>>()
                        .join("; ");
                    write_line(
                        &mut out,
                        &format!(
                            "{{\"run\":\"{run}\",\"action\":\"rename\",\"old\":\"{}\",\"new\":\"{}\",\"reason\":\"{}\",\"src\":\"walk\"}}",
                            json_escape(&it.old.to_string_lossy()),
                            json_escape(&it.new.to_string_lossy()),
                            reason
                        ),
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
            write_line(
                out,
                &format!(
                    "{{\"run\":\"{run}\",\"action\":\"skip\",\"old\":\"{}\",\"reason\":\"hidden\",\"src\":\"walk\"}}",
                    json_escape(&p.to_string_lossy())
                ),
            );
        } else if !quiet {
            write_line(out, &format!("skip '{}' (hidden)", p.display()));
        }
    }
}

fn emit_plan(out: &mut impl Write, plan: &Plan, run: &str, json: bool, quiet: bool) {
    if json {
        for (i, it) in plan.items.iter().enumerate() {
            let reason = it
                .stages
                .iter()
                .map(|s| format!("{s}:{}", stage_detail(s)))
                .collect::<Vec<_>>()
                .join("; ");
            write_line(
                out,
                &format!(
                    "{{\"run\":\"{run}\",\"seq\":{i},\"action\":\"plan\",\"old\":\"{}\",\"new\":\"{}\",\"reason\":\"{}\",\"src\":\"walk\"}}",
                    json_escape(&it.old.to_string_lossy()),
                    json_escape(&it.new.to_string_lossy()),
                    reason
                ),
            );
        }
        for (p, why) in &plan.skipped {
            write_line(
                out,
                &format!(
                    "{{\"run\":\"{run}\",\"action\":\"skip\",\"old\":\"{}\",\"reason\":\"{}\",\"src\":\"walk\"}}",
                    json_escape(&p.to_string_lossy()),
                    json_escape(why)
                ),
            );
        }
        write_line(
            out,
            &format!(
                "{{\"run\":\"{run}\",\"action\":\"summary\",\"planned\":{},\"unchanged\":{},\"skipped\":{}}}",
                plan.items.len(),
                plan.unchanged,
                plan.skipped.len()
            ),
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
