//! `--strings` mode (SLICES.md slice 1): sanitize stdin lines, report
//! old -> new. Pure: touches nothing but stdout.

use std::io::{BufRead, BufWriter};

use detox_rs::{sanitize, Options, Profile, UniqueStyle, Uniquifier};

use super::args::{self, Args};
use super::report::{self, Field};
use super::{flush_exit, write_line};

struct StringsArgs {
    profile: Profile,
    profile_set: bool,
    ascii_flag: bool,
    case_mode: detox_rs::CaseMode,
    max_bytes: usize,
    format_json: bool,
    quiet: bool,
    null_delim: bool,
}

impl StringsArgs {
    fn defaults() -> Self {
        StringsArgs {
            profile: Profile::Clean,
            profile_set: false,
            ascii_flag: false,
            case_mode: detox_rs::CaseMode::Preserve,
            max_bytes: 255,
            format_json: false,
            quiet: false,
            null_delim: false,
        }
    }
}

pub fn run(argv: &[String]) -> i32 {
    // Historical filter, preserved verbatim: the mode words are dropped
    // wherever they appear, so a path literally named "run" never reaches
    // strings mode (observed quirk — fixing it is a behavior change).
    let flags: Vec<String> = argv
        .iter()
        .filter(|a| *a != "--strings" && *a != "check" && *a != "run")
        .cloned()
        .collect();

    let mut c = StringsArgs::defaults();
    let mut a = Args::from_strings(&flags);
    while let Some(arg) = a.next() {
        let cur = arg.to_str().map(str::to_string);
        match cur.as_deref() {
            Some("-0") | Some("--null") => c.null_delim = true,
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
            Some("--max-length") => {
                let v = a.value("--max-length").to_string_lossy().into_owned();
                c.max_bytes = args::max_length_value(&v);
            }
            Some("--format") => {
                let v = a.value("--format").to_string_lossy().into_owned();
                c.format_json = args::format_value(&v);
            }
            Some("--") => {
                // Terminator: the rest would be paths, which strings mode
                // has none of — consume and ignore, as the old parse did.
                a.rest_paths();
                break;
            }
            Some(s) if s.starts_with('-') => {
                eprintln!("detox-rs: unknown option '{s}'");
                super::usage();
            }
            // Positional arguments exist in strings mode but are unused.
            _ => {}
        }
    }
    if c.ascii_flag && c.profile_set {
        super::usage(); // --ascii conflicts with --profile
    }

    let run = report::run_id();
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
    let delim = if c.null_delim { 0u8 } else { b'\n' };

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
                    report::json_line(
                        &mut out,
                        &[
                            Field::S("run", &run),
                            Field::N("seq", seq),
                            Field::S("action", "plan"),
                            Field::S("old", &old),
                            Field::S("new", &new),
                            Field::S("reason", &report::reason(&stages)),
                            Field::S("stage", stage),
                            Field::S("profile", profile_name),
                            Field::S("src", "stdin"),
                        ],
                    );
                } else if !c.quiet {
                    let old = String::from_utf8_lossy(line);
                    write_line(&mut out, &format!("{old}\t{new}"));
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
        report::json_line(
            &mut out,
            &[
                Field::S("run", &run),
                Field::S("action", "summary"),
                Field::N("total", seq),
                Field::N("dirty", dirty),
            ],
        );
    }
    flush_exit(&mut out, if dirty > 0 { 1 } else { 0 })
}
