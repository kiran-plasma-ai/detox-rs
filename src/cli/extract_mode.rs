//! `extract` mode: MIME attachment extraction (EXTRACT.md). Thin wrapper:
//! parse ripMIME-compatible flags into [`ExtractOptions`], call the library,
//! report the parts NDJSON-or-human.

use std::io::BufWriter;
use std::path::PathBuf;

use detox_rs::fs;
use detox_rs::{CaseMode, Profile, UniqueStyle};

use super::args::{self, Args};
use super::report::{self, Field};
use super::{flush_exit, write_line};

struct ExtractArgs {
    input: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    prefix: String,
    name_by_type: bool,
    no_nameless: bool,
    overwrite_count: u8,
    headers_file: Option<PathBuf>,
    mailbox: bool,
    recursion_max: usize,
    format_json: bool,
    journal_dir: Option<PathBuf>,
    profile: Option<Profile>,
    ascii_flag: bool,
    case_mode: CaseMode,
    max_bytes: usize,
    unique_style: UniqueStyle,
}

impl ExtractArgs {
    fn defaults() -> Self {
        ExtractArgs {
            input: None,
            out_dir: None,
            prefix: "text".to_string(),
            name_by_type: false,
            no_nameless: false,
            overwrite_count: 0,
            headers_file: None,
            mailbox: false,
            recursion_max: 20,
            format_json: false,
            journal_dir: None,
            profile: None,
            ascii_flag: false,
            case_mode: CaseMode::Preserve,
            max_bytes: 255,
            unique_style: UniqueStyle::Infix,
        }
    }
}

pub fn run(args: &[std::ffi::OsString]) -> i32 {
    let mut c = ExtractArgs::defaults();
    let mut a = Args::new(args.to_vec());
    while let Some(arg) = a.next() {
        let cur = arg.to_str().map(str::to_string);
        match cur.as_deref() {
            Some("-i") => c.input = Some(PathBuf::from(a.value("-i"))),
            Some("-d") => c.out_dir = Some(PathBuf::from(a.value("-d"))),
            Some("-p") => c.prefix = a.value("-p").to_string_lossy().into_owned(),
            Some("-e") => c.headers_file = Some(PathBuf::from(a.value("-e"))),
            Some("--name-by-type") => c.name_by_type = true,
            Some("--no-nameless") => c.no_nameless = true,
            Some("--mailbox") => c.mailbox = true,
            Some("--overwrite") => c.overwrite_count += 1,
            Some("--ascii") => c.ascii_flag = true,
            Some("--profile") => {
                let v = a.value("--profile").to_string_lossy().into_owned();
                c.profile = Some(args::profile_value(&v));
            }
            Some("--case") => {
                let v = a.value("--case").to_string_lossy().into_owned();
                c.case_mode = args::case_value(&v);
            }
            Some("--max-length") => {
                let v = a.value("--max-length").to_string_lossy().into_owned();
                c.max_bytes = args::max_length_value(&v);
            }
            Some("--unique-style") => {
                let v = a.value("--unique-style").to_string_lossy().into_owned();
                c.unique_style = match v.as_str() {
                    "infix" => UniqueStyle::Infix,
                    "prefix" => UniqueStyle::Prefix,
                    "postfix" => UniqueStyle::Postfix,
                    _ => super::usage(),
                };
            }
            Some("--recursion-max") => {
                let v = a.value("--recursion-max").to_string_lossy().into_owned();
                c.recursion_max = v.parse().unwrap_or(20);
            }
            Some("--journal-dir") => {
                // Same leniency as rename mode: missing value = no override.
                c.journal_dir = a.next().map(PathBuf::from);
            }
            Some("--format") => {
                // Extract's --format is lenient (anything not "json" is
                // human), unlike rename/strings — preserve that.
                let v = a.value("--format").to_string_lossy().into_owned();
                c.format_json = matches!(v.as_str(), "json");
            }
            Some(other) => {
                eprintln!("detox-rs: unexpected argument '{other}'");
                super::usage();
            }
            _ => super::usage(),
        }
    }
    let (Some(input), Some(out_dir)) = (c.input, c.out_dir) else {
        eprintln!("detox-rs: extract requires -i FILE and -d DIR");
        super::usage();
    };
    if c.ascii_flag && c.profile.is_some() {
        super::usage();
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
        profile: if c.ascii_flag {
            Profile::Ascii
        } else {
            c.profile.unwrap_or_default()
        },
        case: c.case_mode,
        max_bytes: c.max_bytes,
        prefix: c.prefix,
        name_by_type: c.name_by_type,
        no_nameless: c.no_nameless,
        unique_style: c.unique_style,
        overwrite: c.overwrite_count >= 2,
        headers_file: c.headers_file,
        mailbox: c.mailbox,
        recursion_max: c.recursion_max,
        parts_max: 10_000,
        format_json: c.format_json,
        journal_dir: c.journal_dir.or_else(|| Some(fs::journal_dir())),
    };

    match detox_rs::extract::extract(&data, &opts) {
        Ok(rep) => {
            let stdout = std::io::stdout();
            let mut out = BufWriter::new(stdout.lock());
            for p in &rep.parts {
                if c.format_json {
                    report::json_line(
                        &mut out,
                        &[
                            Field::S("action", "extract"),
                            Field::S("file", &p.file.to_string_lossy()),
                            Field::S("content_type", &p.content_type),
                            Field::N("size", p.size as u64),
                            Field::S("decoded_from", &p.decoded_from),
                            Field::S("name_source", &p.name_source),
                        ],
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
            if c.format_json {
                report::json_line(
                    &mut out,
                    &[
                        Field::S("action", "summary"),
                        Field::N("total", rep.parts.len() as u64),
                    ],
                );
            } else {
                write_line(
                    &mut out,
                    &format!("summary: {} extracted", rep.parts.len()),
                );
            }
            if let Some(je) = &rep.journal_error {
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
