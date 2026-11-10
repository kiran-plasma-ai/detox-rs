//! Tiny std-only flag iterator shared by the mode parsers.
//!
//! No clap/serde (the 3-crate cap forbids both); each mode owns one small
//! explicit parse loop on top of this. A non-UTF-8 argument is a path,
//! never an error — do not add lossy conversion on the path arm.

use std::ffi::OsString;
use std::path::PathBuf;

use super::usage;

pub struct Args {
    items: Vec<OsString>,
    i: usize,
}

impl Args {
    pub fn new(items: Vec<OsString>) -> Self {
        Args { items, i: 0 }
    }

    /// Consume and return the next argument.
    pub fn next(&mut self) -> Option<OsString> {
        let v = self.items.get(self.i).cloned();
        if v.is_some() {
            self.i += 1;
        }
        v
    }

    /// Value for a flag: names the starving flag instead of dumping usage.
    pub fn value(&mut self, flag: &str) -> OsString {
        match self.next() {
            Some(v) => v,
            None => {
                eprintln!("detox-rs: option {flag} requires a value");
                usage();
            }
        }
    }

    /// Everything from here on is a path (the `--` terminator is consumed
    /// by the caller's match arm before calling this).
    pub fn rest_paths(&mut self) -> Vec<PathBuf> {
        let out: Vec<PathBuf> = self.items[self.i..].iter().map(PathBuf::from).collect();
        self.i = self.items.len();
        out
    }
}

/// `--profile` value, shared by rename/strings/extract parsers.
pub fn profile_value(v: &str) -> detox_rs::Profile {
    match v {
        "clean" => detox_rs::Profile::Clean,
        "portable" => detox_rs::Profile::Portable,
        "ascii" => detox_rs::Profile::Ascii,
        _ => usage(),
    }
}

/// `--case` value, shared by rename/strings/extract parsers.
pub fn case_value(v: &str) -> detox_rs::CaseMode {
    match v {
        "lower" => detox_rs::CaseMode::Lower,
        "upper" => detox_rs::CaseMode::Upper,
        "preserve" => detox_rs::CaseMode::Preserve,
        _ => usage(),
    }
}

/// `--max-length` value: 0 means "default" (255); unparsable is usage.
pub fn max_length_value(v: &str) -> usize {
    match v.parse() {
        Ok(0) => 255,
        Ok(n) => n,
        Err(_) => usage(),
    }
}

/// `--format` value for rename/strings: strict, usage on anything but
/// human|json. (Extract parses its own lenient variant.)
pub fn format_value(v: &str) -> bool {
    match v {
        "json" => true,
        "human" => false,
        _ => usage(),
    }
}
