//! Name pipeline, slices 1–2: NRM → SAN → CLN → LEN (+ UNQ via `Uniquifier`).
//! Contracts: docs/SLICES.md slice 1 v1, slice 2 v1; behavior per SPEC.md.

pub mod extract;
pub mod fs;

use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

/// JSON string escape (shared by NDJSON output and the journal writer).
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Profile {
    #[default]
    Clean,
    /// Lowest common denominator for FAT32/exFAT/NTFS interop (SPEC §3.3).
    Portable,
    /// Lossy legacy escape hatch; behaviorally == Portable this slice.
    Ascii,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CaseMode {
    Preserve,
    Lower,
    Upper,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub profile: Profile,
    pub case: CaseMode,
    /// Byte cap for LEN (SPEC §5.7). Strings-mode default per CLI.md.
    pub max_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            profile: Profile::Clean,
            case: CaseMode::Preserve,
            max_bytes: 255,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Outcome {
    pub name: String,
    pub stages: Vec<&'static str>,
}

/// Exact `clean` charset: \p{L} | \p{M} | \p{N} (SPEC §3.3), UCD-backed.
fn is_word_char(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark
            | GeneralCategory::DecimalNumber
            | GeneralCategory::LetterNumber
            | GeneralCategory::OtherNumber
    )
}

fn is_mark(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark
    )
}

/// Non-decomposable transliteration table (SPEC §7 step 1): Latin-1
/// Supplement + Latin Extended letters lacking canonical decomposition.
const TRL_TABLE: &[(char, &str)] = &[
    ('æ', "ae"), ('Æ', "AE"), ('œ', "oe"), ('Œ', "OE"), ('ø', "oe"), ('Ø', "OE"),
    ('ð', "d"), ('Ð', "D"), ('þ', "th"), ('Þ', "TH"), ('ß', "ss"), ('ẞ', "SS"),
    ('ł', "l"), ('Ł', "L"), ('ŋ', "n"), ('Ŋ', "N"), ('ħ', "h"), ('Ħ', "H"),
    ('đ', "d"), ('Đ', "D"), ('ŧ', "t"), ('Ŧ', "T"), ('ı', "i"), ('ŉ', "'n"),
    ('µ', "u"), ('ƒ', "f"), ('ĸ', "k"),
];

fn trl_lookup(c: char) -> Option<&'static str> {
    TRL_TABLE.iter().find(|(k, _)| *k == c).map(|(_, v)| *v)
}

/// TRL (SPEC §7): table -> NFKD (drop marks, keep ASCII, table re-lookup)
/// -> `_`. ASCII passes through untouched for SAN to handle.
fn trl(input: &str) -> (String, bool) {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        if let Some(m) = trl_lookup(c) {
            out.push_str(m);
            continue;
        }
        for d in c.nfkd() {
            if d.is_ascii_alphanumeric() || matches!(d, '.' | '_' | '-') {
                out.push(d);
            } else if is_mark(d) {
                // dropped combining mark
            } else if let Some(m) = trl_lookup(d) {
                out.push_str(m);
            } else {
                out.push('_');
            }
        }
    }
    (out.clone(), out != input)
}

fn cas_apply(s: &str, mode: CaseMode) -> (String, bool) {
    let out: String = match mode {
        CaseMode::Preserve => return (s.to_string(), false),
        CaseMode::Lower => s.to_lowercase(),
        CaseMode::Upper => s.to_uppercase(),
    };
    (out.clone(), out != s)
}

/// Windows reserved-name escape (SPEC §3.3/§5.5), portable/ascii only.
fn escape_reserved(name: &str) -> Option<String> {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = name.split('.').next().unwrap_or(name);
    if RESERVED.contains(&stem.to_ascii_uppercase().as_str()) {
        Some(format!("_{name}"))
    } else {
        None
    }
}

pub fn sanitize(input: &[u8], opts: &Options) -> Outcome {
    let mut stages = Vec::new();

    // NRM: raw bytes -> lossy UTF-8, then NFC (SPEC §3.1 stage 1).
    let lossy = String::from_utf8_lossy(input).into_owned();
    let normalized: String = lossy.nfc().collect();
    if normalized != lossy {
        stages.push("nrm");
    }

    // TRL (portable/ascii only) then CAS (SPEC §3.1 order: stages 4, 5).
    let mut name = normalized;
    if matches!(opts.profile, Profile::Portable | Profile::Ascii) {
        let (t, ch) = trl(&name);
        name = t;
        if ch {
            stages.push("trl");
        }
    }
    if opts.case != CaseMode::Preserve {
        let (c2, ch) = cas_apply(&name, opts.case);
        name = c2;
        if ch {
            stages.push("cas");
        }
    }

    // SAN: `clean` charset; whitespace/control and other disallowed chars -> `_`;
    // decoration punctuation ()[]{},;!$& removed (SPEC §3.1 v0.2.2). All-dots
    // names need no special case: CLN trailing-dot strip + emptiness guard (§5.5).
    const REMOVE: &[char] = &['(', ')', '[', ']', '{', '}', ',', ';', '!', '$', '&'];
    let mut out = String::with_capacity(name.len());
    let mut changed = false;
    for c in name.chars() {
        match c {
            '\0' => {
                out.push_str("_hidden_null_");
                changed = true;
            }
            '.' | '_' | '-' => out.push(c),
            c if is_word_char(c) => out.push(c),
            c if REMOVE.contains(&c) => changed = true,
            _ => {
                out.push('_');
                changed = true;
            }
        }
    }
    if changed {
        stages.push("san");
    }

    // CLN: collapse `_`/`-` runs (dash precedence, detox wipeup semantics),
    // strip leading `# _ -`, strip trailing `. _ -`; empty -> `_` (§5.5).
    let chars: Vec<char> = out.chars().collect();
    let mut collapsed = String::with_capacity(out.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '_' || chars[i] == '-' {
            let mut has_dash = false;
            while i < chars.len() && (chars[i] == '_' || chars[i] == '-') {
                has_dash |= chars[i] == '-';
                i += 1;
            }
            collapsed.push(if has_dash { '-' } else { '_' });
        } else {
            collapsed.push(chars[i]);
            i += 1;
        }
    }
    let stripped = collapsed.trim_start_matches(['#', '_', '-']).to_string();
    name = stripped.trim_end_matches(['.', '_', '-']).to_string();
    if collapsed != out || name != stripped {
        stages.push("cln");
    }
    if name.is_empty() {
        name.push('_');
    }

    // LEN: byte cap, char-boundary cut, extension = last `.` of THIS (pre-LEN)
    // name preserved (SPEC §5.7; detox's "extension from original" fix).
    let capped = len_stage(&name, opts.max_bytes);
    if let Some(c) = capped {
        name = c;
        stages.push("len");
    }

    // Windows reserved-name escape (portable/ascii), AFTER LEN so stems
    // created by truncation are caught too. Under tight caps the escape may
    // need a second application (documented INV-1 corner, SPEC v0.2.3).
    if matches!(opts.profile, Profile::Portable | Profile::Ascii) {
        if let Some(escaped) = escape_reserved(&name) {
            if escaped.len() <= opts.max_bytes {
                name = escaped;
                stages.push("san");
            } else {
                let cut = cut_at_boundary(&name, opts.max_bytes.saturating_sub(1));
                if !cut.is_empty() {
                    name = format!("_{cut}");
                    stages.push("san");
                }
                // cut empty: cap too small for any escape; emit unescaped.
            }
        }
    }

    // Final NFC: SAN removal / CLN strips can join char sequences that now
    // compose (e.g. `e )\u{301}` -> `e\u{301}` -> `é`). Without this the
    // output is not a fixed point (INV-1). Composition never grows byte
    // length, so the LEN cap still holds.
    let final_nfc: String = name.nfc().collect();
    if final_nfc != name {
        name = final_nfc;
        stages.push("nrm");
    }

    Outcome { name, stages }
}

/// Cut `name` to at most `cap` bytes on a char boundary, preserving the
/// extension (from the last `.`). Falls back to a plain boundary cut when the
/// extension alone would reach the cap. Capped results are re-finished with
/// CLN's trailing strip + emptiness guard — a capped name must itself be a
/// fixed point (INV-1). Never panics.
fn len_stage(name: &str, cap: usize) -> Option<String> {
    if name.len() <= cap {
        return None;
    }
    let finish = |mut s: String| {
        while matches!(s.chars().last(), Some('.' | '_' | '-')) {
            s.pop();
        }
        if s.is_empty() {
            s.push('_');
        }
        s
    };
    if cap == 0 {
        return Some(finish(String::new())); // degenerate; "_" is the least bad fit
    }
    let (stem, ext) = match name.rfind('.') {
        Some(0) | None => (name, ""),
        Some(i) => (&name[..i], &name[i..]),
    };
    if ext.len() >= cap {
        return Some(finish(cut_at_boundary(name, cap)));
    }
    let budget = cap - ext.len();
    let cut_stem = cut_at_boundary(stem, budget.max(1));
    // A multibyte first char can exceed budget; never go over cap.
    let cut_stem = if cut_stem.len() > budget {
        String::new()
    } else {
        cut_stem
    };
    if cut_stem.is_empty() && !ext.is_empty() {
        // Stem cannot fit even one char alongside the extension: prefer
        // filling the cap over preserving the extension.
        return Some(finish(cut_at_boundary(name, cap)));
    }
    Some(finish(format!("{cut_stem}{ext}")))
}

/// Longest prefix of `s` fitting `cap` bytes, cut on a char boundary.
fn cut_at_boundary(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    s.char_indices()
        .take_while(|(bi, c)| bi + c.len_utf8() <= cap)
        .map(|(_, c)| c)
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UniqueStyle {
    Infix,
    Prefix,
    Postfix,
}

/// No uniquified variant of the name fits `max_bytes`.
#[derive(Debug)]
pub struct UniquifyError;

/// Per-invocation collision domain, streaming-safe (SPEC §5.8): outputs are
/// uniquified in arrival order; deterministic for a fixed input order.
pub struct Uniquifier {
    style: UniqueStyle,
    max_bytes: usize,
    seen: std::collections::HashSet<String>,
    next: std::collections::HashMap<String, usize>,
}

impl Uniquifier {
    pub fn new(style: UniqueStyle, max_bytes: usize) -> Self {
        Uniquifier {
            style,
            max_bytes,
            seen: std::collections::HashSet::new(),
            next: std::collections::HashMap::new(),
        }
    }

    /// Ok((name, uniquified?)); Err(UniquifyError) when no uniquified variant
    /// fits `max_bytes` (tag + extension leave no room for a stem char).
    pub fn apply(&mut self, name: String) -> Result<(String, bool), UniquifyError> {
        if self.seen.insert(name.clone()) {
            return Ok((name, false));
        }
        let mut n = *self.next.get(&name).unwrap_or(&1);
        loop {
            match self.candidate(&name, n) {
                Some(candidate) if self.seen.insert(candidate.clone()) => {
                    self.next.insert(name, n + 1);
                    return Ok((candidate, true));
                }
                Some(_) => n += 1, // collided with another base's output
                None => return Err(UniquifyError),
            }
        }
    }

    /// stem + `_n` + ext with the stem cut so the WHOLE fits `max_bytes`.
    /// The tag always survives; only the stem shrinks. Terminates: distinct n
    /// give distinct tags, and shrinking budgets hit zero → None.
    fn candidate(&self, base: &str, n: usize) -> Option<String> {
        let tag = format!("_{n}");
        let (stem, ext) = match base.rfind('.') {
            Some(0) | None => (base, ""),
            Some(i) => (&base[..i], &base[i..]),
        };
        let budget = self
            .max_bytes
            .saturating_sub(tag.len() + ext.len());
        if budget == 0 {
            return None;
        }
        let cut = cut_at_boundary(stem, budget);
        if cut.is_empty() {
            return None;
        }
        Some(match self.style {
            UniqueStyle::Infix => format!("{cut}{tag}{ext}"),
            UniqueStyle::Prefix => format!("{tag}{cut}{ext}"),
            UniqueStyle::Postfix => format!("{cut}{ext}{tag}"),
        })
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn empty_input_uses_guard() {
        assert_eq!(sanitize(b"", &Options::default()).name, "_");
    }

    #[test]
    fn combining_mark_kept_exact_category() {
        // U+20D0 COMBINING LEFT HARPOON ABOVE: Mn, NOT Other_Alphabetic —
        // the case that broke the slice-1 is_alphabetic shortcut.
        let o = sanitize("a\u{20d0}b.txt".as_bytes(), &Options::default());
        assert_eq!(o.name, "a\u{20d0}b.txt");
    }

    #[test]
    fn len_caps_on_char_boundary() {
        let opts = Options {
            max_bytes: 8,
            ..Options::default()
        };
        // é = 2 bytes: stem "éééébc" (8B) + ".txt" — budget forces "éé" + ".txt".
        let o = sanitize("éééébc.txt".as_bytes(), &opts);
        assert_eq!(o.name, "éé.txt");
        assert!(o.name.len() <= 8);
    }

    #[test]
    fn uniquifier_infix_and_deterministic() {
        let mut u = Uniquifier::new(UniqueStyle::Infix, 255);
        assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report.pdf");
        assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report_1.pdf");
        assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report_2.pdf");
    }

    #[test]
    fn uniquifier_respects_cap() {
        let mut u = Uniquifier::new(UniqueStyle::Infix, 12);
        let (n, _) = u.apply("abcdefgh.pdf".into()).unwrap();
        let (n2, _) = u.apply("abcdefgh.pdf".into()).unwrap();
        assert!(n.len() <= 12, "{n}");
        assert!(n2.len() <= 12, "{n2}");
    }
}
