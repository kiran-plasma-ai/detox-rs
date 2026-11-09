//! Golden vectors + slice-2 acceptance (SPEC §9 clean subset + robustness).
//! Oracle: docs/SLICES.md slices 1–2; TESTPLAN T-GV mappings in comments.

use detox_rs::{sanitize, CaseMode, Options, Profile, UniqueStyle, Uniquifier};

fn d() -> Options {
    Options::default()
}

/// (input bytes, expected `clean` name) — SPEC §9 rows tagged S1 in SLICES.md
const VECTORS: &[(&[u8], &str)] = &[
    (b"My Report (final).docx", "My_Report_final.docx"),            // S1-01
    (b"foo  bar__baz--qux.txt", "foo_bar_baz-qux.txt"),             // S1-02
    ("日本語 レポート.txt".as_bytes(), "日本語_レポート.txt"),          // S1-03
    (b"CON.txt", "CON.txt"),                                        // S1-04 reserved: opt-in
    (b".", "_"),                                                    // S1-05a dots family
    (b"..", "_"),                                                    // S1-05b
    (b"...", "_"),                                                   // S1-05c
    (b"a\0b.txt", "a_hidden_null_b.txt"),                            // S1-06 NUL marker
    (b"--help.txt", "help.txt"),                                     // S1-07 leading dash
    (b"name, with (punct)!$&.txt", "name_with_punct.txt"),           // S1-08 removal set
    (&[0xff, 0xfe, b'a', b'.', b't', b'x', b't'], "a.txt"),          // S1-09 lossy repair
    (b"---", "_"),                                                   // S1-10 emptiness guard
    ("\u{202e}txt.exe".as_bytes(), "txt.exe"),                       // S1-11 RLO stripped
    ("a\u{200d}b.png".as_bytes(), "a_b.png"),                        // S1-12 ZWJ
    ("x\u{ff0e}y.txt".as_bytes(), "x_y.txt"),                        // S1-13 fullwidth dot
];

#[test]
fn golden_vectors() {
    for (input, want) in VECTORS {
        let got = sanitize(input, &d());
        assert_eq!(&got.name, want, "input {input:?}");
    }
}

#[test]
fn idempotency_corpus() {
    for (input, _) in VECTORS {
        let once = sanitize(input, &d());
        let twice = sanitize(once.name.as_bytes(), &d());
        assert_eq!(once.name, twice.name, "not idempotent: {input:?}");
    }
}

#[test]
fn nfc_normalization() {
    // NFD "résumé" must converge with NFC form (SPEC §9 row 3, COL-1).
    let nfd = "re\u{301}sume\u{301}.pdf";
    let nfc = "résumé.pdf";
    assert_eq!(
        sanitize(nfd.as_bytes(), &d()).name,
        sanitize(nfc.as_bytes(), &d()).name
    );
}

#[test]
fn output_is_valid_utf8_and_nonempty() {
    for (input, _) in VECTORS {
        let o = sanitize(input, &d());
        assert!(!o.name.is_empty());
        assert!(std::str::from_utf8(o.name.as_bytes()).is_ok());
    }
}

// --- Slice 2: exact charset classification (user: "extremely robust") ---

#[test]
fn exact_general_categories() {
    // Mn outside Other_Alphabetic: kept by \p{M}, misclassified by the old
    // is_alphabetic shortcut (this is the regression that motivated slice 2).
    assert_eq!(sanitize("a\u{20d0}b".as_bytes(), &d()).name, "a\u{20d0}b");
    // Mc (spacing combining mark, Devanagari vowel sign): also \p{M}.
    assert_eq!(sanitize("क\u{93c}".as_bytes(), &d()).name, "क\u{93c}");
    // Cf still replaced (ZWJ, RLO); So still replaced (U+FFFD path covered in S1-09).
    assert_eq!(sanitize("a\u{200d}b".as_bytes(), &d()).name, "a_b");
}

// --- Slice 2: LEN ---

#[test]
fn len_caps_exact_boundaries() {
    // T-GV-026: 254/255/256/257-byte ASCII names.
    for (total, want_len) in [(254usize, 254usize), (255, 255), (256, 255), (257, 255)] {
        let name = format!("{}.txt", "a".repeat(total - 4));
        assert_eq!(name.len(), total);
        let o = sanitize(name.as_bytes(), &d());
        assert_eq!(o.name.len(), want_len, "total {total}");
        assert!(o.name.ends_with(".txt"), "extension lost at {total}");
    }
}

#[test]
fn len_multibyte_boundary_never_panics() {
    // Astral chars (4 bytes) and 2-byte chars straddling the cap.
    for cap in [1usize, 2, 3, 4, 5, 7, 8, 255] {
        let opts = Options {
            max_bytes: cap,
            ..Options::default()
        };
        for name in [
            "😀😀😀😀😀.txt",
            "ééééébc.txt",
            "a\u{20d0}\u{20d1}.pdf",
            ".txt",
            "😀",
        ] {
            let o = sanitize(name.as_bytes(), &opts);
            assert!(o.name.len() <= cap, "{name:?} cap {cap} -> {} bytes", o.name.len());
            std::str::from_utf8(o.name.as_bytes()).expect("valid utf8");
        }
    }
}

#[test]
fn len_extension_from_original_name() {
    // detox 2.0 fix: the extension is taken from the pre-truncation name, so a
    // dot inside the stem region must not be picked up as the extension.
    let opts = Options {
        max_bytes: 10,
        ..Options::default()
    };
    let o = sanitize("my.long_stem.txt".as_bytes(), &opts);
    assert!(o.name.ends_with(".txt"), "{}", o.name);
    assert!(o.name.len() <= 10);
}

// --- Slice 2: UNQ ---

#[test]
fn uniquify_infix_batch() {
    let mut u = Uniquifier::new(UniqueStyle::Infix, 255);
    assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report.pdf");
    assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report_1.pdf");
    assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report_2.pdf");
}

#[test]
fn uniquify_hundred_identical() {
    // T-GV-027: deterministic counters for a whole colliding batch.
    let mut u = Uniquifier::new(UniqueStyle::Infix, 255);
    for i in 0..100 {
        let (n, _) = u.apply("a.txt".into()).unwrap();
        let want = if i == 0 { "a.txt" } else { &format!("a_{i}.txt") };
        assert_eq!(n, want);
    }
}

#[test]
fn uniquify_styles() {
    let mut p = Uniquifier::new(UniqueStyle::Prefix, 255);
    assert_eq!(p.apply("x.pdf".into()).unwrap().0, "x.pdf");
    assert_eq!(p.apply("x.pdf".into()).unwrap().0, "_1x.pdf");
    let mut q = Uniquifier::new(UniqueStyle::Postfix, 255);
    assert_eq!(q.apply("x.pdf".into()).unwrap().0, "x.pdf");
    assert_eq!(q.apply("x.pdf".into()).unwrap().0, "x.pdf_1");
}

#[test]
fn uniquify_never_exceeds_cap() {
    let mut u = Uniquifier::new(UniqueStyle::Infix, 12);
    for _ in 0..50 {
        let (n, _) = u.apply("abcdefgh.pdf".into()).unwrap();
        assert!(n.len() <= 12, "{n}");
    }
}

#[test]
fn batch_is_idempotent_after_uniq() {
    // INV-1 extended: a uniquified batch re-applies unchanged.
    let inputs = ["a.txt", "a.txt", "a.txt", "b.txt"];
    let mut u = Uniquifier::new(UniqueStyle::Infix, 255);
    let mut batch: Vec<String> = inputs
        .iter()
        .map(|i| u.apply(sanitize(i.as_bytes(), &d()).name).unwrap().0)
        .collect();
    let mut u2 = Uniquifier::new(UniqueStyle::Infix, 255);
    for n in &batch {
        let again = u2.apply(sanitize(n.as_bytes(), &d()).name).unwrap().0;
        assert_eq!(&again, n, "batch not a fixed point");
    }
    batch.sort();
    batch.dedup();
    assert_eq!(batch.len(), 4, "outputs must stay distinct");
}

// --- Slice 3: TRL / CAS / portable / ascii ---

fn ascii_opts() -> Options {
    Options {
        profile: Profile::Ascii,
        ..Options::default()
    }
}

#[test]
fn trl_vectors() {
    // SPEC §9 row 6: compatibility chars via NFKD.
    assert_eq!(sanitize("ﬁle①.txt".as_bytes(), &ascii_opts()).name, "file1.txt");
    // Decomposition: precomposed + mark-dropping.
    assert_eq!(sanitize("résumé.pdf".as_bytes(), &ascii_opts()).name, "resume.pdf");
    // Table entries (non-decomposable).
    assert_eq!(sanitize("ß.txt".as_bytes(), &ascii_opts()).name, "ss.txt");
    assert_eq!(sanitize("µs Łódź.txt".as_bytes(), &ascii_opts()).name, "us_Lodz.txt");
    assert_eq!(sanitize("Þing œuvre.txt".as_bytes(), &ascii_opts()).name, "THing_oeuvre.txt");
    // Fraction slash is not a mark: becomes `_`.
    assert_eq!(sanitize("½.txt".as_bytes(), &ascii_opts()).name, "1_2.txt");
    // Non-decomposing scripts: underscore per SLICES shortcut, then CLN
    // strips leading `_` — extension-only result is the documented fixed point.
    assert_eq!(sanitize("日本語.txt".as_bytes(), &ascii_opts()).name, ".txt");
    // Fullwidth compatibility map.
    assert_eq!(sanitize("ｆｉ.txt".as_bytes(), &ascii_opts()).name, "fi.txt");
}

#[test]
fn cas_vectors() {
    // SPEC §9 row 4 (COL-2 fix): full-Unicode lowering.
    let lower = Options {
        case: CaseMode::Lower,
        ..Options::default()
    };
    assert_eq!(sanitize("Ä.TXT".as_bytes(), &lower).name, "ä.txt");
    let upper = Options {
        case: CaseMode::Upper,
        ..Options::default()
    };
    assert_eq!(sanitize("mixed Name.txt".as_bytes(), &upper).name, "MIXED_NAME.TXT");
    // Lower + ascii compose: STRASSE-style table before case is moot, but
    // plain ASCII lowering works through the same path.
    let both = Options {
        profile: Profile::Ascii,
        case: CaseMode::Lower,
        ..Options::default()
    };
    assert_eq!(sanitize("ABC ß.txt".as_bytes(), &both).name, "abc_ss.txt");
}

#[test]
fn reserved_names_escaped_portable_only() {
    let portable = Options {
        profile: Profile::Portable,
        ..Options::default()
    };
    for (input, want) in [
        ("CON.txt", "_CON.txt"),
        ("con.txt", "_con.txt"),
        ("CON", "_CON"),
        ("COM1", "_COM1"),
        ("LPT9.log", "_LPT9.log"),
        ("console.txt", "console.txt"), // stem not in set
        ("CONTACT", "CONTACT"),
    ] {
        assert_eq!(sanitize(input.as_bytes(), &portable).name, want, "{input}");
    }
    // Clean leaves reserved names alone (user ruling: opt-in).
    assert_eq!(sanitize(b"CON.txt", &Options::default()).name, "CON.txt");
    // Fixed point: escape survives a re-run.
    let once = sanitize(b"CON.txt", &portable).name;
    assert_eq!(sanitize(once.as_bytes(), &portable).name, once);
}

#[test]
fn reserved_names_under_cap() {
    // SPEC v0.2.3: escape runs after LEN; tight caps cut the escape to fit.
    let portable = |cap| Options {
        profile: Profile::Portable,
        max_bytes: cap,
        ..Options::default()
    };
    // Truncation-created reserved stem is caught and escaped within cap.
    let o = sanitize(b"CONX", &portable(3));
    assert_eq!(o.name, "_CO");
    assert!(o.name.len() <= 3);
    // Tight cap: escape cut to fit; documented INV-1 exception — second
    // application strips once more and then converges.
    let once = sanitize(b"CON", &portable(3)).name;
    assert_eq!(once, "_CO");
    let twice = sanitize(once.as_bytes(), &portable(3)).name;
    let thrice = sanitize(twice.as_bytes(), &portable(3)).name;
    assert_eq!(thrice, twice, "must converge by the second re-run");
    assert!(thrice.len() <= 3);
}

#[test]
fn portable_output_is_ascii() {
    let portable = Options {
        profile: Profile::Portable,
        ..Options::default()
    };
    for name in ["ﬁle① (draft).doc", "日本語 レポート", "ÄÖÜ ß µ", "a\0b.txt"] {
        let o = sanitize(name.as_bytes(), &portable);
        assert!(
            o.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "{name:?} -> {:?}",
            o.name
        );
    }
}


// --- Fuzz-lite (deterministic LCG, no deps; extended over all profiles) ---

#[test]
fn fuzz_no_panic_and_invariants() {
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let alphabet: Vec<char> = [
        'a', 'Z', '0', '_', '-', '.', ' ', '(', ')', '!', '\u{0}', 'é', '日', '😀',
        '\u{0301}', '\u{20d0}', '\u{202e}', '\u{ff0e}', '\u{200d}', 'æ', 'ß', '½', 'µ',
    ]
    .to_vec();
    for round in 0..2000 {
        let len = (next() % 40) as usize;
        let s: String = (0..len)
            .map(|_| alphabet[(next() as usize) % alphabet.len()])
            .collect();
        let cap = [1usize, 3, 8, 64, 255][(next() as usize) % 5];
        for profile in [Profile::Clean, Profile::Portable, Profile::Ascii] {
            let opts = Options {
                profile,
                max_bytes: cap,
                ..Options::default()
            };
            let o = sanitize(s.as_bytes(), &opts);
            assert!(o.name.len() <= cap, "round {round} cap {cap}");
            std::str::from_utf8(o.name.as_bytes()).expect("valid utf8");
            if profile != Profile::Clean {
                assert!(
                    o.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                    "round {round} {s:?} -> {:?} not ascii",
                    o.name
                );
            }
            let again = sanitize(o.name.as_bytes(), &opts);
            assert_eq!(o.name, again.name, "not idempotent: {s:?} profile {profile:?}");
        }
    }
}
