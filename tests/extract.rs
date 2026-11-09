//! Slice 6 acceptance: detox-rs extract (ripMIME replacement core).
//! Oracle: docs/SLICES.md slice 6 v1; EXTRACT.md §7 vectors T-EX-001..012.

use detox_rs::extract::{extract, ExtractOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn outdir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("detox-ex-{}-{}-{n}", tag, nanos))
}

fn opts(dir: &std::path::Path) -> ExtractOptions {
    ExtractOptions {
        out_dir: dir.to_path_buf(),
        ..Default::default()
    }
}

const B64_PDF: &str = "JVBERi0xLjQK"; // "%PDF-1.4\n"
const B64_HI: &str = "aGk="; // "hi"
const FUZZ_TEMPLATE: &[u8] = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"f.pdf\"\r\n\r\nJVBERi0xLjQK\r\n--BB--\r\n";

fn multipart(boundary: &str, parts: &str) -> Vec<u8> {
    format!(
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n{parts}--{boundary}--\r\n"
    )
    .into_bytes()
}

#[test]
fn t_ex_001_encoded_word_decoded_once() {
    // =?UTF-8?B?w6ZmZmljZS5wZGY=?= is "æffice.pdf" — must decode exactly once.
    let mail = multipart(
        "b1",
        &format!(
            "--b1\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"=?UTF-8?B?w6ZmZmljZS5wZGY=?=\"\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("001");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 1);
    assert_eq!(r.parts[0].file, dir.join("æffice.pdf"), "{:?}", r.parts[0].file);
    assert_eq!(r.parts[0].name_source, "filename= (2047)");
    assert_eq!(std::fs::read(&r.parts[0].file).unwrap(), b"%PDF-1.4\n");
}

#[test]
fn t_ex_002_rfc2231_star_and_continuations() {
    let mail = multipart(
        "b2",
        &format!(
            "--b2\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=UTF-8''%C3%A6%20office.pdf\r\n\r\n{B64_PDF}\r\n--b2\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*0*=\"UTF-8''%C3%A6\"; filename*1*=\" office.pdf\"\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("002");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 2);
    assert_eq!(r.parts[0].file, dir.join("æ_office.pdf"));
    assert_eq!(r.parts[1].file, dir.join("æ_office_1.pdf"), "UNQ in part order");
}

#[test]
fn t_ex_003_iso_8859_1_encoded_word() {
    // =?ISO-8859-1?Q?eine=E4.txt?= -> "eineä.txt" (kept under clean).
    let mail = multipart(
        "b3",
        &format!(
            "--b3\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"=?ISO-8859-1?Q?eine=E4.txt?=\"\r\n\r\n{B64_HI}\r\n"
        ),
    );
    let dir = outdir("003");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts[0].file, dir.join("eineä.txt"));
}

#[test]
fn t_ex_004_traversal_is_dead() {
    let mail = multipart(
        "b4",
        &format!(
            "--b4\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"../../..\\\\evil.txt\"\r\n\r\n{B64_HI}\r\n--b4\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"C:\\\\Windows\\\\x.dll\"\r\n\r\n{B64_HI}\r\n"
        ),
    );
    let dir = outdir("004");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 2);
    assert!(r.parts.iter().all(|p| p.file.parent() == Some(dir.as_path())));
    assert!(r.parts.iter().any(|p| p.file == dir.join("evil.txt")));
    assert!(r.parts.iter().any(|p| p.file == dir.join("x.dll")));
}

#[test]
fn qp_invalid_escape_passthrough_regress() {
    // Differential fuzzing (cases 138/343/387): match CPython a2b_qp edge
    // semantics exactly — invalid escapes pass '=' through literally, "=="
    // is a literal '=', "=\r" / "=\n" / trailing "=" are soft breaks.
    let body = "k=FA==B7z=G1=\rX=\r\nY=Z"; // valid, ==, invalid, =CR, =CRLF, trailing =
    // "=\rX=\r\n" is ONE soft break over the line tail (X and the second
    // '=' are consumed), so no '=' or X precede Y.
    let want = vec![
        b'k', 0xFA, b'=', b'B', b'7', b'z', b'=', b'G', b'1', b'Y', b'=', b'Z',
    ];
    let part = format!(
        "--bqp\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Disposition: attachment; filename=\"qp.bin\"\r\n\r\n{body}\r\n"
    );
    let mail = multipart("bqp", &part);
    let dir = outdir("qpinvalid");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 1);
    assert_eq!(std::fs::read(&r.parts[0].file).unwrap(), want);
}

#[test]
fn us_ascii_high_bytes_are_lossy_regress() {
    // Differential fuzzing (case 358): us-ascii is strictly 7-bit; high
    // bytes decode to U+FFFD with a lossy note (previously shared the
    // latin-1 mapping, producing mojibake and no note).
    let part = "--bas\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename*=us-ascii''%61%C3%89b\r\n\r\nhi\r\n";
    let mail = multipart("bas", part);
    let dir = outdir("usascii");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 1);
    // a, U+FFFD, b -> sanitize: U+FFFD -> '_' -> "a_b"
    assert_eq!(r.parts[0].file, dir.join("a_b"));
    assert!(
        r.parts[0]
            .note
            .as_deref()
            .unwrap_or("")
            .contains("lossy"),
        "expected lossy note, got {:?}",
        r.parts[0].note
    );
}

#[test]
fn colon_prefix_is_not_a_drive_letter_regress() {
    // Differential fuzzing vs Python's email (case 52): an "X:"-prefixed
    // basename is an ordinary name, not a drive letter — stripping it ate
    // the first two chars ("c:d" -> "d"). Colons are sanitize's job.
    let mail = multipart(
        "b4c",
        &format!(
            "--b4c\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"e:mail.pdf\"\r\n\r\n{B64_HI}\r\n--b4c\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"a/b\\\\c:d\"\r\n\r\n{B64_HI}\r\n"
        ),
    );
    let dir = outdir("colondrv");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 2);
    assert!(r.parts.iter().any(|p| p.file == dir.join("e_mail.pdf")));
    assert!(r.parts.iter().any(|p| p.file == dir.join("c_d")));
}

#[test]
fn t_ex_005_duplicate_names_uniquified() {
    let part = format!(
        "--b5\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\n\r\n{B64_PDF}\r\n"
    );
    let mail = multipart("b5", &format!("{part}{part}"));
    let dir = outdir("005");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 2);
    assert_eq!(r.parts[0].file, dir.join("report.pdf"));
    assert_eq!(r.parts[1].file, dir.join("report_1.pdf"));
}

#[test]
fn t_ex_006_qp_decoding_and_binary_exact() {
    let mail = multipart(
        "b6",
        "--b6\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\n\r\nab=00cd=FF\r\n",
    );
    let dir = outdir("006");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(std::fs::read(&r.parts[0].file).unwrap(), vec![b'a', b'b', 0x00, b'c', b'd', 0xFF]);
}

#[test]
fn t_ex_008_nameless_part_variants() {
    let part = "--b8\r\nContent-Type: image/jpeg\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n";
    // default: text.jpeg
    let dir = outdir("008a");
    let mail = multipart("b8", part);
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts[0].file, dir.join("text.jpeg"));
    // --name-by-type
    let dir = outdir("008b");
    let r = extract(&mail, &ExtractOptions { out_dir: dir.clone(), name_by_type: true, ..opts(&dir) }).unwrap();
    assert_eq!(r.parts[0].file, dir.join("image_jpeg"));
    // -p doc
    let dir = outdir("008c");
    let r = extract(&mail, &ExtractOptions { out_dir: dir.clone(), prefix: "doc".into(), ..opts(&dir) }).unwrap();
    assert_eq!(r.parts[0].file, dir.join("doc.jpeg"));
}

#[test]
fn tiny_mbox_no_panic_regress() {
    // Fuzz-found: envelope-slice arithmetic could index past end of short
    // mbox inputs.
    let dir = outdir("tinymbox");
    for mbox in [
        &b"From a@b"[..],
        &b"From a@b c\r\n\r\nFrom "[..],
        &b"From x\nFrom y\nFrom z"[..],
        &b"\nFrom a@b"[..],
    ] {
        let r = extract(
            mbox,
            &ExtractOptions {
                out_dir: dir.clone(),
                mailbox: true,
                ..opts(&dir)
            },
        );
        // Ok or graceful Err — never a panic (test harness would catch).
        let _ = r;
    }
}

#[test]
fn fuzz_extract_compact() {
    // Permanent trimmed version of examples/fuzz_extract.rs (200k rounds
    // there, 3k here) — soup + template mutation, oracle: no panic, every
    // emitted path under out dir. Seeded LCG, deterministic.
    let mut rng: u64 = 0x9e3779b97f4a7c15;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let dir = outdir("compact-fuzz");
    for round in 0..3000 {
        let mut input: Vec<u8> = Vec::new();
        match round % 3 {
            0 => {
                let len = (next() % 1024) as usize;
                input.extend((0..len).map(|_| (next() & 0xff) as u8));
            }
            1 => {
                input.extend_from_slice(FUZZ_TEMPLATE);
                for _ in 0..1 + next() % 6 {
                    let i = (next() as usize) % input.len().max(1);
                    if i < input.len() {
                        match next() % 3 {
                            0 => input[i] = (next() & 0xff) as u8,
                            1 => input.insert(i, (next() & 0xff) as u8),
                            _ => {
                                input.remove(i);
                            }
                        }
                    }
                }
            }
            _ => {
                input = b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"=?utf-8?Q?a_b?=\"\r\n\r\naGk=\r\n--BB--\r\n".to_vec();
                for _ in 0..next() % 8 {
                    let i = (next() as usize) % input.len();
                    input[i] = (next() & 0xff) as u8;
                }
            }
        }
        let report = extract(
            &input,
            &ExtractOptions {
                out_dir: dir.clone(),
                mailbox: round % 2 == 0,
                recursion_max: 8,
                parts_max: 500,
                journal_dir: None,
                ..opts(&dir)
            },
        );
        if let Ok(r) = report {
            for p in &r.parts {
                assert_eq!(p.file.parent(), Some(dir.as_path()), "escape: {:?}", p.file);
                assert!(std::str::from_utf8(p.file.as_os_str().as_encoded_bytes()).is_ok());
            }
        }
    }
}

#[test]
fn iso_8859_2_q_encoded_word_regress() {
    // User-reported: Hungarian drawing name must decode É (0xC9), not fall
    // through raw. =?iso-8859-2?Q?=C9P-RE-01_R_=C9SZLETRAJZ-PINCE_ALAPRAJZ.pdf?=
    let mail = multipart(
        "bhu",
        &format!(
            "--bhu\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"=?iso-8859-2?Q?=C9P-RE-01_R=C9SZLETRAJZ-PINCE_ALAPRAJZ.pdf?=\"\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("hu");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(
        r.parts[0].file,
        dir.join("ÉP-RE-01_RÉSZLETRAJZ-PINCE_ALAPRAJZ.pdf"),
        "{:?}",
        r.parts[0].file
    );
    assert!(r.parts[0].note.is_none(), "charset must be known");
}

#[test]
fn iso_8859_2_via_rfc2231_star() {
    // Same name delivered as RFC 2231 percent-encoded filename*.
    let mail = multipart(
        "bhu2",
        &format!(
            "--bhu2\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename*=iso-8859-2''%C9P-RE-01%20R%C9SZLETRAJZ%20-%20PINCE%20ALAPRAJZ.pdf\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("hu2");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(
        r.parts[0].file,
        dir.join("ÉP-RE-01_RÉSZLETRAJZ-PINCE_ALAPRAJZ.pdf"),
        "{:?}",
        r.parts[0].file
    );
}

#[test]
fn multipart_nesting_is_depth_capped_regress() {
    // Security review F1: multipart recursion passed `depth` unchanged —
    // ~10k nested shells blew the 8 MB stack (SIGABRT, invisible to the
    // no-panic fuzz oracle). Now capped by the same recursion_max as
    // message/rfc822. Surviving this test at depth 60 IS the assertion.
    fn shell(depth: usize) -> String {
        let b = format!("bd{depth}");
        let inner = if depth == 0 {
            "--b0\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"deep.txt\"\r\n\r\nhi\r\n".to_string()
        } else {
            format!("--{b}\r\n{}\r\n", shell(depth - 1))
        };
        format!(
            "Content-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\n{inner}--{b}--\r\n"
        )
    }
    let mail = format!("MIME-Version: 1.0\r\n{}", shell(60));
    let dir = outdir("deepnest");
    let r = extract(mail.as_bytes(), &opts(&dir)).unwrap();
    assert!(
        r.parts.is_empty(),
        "depth 60 > default recursion_max 20: {r:?}"
    );
    assert!(r.journal_error.as_deref().unwrap_or("").contains("cap"));
}

#[test]
fn oversized_boundary_is_refused_regress() {
    // Security review F2: boundary is attacker-controlled and was uncapped;
    // a long needle over a long body made the delimiter scan O(n x m).
    // Boundaries > 200 bytes (RFC 2046 allows 70) are refused: part is
    // opaque, no sub-parts.
    let b = "B".repeat(500);
    let mail = format!(
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\n--{b}\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"x.txt\"\r\n\r\nhi\r\n--{b}--\r\n"
    );
    let dir = outdir("longb");
    let r = extract(mail.as_bytes(), &opts(&dir)).unwrap();
    assert!(r.parts.is_empty(), "{r:?}");
}

#[test]
fn rfc2231_value_is_not_double_decoded_regress() {
    // Security review F3: %3D%3F is "=?", so an encoded-word smuggled through
    // a charset-marked RFC 2231 param must stay literal (MIME-1: no second
    // decode pass). Value percent-decodes to the valid-UTF-8 literal
    // "=?UTF-8?B?ZmaWxl?="; the pipeline then maps unsafe chars to '_' and
    // strips leading/trailing runs: "_UTF-8_B_ZmaWxl__" -> "UTF-8_B_ZmaWxl".
    // (The assertion that matters: it is NOT base64-decoded to "ZmaWxl".)
    let mail = multipart(
        "b2231",
        "--b2231\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename*=utf-8''%3D%3FUTF-8%3FB%3FZmaWxl%3F%3D\r\n\r\nhi\r\n",
    );
    let dir = outdir("mime1");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 1, "{r:?}");
    assert_eq!(r.parts[0].file, dir.join("UTF-8_B_ZmaWxl"));
    assert_eq!(std::fs::read_to_string(&r.parts[0].file).unwrap(), "hi");
}

#[test]
fn undo_removes_hard_link_aliases_regress() {
    // Security review F5: the extract journal skipped hard-link aliases, so
    // undo left them on disk. Both names are journaled now.
    use detox_rs::fs::{self, UndoSel};
    let mail = multipart(
        "bhx",
        &format!(
            "--bhx\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"hp.pdf\"; filename=\"ha.pdf\"\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("hlinkundo");
    let jdir = outdir("hlinkundo-j");
    let mut o = opts(&dir);
    o.journal_dir = Some(jdir.clone());
    let r = extract(&mail, &o).unwrap();
    assert_eq!(r.parts.len(), 2, "{r:?}");
    assert!(dir.join("hp.pdf").exists() && dir.join("ha.pdf").exists());
    let undo = fs::undo(UndoSel::Last, &jdir).unwrap();
    assert_eq!(undo.restored, 2, "{undo:?}");
    assert!(!dir.join("hp.pdf").exists() && !dir.join("ha.pdf").exists());
}

#[test]
fn t_ex_010_nested_rfc822_and_recursion_cap() {
    let inner = "Content-Type: multipart/mixed; boundary=\"bi\"\r\n\r\n--bi\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"inner.txt\"\r\n\r\nhi\r\n--bi--\r\n".to_string();
    let mail = multipart(
        "b10",
        &format!(
            "--b10\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n{inner}\r\n"
        ),
    );
    let dir = outdir("010");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert!(r.parts.iter().any(|p| p.file == dir.join("inner.txt")), "{r:?}");

    // recursion cap 0: nothing extracted from nested content
    let dir = outdir("010cap");
    let r = extract(&mail, &ExtractOptions { out_dir: dir.clone(), recursion_max: 0, ..opts(&dir) }).unwrap();
    assert!(r.parts.is_empty(), "{r:?}");
}

#[test]
fn t_ex_011_mbox_two_messages() {
    let msg = |name: &str| {
        String::from_utf8(multipart(
            "bm",
            &format!(
                "--bm\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"{name}\"\r\n\r\n{B64_HI}\r\n"
            ),
        ))
        .unwrap()
    };
    let mbox = format!("From a@b {}\r\n{}\r\nFrom c@d {}\r\n{}\r\n", 1, msg("one.txt"), 2, msg("two.txt"));
    let dir = outdir("011");
    let r = extract(
        mbox.as_bytes(),
        &ExtractOptions {
            out_dir: dir.to_path_buf(),
            mailbox: true,
            ..opts(&dir)
        },
    )
    .unwrap();
    assert_eq!(r.parts.len(), 2, "{r:?}");
    assert!(r.parts.iter().any(|p| p.file == dir.join("one.txt")));
    assert!(r.parts.iter().any(|p| p.file == dir.join("two.txt")));
}

#[test]
fn headers_dump_written() {
    let mail = multipart(
        "bh",
        &format!(
            "--bh\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"x.txt\"\r\n\r\n{B64_HI}\r\n"
        ),
    );
    let dir = outdir("hdr");
    let hf = dir.join("headers.txt");
    let _ = extract(
        &mail,
        &ExtractOptions {
            out_dir: dir.to_path_buf(),
            headers_file: Some(hf.clone()),
            ..opts(&dir)
        },
    )
    .unwrap();
    let h = std::fs::read_to_string(&hf).unwrap();
    assert!(h.contains("Content-Type:"), "{h}");
}

#[test]
fn no_overwrite_without_double_arm() {
    let part = format!(
        "--bn\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"same.pdf\"\r\n\r\n{B64_PDF}\r\n"
    );
    let mail = multipart("bn", &format!("{part}{part}"));
    let dir = outdir("noov");
    let o = ExtractOptions {
        out_dir: dir.clone(),
        ..opts(&dir)
    };
    let r = extract(&mail, &o).unwrap();
    assert_eq!(r.parts.len(), 2); // UNQ kept them distinct — no overwrite needed
}

#[test]
fn extra_filename_params_become_hard_links() {
    // EXT-6: first filename extracted, extras hard-linked to it.
    let mail = multipart(
        "bx",
        &format!(
            "--bx\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"primary.pdf\"; filename=\"alias.pdf\"\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("link");
    let r = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r.parts.len(), 2, "{r:?}");
    let primary = &r.parts[0];
    let alias = &r.parts[1];
    assert_eq!(primary.file, dir.join("primary.pdf"));
    assert_eq!(alias.file, dir.join("alias.pdf"));
    assert!(alias.hard_link_of.is_some());
    use std::os::unix::fs::MetadataExt;
    let a = std::fs::metadata(&primary.file).unwrap();
    let b = std::fs::metadata(&alias.file).unwrap();
    assert_eq!(a.ino(), b.ino(), "must be the same inode");
}

#[test]
fn second_run_uniquifies_against_existing_files() {
    // Review finding: re-extracting into the same DIR must UNQ, not abort.
    let part = format!(
        "--br\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"again.pdf\"\r\n\r\n{B64_PDF}\r\n"
    );
    let mail = multipart("br", &part);
    let dir = outdir("rerun");
    let r1 = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r1.parts[0].file, dir.join("again.pdf"));
    let r2 = extract(&mail, &opts(&dir)).unwrap();
    assert_eq!(r2.parts[0].file, dir.join("again_1.pdf"), "{r2:?}");
}

#[test]
fn planted_symlink_is_refused() {
    // Review finding: a dangling symlink must not capture the write.
    let mail = multipart(
        "bs",
        &format!(
            "--bs\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"evil.pdf\"\r\n\r\n{B64_PDF}\r\n"
        ),
    );
    let dir = outdir("symlink");
    std::fs::create_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink("/tmp/detox-rs-escape-target", dir.join("evil.pdf")).unwrap();
    let r = extract(&mail, &opts(&dir)).unwrap();
    // The seeded Uniquifier routes around the occupied name; the symlink is
    // never written through.
    assert_eq!(r.parts[0].file, dir.join("evil_1.pdf"), "{r:?}");
    assert!(!std::path::Path::new("/tmp/detox-rs-escape-target").exists());
}
