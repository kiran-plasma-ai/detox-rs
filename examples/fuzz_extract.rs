//! Throwaway fuzz harness for the extract surface (slice 6/6.1).
//! Run: cargo run --release --example fuzz_extract
//! Mutators: byte soup, template mutation, header/filename soup, mbox soup.
//! Oracle: no panic; every emitted path stays under the out dir; names are
//! valid UTF-8. Findings print the offending input (hex) and are saved to
//! /tmp/detox-fuzz-findings.log

use detox_rs::extract::{extract, ExtractOptions};
use detox_rs::fs::{self, UndoSel};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn find(_rng: &mut Rng, n: usize, kind: &str, input: &[u8], panicked: bool) {
    println!(
        "FUZZ {kind} #{n}: panic={panicked} len={} input(hex)={}",
        input.len(),
        input
            .iter()
            .take(400)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    if panicked {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/detox-fuzz-findings.log")
        {
            let _ = writeln!(f, "{kind} #{n} len={} hex={}", input.len(), hex(input));
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const TEMPLATE: &[u8] = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"=?iso-8859-2?Q?=C9P-RE-01_R=C9SZLETRAJZ.pdf?=\"\r\n\r\nJVBERi0xLjQK\r\n--BB--\r\n";

const HEADER_SOUP: &[&str] = &[
    "filename=\"=?utf-8?B?w6ZmZmljZS5wZGY=?=\"",
    "filename=\"=?iso-8859-2?Q?=C9=50?=\"",
    "filename*=utf-8''%C3%A6%20x.pdf",
    "filename*0*=\"utf-8''%C3%A6\"; filename*1*=\" x.pdf\"",
    "filename=\"../../..\\\\evil\"",
    "filename=\"C:\\\\Windows\\\\x.dll\"",
    "filename",
    "filename=",
    "filename=\"=?utf-8?Q??=\"",
    "filename=\"=?utf-8?Q?ab\"",
    "name=\"n.txt\"",
    "filename=\"=?unknown-9?Q?=C9x?=\"",
    "filename=\"=?utf-8?B?!invalid!?=\"",
    "filename*0*=x; filename*2*=y",
    "filename=\"=?utf-7?B?KGR-DstW?=\"",
    "filename=\"=?utf-16?B?AEQAdwA=?=\"",
    "filename=\"ok.pdf\\r\\nX-Injected: 1\"",
    "filename*=\"=?iso-8859-2?Q?=C9x?=\"",
];

// Malformed-UTF-8 / naughty / traversal probes (mirrors tests/malformed.rs).
// Strings are inserted into mail bytes via .as_bytes(); the lossy header
// path sees them as raw bytes either way.
const EVIL_NAMES: &[&str] = &[
    "\u{0080}", "\u{c0}\u{af}", "\u{ed}\u{a0}\u{80}", "\u{f4}\u{90}\u{80}\u{80}",
    "\u{fffe}E\u{0}P\u{0}", "\u{feff}\u{e}", "\u{efbb}\u{bf}bom", "ok\u{e2}\u{82}bad",
    "\u{202e}txt\u{202c}", "\u{0}nul", "$PATH $(id)", "%s%d%n", "{g}[b]*?",
    "../", "..\\", "..;/", "%2e%2e/", "..%c0%af", "C:\\x", "\\\\?\\C:\\x",
    "name:ads", " trailing", "trailing. ", "CON", "COM1", "-rf", "..",
    "\u{ff0e}\u{ff0e}/x", "ＣＯＮ.txt", "z\u{301}\u{334}a", "\u{e0001}",
];

fn main() {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let out = std::env::temp_dir().join("detox-fuzz-out");
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let mut panics = 0usize;

    for n in 0..rounds {
        let mailbox = n % 2 == 0;
        let mut input: Vec<u8> = Vec::new();
        match n % 5 {
            0 => {
                // byte soup
                let len = rng.below(2048);
                input.extend((0..len).map(|_| rng.byte()));
            }
            1 => {
                // template mutation
                input.extend_from_slice(TEMPLATE);
                let ops = 1 + rng.below(8);
                for _ in 0..ops {
                    match rng.below(3) {
                        0 => {
                            let i = rng.below(input.len());
                            input[i] = rng.byte();
                        }
                        1 => {
                            let i = rng.below(input.len());
                            input.insert(i, rng.byte());
                        }
                        _ => {
                            if !input.is_empty() {
                                let i = rng.below(input.len());
                                input.remove(i);
                            }
                        }
                    }
                }
            }
            2 => {
                // header/filename soup
                let mut s = String::from(
                    "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n",
                );
                for _ in 0..rng.below(4) {
                    s.push_str(HEADER_SOUP[rng.below(HEADER_SOUP.len())]);
                    s.push_str("; ");
                }
                s.push_str("\r\n\r\nQUJD\r\n--BB--\r\n");
                input = s.into_bytes();
                for _ in 0..rng.below(6) {
                    let i = rng.below(input.len());
                    input[i] = rng.byte();
                }
            }
            3 => {
                // evil-name injection: catalog name as filename, plus random
                // truncation inside multibyte sequences
                let name = EVIL_NAMES[rng.below(EVIL_NAMES.len())].as_bytes();
                let cut = rng.below(name.len() + 1);
                let name = &name[..cut.min(name.len())];
                let mut m = Vec::new();
                m.extend_from_slice(b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"");
                m.extend_from_slice(name);
                m.extend_from_slice(b"\"\r\n\r\nJVBERi0xLjQK\r\n--BB--\r\n");
                input = m;
                for _ in 0..rng.below(4) {
                    let i = rng.below(input.len());
                    input[i] = rng.byte();
                }
            }
            _ => {
                // mbox soup
                let mut s = String::from("From a@b c\r\n");
                s.push_str(
                    "Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=f.txt\r\n\r\naGk=\r\n--BB--\r\n",
                );
                for _ in 0..rng.below(3) {
                    s.push_str("From ");
                    s.push_str(match rng.below(3) {
                        0 => "nobody\r\n",
                        1 => "x@y z\r\n",
                        _ => "not-an-envelope\r\n",
                    });
                    s.push_str("garbage\r\n");
                }
                input = s.into_bytes();
                for _ in 0..rng.below(8) {
                    let i = rng.below(input.len());
                    input[i] = rng.byte();
                }
            }
        }

        let opts = ExtractOptions {
            out_dir: out.clone(),
            mailbox,
            recursion_max: 8,
            parts_max: 500,
            journal_dir: None,
            ..Default::default()
        };
        let input_c = input.clone();
        let out_c = out.clone();
        let r = std::panic::catch_unwind(|| {
            let _ = std::fs::remove_dir_all(&out_c);
            extract(&input_c, &opts).map(|report| {
                for p in &report.parts {
                    assert!(
                        p.file.starts_with(&out_c),
                        "path escape: {}",
                        p.file.display()
                    );
                    assert!(std::str::from_utf8(p.file.as_os_str().as_encoded_bytes()).is_ok());
                    if let Some(parent) = p.file.parent() {
                        assert_eq!(parent, out_c.as_path(), "parent must be out dir");
                    }
                }
            })
        });
        if r.is_err() {
            panics += 1;
            find(&mut rng, n, "panic", &input, true);
            if panics >= 10 {
                println!("stopping after 10 panics");
                break;
            }
        }
        // Journal/undo fuzz: random bytes as a journal file, then undo.
        if n % 3 == 0 {
            let jdir = std::env::temp_dir().join("detox-fuzz-journal");
            let _ = std::fs::remove_dir_all(&jdir);
            let _ = std::fs::create_dir_all(&jdir);
            let mut content: Vec<u8> = Vec::new();
            let len = rng.below(512);
            content.extend((0..len).map(|_| rng.byte()));
            // Bias toward journal-like shapes half the time.
            if n % 6 == 0 {
                content = format!(
                    "{{\"run\":\"r\",\"old\":\"a\",\"new\":\"b\",\"dev\":{},\"ino\":{}}}\n",
                    rng.next() % 1000,
                    rng.next() % 1000
                )
                .into_bytes();
                for _ in 0..rng.below(6) {
                    let i = rng.below(content.len());
                    content[i] = rng.byte();
                }
            }
            let _ = std::fs::write(jdir.join("1-r.jsonl"), &content);
            let jc = jdir.clone();
            let r = std::panic::catch_unwind(|| {
                let _ = fs::undo(UndoSel::Last, &jc);
            });
            if r.is_err() {
                panics += 1;
                find(&mut rng, n, "journal-panic", &content, true);
                if panics >= 10 {
                    println!("stopping after 10 panics");
                    break;
                }
            }
        }

        if n % 10_000 == 0 {
            println!("... {n}/{rounds} (panics so far: {panics})");
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    println!("done: {rounds} rounds, {panics} panics");
}
