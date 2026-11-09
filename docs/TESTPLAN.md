# TESTPLAN — conformance & verification (companion to SPEC.md §9–§11)

Normative source of behavior: `SPEC.md`. This document makes "much better tested" executable: every requirement carries at least one test ID, every test names its oracle. Test IDs are stable and referenced by CI and by SPEC §13's coverage column.

## 1. Environments

| ID | Filesystem | Setup | Purpose |
|---|---|---|---|
| E1 | ext4 loop | `mkfs.ext4` image, mounted | reference ci-sensitive behavior |
| E2 | tmpfs | `-t tmpfs` | fast local dev runs |
| E3 | vfat loop | `mkfs.vfat`, mounted (always ci) | ci + FAT legality (INV-8) |
| E4 | exfat or ntfs3g loop | FUSE | UTF-16-unit length arithmetic (SPEC §3.2) |
| E5 | `FROM scratch` container | only the release binary copied | §3.4 distribution acceptance |

CI: PR gate = E1 + E2 + unit/property/fuzz-smoke. Nightly = full matrix. Release = full matrix green + E5 + published checksums.

## 2. Golden vectors (T-GV-###)

SPEC §9 vectors run on every applicable (environment × profile) pair. **ID convention**: SPEC §9 rows map to T-GV-001…T-GV-021 in top-down order (21 rows); extended vectors below are T-GV-022+. Applicability: most vectors `clean`; vector 6 runs `--profile ascii`; vectors 7–9 run with `-s mime`; vector 12 asserts both profiles; vector 14 asserts byte caps under both `clean` and `portable`; vector 15 runs `portable`. Assertion per run: exact output bytes, exit code, NDJSON line-for-line match against frozen expectations, and (E3/E4) post-run fs legality scan. Extended vectors (this document, equally normative):

| ID | Input | Expect |
|---|---|---|
| T-GV-022 | `‮txt.exe` (U+202E RLO) | RLO stripped: `txt.exe` — bidi control is a Cf char, not in `clean` charset |
| T-GV-023 | `a‍b.png` (ZWJ) | ZWJ (Cf) → `_`: `a_b.png` |
| T-GV-024 | `ﷺ.txt` (U+FDFA ligature) | `clean`: kept (Lo char); `ascii`: `SWASALLH`? — expected value fixed by chosen TRL table, asserted against table data, not hardcoded guesses |
| T-GV-025 | `x．y.txt` (U+FF0E fullwidth dot) | fullwidth dot is not `.` → `_`: `x_y.txt` |
| T-GV-026 | name of 254, 255, 256, 257 bytes | exact caps per SPEC §5.7, extension preserved, suffix headroom never violated |
| T-GV-027 | 100 identical names `a.txt` | `a.txt`, `a_1.txt` … `a_99.txt`, counter order = input (path,inode) order, deterministic across 3 shuffled reruns |
| T-GV-028 | `A.txt` + `a.txt` on E3 | uniquified pair (order-stable); on E1 both unchanged |
| T-GV-029 | batch `a→b, b→a, c→b` | full cycle via temp names; result `b→?` resolved per UNQ, no overwrite, journal records every temp step |
| T-GV-030 | read-only directory | exit 2, error line names errno, zero changes, journal absent (nothing committed) |
| T-GV-031 | full path >240 chars, `--profile portable` | advisory warning line, name unchanged, exit 1 |
| T-GV-032 | `.` / `..` / `...` | `_` in all cases — trailing-dot strip + emptiness guard (SPEC §5.5), never empty output |
| T-GV-033 | `---`, `___`, `#!-` | `_` in all cases — emptiness guard after strip (SPEC §5.5) |

## 3. Property tests (T-P-###) — randomized, seeded, CI-reproducible

| ID | Property (formal) | Generator | Oracle |
|---|---|---|---|
| T-P-001 | ∀n,p: sanitize(sanitize(n,p),p) = sanitize(n,p) | unicode strings (printable, marks, Cf, ZWJ, astral, fullwidth) + raw byte strings | INV-1 byte equality |
| T-P-002 | ∀n,p: output matches profile charset regex; ∉ {`.`,`..`}; no leading `-`; no trailing `[. ]`; byte length ≤ cap | same | INV-3/INV-7/§5.7; regexes frozen in repo |
| T-P-003 | ∀n: portable(n) is FAT/NTFS-legal: ASCII-only, reserved-name-free, ≤255B | same | INV-8 checker implemented independently of the pipeline (no shared code) |
| T-P-004 | ∀batch: old→new injective modulo UNQ suffixes | batches of 2–50 colliding names (case folds, NFC/NFD pairs, truncation twins) | INV-4 multiset compare |
| T-P-005 | run then undo ⇒ byte-identical tree (E1–E3) | random trees, random profiles | INV-5 tree hash |
| T-P-006 | plan output identical for 10 random traversal orders of same tree | seeded shuffles | NDJSON diff |
| T-P-007 | ∀n: no panic, exit ∈ {0,1}; output valid UTF-8 | arbitrary **byte** strings (not just UTF-8) — Linux fs reality | INV-7, crash-freedom |

## 4. Concurrency & crash (T-C-###)

T-C-001 — background process creates/deletes sibling files during `--apply`; oracle: pre/post content hashes prove no file content changed hands (INV-2 under noise). Runs on E1 only, 30 iterations.

T-C-002 — `kill -9` the process at a random point mid-apply (instrumented delay between renames, seeded); then `detox undo --last`. Oracles: journal is well-formed NDJSON; every journal entry whose `new` exists is reverted; missing-`new` entries are skipped-with-warning (exit 1, SPEC §5.3); no path ends up occupied by the wrong dev+inode; re-running the original command converges to the same final tree as an uninterrupted run (T-P-006 determinism applied to recovery).

## 5. Fuzz (T-F-###)

| ID | Target | Mutators | Oracle |
|---|---|---|---|
| T-F-001 | full pipeline | byte flips, truncations, overlong UTF-8, raw 0x80–0xFF | T-P-002 regexes, no panic |
| T-F-002 | DEC stage (phase 2) | RFC 2047 word soup, nested encoded-words, **double-encoding mutants** (payload that is itself UTF-8 of percent-encoded text), 2231 continuations with charsets, lone `?` and `=` | MIME-1: ≤1 decode pass — detector instrumented; output never contains `%XX` residues from input-encoded names unless `uncgi` armed |
| T-F-003 | planner | random rename graphs incl. swap cycles, self-maps, case-fold knots | INV-4, cycle completion, no partial batches without journal |
| T-F-004 | TOML config | schema mutations | exit 3 with line:col, never accepted silently |

Fuzz execution notes (2026-11-09): `examples/fuzz_extract.rs` (in-tree, `cargo run --release --example fuzz_extract [rounds]`) covers T-F-001/T-F-002/T-F-003-class input against the real `extract()`/`undo()` code paths — byte soup, template mutation, filename/header soup (RFC 2047/2231/traversal/charset cases), mbox envelope soup, journal-content soup, and malicious-name catalog injection (Kuhn UTF-8 stress categories, BLNS-derived strings, fuzzdb traversal patterns, CRLF/2231-smuggling cases). 300,000 rounds: 0 panics, 0 path escapes. Bugs found by inspection alongside the harness and regression-pinned: mbox envelope slicing past end on short inputs (`tiny_mbox_no_panic_regress`); unknown-charset note not propagated through the RFC 2047 path.

Differential fuzzing (2026-11-09): `scripts/diff_fuzz.py` (dev-time, stdlib-only) generates structured-random mails, extracts with both detox-rs and Python's `email`, and compares base64/QP payload shas and sanitized name multisets (with detox's basename-reduction and UNQ semantics replicated on the reference side). Mutated mails are exercised for crash-freedom only; any single-byte flip can change parser tolerance arbitrarily. Bugs found & fixed: drive-letter drop in `basename_reduce` ate `e:mail.pdf`-style names (`colon_prefix_is_not_a_drive_letter_regress`); QP decoder diverged from the ecosystem reference on invalid escapes — now a byte-for-byte port of CPython 3.14 `binascii.a2b_qp(header=False)` (`qp_invalid_escape_passthrough_regress`); `us-ascii` charset shared the latin-1 mapping for high bytes instead of lossy U+FFFD + note (`us_ascii_high_bytes_are_lossy_regress`). Unknown-charset encoded-words are compared only for crash-freedom (divergent by design: detox lossy-fallback per EXTRACT.md §4, Python keeps raw).

Corpus: SPEC/T-GV vectors + real-world nasty names (conFails, emoji, bidi, Mac NFD exports) committed to repo; nightly runs 30 min/target with corpus growth tracked.

## 6. Fallacy coverage (every SPEC §13 row has ≥1 test)

| Defect | Tests |
|---|---|
| COL-1, COL-2, COL-3 | T-GV-003/004, T-GV-028, E3/E4 matrix |
| UNQ-1 | T-GV-010, T-GV-027 |
| LEN-1 | T-GV-014/015/026 |
| TRL-1/2/3 | T-GV-006/020, T-F-001 |
| UX-1 | T-P-005, T-GV-030 |
| UX-2 | CLI flag tests + hidden-count assertion in summary line |
| UX-3 | T-F-004, CONFIG schema tests |
| UX-4/5 | NDJSON schema validation on every CLI test; exit-code table test |
| RAC-1 | T-C-001 |
| DIS-1 | E5 acceptance = full golden set in scratch container |
| MIME-1 | T-F-002, T-GV-007/008/009 |
| MIME-2 | `ascii` profile vectors |
| MIME-3 | T-F-001 length propagation cases |
| MIME-4 | phase-2 content-hash fixtures (EXTRACT.md §7) |
| INV-3 / robustness | T-GV-032/033 (dots family, emptiness guard) |
| RAC-1 / crash | T-C-002 (kill -9 mid-apply, journal recovery) |

## 7. Performance smoke (informational, regression-catching only)

100k-file tree on E1: plan < 30 s, `--apply` < 60 s, undo < 60 s. Failure blocks release until triaged — it exists to catch accidental O(n²), not to chase benchmarks.
