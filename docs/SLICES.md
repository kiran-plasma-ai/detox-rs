# Slices — construction log

One slice = one versioned contract, one reviewable unit. Specs in SPEC.md + docs/ stay normative; slices implement them.

## Slice 1 — pipeline core (`clean`) + `--strings`

Contract version: **1 (frozen 2026-11-09)**

- **Goal:** `sanitize(name, clean) -> Outcome` implementing SPEC §3.1 stages NRM→SAN→CLN; `detox --strings` per CLI.md (stdin name mapping, nothing on disk).
- **Tradeoffs:** may improve: nothing yet. Must not regress: SPEC §10 INV-1 (idempotency), INV-3 (charset/leading/trailing), INV-7 (valid UTF-8 out).
- **Interface:**
  - lib: `pub enum Profile { Clean }` (Portable/Ascii reserved, slice 3); `pub struct Outcome { name: String, stages: Vec<&'static str> }`; `pub fn sanitize(input: &[u8], profile: Profile) -> Outcome` (raw bytes in — SPEC NRM lossy-decode).
  - bin: `detox --strings [--format human|json] [-0]`; unknown flags → exit 3. NDJSON per CLI.md schema (`action:"plan"`, `src:"stdin"`, final `summary` line); human = `old\tnew`.
- **Invariants:** empty output unreachable (→ `_`); all-dots names reduce to `_` (CLN trailing-dot strip + emptiness guard, SPEC §5.5); NUL → `_hidden_null_`; exit 1 if any name dirty else 0.
- **Versions:** rustc 1.96.0; single dep `unicode-normalization`.
- **Acceptance:** `cargo test` green (golden vectors S1-01…S1-13 + double-apply idempotency corpus in tests/golden.rs); mutation check (flip one SAN mapping → red); `cargo clippy -- -D warnings`; `cargo build --release` produces `target/release/detox`.
- **Non-goals:** filesystem walk, plan/commit, journal, undo, LEN/UNQ/TRL/DEC/CAS stages, `portable`/`ascii`, config files, full CLI, extract phase 2.
- **Unknowns:** none.
- **Rollout:** none (no deployed system).
- **Outcome (2026-11-09): accepted.** Gates green: 5 tests, clippy `-D warnings`, release build. Mutation check red→green. Independent review: 7 findings applied (interior empty lines, uuid run id, streaming stdin, BrokenPipe exit 0, reason detail shape, SPEC punct-vector + delta-citation + dots wording fixes). Spec deltas during construction: v0.2.2 SAN removal set; dots special case deleted (INV-1). Next slice: 2 = LEN + UNQ stages (pure), then 3 = profiles portable/ascii + TRL/CAS.
- **Shortcut:** `sanitize` charset uses `is_alphabetic() || is_numeric()` as a stand-in for `\p{L}\p{M}\p{N}` — ceiling: a vector requiring exact general categories (e.g. a mark that is not `Other_Alphabetic`); upgrade: switch to a UCD-backed category check when that vector lands.

## Slice 2 — LEN + UNQ stages, exact charset classification

Contract version: **1 (frozen 2026-11-09)**

- **Goal:** add LEN (SPEC §5.7) and UNQ (§5.8) to the pipeline; replace the slice-1 charset shortcut with exact UCD general categories (user directive: "charset handling extremely robust").
- **Tradeoffs:** may improve: classification exactness; must not regress: slice-1 vectors, INV-1/3/7.
- **Interface:**
  - `pub struct Options { pub max_bytes: usize }` (Default 255 — strings-mode default per CLI.md).
  - `pub fn sanitize(input: &[u8], opts: &Options) -> Outcome` — NRM→SAN→CLN→LEN. (Replaces slice-1 `sanitize(input, Profile)`; callers updated.)
  - `pub struct Uniquifier { ... }` with `new(style: UniqueStyle, max_bytes: usize)` and `apply(&mut self, name: String) -> Result<(String, bool), UniquifyError>` — per-invocation collision domain, deterministic input order, streaming-safe (SPEC §5.8). Styles `Infix` (default, `report_1.pdf`) / `Prefix` / `Postfix`.
  - LEN rule (frozen): extension = from last `.` of the **original** post-CLN name; stem cut on char boundary to `cap − ext.len()`; extension dropped only if it alone ≥ cap (then plain char-boundary cut of the whole name). Hard invariant: output byte length ≤ `max_bytes` for cap ≥ 1 (cap 0 degenerates to `_` per SPEC §5.5), always valid UTF-8, never panics.
- **Invariants:** INV-1 extended: uniquified batch re-applied unchanged (distinct outputs are fixed points); LEN never exceeds cap even with UNQ suffix (suffix forces further stem cut); charset = exact `\p{L}|\p{M}|\p{N}` via `unicode-general-category` (U+20D0 combining mark kept — the discriminating test).
- **Versions:** rustc 1.96.0; deps `unicode-normalization 0.1`, `unicode-general-category 1.1`.
- **Acceptance:** `cargo test` green (slice-1 vectors + S2 vectors: U+20D0 kept, 254/255/256/257-byte caps incl. multibyte boundary, `report.pdf`×2 → `report_1.pdf`, 100-identical batch, prefix/postfix, idempotency post-UNQ, LCG fuzz no-panic + boundary validity); clippy `-D warnings`; mutation check; release build; independent review.
- **Non-goals:** ci-fs folding, on-disk collision checks, `--on-collision skip|error` CLI wiring (lib supports Skip/Error via `apply` contract but CLI defaults to uniquify), DEC/TRL/CAS, other profiles, config files.
- **Unknowns:** none.
- **Outcome (2026-11-09): accepted.** Gates green: 19 tests, clippy `-D warnings`, release build; mutation check red→green. Fuzz caught 3 real bugs pre-review: UNQ infinite loop (truncation destroyed counter → tag-preserving redesign), LEN trailing-dot outputs (→ re-finish with CLN rules), removal-joins-composable-pairs (→ final NFC pass). Independent review: no P0–P2; 4 P3 applied (dead `Profile` enum deleted, `--max-length 0` = default per SPEC §4, SLICES contract wording, doc comment). Next: slice 3 = `portable`/`ascii` profiles + TRL (NFKD transliteration) + CAS (case fold).

## Slice 3 — profiles `portable`/`ascii`, TRL, CAS

Contract version: **1 (frozen 2026-11-09)**

- **Goal:** `Profile::{Portable, Ascii}` (SPEC §3.3) with TRL stage (§7) and CAS stage (§5/§3.1); CLI `--profile`, `--ascii`, `--case`.
- **Tradeoffs:** may improve: transliteration coverage; must not regress: slices 1–2 behavior (`clean` default), INV-1/3/7.
- **Interface:**
  - `pub enum Profile { Clean, Portable, Ascii }`; `pub enum CaseMode { Preserve, Lower, Upper }`.
  - `pub struct Options { pub profile: Profile, pub case: CaseMode, pub max_bytes: usize }` (Default = Clean/Preserve/255).
  - Pipeline order frozen: NRM → TRL(portable/ascii) → CAS(case≠preserve) → SAN → CLN → LEN → final NFC. UNQ unchanged.
  - CLI: `--profile clean|portable|ascii`, `--ascii` (shorthand, conflicts `--profile` → exit 3), `--case lower|upper|preserve`.
- **Invariants:** portable/ascii output matches `^[A-Za-z0-9._-]+$` (INV-8 core, T-P-003 oracle); reserved-name escape (CON/PRN/AUX/NUL/COM1–9/LPT1–9, case-insensitive stem before first `.`) prefixes `_`, portable/ascii only; idempotency incl. oscillation check (`_CON.txt` → CLN strips → `CON.txt` → escape → `_CON.txt` fixed point).
- **TRL rule (frozen):** per char — ASCII passes through untouched; builtin table first (Latin-1 Supplement + common Latin Extended-A, both cases ≈40 entries); else NFKD: ASCII alnum + `._-` kept, marks (`Mn|Mc|Me`) dropped, table re-lookup for non-ASCII decomposed chars, else `_`. No locale digraphs this slice (non-goal; `de` table lands with config).
- **CAS rule (frozen):** std `to_lowercase`/`to_uppercase` char mapping (full Unicode case mapping; not full case *folding* — ß stays ß under Lower; known divergence, accepted).
- **Versions:** rustc 1.96.0; deps unchanged.
- **Acceptance:** `cargo test` green (slices 1–2 suites + S3 vectors: SPEC §9 rows 4 (`Ä.TXT --case lower` → `ä.txt`), 6 (`ﬁle①.txt --profile ascii` → `file1.txt`), 12 (`CON.txt` portable → `_CON.txt`); TRL cases `résumé→resume`, `ß→ss`, `½→1_2`, `日本語→___`; reserved set; portable fuzz with charset regex + idempotency across all profiles); clippy; mutation; release; independent review.
- **Non-goals:** locale digraph tables, deunicode-class romanization for non-decomposing scripts (CJK/Hangul → `_` — shortcut with ceiling, see below), DEC stage, config files.
- **Shortcut:** TRL covers decomposition + builtin table only; ceiling: users needing romanization of CJK/Korean (e.g. via `deunicode`); upgrade trigger: a golden vector or real-world report demanding it.
- **Outcome (2026-11-09): accepted.** Gates green: 24 tests (fuzz now ×3 profiles, 2000 rounds), clippy `-D warnings`, release build; mutation check red→green (added `µs Łódź` vector after first mutation proved invisible — oracle gap fixed). Independent review: 2×P2 applied — reserved-escape moved after LEN with cap-aware cut (`CONX` cap 3 → `_CO`; tight-cap INV-1 exception documented in SPEC v0.2.3: converges after ≤2 runs), NDJSON `profile` field now reflects actual profile. Next: slice 4 = DEC stage (uncgi; RFC 2047/2231 stay extract-phase) or fs walk/plan/journal — walk is the critical path to a usable tool.

## Slice 4 — fs walk, plan/commit, journal, undo

Contract version: **1 (frozen 2026-11-09)**

- **Goal:** rename files on disk safely: `detox [check] PATH...` (plan, default) / `detox --apply` / `detox run`; `detox undo --last|--run ID`. SPEC §5.1–5.3, §5.9.
- **Tradeoffs:** may improve: correctness under collision/cycles; must not regress: strings mode, pipeline behavior, never-lose-data.
- **Interface (src/fs.rs):**
  - `pub struct WalkOptions { pub recursive: bool, pub hidden: HiddenMode, pub special: bool, pub max_depth: usize }`; `pub enum HiddenMode { Skip, Include, Only }` (Default: Skip, max_depth 64).
  - `pub fn walk(paths: &[PathBuf], w: &WalkOptions) -> Result<Vec<PathBuf>, String>` — files before dirs, dirs post-order; explicit args always processed; symlinks never followed; special files skipped unless `special`.
  - `pub fn plan(entries: &[PathBuf], opts: &Options) -> Plan` — `Plan { items: Vec<PlanItem{old,new,stages}>, unchanged: usize, skipped: Vec<(PathBuf,String)> }`; per-dir on-disk collision resolution via `Uniquifier` (plan-time `lstat`); targets occupied by other batch members are left for commit-time ordering, not uniquified.
  - `pub fn commit(plan: &Plan, journal_dir: &Path) -> Result<CommitReport, CommitError>` — journal write+fsync BEFORE first rename (SPEC §5.3); renames via `renameat2(RENAME_NOREPLACE)` (libc, Linux; fallback `lstat`+`rename` on ENOSYS); batch-internal dependency cycles broken by journaled temp names; commit-time true collision → error line, continue, exit class 2.
  - `pub fn undo(run: UndoSel, journal_dir: &Path) -> Result<UndoReport, UndoError>` — reverse order; restore only when `new` exists and dev+inode match journal; else skip+warn (exit 1 class); never recreates deleted parent dirs.
  - Journal: `$XDG_STATE_HOME/detox/journal/<unixts>-<runid>.jsonl`, override `--journal-dir`/`DETOX_JOURNAL_DIR`; lines `{"run","old","new","dev","ino}` (+`"tmp":true` steps); minimal hand-rolled JSON escape/unescape (writer/reader are inverse, tested round-trip).
- **Invariants:** INV-2 (no overwrite: NOREPLACE + plan-time resolution), INV-4 (injective per batch), journal-before-rename (crash recovery per SPEC failure taxonomy), post-order dir commits.
- **Shortcuts (with ceilings):** ci-fs treated as case-sensitive (ceiling: APFS/NTFS semantics differ; upgrade: per-dir probe, slice 5); journal retention pruning deferred (config slice); `-r` dotfile default skip silently counts (report only).
- **Versions:** rustc 1.96.0; new dep `libc = "0.2"` (renameat2, unix metadata).
- **Acceptance:** `cargo test` green (slices 1–3 + tests/fs.rs: apply+undo round-trip, a↔b swap, on-disk collision uniquify, post-order dir rename, hidden policy, no-clobber of foreign target, read-only-dir abort w/o journal, undo missing-new skip, journal JSON round-trip, exit-class mapping); clippy; mutation; release; independent review.
- **Non-goals:** ci probing, TOML config, `--include/--exclude` globs, `--xdev` mount-boundary checks, `--best-effort` partial apply, extract/DEC.
- **Outcome (2026-11-09): accepted.** Gates green: 42 tests (7 lib + 11 fs-lib + 5 CLI + 19 golden), clippy `-D warnings`, release build; mutation checks red→green (chain reversal + earlier oracle-gap fix). Construction caught: plan double-counting unchanged batch members as free targets (two-pass pending set), cycle undo mis-ordering (restructured to precomputed execution schedule — journaled sequence == executed sequence, undo = pure reverse replay), tmp dev/ino resolution via inode-inheritance map, invalid chain test (target occupied). Independent review (9 findings): `check` subcommand arm, walk dedupe for overlapping roots, symlink_metadata for dev/ino + restore, apply-mode abort on plan.skipped (SPEC §5.1), tmp names carry run id + lstat-checked, exact run-id journal match, walk skip reporting, lexical per-dir keys, typed SkipReason with SPEC-aligned exit classes (conflict=2, missing=1), CLI-level test suite added. Next: slice 5 = ci-fs probing (--ci auto) or TOML config or DEC/uncgi — ci probing closes the last correctness gap on case-insensitive filesystems.

## Slice 5 — static musl distribution (user directive: "simple binary without external deps")

Contract version: **1 (frozen 2026-11-09)**

- **Goal:** `cargo build --release` produces a zero-runtime-dependency binary (SPEC §3.4).
- **Change:** `.cargo/config.toml` defaults workspace to `x86_64-unknown-linux-musl` + `+crt-static`; `renameat2` libc wrapper replaced by raw `syscall(SYS_renameat2)` (the libc symbol is gated to glibc — musl links fail otherwise); `RENAME_NOREPLACE = 1` defined locally (linux/fs.h).
- **Acceptance:** `file` reports "static-pie linked, statically linked"; `ldd` → "not a dynamic executable"; full test suite green on the musl target; copied binary runs from an unrelated directory.
- **Outcome (2026-11-09): accepted.** 848 KiB static-pie; 6/6 suites green on musl; drop-anywhere smoke passed. Next: slice 6 = `detox extract` phase-2 core (user asked about ripMIME drop-in replacement — decode half is the missing piece; filenames already solved by the pipeline).

## Slice 6 — `detox-rs extract` (ripMIME replacement core)

Contract version: **1 (frozen 2026-11-09)** · binary renamed `detox-rs` before this slice (user ruling; env prefix `DETOX_RS_*`).

- **Goal:** `detox-rs extract -i FILE|- -d DIR` decodes MIME attachments with pipeline-clean names at birth (SPEC §8, EXTRACT.md §§1–7). This is the slice that makes the ripMIME/mutt drop-in real.
- **Tradeoffs:** may improve: decode coverage; must not regress: rename behavior, static binary, no-clobber.
- **Interface:**
  - `pub fn extract(input: &[u8], opts: &ExtractOptions) -> Result<Vec<Extracted>, ExtractError>` in `src/extract.rs`.
  - `ExtractOptions { out_dir, profile, case, max_bytes, prefix: "text", name_by_type, no_nameless, unique_style, overwrite, headers_file: Option, mailbox, recursion_max: 20, parts_max: 10_000 }` (defaults per EXTRACT.md).
  - CLI: `detox-rs extract -i FILE|- -d DIR [--profile P] [--case C] [--max-length N] [-p PREFIX] [--name-by-type] [--no-nameless] [--unique-style S] [--overwrite --overwrite] [-e FILE] [--mailbox] [--recursion-max N] [--format human|json] [--journal-dir D]`.
- **Invariants:** MIME-1 single-decode (valid UTF-8 stops the chain); every emitted path provably under DIR (absolute paths, `..`, drive letters, backslashes reduced to basenames BEFORE the pipeline); byte-exact decoded content; no-clobber (`create_new` + UNQ, `--overwrite` double-armed); nameless parts `<prefix><n?>.<ext-from-content-type>`; duplicate part names uniquified in part order (T-EX-005).
- **Filename resolution (frozen order, EXTRACT.md §3):** source precedence RFC 6266 (`filename*=`/`filename*0*=` > `filename=` > `name=`) → RFC 2231 reassembly (percent-decode once) → RFC 2047 encoded-words (adjacent runs joined) → charset decode to UTF-8 (utf-8/us-ascii/iso-8859-1/cp1252 built in) → basename reduction → `sanitize()` + UNQ. Charset coverage beyond those four → lossy fallback, recorded in `Extracted.note`.
- **Decoders this slice:** base64, quoted-printable, 7bit/8bit/binary (identity), `message/rfc822` recursion (cap 20), mbox splitting (`--mailbox`, `\nFrom ` boundaries), nested multiparts (cap 10k parts). **Non-goals:** uuencode, TNEF, OLE, MHT (slice 7); content beyond MIME (no zip etc.).
- **Journal:** extraction appends `{"run","new":path,"dev","ino,"create":true}` lines (reusing the journal dir); `undo` deletes created files whose dev+ino match (EXTRACT.md: undo removes emitted files). Crash window documented: files created before their journal line are orphaned (single fsync at batch end — noted, accepted for slice 6).
- **Reporting:** per part NDJSON `{action:"extract", file, content_type, size, decoded_from, name_source}` + summary; human: one line per part.
- **Versions:** rustc 1.96.0 musl; no new deps.
- **Acceptance:** tests/extract.rs green — T-EX-001…T-EX-012 equivalents (encoded-word once-only, 2231 continuations, ISO-8859-1 2047 word, traversal `../..\\evil` + `C:\Windows\x`, duplicate names, nameless jpeg (`text.jpeg` / `image_jpeg` / `-p doc` variants), binary NUL content sha, mbox 2 messages, nested rfc822 recursion cap, byte-exact base64/QP fixtures); existing 6 suites stay green; clippy; mutation; release static.
- **Outcome (2026-11-09): accepted.** 7/7 suites (57 tests), clippy `-D warnings`, static-pie release; mutation check red→green (2047 decode disabled). Binary renamed `detox-rs` before this slice (env prefix `DETOX_RS_*`, SPEC v0.2.4). Independent review: 13 findings all applied — the load-bearing ones: write path hardened against planted-symlink escape (`create_new` + symlink ⇒ occupied), parts cap enforced inside the parser per message, recursion cap surfaces as partial-batch exit 1, mid-batch errors still journal orphans, Uniquifier seeded with existing DIR names (re-extract UNQs instead of aborting), boundary matching validated at line start (prefix/mid-line false positives), EXT-6 hard links for extra filename params, `Extracted.note` for unknown charsets, summary line guaranteed, RFC 2047 adjacent-word whitespace skip, mbox envelope heuristic. Next: slice 7 = uuencode/TNEF/OLE/MHT decoders + `--formdata`, or DEC wiring into the rename pipeline (`-s mime` for `--strings`).
