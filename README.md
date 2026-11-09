# detox-rs

**Filename remediation and MIME attachment extraction — a from-scratch successor to [detox](https://github.com/dharple/detox), informed by the filename-handling failures of [ripMIME](https://github.com/inflex/ripmime).**

Clean names, never lose data: no overwrites ever (renameat2 `RENAME_NOREPLACE`), every rename journaled and undoable, output provably confined to the target directory, dry-run first-class, machine-readable output throughout.

## Why

`detox` (BSD-licensed, maintained 2004–2025) cleans filenames but is a C codebase with static translation tables, no undo, silent dotfile skipping, and a custom config syntax. `ripMIME` extracts attachments but double-encodes UTF-8 names and trusts header bytes into paths. detox-rs rethinks both from first principles: one sanitization core, two entry points, every normative behavior written down and testable ([SPEC.md](SPEC.md)).

## Features

**Rename mode** — sanitize names already on disk:

- Pipeline: normalize → transliterate (NFKD-based) → case-fold → charset-restrict → collapse/strip → length-cap (filesystem-aware) → collision-resolve, per profile (`clean` default, `portable` for FAT/NTFS interop, `ascii`).
- `detox-rs check` plans and reports without touching anything (exit 0/1/2); `--apply` commits; `undo` reverts the last run via the journal.
- NDJSON output for scripting; hidden-file skips counted and listed; case-insensitive-filesystem aware.

**Extract mode** — ripMIME's job, done correctly:

- RFC 2231 continuations/charsets and RFC 2047 encoded-words decoded **exactly once** (the single-decode invariant); built-in charset tables (utf-8, us-ascii, iso-8859-1/2, windows-1250/1252), honest lossy-fallback notes.
- Traversal-proof by construction: names are reduced to basenames, sanitized, and emitted under the output directory with `create_new` — a filename can never escape.
- mbox support, nested `message/rfc822` (depth-capped), hard links for multi-filename parts, per-part sha256 in the report.
- Every extracted file journaled; `undo` removes the batch.

**Distribution** — one static-pie musl binary (≈950 KB), no runtime dependencies, runs in `scratch`/`alpine` containers and rescue shells. Linux release builds go through `dist/build.sh` (v0.2.5: no forced default target; `crt-static` pinned per musl target — native macOS/Windows builds stay native).

## Quickstart

```sh
# see what would change (exit 1 = changes pending, 0 = clean, 2 = errors)
detox-rs check -r ~/Downloads

# commit, then change your mind
detox-rs --apply -r ~/Downloads
detox-rs undo

# sanitize a stream of names
printf 'my report (final).PDF\n' | detox-rs --strings

# pull attachments out of a mail with safe names at birth
detox-rs extract -i mail.eml -d ./out
detox-rs undo                    # removes the extracted batch too
```

## Build

```sh
# Linux x86_64 static binary (the primary artifact):
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/detox-rs

# or packaged, for any supported target:
dist/build.sh                                   # host-appropriate default
dist/build.sh aarch64-unknown-linux-musl        # needs aarch64-linux-musl-gcc
```

Cross-platform: the crate compiles for `x86_64/aarch64-unknown-linux-musl`, `x86_64/aarch64-apple-darwin` (lipo them for universal2), and `x86_64-pc-windows-msvc` — `dist/build.sh` and `.github/workflows/release.yml` build all of them; macOS gets an atomic no-replace rename (`renamex_np`) and Windows gets a real volume+file-index identity for undo checks. Release binaries attach to GitHub tags.

Three small crates (`libc`, `unicode-normalization`, `unicode-general-category`) are statically linked in; there are no runtime dependencies. `Cargo.lock` is committed and the build is reproducible (verified bit-for-bit from a clean tree). Do not export `RUSTFLAGS` — an env override silently replaces the per-target `+crt-static` pinning in `.cargo/config.toml` (and the static asserts in `dist/build.sh` will catch a regressed artifact).

## Testing

83 tests across 8 suites: golden vectors and filesystem-matrix integration (ext4/tmpfs/vfat), a malformed-input catalog (UTF-8 attacks, naughty strings, traversal, CRLF injection, RFC 2231 smuggling), property tests, and two fuzz harnesses — an invariant fuzzer (`examples/fuzz_extract.rs`, std-only, runs in CI at 3k rounds) and a differential fuzzer against Python's `email` (`scripts/diff_fuzz.py`, dev-time). See [docs/TESTPLAN.md](docs/TESTPLAN.md).

## Documentation

| File | Contents |
|---|---|
| [SPEC.md](SPEC.md) | Normative functional spec: principles, pipeline, invariants, golden vectors |
| [docs/CLI.md](docs/CLI.md) | Flag reference, exit codes, output formats |
| [docs/EXTRACT.md](docs/EXTRACT.md) | Extract-mode contract: decode order, security requirements, test vectors |
| [docs/TESTPLAN.md](docs/TESTPLAN.md) | How every spec row is verified |
| [docs/CONFIG.md](docs/CONFIG.md) | Profiles and sequences (TOML) |
| [PROJECT_LOG.md](PROJECT_LOG.md) | Construction and review history |

## Status

0.1.0 — the spec is implemented end-to-end and independently reviewed; the surface may still evolve.

## License

BSD-3-Clause, matching upstream detox. Clean-room rewrite: no code is shared with either upstream project. See [LICENSE](LICENSE).
