# CLI reference (companion to SPEC.md — normative core: `SPEC.md`)

Conventions: flags are long-form `--flag value`. An env-var fallback `DETOX_<NAME>` exists exactly where the table's Env column names one; CLI arguments override env. `--no-<flag>` negates booleans, except pure markers (`--apply`, `--dry-run`), which have no `--no-` form. `-h` is exhaustive; this document is the contract.

## Commands

| Invocation | Behavior |
|---|---|
| `detox-rs [check] [OPTIONS] PATH...` | Plan + report only. **Default; never touches disk.** Exit 0 with an empty plan is success. |
| `detox run PATH...` / `detox-rs --apply PATH...` | Identical: execute the plan. `run` exists for muscle memory. |
| `detox-rs undo [--last \| --run ID]` | Revert a committed run, reverse order, dev+inode verified (SPEC §5.3). Without a journal hit: exit 2, nothing changed. |
| `detox seq list [-v]` | `-v`: stages + effective options per sequence. `--format json` supported. |
| `detox-rs extract ...` | Phase 2 — see `EXTRACT.md`. |
| `detox-rs --init` | Print the default TOML config to stdout; `--init --write` installs it at `$XDG_CONFIG_HOME/detox/config.toml` (never overwrites; exit 2 if present). |

## Flag reference

| Flag | Value (default) | Env | Conflicts | Notes |
|---|---|---|---|---|
| `--apply` | bool (false) | — | `--dry-run` | sole executor of renames; pure marker, no `--no-` form |
| `-n, --dry-run` | marker | — | `--apply` | explicit no-op; the default behavior anyway; pure marker |
| `-r, --recursive` | bool (false) | — | — | dirs: post-order renames |
| `--max-depth` | int (64) | `DETOX_RS_MAX_DEPTH` | — | 0 = unlimited |
| `--hidden` | skip\|include\|only (skip) | `DETOX_RS_HIDDEN` | — | applies to recursion only; explicit PATH args always processed |
| `--profile` | clean\|portable\|ascii (clean) | `DETOX_RS_PROFILE` | — | selects builtin profile; sequence may refine |
| `-s, --sequence` | name (config `default_sequence`) | `DETOX_RS_SEQUENCE` | — | |
| `-f, --config` | path | `DETOX_RS_CONFIG` | `--local-config` | skips discovery |
| `--local-config` | bool (false) | — | `-f` | honor `./.detox.toml` at walk root |
| `--include` / `--exclude` | glob, repeatable | — | — | last matching pattern wins; include ⊄ exclude |
| `--ci` | auto\|on\|off (auto) | — | — | forces ci-fs semantics (SPEC §3.2) |
| `--special` | bool (false) | — | — | sockets/FIFOs/devices |
| `--follow-symlinks` | bool (false) | — | — | symlinked dirs never descended regardless |
| `--xdev` | bool (false) | — | — | cross mount points |
| `--case` | lower\|upper\|preserve (per profile) | — | — | CAS override |
| `--max-length` | int (0 = fs cap) | — | — | hard byte cap (SPEC §5.7) |
| `--ascii` | bool (false) | — | `--profile` | shorthand `--profile ascii` |
| `--unique-style` | prefix\|infix\|postfix (infix) | — | — | UNQ placement |
| `--on-collision` | uniquify\|skip\|error (uniquify) | — | — | |
| `--best-effort` | bool (false) | — | — | apply valid subset of a failing plan |
| `--dedupe-hardlinks` | bool (false) | — | — | content-collapse (SPEC §5.9) |
| `--journal-dir` | path | `DETOX_RS_JOURNAL_DIR` | — | overrides state-dir discovery (sudo case) |
| `-0, --null` | bool (false) | — | — | NUL-delimited PATHs from stdin/args, NDJSON unaffected |
| `--format` | human\|json (human) | `DETOX_RS_FORMAT` | — | |
| `--strings` | bool (false) | — | `-r`, `--apply`, walk flags | pure name mapping, no fs probes (below) |
| `-v, --verbose` / `-q, --quiet` | bool | — | each other | `-q` suppresses human output only |
| `--color` | auto\|always\|never (auto) | `NO_COLOR` honored | — | human format only |
| `-h, --help` / `-V, --version` | — | — | — | |

## Output

### Human (default, TTY)

```
plan   'My Report (final).docx' -> 'My_Report_final.docx'   (san, cln)
skip   '.git'                                                 (hidden)
summary: 12 planned, 1 unchanged, 1 skipped, 0 errors
hint: re-run with --apply to execute
```

Columns: action · quoted old → new · parenthesized stage reasons. Under `--apply`, actions read `rename`/`error` and the hint line is omitted. `--color=auto` colors old (red) / new (green) / errors only. `NO_COLOR` or non-TTY → plain.

### NDJSON (`--format json`)

One object per line, all streams (plan/commit/undo/extract). Schema:

```json
{"run":"9f3c…","seq":17,"action":"plan|rename|undo|skip|unchanged|warning|error","old":"My Report (final).docx","new":"My_Report_final.docx","reason":"san:()→_; cln:collapse","stage":"cln","profile":"clean","src":"walk"}
```

| Field | Type | Presence |
|---|---|---|
| `run` | uuid | all lines of one invocation share it |
| `seq` | int | per-line ordering, gapless from 0 |
| `action` | enum | see values above |
| `old`, `new` | string | `new` absent on `unchanged`/`error` |
| `reason` | string | stage attribution; free text on `error` (includes errno) |
| `stage` | string\|null | pipeline stage that produced the change |
| `profile`, `src` | string | `src` ∈ cli\|walk\|stdin\|mime |

Guarantees: valid NDJSON even under `-q` and non-UTF-8 input names (JSON-escaped, INV-7); final line is always `{"action":"summary", ...}` with counts and exit-relevant tallies.

### Exit codes

`0` — plan empty or all applied/undone cleanly · `1` — warnings: uniquified, policy-`skip` skips, advisories · `2` — failures: permission, journal write, undo conflict, or any collision under `--on-collision error` · `3` — usage/config error, including a `--sequence`/`DETOX_RS_SEQUENCE` reference to a nonexistent sequence. `check` and `run` share the code space; `--format json` consumers should rely on `action:"error"` lines plus the code's class (0/1 vs 2 vs 3), not exact tallies.

## `--strings` protocol

stdin: newline-delimited names (`-0` for NUL). stdout: one `old\tnew` per line (human) or the NDJSON schema with `src:"stdin"` (fs-independent: no `NAME_MAX` probe — LEN cap defaults to 255 bytes; UNQ simulated in input order). Nothing on disk is touched; exit 1 if any name would change, else 0 — the dirty count appears only in the summary line, never in the exit code. Use case: `git ls-files -z | detox-rs --strings -0` preview.

## Shell completion

Static completions for bash/zsh/fish generated at build time from this table (`detox-rs --completions <shell>`); no runtime files installed (SPEC §3.4).
