# Configuration reference (companion to SPEC.md §6)

Format: TOML, strict — unknown keys or wrong types are config errors (exit 3), never silently ignored. The parser must reject a file with a line:col message; `--config` failures are fatal, discovered-file failures fall back to the next source with a warning.

## Discovery order (first hit wins, except `./.detox.toml` needs `--local-config`)

1. `--config PATH`
2. `./.detox.toml` (walk root only; off by default so untrusted trees can't reconfigure runs)
3. `$XDG_CONFIG_HOME/detox/config.toml` (else `~/.config/detox/config.toml`)
4. Embedded defaults (equivalent to `default_profile = "clean"` + builtin sequences below)

No `/etc/detoxrc` and no merging of system+user files: one file, fully specified. detox's two-file inheritance is retired (UX-3).

## Top level

```toml
default_profile = "clean"     # builtin or [profiles.*] name
default_sequence = "clean"    # builtin or [sequences.*] name; DETOX_RS_SEQUENCE env overrides

[journal]
retention_days = 30           # pruning (SPEC §5.3)
```

## Builtin sequences (embedded, exact definitions)

```toml
[sequences.clean]
profile = "clean"
stages = ["nrm", "san", "cln", "len", "unq"]

[sequences.portable]
profile = "portable"
stages = ["nrm", "dec", "trl", "san", "cln", "len", "unq"]

[sequences.ascii]
profile = "ascii"
stages = ["nrm", "dec", "trl", "san", "cln", "len", "unq"]

[sequences.uncgi]            # detox's uncgi sequence, modernized
profile = "clean"
stages = ["nrm", "dec", "san", "cln", "len", "unq"]
[sequences.uncgi.stage.dec]
uncgi = true

[sequences.mime]             # decode-enabled (RFC 2047/2231); SPEC §9 vectors 7–9
profile = "clean"
stages = ["nrm", "dec", "san", "cln", "len", "unq"]
[sequences.mime.stage.dec]
rfc2047 = true
rfc2231 = true
```

## Stage options

Precedence: CLI flag > sequence's `[sequences.NAME.stage.X]` > global `[stage.X]` > profile builtin > compiled default. CLI `--profile` overrides the base profile a sequence names; the sequence's stage deltas still apply.

| Stage | Option | Type (default) | Meaning |
|---|---|---|---|
| nrm | `form` | "NFC" | normalization form; "none" disables |
| dec | `uncgi` | bool (false) | %-decode + `+`→space |
| dec | `rfc2047` | bool (false) | encoded-word decode (extract phase default true) |
| dec | `rfc2231` | bool (false) | `filename*=` + continuations (extract phase default true) |
| chr | `from` | string\|null | force source charset (else declared only) |
| trl | `table` | "builtin" | translation table name (below) |
| trl | `locale` | string\|null | digraph table, e.g. "de" |
| trl | `fallback` | "_" (string) | unmappable char replacement |
| cas | `case` | "preserve" | lower\|upper\|preserve |
| san | `escape_reserved` | bool (profile) | Windows reserved-name escaping; `portable`/`ascii` default true, `clean` false (user ruling 2026-11-09) |
| cln | `collapse` | "dash" | run collapse; dash takes precedence over underscore (detox semantics) |
| cln | `remove_trailing` | bool (true) | strip trailing `. _ -` |
| cln | `strip_leading` | bool (true) | strip leading `# _ -` |
| len | `max` | int (0) | extra cap; 0/absent = fs probed limit |
| unq | `style` | "infix" | prefix\|infix\|postfix |
| unq | `on_collision` | "uniquify" | uniquify\|skip\|error |
| unq | `sep` | "_" | counter separator |

## User sequences and profiles

```toml
[profiles.mine]              # inherits a builtin, overrides stages
base = "clean"
[profiles.mine.stage.san]
escape_reserved = true

[sequences.photos]
profile = "mine"
[sequences.photos.stage.cas]
case = "lower"
```

`base` is required for user profiles. A sequence names a profile and stage deltas only — it cannot introduce new stage logic (sequences are data, SPEC §6). Referencing a nonexistent sequence (config, CLI, or `DETOX_RS_SEQUENCE`) is a config error: exit 3 at startup, before any walk.

## Translation tables

Builtin: `safe`, `unicode`, `cp1252`, `latin1` (embedded). User tables: `$XDG_DATA_HOME/detox/tables/<name>.toml` or `tables_dir` in config.

```toml
name = "german"
default = "_"

[map]                        # keys: decimal Unicode codepoints
 223 = "ss"                  # ß
 228 = "ae"                  # ä
 8364 = "EUR"                # €

[locale.de]                  # optional per-locale overrides of [map]
 223 = "sz"
```

Rules: values must be valid UTF-8 strings (1+ chars, ≤8 chars — longer is a config error, prevents table-as-codebase drift); `default` applied when no map entry matches; NFKD/compat maps (SPEC §7) run after table lookup, so a table entry always wins over algorithmic fallback.

## Environment variables

`DETOX_RS_SEQUENCE`, `DETOX_RS_PROFILE`, `DETOX_RS_CONFIG`, `DETOX_RS_JOURNAL_DIR`, `DETOX_RS_FORMAT`, `DETOX_RS_HIDDEN`, `DETOX_RS_MAX_DEPTH` (see CLI.md table). `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` honored. No other env influence; in particular locale (`LC_*`) never changes filename output — locale affects only human messages.
