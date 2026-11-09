# EXTRACT — MIME attachment extraction, phase 2 (companion to SPEC.md §8)

Gating: ships only when phase-1 conformance (TESTPLAN §1–§6) is 100% green. Same binary, same pipeline, same journal; extraction batches are journaled like rename batches so `detox-rs undo` restores pre-extraction state (files removed, nothing else).

## 1. Inputs and outputs

`-i FILE | -` (stdin), `-d DIR` (must exist, writable). Output layout: flat under DIR — every emitted name is a basename; nesting from MIME is never recreated (SPEC §2, INV-3). `--mailbox` splits mbox; each message is a separate batch with its own journal entry.

## 2. Decoders (each individually disable-able, ripMIME parity)

base64, quoted-printable, uuencode (`begin 644 …`), TNEF/winmail.dat, OLE/CFB document streams, MHT archives, embedded `message/rfc822` recursion. `--recursion-max N` (default 20) caps nesting (ripMIME's DoS guard, kept); additionally a parts-per-message cap (default 10 000) bounds header bombs.

## 3. Filename resolution (normative order — this is the point of the exercise)

For each part, source precedence follows RFC 6266 §4.3: `filename*=` / `filename*0*=` continuations first, then `filename=`, then `Content-Type name=`. Then:

1. **RFC 2231**: reassemble `filename*0*=`… continuations; parse `charset'lang'value`; percent-decode **once**.
2. **RFC 2047**: decode encoded-words (`=?cs?B?…?=`, `=?cs?Q?…?=`), including adjacent-word runs; charset-decode payload to UTF-8. `us-ascii` is strictly 7-bit — bytes ≥ 0x80 decode to U+FFFD and mark the result lossy (matches Python `email` behavior; previously this table shared latin-1's mapping).
3. **Single-decode invariant (MIME-1)**: after steps 1–2, if the string is valid UTF-8, stop decoding. Only if invalid: apply the declared charset from step 1/2. No stage may fire twice; a valid-UTF-8 string is never percent- or charset-decoded again.
4. Pipeline per active profile (`clean` default): NRM → SAN → CLN → LEN → UNQ, UNQ deterministic in part-sequence order.
5. Emit under DIR; traversal defense: absolute paths, `..`, `C:\…`-style device paths, UNC paths, and backslash separators are reduced to basenames *before* step 4 — the pipeline itself never sees a separator (ripMIME's `strrchr` approach, done deliberately). Reduction takes the component after the LAST `/` or `\` only; colons are not separators and no `X:` prefix is stripped (sanitize already maps `:` to `_` — stripping would eat ordinary names like `e:mail.pdf`).

Worked regression (the ripMIME failure): header `filename="=?UTF-8?B?w6ZmaWNlLnBkZg==?="` → step 2 yields `æffice.pdf` (valid UTF-8) → step 3 stops → never re-encoded, never double-mangled. Header `filename*=UTF-8''%C3%A6ffice.pdf` → step 1 yields `æffice.pdf` → stop. A literal name `%C3%A6ffice.pdf` (no 2231 marker) stays literal under `clean` (no `uncgi` in the extract pipeline).

## 4. Flags (ripMIME parity → ours)

| ripMIME | Ours |
|---|---|
| `-i`, `-d`, `-v`, `-q`, `--syslog` | same (`--syslog` mapped to NDJSON `action:"log"`) |
| `--paranoid` | `--profile ascii` |
| `--unique-names [--prefix/--postfix/--infix]` | `--unique-style` (default infix) |
| `--overwrite` | same, double-armed (SPEC §5.2) |
| `-p PREFIX` (nameless), `--name-by-type`, `--no-nameless` | same |
| `--no-multiple-filenames` | same; default = hard link per extra filename param (EXT-6) |
| `-e FILE` header dump | same (default `_headers_`); single-message scope — in `--mailbox` mode only the first message's headers are dumped |
| `--mailbox`, `--formdata` | same |
| `--no-tnef/--no-ole/--no-uudecode/--no-quotedprintable/--no-mht/--no-doublecr`, `--disable-qmail-bounce` | same |
| `--recursion-max` | same (default 20) |
| `--verbose-defects`, `--extended-errors` | `--verbose-defects`; errors always in NDJSON (no opt-in) |
| `--stdout/--stderr` | replaced by `--format human\|json` |

## 5. Reporting

Per part, NDJSON: `{"action":"extract","file":"æffice.pdf","content_type":"application/pdf","size":183220,"source_part":"2.1.3","decoded_from":"base64","name_source":"filename*=","run":"…"}`. Plus `summary` line with counts and a `defects` array when `--verbose-defects`.

## 6. Security requirements

- Every emitted path provably under DIR (asserted, not assumed — canonical parent check).
- No symlinks created; if a part name collides with an existing symlink, UNQ applies (never follows).
- Recursion and parts caps (§2); no decompression beyond MIME encodings (no zip-of-death surface).
- Content is byte-exact decoded data (EXT-8): NUL handling opt-in via `--formdata`; decoded streams hashed (sha256 in NDJSON) so `TESTPLAN` can prove no corruption.
- Disk-full/write-failure mid-batch (ENOSPC, EDQUOT): abort the batch, keep the journal, exit 2; `detox-rs undo` removes the emitted files. Crash-window honesty (sec-review F4): in **rename** mode the journal is written and fsync'd *before* the first rename (SPEC §5.3 holds there). In **extract** mode the journal is written and fsync'd *after* the write loop — a crash mid-extraction can leave emitted files the journal does not reach; `undo` removes everything the journal does reach. That residue is creation-only (never corruption of pre-existing files), but "unjournaled output is unreachable" is **not** claimed for extract mode.

## 7. Test vectors (extract-specific, normative)

| ID | Fixture | Assert |
|---|---|---|
| T-EX-001 | header per §3 worked example | `æffice.pdf`, single-decode instrumentation = 1 pass |
| T-EX-002 | `filename*0*="utf-8''%C3%A6"; filename*1*="%20office.pdf"` (split mid-codepoint? — no: split at char boundary per RFC) | `æ_office.pdf` |
| T-EX-003 | `filename="=?ISO-8859-1?Q?eine_akte_mit_sonderzeichen=E4=F6=FC.txt?="` | `eine_akte_mit_sonderzeichenäöü.txt` → `clean`: `eine_akte_mit_sonderzeichenäöü.txt` (Umlauts kept) |
| T-EX-004 | `filename="../..\\..\\evil.txt"` and `filename="C:\\Windows\\x.dll"` | `evil.txt`, `x.dll` — under DIR, traversal dead |
| T-EX-005 | two parts named `report.pdf` | `report.pdf`, `report_1.pdf` (UNQ) |
| T-EX-006 | TNEF winmail.dat with `Vacation pics.zip` | extracted, name piped through `clean` |
| T-EX-007 | uuencode `begin 644 ev il.txt` | `ev_il.txt` |
| T-EX-008 | nameless `image/jpeg`, default flags | `text.jpeg` — `<prefix><counter>.<ext-from-content-type>`, prefix default `text`; with `--name-by-type` → `image_jpeg`; with `-p doc` → `doc.jpeg` |
| T-EX-009 | binary part containing NULs, no `--formdata` | sha256 matches decoded fixture byte-for-byte (MIME-4) |
| T-EX-010 | one part, two filename params | hard link at second name; `--no-multiple-filenames` → first only |
| T-EX-011 | nested message/rfc822 ×25 | stops at `--recursion-max 20`, partial batch journaled, exit 1 |
| T-EX-012 | MHT archive with percent-encoded name | per §3: decoded once, then `clean` |

Acceptance for phase 2 = T-EX-001…012 green on E1/E2/E3 + T-F-002 nightly green for 30 days.

## Mutt integration (verified 2026-11-09)

Drop-in replacement for the common ripMIME binding (stdin form, `<pipe-message>`):

```
# was:
# macro index,pager S "<enter-command>unset wait_key<enter><pipe-message>ripmime --no-paranoid -i - -d ${DOWNLOADS} ; <enter>" "save all attachments"
macro index,pager S "<enter-command>unset wait_key<enter><pipe-message>detox-rs extract -i - -d ${DOWNLOADS}<enter>" "save all attachments"
```

- `--no-paranoid` has no equivalent: ripMIME's strict 7-bit mangling never existed here; the default `clean` profile keeps UTF-8 names intact (ripMIME's double-encoding bug is gone by design, MIME-1).
- Add `--profile portable` before `-i` if `${DOWNLOADS}` syncs to Windows/FAT targets.
- Extraction is journaled by default (`$XDG_STATE_HOME/detox-rs/journal`), so a fat-fingered extract is reversible: `detox-rs undo --last`.
- Flag parity for other ripMIME bindings: `-i`, `-d`, `-p`, `-e`, `--mailbox`, `--recursion-max` map 1:1 (§4); `--unique-names` styles via `--unique-style prefix|infix|postfix`; `--overwrite` requires two occurrences.
