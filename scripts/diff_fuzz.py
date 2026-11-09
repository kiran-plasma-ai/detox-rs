#!/usr/bin/env python3
"""Differential fuzzer: detox-rs extract vs Python's email module.

Generates structured-random mails, extracts attachments with both, and
compares: payload bytes (sha256 multisets) and sanitized filenames (Python's
decoded name piped through `detox-rs --strings` vs detox-rs's own extract
basename). Divergences land in /tmp/diff-fuzz/NNN/ with mail.eml + both
views for triage.

Dev-time tooling only; not part of the shipped binary or its test gates.
Usage: python3 scripts/diff_fuzz.py [rounds]
"""
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from email import message_from_bytes
from email.header import decode_header, make_header

DETOX = os.environ.get("DETOX_BIN", "/tmp/detox-rs")
CHARSETS = ["utf-8", "iso-8859-1", "iso-8859-2", "windows-1250", "us-ascii"]
WORDS = ["report.pdf", "Építési terv.doc", "日本語.txt", "a b(c)!$.x",
         "résumé.pdf", "plain name.txt", "a/b\\c:d", "../evil", "-dash",
         "trailing. ", "CON.txt", "zalgóx", "Ωμέγα"]
EXTS = [".pdf", ".txt", ".jpg", ".bin", ""]


def rword(r):
    w = r.choice(WORDS)
    if r.random() < 0.4:
        w += str(r.randrange(100))
    if r.random() < 0.3:
        w += r.choice(EXTS)
    return w


def enc_2047(r, s):
    cs = r.choice(CHARSETS)
    if r.random() < 0.5:
        try:
            payload = base64.b64encode(s.encode(cs.split("-")[0] if cs == "utf-8" else cs, "replace")).decode()
            enc = "B"
        except (LookupError, UnicodeError):
            payload = base64.b64encode(s.encode("utf-8")).decode()
            enc = "B"
    else:
        try:
            raw = s.encode("utf-8" if cs.startswith("utf") else cs, "replace")
        except LookupError:
            cs = "utf-8"
            raw = s.encode("utf-8")
        out = []
        for b in raw:
            c = chr(b)
            if c in " _=?":
                out.append("={:02X}".format(b) if c != " " else "_")
            elif 33 <= b <= 126 and c not in "?=":
                out.append(c)
            else:
                out.append("={:02X}".format(b))
        payload = "".join(out)
        enc = "Q"
    return "=?{}?{}?{}?=".format(cs, enc, payload)


def filename_param(r, s):
    mode = r.randrange(5)
    if mode == 0:
        return 'filename="{}"'.format(s.replace("\\", "\\\\").replace('"', ""))
    if mode == 1:
        return 'filename="{}"'.format(enc_2047(r, s))
    if mode == 2:
        cs = r.choice(["utf-8", "iso-8859-1", "iso-8859-2", "windows-1250", "us-ascii"])
        try:
            raw = s.encode("utf-8" if cs.startswith("utf") else cs, "replace")
        except Exception:
            raw = s.encode("utf-8")
        return "filename*={}''{}".format(cs, "".join("%{:02X}".format(b) for b in raw))
    if mode == 3:  # split continuation
        cs = r.choice(["utf-8", "iso-8859-1", "iso-8859-2", "windows-1250", "us-ascii"])
        raw = s.encode("utf-8")
        pct = "".join("%{:02X}".format(b) for b in raw)
        cut = r.randrange(len(pct) + 1)
        cut -= cut % 3
        p0, p1 = pct[:cut], pct[cut:]
        return 'filename*0*="{}\'\'{}"; filename*1*="{}"'.format(cs, p0, p1)
    return 'filename="{}"'.format(enc_2047(r, s))  # 2047 again for weight


def gen_mail(r):
    boundary = r.choice(["BB", "b1", "x" * r.randrange(1, 20), "end-boundary"])
    n_parts = r.randrange(1, 4)
    lines = ["MIME-Version: 1.0",
             'Content-Type: multipart/mixed; boundary="{}"'.format(boundary)]
    if r.random() < 0.3:
        lines.append("Subject: {}".format(enc_2047(r, "subject " + rword(r))))
    body = "\r\n".join(lines) + "\r\n\r\n"
    for _ in range(n_parts):
        name = rword(r)
        cte = r.choice(["base64", "quoted-printable", "7bit", "8bit"])
        data = bytes(r.randrange(256) for _ in range(r.randrange(0, 64)))
        if cte == "base64":
            payload = base64.b64encode(data).decode()
        elif cte == "quoted-printable":
            payload = "".join("={:02X}".format(b) if b < 32 or b > 126 else chr(b) for b in data)
        else:
            payload = "".join(chr(b) if 32 <= b < 127 else "" for b in data)
            data = payload.encode()
        part = ["--" + boundary,
                "Content-Type: " + r.choice(["application/pdf", "text/plain", "image/jpeg", "application/octet-stream"]),
                "Content-Transfer-Encoding: " + cte,
                "Content-Disposition: attachment; " + filename_param(r, name),
                "", payload]
        body += "\r\n".join(part) + "\r\n"
    body += "--" + boundary + "--\r\n"
    raw = body.encode("latin-1", "replace")
    # Random byte mutations. Any single-byte flip can change parser tolerance
    # somewhere (encoded-word shape, charset spelling, header folding), so
    # mutated mails are exercised for crash-freedom only; structural and
    # value comparisons run on pristine generated mails.
    n_mut = 0 if r.random() < 0.5 else r.randrange(1, 6)
    tainted = n_mut > 0
    for _ in range(n_mut):
        i = r.randrange(len(raw))
        raw = raw[:i] + bytes([r.randrange(256)]) + raw[i + 1:]
    return raw, tainted


def py_extract(raw):
    """Return (strict_payload_shas, name_list, n_parts).

    strict_payload_shas: sha256 of payloads whose CTE is base64/quoted-
    printable (byte-exact decoding is well-defined there).
    name_list: sanitized names with detox-style `_1` de-duping, in part
    order, for attachment names we can fairly compare: raw name basename-
    reduced (mirroring detox's traversal defense), RFC 2047-decoded, and
    skipped individually if an encoded-word survived (unknown charset:
    detox lossy-decodes per spec, Python keeps it raw).
    """
    msg = message_from_bytes(raw)
    strict = []
    names = []
    n_parts = 0
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        n_parts += 1
        cte = str(part.get("Content-Transfer-Encoding") or "").lower()
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
        sha = hashlib.sha256(payload).hexdigest()
        if cte in ("base64", "quoted-printable"):
            strict.append(sha)
        fn = part.get_filename()
        if fn:
            try:
                dec = str(make_header(decode_header(fn)))
            except Exception:
                dec = fn
            if "=?" in dec:
                continue  # unknown charset: divergent-by-design class
            # detox reduces the DECODED name (basename_reduce runs after
            # decoding), so reduce here, not on the raw value
            dec = dec.replace("\\", "/").rsplit("/", 1)[-1]
            names.append(sanitize_with_detox(dec))
    # replicate detox's UNQ de-duping: counter before the final extension,
    # but a LEADING dot means a hidden file with no extension — counter
    # goes at the end (`.txt` -> `.txt_1`, matching uniquify())
    seen = {}
    out = []
    for n in names:
        if n in seen:
            seen[n] += 1
            if "." in n and not n.startswith("."):
                stem, ext = n.rsplit(".", 1)
                out.append("{}_{}.{}".format(stem, seen[n], ext))
            else:
                out.append("{}_{}".format(n, seen[n]))
        else:
            seen[n] = 0
            out.append(n)
    return sorted(strict), sorted(out), n_parts


def detox_extract(raw, workdir):
    outdir = os.path.join(workdir, "out")
    p = subprocess.run([DETOX, "extract", "-i", "-", "-d", outdir, "--format", "json"],
                       input=raw, capture_output=True)
    shas = []
    names = []
    n_out = 0
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("action") != "extract":
            continue
        n_out += 1
        path = rec["file"]
        with open(path, "rb") as f:
            shas.append(hashlib.sha256(f.read()).hexdigest())
        if "hard link" not in rec.get("name_source", ""):
            names.append(os.path.basename(path))
    return shas, sorted(names), n_out, p.stderr.decode("utf-8", "replace")


def sanitize_with_detox(name):
    p = subprocess.run([DETOX, "--strings"], input=(name + "\n").encode(),
                       capture_output=True)
    return p.stdout.decode().split("\t")[-1].strip()


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    r = random.Random(1234)
    dump_root = "/tmp/diff-fuzz"
    os.makedirs(dump_root, exist_ok=True)
    diverge = 0
    for n in range(rounds):
        raw, tainted = gen_mail(r)
        workdir = tempfile.mkdtemp(prefix="diffz-")
        with open(os.path.join(workdir, "mail.eml"), "wb") as f:
            f.write(raw)
        try:
            py_strict, py_names, py_n = py_extract(raw)
            dx_shas, dx_names, dx_n, dx_err = detox_extract(raw, workdir)
        except Exception as e:
            print("HARNESS ERROR at {}: {}".format(n, e))
            continue
        if tainted:
            # Both parsers still exercised above (crash-freedom); structural
            # divergence on corrupted headers/boundaries is arbitrary.
            if n % 1000 == 0:
                print("... {}/{} (divergences: {}, tainted skipped)".format(
                    n, rounds, diverge))
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
            continue
        problems = []
        for sha in py_strict:
            if sha not in dx_shas:
                problems.append("py base64/QP payload missing in detox output")
                break
        if py_n != dx_n:
            problems.append("attachment count differs (py={} dx={})".format(py_n, dx_n))
        if py_names != dx_names:
            only_py = sorted(set(py_names) - set(dx_names))
            only_dx = sorted(set(dx_names) - set(py_names))
            problems.append("name multiset differs; only py={} only dx={}".format(
                only_py[:3], only_dx[:3]))
        if problems:
            diverge += 1
            case = os.path.join(dump_root, "{:05d}".format(n))
            os.makedirs(case, exist_ok=True)
            with open(os.path.join(case, "mail.eml"), "wb") as f:
                f.write(raw)
            with open(os.path.join(case, "problem.txt"), "w") as f:
                f.write("\n".join(problems) + "\n\npy_names={}\ndx_names={}\ndx_stderr={}\n".format(
                    py_names, dx_names, dx_err))
            print("DIVERGE #{} -> {}".format(n, case))
            for p in problems[:3]:
                print("   ", p)
            if diverge >= 15:
                print("stopping after 15 divergences")
                break
        else:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
        if n % 1000 == 0:
            print("... {}/{} (divergences: {})".format(n, rounds, diverge))
    print("done: {} rounds, {} divergences".format(rounds, diverge))


if __name__ == "__main__":
    main()
