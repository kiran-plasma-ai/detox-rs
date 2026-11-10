//! The extraction driver: recursive part walk (multipart / message/rfc822
//! nesting caps), leaf decode + name pipeline + no-clobber create, hard-link
//! aliases, and the extraction journal writer. EXTRACT.md §3/§6 contracts.

use std::path::PathBuf;

use crate::fs;
use crate::{sanitize, Options, Uniquifier};

use super::decode::{base64_decode, qp_decode};
use super::filename::{basename_reduce, ext_for_type, raw_filename};
use super::mime::{header_value, parse_params, split_head_body, split_multipart};
use super::{Extracted, ExtractError, ExtractOptions};


pub(super) fn write_extract_journal(
    journal_dir: &Option<PathBuf>,
    out: &[Extracted],
) -> Option<String> {
    let (Some(jdir), true) = (journal_dir, !out.is_empty()) else {
        return None;
    };
    let mut created = Vec::with_capacity(out.len());
    for e in out {
        // Hard-link aliases are journaled too (sec review F5): undo's
        // dev+inode check makes remove_file delete exactly one name, so
        // both the primary and its aliases must be journaled for undo to
        // restore pre-extraction state fully.
        if let Ok(md) = std::fs::symlink_metadata(&e.file) {
            let (d, i) = fs::file_identity(&e.file, &md);
            created.push((e.file.clone(), d, i));
        }
    }
    if created.is_empty() {
        return None;
    }
    fs::write_create_journal(jdir, &run_id(), &created)
        .err()
        .map(|e| format!("journal write: {e}"))
}

fn run_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(nanos);
    h.write_u32(std::process::id());
    format!("{:016x}", h.finish())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn walk_part(
    headers: &[(String, String)],
    body: &[u8],
    opts: &ExtractOptions,
    depth: usize,
    out: &mut Vec<Extracted>,
    uniq: &mut Uniquifier,
    parts_seen: &mut usize,
    cap_hit: &mut bool,
) -> Result<(), ExtractError> {
    *parts_seen += 1;
    if *parts_seen > opts.parts_max {
        *cap_hit = true;
        return Ok(()); // cap: skip the rest of this message
    }
    let ct = header_value(headers, "Content-Type")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "text/plain".into());
    let (main, params) = parse_params(&ct);
    let main_l = main.to_ascii_lowercase();

    if main_l.starts_with("multipart/") {
        // F2 (security review): RFC 2046 bounds boundaries at 70 chars; an
        // uncapped attacker-controlled needle makes the delimiter scan
        // O(body x boundary). Oversized boundary -> treat as opaque part.
        const BOUNDARY_MAX: usize = 200;
        let boundary = params
            .iter()
            .find(|(k, _)| k == "boundary")
            .map(|(_, v)| v.trim_matches('"').to_string())
            .ok_or_else(|| ExtractError("multipart without boundary".into()))?;
        if boundary.len() > BOUNDARY_MAX {
            *cap_hit = true;
            return Ok(());
        }
        // F1 (security review): nesting depth is capped for message/rfc822
        // but multipart recursion passed `depth` unchanged — ~10k nested
        // shells blew the 8 MB main-thread stack (SIGABRT, not a panic, so
        // the fuzz oracles stayed green). Same guard for both.
        if depth + 1 > opts.recursion_max {
            *cap_hit = true;
            return Ok(());
        }
        for sub in split_multipart(body, &boundary) {
            let (sh, sb) = split_head_body(sub);
            walk_part(&sh, sb, opts, depth + 1, out, uniq, parts_seen, cap_hit)?;
        }
        return Ok(());
    }

    if main_l == "message/rfc822" {
        if depth + 1 > opts.recursion_max {
            *cap_hit = true; // partial: caller records it (EXTRACT §7 T-EX-011)
            return Ok(());
        }
        let (sh, sb) = split_head_body(body);
        return walk_part(&sh, sb, opts, depth + 1, out, uniq, parts_seen, cap_hit);
    }

    // Leaf part: decode content.
    let cte = header_value(headers, "Content-Transfer-Encoding")
        .unwrap_or("7bit")
        .to_ascii_lowercase();
    let decoded = match cte.as_str() {
        "base64" => base64_decode(body).ok_or_else(|| ExtractError("bad base64".into()))?,
        "quoted-printable" => qp_decode(body),
        _ => body.to_vec(), // 7bit/8bit/binary/unknown: byte-exact
    };
    let decoded_from = if cte == "base64" || cte == "quoted-printable" {
        cte.clone()
    } else {
        "identity".into()
    };

    // Name resolution.
    let (raw_name, name_source, extras, note) = raw_filename(headers);
    let name = match raw_name {
        Some(raw) if !raw.trim().is_empty() => {
            let base = basename_reduce(raw.trim().trim_matches('"'));
            let o = sanitize(base.as_bytes(), &Options {
                profile: opts.profile,
                case: opts.case,
                max_bytes: opts.max_bytes,
            });
            o.name
        }
        _ => {
            if opts.no_nameless {
                return Ok(());
            }
            // Generate a candidate, THEN run it through the pipeline — a
            // forged Content-Type must not inject separators (review finding).
            let candidate = if opts.name_by_type {
                main.split('/').map(|s| s.trim()).collect::<Vec<_>>().join("_")
            } else {
                match ext_for_type(&main) {
                    Some(ext) => format!("{}.{}", opts.prefix, ext),
                    None => opts.prefix.clone(),
                }
            };
            sanitize(candidate.as_bytes(), &Options {
                profile: opts.profile,
                case: opts.case,
                max_bytes: opts.max_bytes,
            })
            .name
        }
    };

    let name = match uniq.apply(name) {
        Ok((n, _)) => n,
        Err(_) => return Err(ExtractError("cannot uniquify within max-length".into())),
    };
    let path = opts.out_dir.join(&name);
    // Provably under out_dir: name came from sanitize (no separators) or
    // name_by_type (alnum+underscore), and join() with a relative name cannot
    // escape; belt-and-suspenders: verify parent == out_dir.
    if path.parent() != Some(opts.out_dir.as_path()) {
        return Err(ExtractError(format!("path escape rejected: {name}")));
    }
    // No-clobber: a symlink (even dangling) is an occupied slot — never
    // follow it (EXTRACT §6). create_new unless double-armed --overwrite.
    if std::fs::symlink_metadata(&path).is_ok() && !opts.overwrite {
        return Err(ExtractError(format!("refusing to overwrite {name}")));
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true);
    if opts.overwrite {
        // Overwrite REGULAR files only; symlinks refused above, and the
        // open itself gets O_NOFOLLOW so a swap between the check and the
        // open cannot redirect the write through a planted link (sec F7).
        if let Ok(md) = std::fs::symlink_metadata(&path) {
            if md.file_type().is_symlink() {
                return Err(ExtractError(format!("refusing to overwrite {name}")));
            }
        }
        open.truncate(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            // FILE_FLAG_OPEN_REPARSE_POINT: don't resolve a swapped-in
            // symlink at open time (O_NOFOLLOW equivalent on Windows).
            use std::os::windows::fs::OpenOptionsExt;
            open.custom_flags(0x0020_0000);
        }
    } else {
        open.create_new(true);
    }
    open.open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &decoded))
        .map_err(|e| ExtractError(format!("write {name}: {e}")))?;
    out.push(Extracted {
        file: path.clone(),
        content_type: main.clone(),
        size: decoded.len(),
        decoded_from: decoded_from.clone(),
        name_source: name_source.clone(),
        note: note.clone(),
        hard_link_of: None,
    });

    // EXT-6: hard link per additional filename param (same content).
    for extra in extras {
        let base = basename_reduce(extra.trim().trim_matches('"'));
        let o = sanitize(base.as_bytes(), &Options {
            profile: opts.profile,
            case: opts.case,
            max_bytes: opts.max_bytes,
        });
        let en = match uniq.apply(o.name) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };
        let epath = opts.out_dir.join(&en);
        if epath.parent() != Some(opts.out_dir.as_path())
            || std::fs::symlink_metadata(&epath).is_ok()
        {
            continue;
        }
        if std::fs::hard_link(&path, &epath).is_ok() {
            out.push(Extracted {
                file: epath,
                content_type: main.clone(),
                size: decoded.len(),
                decoded_from: decoded_from.clone(),
                name_source: "filename= (hard link)".into(),
                note: note.clone(),
                hard_link_of: Some(path.clone()),
            });
        }
    }
    Ok(())
}
