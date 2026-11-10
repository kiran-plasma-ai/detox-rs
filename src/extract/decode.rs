//! Byte-level decoders and charset tables: charset_decode (built-in
//! tables, honest lossy fallback), base64, quoted-printable (byte-exact
//! CPython a2b_qp port), hexval. Pure functions, no I/O.

/// Minimal charset coverage (SPEC slice-6 contract): utf-8, us-ascii,
/// iso-8859-1/latin1, windows-1252/cp1252. Anything else: lossy UTF-8,
/// reported via the `false` return.
pub(super) fn charset_decode(bytes: &[u8], charset: &str) -> (String, bool) {
    let cs = charset.trim().to_ascii_lowercase();
    match cs.as_str() {
        "utf-8" | "utf8" => (String::from_utf8_lossy(bytes).into_owned(), true),
        "us-ascii" | "us_ascii" | "ascii" => {
            // Strictly 7-bit: higher bytes have no mapping. Lossy U+FFFD per
            // byte AND report lossiness (matches Python email's
            // errors=replace behavior; found via differential fuzzing —
            // previously this arm shared the latin-1 mapping).
            let mut out = String::with_capacity(bytes.len());
            let mut clean = true;
            for &b in bytes {
                if b < 0x80 {
                    out.push(char::from(b));
                } else {
                    out.push('\u{FFFD}');
                    clean = false;
                }
            }
            (out, clean)
        }
        "iso-8859-1" | "iso_8859-1" | "latin1" | "latin-1" => {
            (bytes.iter().map(|&b| char::from(b)).collect(), true)
        }
        "windows-1252" | "cp1252" => {
            const T: [char; 32] = [
                '\u{20ac}', '\u{81}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}',
                '\u{2021}', '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8d}',
                '\u{17d}', '\u{8f}', '\u{90}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}',
                '\u{2022}', '\u{2013}', '\u{2014}', '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}',
                '\u{153}', '\u{9d}', '\u{17e}', '\u{178}',
            ];
            (
                bytes
                    .iter()
                    .map(|&b| {
                        if (0x80..0xa0).contains(&b) {
                            T[(b - 0x80) as usize]
                        } else {
                            char::from(b)
                        }
                    })
                    .collect(),
                true,
            )
        }
        "iso-8859-2" | "iso_8859-2" | "latin2" | "latin-2" => {
            const T: [char; 128] = [
                '\u{0080}', '\u{0081}', '\u{0082}', '\u{0083}', '\u{0084}', '\u{0085}', '\u{0086}', '\u{0087}',
                '\u{0088}', '\u{0089}', '\u{008A}', '\u{008B}', '\u{008C}', '\u{008D}', '\u{008E}', '\u{008F}',
                '\u{0090}', '\u{0091}', '\u{0092}', '\u{0093}', '\u{0094}', '\u{0095}', '\u{0096}', '\u{0097}',
                '\u{0098}', '\u{0099}', '\u{009A}', '\u{009B}', '\u{009C}', '\u{009D}', '\u{009E}', '\u{009F}',
                '\u{00A0}', '\u{0104}', '\u{02D8}', '\u{0141}', '\u{00A4}', '\u{013D}', '\u{015A}', '\u{00A7}',
                '\u{00A8}', '\u{0160}', '\u{015E}', '\u{0164}', '\u{0179}', '\u{00AD}', '\u{017D}', '\u{017B}',
                '\u{00B0}', '\u{0105}', '\u{02DB}', '\u{0142}', '\u{00B4}', '\u{013E}', '\u{015B}', '\u{02C7}',
                '\u{00B8}', '\u{0161}', '\u{015F}', '\u{0165}', '\u{017A}', '\u{02DD}', '\u{017E}', '\u{017C}',
                '\u{0154}', '\u{00C1}', '\u{00C2}', '\u{0102}', '\u{00C4}', '\u{0139}', '\u{0106}', '\u{00C7}',
                '\u{010C}', '\u{00C9}', '\u{0118}', '\u{00CB}', '\u{011A}', '\u{00CD}', '\u{00CE}', '\u{010E}',
                '\u{0110}', '\u{0143}', '\u{0147}', '\u{00D3}', '\u{00D4}', '\u{0150}', '\u{00D6}', '\u{00D7}',
                '\u{0158}', '\u{016E}', '\u{00DA}', '\u{0170}', '\u{00DC}', '\u{00DD}', '\u{0162}', '\u{00DF}',
                '\u{0155}', '\u{00E1}', '\u{00E2}', '\u{0103}', '\u{00E4}', '\u{013A}', '\u{0107}', '\u{00E7}',
                '\u{010D}', '\u{00E9}', '\u{0119}', '\u{00EB}', '\u{011B}', '\u{00ED}', '\u{00EE}', '\u{010F}',
                '\u{0111}', '\u{0144}', '\u{0148}', '\u{00F3}', '\u{00F4}', '\u{0151}', '\u{00F6}', '\u{00F7}',
                '\u{0159}', '\u{016F}', '\u{00FA}', '\u{0171}', '\u{00FC}', '\u{00FD}', '\u{0163}', '\u{02D9}',
            ];
            (
                bytes
                    .iter()
                    .map(|&b| if b >= 0x80 { T[(b - 0x80) as usize] } else { char::from(b) })
                    .collect(),
                true,
            )
        }
        "windows-1250" | "cp1250" => {
            const T: [char; 128] = [
                '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{FFFD}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
                '\u{FFFD}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{015A}', '\u{0164}', '\u{017D}', '\u{0179}',
                '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
                '\u{FFFD}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{015B}', '\u{0165}', '\u{017E}', '\u{017A}',
                '\u{00A0}', '\u{02C7}', '\u{02D8}', '\u{0141}', '\u{00A4}', '\u{0104}', '\u{00A6}', '\u{00A7}',
                '\u{00A8}', '\u{00A9}', '\u{015E}', '\u{00AB}', '\u{00AC}', '\u{00AD}', '\u{00AE}', '\u{017B}',
                '\u{00B0}', '\u{00B1}', '\u{02DB}', '\u{0142}', '\u{00B4}', '\u{00B5}', '\u{00B6}', '\u{00B7}',
                '\u{00B8}', '\u{0105}', '\u{015F}', '\u{00BB}', '\u{013D}', '\u{02DD}', '\u{013E}', '\u{017C}',
                '\u{0154}', '\u{00C1}', '\u{00C2}', '\u{0102}', '\u{00C4}', '\u{0139}', '\u{0106}', '\u{00C7}',
                '\u{010C}', '\u{00C9}', '\u{0118}', '\u{00CB}', '\u{011A}', '\u{00CD}', '\u{00CE}', '\u{010E}',
                '\u{0110}', '\u{0143}', '\u{0147}', '\u{00D3}', '\u{00D4}', '\u{0150}', '\u{00D6}', '\u{00D7}',
                '\u{0158}', '\u{016E}', '\u{00DA}', '\u{0170}', '\u{00DC}', '\u{00DD}', '\u{0162}', '\u{00DF}',
                '\u{0155}', '\u{00E1}', '\u{00E2}', '\u{0103}', '\u{00E4}', '\u{013A}', '\u{0107}', '\u{00E7}',
                '\u{010D}', '\u{00E9}', '\u{0119}', '\u{00EB}', '\u{011B}', '\u{00ED}', '\u{00EE}', '\u{010F}',
                '\u{0111}', '\u{0144}', '\u{0148}', '\u{00F3}', '\u{00F4}', '\u{0151}', '\u{00F6}', '\u{00F7}',
                '\u{0159}', '\u{016F}', '\u{00FA}', '\u{0171}', '\u{00FC}', '\u{00FD}', '\u{0163}', '\u{02D9}',
            ];
            (
                bytes
                    .iter()
                    .map(|&b| if b >= 0x80 { T[(b - 0x80) as usize] } else { char::from(b) })
                    .collect(),
                true,
            )
        }
        _ => (
            String::from_utf8_lossy(bytes).into_owned(),
            false,
        ),
    }
}

pub(super) fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    // Ignore non-alphabet bytes (whitespace, per RFC 2045).
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &b in data {
        let v = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b'\t' | b' ' => continue,
            _ => continue,
        };
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

pub(super) fn qp_decode(data: &[u8]) -> Vec<u8> {
    // Byte-for-byte port of CPython 3.14 binascii.a2b_qp(header=False), the
    // decoder behind Python's email module — the ecosystem reference for
    // QP edge semantics (differential fuzzing found 3 divergences here):
    //   '=':
    //     EOF after it            -> dropped
    //     '\n'                    -> soft break
    //     '\r' [junk] '\n'        -> soft break over the whole line tail
    //     '='                     -> literal '=', second '=' consumed
    //                              ("broken case from broken python qp")
    //     hexdigit hexdigit       -> byte (requires both to exist)
    //     anything else           -> literal '=', rest re-examined as data
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'=' {
            out.push(data[i]);
            i += 1;
            continue;
        }
        i += 1; // consume '='
        if i >= data.len() {
            break; // dangling '=' at EOF
        }
        let c = data[i];
        if c == b'\n' {
            i += 1;
        } else if c == b'\r' {
            while i < data.len() && data[i] != b'\n' {
                i += 1;
            }
            if i < data.len() {
                i += 1; // consume '\n'
            }
        } else if c == b'=' {
            out.push(b'=');
            i += 1;
        } else if i + 1 < data.len() && c.is_ascii_hexdigit() && data[i + 1].is_ascii_hexdigit() {
            out.push((hexval(c) << 4) | hexval(data[i + 1]));
            i += 2;
        } else {
            out.push(b'=');
        }
    }
    out
}

fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

