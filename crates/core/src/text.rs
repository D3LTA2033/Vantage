use std::fmt::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn from_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_clean(&mut out, s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                push_clean(&mut out, std::str::from_utf8(good).unwrap_or_default());
                let n = e.error_len().unwrap_or(bad.len());
                for b in &bad[..n] {
                    let _ = write!(out, "\\x{b:02x}");
                }
                rest = &bad[n..];
            }
        }
    }
    out
}

pub fn from_path(path: &Path) -> String {
    from_bytes(path.as_os_str().as_bytes())
}

pub fn from_cstr_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    from_bytes(&bytes[..end])
}

fn push_clean(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                if (c as u32) < 0x100 {
                    let _ = write!(out, "\\x{:02x}", c as u32);
                } else {
                    let _ = write!(out, "\\u{{{:x}}}", c as u32);
                }
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_unchanged() {
        assert_eq!(from_bytes(b"/usr/bin/ls"), "/usr/bin/ls");
        assert_eq!(from_bytes("é😀".as_bytes()), "é😀");
    }

    #[test]
    fn control_and_invalid_escaped() {
        assert_eq!(from_bytes(b"a\x1b[31mb"), "a\\x1b[31mb");
        assert_eq!(from_bytes(b"x\xffy\xc3"), "x\\xffy\\xc3");
        assert_eq!(from_bytes(b"new\nline\\"), "new\\x0aline\\\\");
        assert_eq!(from_bytes("\u{85}".as_bytes()), "\\x85");
    }

    #[test]
    fn escaping_is_injective_for_backslash_sequences() {
        assert_ne!(from_bytes(b"\\xff"), from_bytes(b"\xff"));
    }

    #[test]
    fn cstr_stops_at_nul() {
        assert_eq!(from_cstr_bytes(b"bash\0\0garbage"), "bash");
        assert_eq!(from_cstr_bytes(b"full"), "full");
    }
}
