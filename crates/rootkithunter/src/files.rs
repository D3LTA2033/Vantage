use crate::Options;
use crate::network::describe_socket_key;
use crate::processes::raw_pids;
use std::collections::BTreeSet;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use vantage_core::{Finding, IoContext, Outcome, Result, Severity, proc, rawsys, sys, text};

type Names = BTreeSet<Vec<u8>>;

fn libc_names(dir: &Path) -> io::Result<Names> {
    std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().into_vec()))
        .collect()
}

fn raw_names(dir: &Path) -> io::Result<Names> {
    Ok(rawsys::read_dir(dir)?.into_iter().map(|e| e.name).collect())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub hidden: Names,
    pub phantom: Names,
}

pub fn stable_diff(raw: [&Names; 3], libc: [&Names; 2]) -> Diff {
    let seen_libc: Names = libc[0].union(libc[1]).cloned().collect();
    let raw_all: Names = raw[0]
        .iter()
        .filter(|n| raw[1].contains(*n) && raw[2].contains(*n))
        .cloned()
        .collect();
    let raw_any: Names = raw.iter().flat_map(|s| s.iter().cloned()).collect();
    Diff {
        hidden: raw_all.difference(&seen_libc).cloned().collect(),
        phantom: libc[0]
            .intersection(libc[1])
            .filter(|n| !raw_any.contains(*n))
            .cloned()
            .collect(),
    }
}

fn compare(
    mut raw: impl FnMut() -> io::Result<Names>,
    mut libc: impl FnMut() -> io::Result<Names>,
) -> io::Result<Option<Diff>> {
    let r1 = raw()?;
    let l1 = libc()?;
    if r1 == l1 {
        return Ok(None);
    }
    let r2 = raw()?;
    let l2 = libc()?;
    let r3 = raw()?;
    let diff = stable_diff([&r1, &r2, &r3], [&l1, &l2]);
    Ok((!diff.hidden.is_empty() || !diff.phantom.is_empty()).then_some(diff))
}

fn dir_findings(dir: &Path, diff: &Diff) -> Vec<Finding> {
    let shown = text::from_path(dir);
    let mut out = Vec::new();
    for name in &diff.hidden {
        let name_s = text::from_bytes(name);
        let mut f = if dir == Path::new("/proc") && proc::parse_pid(name).is_some() {
            let comm =
                rawsys::read_file(&dir.join(std::ffi::OsStr::new(&name_s)).join("comm"), 4096)
                    .ok()
                    .map(|c| text::from_bytes(c.trim_ascii_end()));
            Finding::new(
                Severity::High,
                format!("process {name_s} hidden from libc readdir"),
            )
            .evidence("pid", name_s.clone())
            .evidence("comm", comm)
        } else {
            Finding::new(
                Severity::High,
                format!("{shown}/{name_s} hidden from libc readdir"),
            )
        };
        f = f
            .detail("getdents64 returns the entry on repeated reads but readdir() in this process never does; a library preloaded into userland processes is filtering directory listings")
            .evidence("directory", shown.clone())
            .evidence("name", name_s);
        out.push(f);
    }
    for name in &diff.phantom {
        out.push(
            Finding::new(
                Severity::Medium,
                "libc readdir returns an entry the kernel does not",
            )
            .detail("readdir() output was modified inside this process")
            .evidence("directory", shown.clone())
            .evidence("name", text::from_bytes(name)),
        );
    }
    out
}

#[derive(Debug, Clone, Copy)]
enum Key {
    FirstToken,
    Socket,
    Line,
}

fn keys(data: &[u8], key: Key) -> Names {
    let lines = data
        .split(|&b| b == b'\n')
        .filter(|l| !l.trim_ascii().is_empty());
    match key {
        Key::Line => lines.map(|l| l.trim_ascii().to_vec()).collect(),
        Key::FirstToken => lines
            .filter_map(|l| l.split(|b| b.is_ascii_whitespace()).find(|t| !t.is_empty()))
            .map(<[u8]>::to_vec)
            .collect(),
        Key::Socket => lines
            .skip(1)
            .filter_map(|l| {
                let cols: Vec<&[u8]> = l
                    .split(|b| b.is_ascii_whitespace())
                    .filter(|t| !t.is_empty())
                    .collect();
                if cols.len() < 10 {
                    return None;
                }
                Some([cols[1], cols[2], cols[3], cols[9]].join(&b' '))
            })
            .collect(),
    }
}

fn file_findings(path: &Path, key: Key) -> Result<Vec<Finding>> {
    let shown = text::from_path(path);
    let raw_read = || match rawsys::read_file(path, 64 << 20) {
        Ok(d) => Ok(Some(keys(&d, key))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let libc_read = || match std::fs::read(path) {
        Ok(d) => Ok(Some(keys(&d, key))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let first_raw = match raw_read() {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {shown}")),
    };
    let first_libc = libc_read().with_context(|| format!("read {shown}"))?;
    match (first_raw, first_libc) {
        (None, None) => Ok(Vec::new()),
        (Some(_), None) => {
            let still = raw_read().ok().flatten().is_some() && libc_read().ok().flatten().is_none();
            Ok(if still {
                vec![Finding::new(Severity::High, format!("{shown} hidden from libc"))
                    .detail("the file opens with a raw openat syscall but libc reports it does not exist")
                    .evidence("path", shown)]
            } else {
                Vec::new()
            })
        }
        (None, Some(_)) => Ok(vec![
            Finding::new(
                Severity::Medium,
                format!("{shown} exists only through libc"),
            )
            .evidence("path", shown),
        ]),
        (Some(r1), Some(l1)) => {
            if r1 == l1 {
                return Ok(Vec::new());
            }
            let again = || -> io::Result<(Names, Names)> {
                Ok((
                    raw_read()?.unwrap_or_default(),
                    libc_read()?.unwrap_or_default(),
                ))
            };
            let (r2, l2) = again().with_context(|| format!("read {shown}"))?;
            let r3 = raw_read()
                .with_context(|| format!("read {shown}"))?
                .unwrap_or_default();
            let diff = stable_diff([&r1, &r2, &r3], [&l1, &l2]);
            let mut out = Vec::new();
            if !diff.hidden.is_empty() {
                let entries: Vec<String> = diff
                    .hidden
                    .iter()
                    .map(|k| match key {
                        Key::Socket => describe_socket_key(k),
                        _ => text::from_bytes(k),
                    })
                    .collect();
                out.push(
                    Finding::new(Severity::High, format!("lines of {shown} hidden from libc reads"))
                        .detail("raw read() returns these entries but reads through libc in this process do not; a preloaded library is filtering file contents")
                        .evidence("path", shown.clone())
                        .evidence("entries", entries),
                );
            }
            if !diff.phantom.is_empty() {
                out.push(
                    Finding::new(
                        Severity::Medium,
                        format!("libc reads of {shown} contain injected lines"),
                    )
                    .evidence("path", shown)
                    .evidence(
                        "entries",
                        diff.phantom
                            .iter()
                            .map(|k| text::from_bytes(k))
                            .collect::<Vec<_>>(),
                    ),
                );
            }
            Ok(out)
        }
    }
}

pub fn userland_hiding(opts: &Options) -> Result<Outcome> {
    if cfg!(target_feature = "crt-static") {
        return Ok(Outcome::skipped(
            "statically linked build: preloaded libraries cannot load into this binary, so libc and raw views are always identical",
        ));
    }
    let release = sys::uname().release;
    let mut dirs: Vec<PathBuf> = [
        "/proc",
        "/etc",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
    ]
    .iter()
    .map(PathBuf::from)
    .chain(std::iter::once(
        PathBuf::from("/lib/modules").join(&release),
    ))
    .filter(|p| p.is_dir())
    .collect();
    for d in &opts.extra_dirs {
        if !dirs.contains(d) {
            dirs.push(d.clone());
        }
    }
    let mut findings = Vec::new();
    let mut unreadable = Vec::new();
    for dir in &dirs {
        match compare(|| raw_names(dir), || libc_names(dir)) {
            Ok(Some(diff)) => findings.extend(dir_findings(dir, &diff)),
            Ok(None) => {}
            Err(e) if opts.extra_dirs.contains(dir) => {
                return Err(e).with_context(|| format!("list {}", text::from_path(dir)));
            }
            Err(_) => unreadable.push(text::from_path(dir)),
        }
    }
    let files = [
        ("/proc/modules", Key::FirstToken),
        ("/proc/net/tcp", Key::Socket),
        ("/proc/net/tcp6", Key::Socket),
        ("/proc/net/udp", Key::Socket),
        ("/proc/net/udp6", Key::Socket),
        ("/etc/ld.so.preload", Key::Line),
    ];
    for (path, key) in files {
        findings.extend(file_findings(Path::new(path), key)?);
    }
    let mut summary = format!(
        "compared libc and raw syscall views of {} directories and {} files",
        dirs.len() - unreadable.len(),
        files.len()
    );
    if !unreadable.is_empty() {
        summary.push_str(&format!("; unreadable: {}", unreadable.join(", ")));
    }
    Ok(Outcome::done(summary, findings))
}

pub fn parse_preload(data: &[u8]) -> Vec<String> {
    data.split(|b| matches!(b, b' ' | b'\t' | b'\n' | b':'))
        .filter(|t| !t.is_empty())
        .map(text::from_bytes)
        .collect()
}

pub fn preload(_: &Options) -> Result<Outcome> {
    let mut findings = Vec::new();
    match rawsys::read_file(Path::new("/etc/ld.so.preload"), 1 << 20) {
        Ok(data) => {
            for lib in parse_preload(&data) {
                let meta = std::fs::metadata(&lib).ok();
                findings.push(
                    Finding::new(Severity::High, format!("system-wide preload library {lib}"))
                        .detail("every dynamically linked program loads this library first; this is the standard persistence point for userland rootkits, though a few debugging tools use it legitimately")
                        .evidence("path", lib.clone())
                        .evidence("exists", meta.is_some())
                        .evidence("owner_uid", meta.as_ref().map(|m| m.uid()))
                        .evidence("mode", meta.as_ref().map(|m| format!("{:o}", m.mode() & 0o7777))),
                );
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("read /etc/ld.so.preload"),
    }
    let pids = raw_pids(Path::new("/proc")).context("getdents64 /proc")?;
    let mut unreadable = 0usize;
    let mut injected: std::collections::BTreeMap<(&str, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for pid in &pids {
        let env = match std::fs::read(format!("/proc/{pid}/environ")) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                unreadable += 1;
                continue;
            }
            Err(_) => continue,
        };
        for var in env.split(|&b| b == 0) {
            for name in ["LD_PRELOAD", "LD_AUDIT"] {
                let Some(value) = var
                    .strip_prefix(name.as_bytes())
                    .and_then(|v| v.strip_prefix(b"="))
                else {
                    continue;
                };
                if value.is_empty() {
                    continue;
                }
                let comm = proc::ProcStatus::read(*pid)
                    .map(|s| s.name)
                    .unwrap_or_default();
                injected
                    .entry((name, text::from_bytes(value)))
                    .or_default()
                    .push(format!("{pid}:{comm}"));
            }
        }
    }
    for ((name, value), procs) in injected {
        findings.push(
            Finding::new(Severity::Medium, format!("{} processes started with {name}={value}", procs.len()))
                .detail("the dynamic loader injects these libraries into every listed process; confirm the library is expected")
                .evidence("variable", name)
                .evidence("value", value)
                .evidence("processes", procs),
        );
    }
    let mut summary = format!(
        "checked /etc/ld.so.preload and the environment of {} processes",
        pids.len() - unreadable
    );
    if unreadable > 0 {
        summary.push_str(&format!(", {unreadable} not readable without root"));
    }
    Ok(Outcome::done(summary, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> Names {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn stable_diff_ignores_churn() {
        let r1 = set(&["a", "b", "hidden", "tmp1"]);
        let r2 = set(&["a", "b", "hidden"]);
        let r3 = set(&["a", "b", "hidden", "tmp2"]);
        let l1 = set(&["a", "b", "tmp1"]);
        let l2 = set(&["a", "b", "fake"]);
        let d = stable_diff([&r1, &r2, &r3], [&l1, &l2]);
        assert_eq!(d.hidden, set(&["hidden"]));
        assert!(d.phantom.is_empty());
        let l2 = set(&["a", "b", "fake"]);
        let l1 = set(&["a", "fake"]);
        let d = stable_diff([&r1, &r2, &r3], [&l1, &l2]);
        assert_eq!(d.phantom, set(&["fake"]));
    }

    #[test]
    fn socket_keys() {
        let data = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n";
        let k = keys(data, Key::Socket);
        assert_eq!(k, set(&["0100007F:0277 00000000:0000 0A 23456"]));
    }

    #[test]
    fn preload_parsing() {
        assert_eq!(
            parse_preload(b"/lib/a.so /lib/b.so\n:/lib/c.so\t\n"),
            vec!["/lib/a.so", "/lib/b.so", "/lib/c.so"]
        );
        assert!(parse_preload(b"\n\n").is_empty());
    }

    #[test]
    fn clean_views_agree() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert_eq!(
            compare(|| raw_names(&dir), || libc_names(&dir)).unwrap(),
            None
        );
        assert!(
            file_findings(Path::new("/proc/modules"), Key::FirstToken)
                .unwrap()
                .is_empty()
        );
        assert!(
            file_findings(Path::new("/nonexistent/vantage"), Key::Line)
                .unwrap()
                .is_empty()
        );
    }
}
