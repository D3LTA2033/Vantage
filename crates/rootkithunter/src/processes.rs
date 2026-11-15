use crate::Options;
use std::collections::BTreeSet;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use vantage_core::{Finding, IoContext, Outcome, Result, Severity, proc, rawsys, sys, text};

pub fn raw_pids(path: &Path) -> io::Result<BTreeSet<u32>> {
    Ok(rawsys::read_dir(path)?
        .into_iter()
        .filter_map(|e| proc::parse_pid(&e.name))
        .collect())
}

pub fn raw_visible_ids() -> Result<(BTreeSet<u32>, BTreeSet<u32>)> {
    let pids = raw_pids(Path::new("/proc")).context("getdents64 /proc")?;
    let mut ids = pids.clone();
    for pid in &pids {
        if let Ok(tasks) = raw_pids(Path::new(&format!("/proc/{pid}/task"))) {
            ids.extend(tasks);
        }
    }
    Ok((pids, ids))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Probe {
    pub kill: bool,
    pub getpgid: bool,
}

impl Probe {
    pub fn any(self) -> bool {
        self.kill || self.getpgid
    }

    pub fn names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.kill {
            v.push("kill");
        }
        if self.getpgid {
            v.push("getpgid");
        }
        v
    }
}

pub fn probe(pid: u32) -> Probe {
    let Ok(pid) = i32::try_from(pid) else {
        return Probe::default();
    };
    let kill = rawsys::pid_exists(pid);
    let getpgid = match rawsys::getpgid(pid) {
        Ok(_) => true,
        Err(e) => e.raw_os_error() == Some(libc::EPERM),
    };
    Probe { kill, getpgid }
}

pub fn sweep(lo: u32, hi: u32, visible: &BTreeSet<u32>) -> Vec<u32> {
    if hi < lo {
        return Vec::new();
    }
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(16) as u32;
    let span = (hi - lo) / threads + 1;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let start = lo.saturating_add(t * span);
                let end = start.saturating_add(span - 1).min(hi);
                scope.spawn(move || {
                    (start..=end)
                        .filter(|pid| start <= hi && !visible.contains(pid) && probe(*pid).any())
                        .collect::<Vec<u32>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

fn raw_text(path: &str) -> Option<String> {
    let data = rawsys::read_file(Path::new(path), 1 << 20).ok()?;
    Some(text::from_bytes(data.strip_suffix(b"\n").unwrap_or(&data)))
}

pub fn hidden_processes(opts: &Options) -> Result<Outcome> {
    let max = opts.pid_max.unwrap_or_else(sys::pid_max);
    let (_, visible) = raw_visible_ids()?;
    let candidates = sweep(1, max, &visible);
    let mut findings = Vec::new();
    if !candidates.is_empty() {
        let (_, visible) = raw_visible_ids()?;
        for pid in candidates {
            if visible.contains(&pid) {
                continue;
            }
            let p = probe(pid);
            if !p.any() {
                continue;
            }
            let status = raw_text(&format!("/proc/{pid}/status"));
            let field = |k: &str| {
                status
                    .as_deref()
                    .and_then(|s| proc::status_field(s, k))
                    .map(str::to_owned)
            };
            let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| text::from_path(&p));
            findings.push(
                Finding::new(Severity::Critical, format!("process {pid} hidden from /proc"))
                    .detail("the PID answers syscall probes but getdents64 on /proc and on every /proc/<pid>/task does not return it; this is what kernel-level getdents/filldir hooks produce")
                    .evidence("pid", pid)
                    .evidence("probes", p.names())
                    .evidence("comm", raw_text(&format!("/proc/{pid}/comm")))
                    .evidence("exe", exe)
                    .evidence("tgid", field("Tgid"))
                    .evidence("ppid", field("PPid"))
                    .evidence("uid", field("Uid")),
            );
        }
    }
    Ok(Outcome::done(
        format!(
            "probed PIDs 1..={max} against {} visible task IDs",
            visible.len()
        ),
        findings,
    ))
}

const WRITABLE_PREFIXES: [&[u8]; 4] = [b"/tmp/", b"/dev/shm/", b"/var/tmp/", b"/run/shm/"];

fn in_writable_dir(path: &[u8]) -> bool {
    if WRITABLE_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    let p = Path::new(std::ffi::OsStr::from_bytes(path));
    p.parent().is_some_and(proc::is_world_writable_dir)
}

pub fn classify_exe(path: &[u8]) -> Option<(Severity, &'static str, &'static str)> {
    if path.starts_with(b"/memfd:") {
        if path.windows(11).any(|w| w == b"runc_cloned") {
            return Some((
                Severity::Low,
                "process executing from memfd (runc self-clone)",
                "runc re-executes itself from a sealed memfd as a CVE-2019-5736 mitigation; the name is set by the process and is not proof of origin",
            ));
        }
        return Some((
            Severity::High,
            "process executing from memfd",
            "the executable exists only in memory (memfd_create + execve), a common fileless malware technique",
        ));
    }
    if let Some(orig) = path.strip_suffix(b" (deleted)") {
        if in_writable_dir(orig) {
            return Some((
                Severity::High,
                "deleted executable from world-writable directory",
                "the binary was started from a world-writable location and then removed from disk",
            ));
        }
        return Some((
            Severity::Low,
            "executable deleted from disk",
            "commonly caused by package upgrades of long-running processes; also used to remove dropped payloads",
        ));
    }
    if in_writable_dir(path) {
        return Some((
            Severity::Medium,
            "process running from world-writable directory",
            "executables in /tmp, /dev/shm or similar can be written by any user",
        ));
    }
    None
}

pub fn executables(_: &Options) -> Result<Outcome> {
    let pids = raw_pids(Path::new("/proc")).context("getdents64 /proc")?;
    let mut findings = Vec::new();
    let mut unreadable = 0usize;
    let mut inspected = 0usize;
    let mut replaced = Vec::new();
    for pid in &pids {
        let exe = match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                unreadable += 1;
                continue;
            }
            Err(_) => continue,
        };
        inspected += 1;
        let bytes = exe.as_os_str().as_bytes();
        if let Some((sev, title, detail)) = classify_exe(bytes) {
            if sev == Severity::Low && !bytes.starts_with(b"/memfd:") {
                replaced.push(format!("{pid}:{}", text::from_bytes(bytes)));
                continue;
            }
            let status = proc::ProcStatus::read(*pid).ok();
            findings.push(
                Finding::new(sev, title)
                    .detail(detail)
                    .evidence("pid", *pid)
                    .evidence("exe", text::from_bytes(bytes))
                    .evidence("comm", status.as_ref().map(|s| s.name.clone()))
                    .evidence("uid", status.as_ref().map(|s| s.uid[0]))
                    .evidence("cmdline", proc::cmdline(*pid).ok()),
            );
        }
    }
    if !replaced.is_empty() {
        findings.push(
            Finding::new(
                Severity::Low,
                format!("{} processes run executables deleted from disk", replaced.len()),
            )
            .detail("usually long-running processes whose package was upgraded; dropped payloads are also deleted after start")
            .evidence("processes", replaced),
        );
    }
    let mut summary = format!("{inspected} executables inspected");
    if unreadable > 0 {
        summary.push_str(&format!(
            ", {unreadable} processes not readable without root"
        ));
    }
    Ok(Outcome::done(summary, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_classification() {
        assert_eq!(classify_exe(b"/usr/bin/bash"), None);
        assert_eq!(
            classify_exe(b"/memfd:payload (deleted)").unwrap().0,
            Severity::High
        );
        assert_eq!(
            classify_exe(b"/memfd:runc_cloned:/proc/self/exe (deleted)")
                .unwrap()
                .0,
            Severity::Low
        );
        assert_eq!(
            classify_exe(b"/usr/bin/sshd (deleted)").unwrap().0,
            Severity::Low
        );
        assert_eq!(
            classify_exe(b"/tmp/.x/miner (deleted)").unwrap().0,
            Severity::High
        );
        assert_eq!(classify_exe(b"/dev/shm/a").unwrap().0, Severity::Medium);
    }

    #[test]
    fn self_is_visible_and_probes_positive() {
        let me = std::process::id();
        let (pids, ids) = raw_visible_ids().unwrap();
        assert!(pids.contains(&me));
        assert!(ids.contains(&me));
        assert_eq!(
            probe(me),
            Probe {
                kill: true,
                getpgid: true
            }
        );
        assert!(!probe(u32::MAX).any());
    }

    #[test]
    fn threads_are_counted_as_visible() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() } as u32).unwrap();
            let _ = done_rx.recv();
        });
        let tid = rx.recv().unwrap();
        let (pids, ids) = raw_visible_ids().unwrap();
        assert!(!pids.contains(&tid));
        assert!(ids.contains(&tid));
        assert!(probe(tid).any());
        done_tx.send(()).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn clean_scan_of_low_pid_range() {
        let out = hidden_processes(&Options {
            pid_max: Some(std::process::id()),
            ..Default::default()
        })
        .unwrap();
        match out {
            Outcome::Done { findings, .. } => assert!(findings.is_empty(), "{findings:?}"),
            Outcome::Skipped(r) => panic!("skipped: {r}"),
        }
    }
}
