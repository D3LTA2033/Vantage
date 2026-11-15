use crate::ENGINE;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use vantage_core::sys::{self, cap_names};
use vantage_core::{CheckResult, Finding, Outcome, Result, Severity, proc, text};

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub extra_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
enum Want {
    Min(i64),
    Eq(i64),
    Ne(i64),
}

impl Want {
    fn ok(self, v: i64) -> bool {
        match self {
            Want::Min(m) => v >= m,
            Want::Eq(e) => v == e,
            Want::Ne(n) => v != n,
        }
    }

    fn describe(self) -> String {
        match self {
            Want::Min(m) => format!("at least {m}"),
            Want::Eq(e) => format!("exactly {e}"),
            Want::Ne(n) => format!("anything but {n}"),
        }
    }
}

const KNOBS: [(&str, Want, Severity, &str); 18] = [
    (
        "kernel.kptr_restrict",
        Want::Min(1),
        Severity::Medium,
        "kernel pointers in /proc and logs help defeat KASLR",
    ),
    (
        "kernel.dmesg_restrict",
        Want::Eq(1),
        Severity::Low,
        "unprivileged users can read the kernel log, which leaks addresses and state",
    ),
    (
        "kernel.unprivileged_bpf_disabled",
        Want::Min(1),
        Severity::Medium,
        "unprivileged BPF has been a recurring local privilege escalation vector",
    ),
    (
        "net.core.bpf_jit_harden",
        Want::Eq(2),
        Severity::Low,
        "constant blinding in the BPF JIT mitigates JIT spraying",
    ),
    (
        "kernel.perf_event_paranoid",
        Want::Min(2),
        Severity::Medium,
        "perf events expose kernel profiling and a large attack surface to unprivileged users",
    ),
    (
        "kernel.yama.ptrace_scope",
        Want::Min(1),
        Severity::Medium,
        "any process can ptrace every other process of the same user",
    ),
    (
        "kernel.kexec_load_disabled",
        Want::Eq(1),
        Severity::Low,
        "root can replace the running kernel with kexec",
    ),
    (
        "kernel.sysrq",
        Want::Ne(1),
        Severity::Low,
        "every magic SysRq function is enabled from the keyboard",
    ),
    (
        "fs.protected_symlinks",
        Want::Eq(1),
        Severity::Medium,
        "symlink races in sticky world-writable directories are possible",
    ),
    (
        "fs.protected_hardlinks",
        Want::Eq(1),
        Severity::Medium,
        "users can hardlink files they do not own",
    ),
    (
        "fs.protected_fifos",
        Want::Min(1),
        Severity::Low,
        "FIFO spoofing in sticky world-writable directories is possible",
    ),
    (
        "fs.protected_regular",
        Want::Min(1),
        Severity::Low,
        "regular file spoofing in sticky world-writable directories is possible",
    ),
    (
        "fs.suid_dumpable",
        Want::Eq(0),
        Severity::Medium,
        "setuid processes may write core dumps containing privileged memory",
    ),
    (
        "kernel.randomize_va_space",
        Want::Eq(2),
        Severity::High,
        "address space layout randomization is weakened or off",
    ),
    (
        "vm.mmap_min_addr",
        Want::Min(4096),
        Severity::High,
        "user space can map page zero, making NULL dereference bugs exploitable",
    ),
    (
        "vm.unprivileged_userfaultfd",
        Want::Eq(0),
        Severity::Low,
        "userfaultfd makes kernel race conditions easier to win",
    ),
    (
        "dev.tty.ldisc_autoload",
        Want::Eq(0),
        Severity::Low,
        "unprivileged users can autoload TTY line disciplines",
    ),
    (
        "kernel.io_uring_disabled",
        Want::Min(1),
        Severity::Info,
        "io_uring is available to every user",
    ),
];

pub fn hardening(_: &Options) -> Result<Outcome> {
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    let mut unreadable = Vec::new();
    for (name, want, sev, why) in KNOBS {
        match sys::sysctl_int(name) {
            Ok(Some(v)) if !want.ok(v) => findings.push(
                Finding::new(sev, format!("{name} = {v}"))
                    .detail(why)
                    .evidence("sysctl", name)
                    .evidence("value", v)
                    .evidence("recommended", want.describe()),
            ),
            Ok(Some(_)) => {}
            Ok(None) => missing.push(name),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => unreadable.push(name),
            Err(e) => return Err(vantage_core::Error::io(format!("read {name}"), e)),
        }
    }
    let userns = sys::sysctl_int("user.max_user_namespaces")
        .ok()
        .flatten()
        .unwrap_or(0);
    let clone = sys::sysctl_int("kernel.unprivileged_userns_clone")
        .ok()
        .flatten();
    let apparmor = sys::sysctl_int("kernel.apparmor_restrict_unprivileged_userns")
        .ok()
        .flatten();
    if userns > 0 && clone != Some(0) && apparmor != Some(1) {
        findings.push(
            Finding::new(Severity::Info, "unprivileged user namespaces enabled")
                .detail("unprivileged users can reach namespace-gated kernel code, a frequent source of privilege escalation bugs")
                .evidence("user.max_user_namespaces", userns),
        );
    }
    let mut summary = format!(
        "{} kernel settings checked",
        KNOBS.len() - missing.len() - unreadable.len()
    );
    if !missing.is_empty() {
        summary.push_str(&format!(
            "; not present on this kernel: {}",
            missing.join(", ")
        ));
    }
    if !unreadable.is_empty() {
        summary.push_str(&format!(
            "; unreadable without root: {}",
            unreadable.join(", ")
        ));
    }
    Ok(Outcome::done(summary, findings))
}

pub fn secure_boot() -> Option<bool> {
    let dir = std::fs::read_dir("/sys/firmware/efi/efivars").ok()?;
    for e in dir.flatten() {
        if e.file_name()
            .as_bytes()
            .starts_with(b"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        {
            let data = std::fs::read(e.path()).ok()?;
            return data.last().map(|&b| b == 1);
        }
    }
    None
}

pub fn lockdown(_: &Options) -> Result<Outcome> {
    let mut findings = Vec::new();
    match sys::lockdown().as_deref() {
        Some("none") => findings.push(
            Finding::new(Severity::Low, "kernel lockdown disabled")
                .detail("root can modify the running kernel through /dev/mem, kprobes, unsigned kexec and similar interfaces"),
        ),
        Some(_) => {}
        None => findings.push(Finding::new(Severity::Info, "lockdown LSM not available")),
    }
    match std::fs::read_to_string("/sys/module/module/parameters/sig_enforce") {
        Ok(v) if v.trim() == "N" => findings.push(
            Finding::new(Severity::Medium, "module signature enforcement off")
                .detail("unsigned kernel modules load after only tainting the kernel"),
        ),
        Ok(_) => {}
        Err(_) => findings.push(Finding::new(
            Severity::Low,
            "kernel built without module signature verification",
        )),
    }
    if sys::sysctl_int("kernel.modules_disabled").ok().flatten() == Some(0) {
        findings.push(
            Finding::new(Severity::Info, "runtime module loading allowed")
                .detail("kernel.modules_disabled=1 blocks all further module loads until reboot"),
        );
    }
    match secure_boot() {
        Some(false) => findings.push(Finding::new(Severity::Low, "UEFI Secure Boot disabled")),
        Some(true) => {}
        None if Path::new("/sys/firmware/efi").exists() => {}
        None => findings.push(Finding::new(Severity::Info, "not booted through UEFI")),
    }
    Ok(Outcome::done(
        format!(
            "lockdown: {}",
            sys::lockdown().unwrap_or_else(|| "n/a".into())
        ),
        findings,
    ))
}

pub const DANGEROUS_CAPS: u64 = (1 << 0)
    | (1 << sys::CAP_DAC_OVERRIDE)
    | (1 << sys::CAP_DAC_READ_SEARCH)
    | (1 << 3)
    | (1 << sys::CAP_SETGID)
    | (1 << sys::CAP_SETUID)
    | (1 << sys::CAP_SYS_MODULE)
    | (1 << sys::CAP_SYS_RAWIO)
    | (1 << sys::CAP_SYS_PTRACE)
    | (1 << sys::CAP_SYS_ADMIN)
    | (1 << 31)
    | (1 << sys::CAP_BPF);

fn user_ns(pid: &str) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/ns/user")).ok()
}

pub fn processes(_: &Options) -> Result<Outcome> {
    let reference = user_ns("1").or_else(|| user_ns("self"));
    let mut findings = Vec::new();
    let mut inspected = 0usize;
    for pid in proc::list_pids().map_err(|e| vantage_core::Error::io("list /proc", e))? {
        let Ok(st) = proc::ProcStatus::read(pid) else {
            continue;
        };
        inspected += 1;
        let ns = user_ns(&pid.to_string());
        if let (Some(ns), Some(r)) = (&ns, &reference)
            && ns != r
        {
            continue;
        }
        let ns_note = if ns.is_some() {
            "initial"
        } else {
            "unknown (not readable)"
        };
        let euid = st.uid[1];
        let held = st.cap_eff & DANGEROUS_CAPS;
        let mk = |f: Finding| {
            f.evidence("pid", pid)
                .evidence("comm", st.name.as_str())
                .evidence("uid", st.uid[0])
                .evidence("euid", euid)
                .evidence("user_namespace", ns_note)
        };
        if euid != 0 && held != 0 {
            findings.push(mk(Finding::new(
                Severity::Medium,
                format!(
                    "non-root process {} holds {}",
                    st.name,
                    cap_names(held).join(",")
                ),
            )
            .detail(
                "these capabilities are each sufficient or nearly sufficient to become root",
            )));
        }
        if st.cap_amb != 0 && euid != 0 {
            findings.push(mk(Finding::new(
                Severity::Low,
                format!("process {} has ambient capabilities", st.name),
            )
            .detail("ambient capabilities survive execve of unprivileged programs")
            .evidence("ambient", cap_names(st.cap_amb))));
        }
        if st.uid[0] != 0 && euid == 0 {
            findings.push(mk(Finding::new(
                Severity::Info,
                format!("process {} running setuid root", st.name),
            )));
        }
    }
    Ok(Outcome::done(
        format!("{inspected} processes inspected"),
        findings,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCaps {
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
    pub rootid: Option<u32>,
}

pub fn parse_vfs_caps(d: &[u8]) -> Option<FileCaps> {
    let le = |off: usize| {
        d.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let magic = le(0)?;
    let effective = magic & 1 != 0;
    match magic & 0xff00_0000 {
        0x0100_0000 => Some(FileCaps {
            permitted: u64::from(le(4)?),
            inheritable: u64::from(le(8)?),
            effective,
            rootid: None,
        }),
        rev @ (0x0200_0000 | 0x0300_0000) => Some(FileCaps {
            permitted: u64::from(le(4)?) | (u64::from(le(12)?) << 32),
            inheritable: u64::from(le(8)?) | (u64::from(le(16)?) << 32),
            effective,
            rootid: if rev == 0x0300_0000 {
                Some(le(20)?)
            } else {
                None
            },
        }),
        _ => None,
    }
}

fn file_caps(path: &Path) -> Option<FileCaps> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::lgetxattr(
            c.as_ptr(),
            c"security.capability".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n <= 0 {
        return None;
    }
    parse_vfs_caps(&buf[..n as usize])
}

#[derive(Debug, Clone)]
pub struct PrivilegedFile {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub caps: Option<FileCaps>,
}

impl PrivilegedFile {
    pub fn setuid(&self) -> bool {
        self.mode & 0o4000 != 0
    }

    pub fn setgid(&self) -> bool {
        self.mode & 0o2000 != 0 && self.mode & 0o010 != 0
    }
}

pub const DEFAULT_ROOTS: [&str; 13] = [
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/local/lib",
    "/opt",
    "/bin",
    "/sbin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

pub fn find_privileged(extra: &[PathBuf]) -> (Vec<PrivilegedFile>, usize) {
    let mut roots: Vec<PathBuf> = Vec::new();
    for r in DEFAULT_ROOTS
        .iter()
        .map(PathBuf::from)
        .chain(extra.iter().cloned())
    {
        if let Ok(c) = std::fs::canonicalize(&r)
            && !roots.contains(&c)
        {
            roots.push(c);
        }
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut scanned = 0usize;
    let mut stack = roots;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(m) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !seen.insert((m.dev(), m.ino())) {
                continue;
            }
            if m.is_dir() {
                stack.push(path);
                continue;
            }
            if !m.is_file() {
                continue;
            }
            scanned += 1;
            let mode = m.mode();
            let special = mode & 0o6000 != 0;
            let caps = if mode & 0o111 != 0 {
                file_caps(&path)
            } else {
                None
            };
            if special || caps.is_some() {
                out.push(PrivilegedFile {
                    path,
                    dev: m.dev(),
                    ino: m.ino(),
                    mode,
                    uid: m.uid(),
                    gid: m.gid(),
                    caps,
                });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    (out, scanned)
}

const INTERPRETERS: [&str; 16] = [
    "python", "perl", "ruby", "node", "bash", "sh", "dash", "zsh", "php", "lua", "gdb", "vim",
    "env", "busybox", "tclsh", "awk",
];

fn in_writable_location(path: &Path) -> bool {
    let p = path.as_os_str().as_bytes();
    [b"/tmp/".as_slice(), b"/var/tmp/", b"/dev/shm/"]
        .iter()
        .any(|w| p.starts_with(w))
        || path.parent().is_some_and(proc::is_world_writable_dir)
}

fn replaceable_dir(dir: &Path) -> bool {
    std::fs::metadata(dir).is_ok_and(|m| {
        let mode = m.permissions().mode();
        let sticky = mode & 0o1000 != 0;
        m.uid() != 0 || (!sticky && (mode & 0o002 != 0 || (mode & 0o020 != 0 && m.gid() != 0)))
    })
}

pub fn file_findings(f: &PrivilegedFile) -> Vec<Finding> {
    let shown = text::from_path(&f.path);
    let mut out = Vec::new();
    let special = f.setuid() || f.setgid();
    let kind = if f.setuid() { "setuid" } else { "setgid" };
    if special && f.mode & 0o022 != 0 {
        out.push(
            Finding::new(
                Severity::Critical,
                format!("{kind} file writable by group or others: {shown}"),
            )
            .detail(
                "anyone with write access can replace the code that runs with elevated privileges",
            ),
        );
    }
    if special && in_writable_location(&f.path) {
        out.push(
            Finding::new(
                Severity::High,
                format!("{kind} file in world-writable location: {shown}"),
            )
            .detail(
                "a classic persistence backdoor is a setuid copy of a shell in /tmp or /dev/shm",
            ),
        );
    }
    if f.setuid() && f.uid != 0 {
        out.push(Finding::new(
            Severity::Medium,
            format!("setuid file owned by uid {}: {shown}", f.uid),
        ));
    }
    if f.setuid() && f.uid == 0 && f.path.parent().is_some_and(replaceable_dir) {
        out.push(
            Finding::new(
                Severity::High,
                format!("setuid root file in a directory non-root users can modify: {shown}"),
            )
            .detail("the binary can be swapped by renaming within the directory"),
        );
    }
    if let Some(c) = f.caps {
        let dangerous = c.permitted & DANGEROUS_CAPS;
        if dangerous != 0 {
            let base = f
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let interp = INTERPRETERS.iter().any(|i| base.starts_with(i));
            let sev = if interp {
                Severity::High
            } else {
                Severity::Low
            };
            out.push(
                Finding::new(sev, format!("file capabilities {} on {shown}", cap_names(dangerous).join(",")))
                    .detail(if interp {
                        "an interpreter with these capabilities lets any user run arbitrary code with them"
                    } else {
                        "a bug in this binary is a direct path to these root-level capabilities"
                    })
                    .evidence("effective", c.effective),
            );
        }
    }
    out.into_iter()
        .map(|x| {
            x.evidence("path", shown.as_str())
                .evidence("mode", format!("{:o}", f.mode & 0o7777))
                .evidence("uid", f.uid)
                .evidence("gid", f.gid)
        })
        .collect()
}

pub fn files_outcome(found: &[PrivilegedFile], scanned: usize) -> Outcome {
    let findings = found.iter().flat_map(file_findings).collect();
    let setuid = found.iter().filter(|f| f.setuid()).count();
    let setgid = found.iter().filter(|f| f.setgid()).count();
    let capped = found.iter().filter(|f| f.caps.is_some()).count();
    Outcome::done(
        format!(
            "{scanned} files scanned; {setuid} setuid, {setgid} setgid, {capped} with file capabilities"
        ),
        findings,
    )
}

pub fn files(opts: &Options) -> Result<Outcome> {
    let (found, scanned) = find_privileged(&opts.extra_paths);
    Ok(files_outcome(&found, scanned))
}

pub type CheckFn = fn(&Options) -> Result<Outcome>;

pub const CHECKS: [(&str, &str, CheckFn); 4] = [
    (
        "hardening",
        "kernel sysctls that reduce local privilege escalation attack surface",
        hardening,
    ),
    (
        "lockdown",
        "lockdown mode, module signature enforcement and Secure Boot",
        lockdown,
    ),
    (
        "privileged-processes",
        "non-root processes holding root-equivalent capabilities",
        processes,
    ),
    (
        "privileged-files",
        "setuid/setgid files and file capabilities with unsafe permissions",
        files,
    ),
];

pub fn run(opts: &Options, only: &[String]) -> Result<Vec<CheckResult>> {
    for id in only {
        if !CHECKS.iter().any(|(c, _, _)| c == id) {
            return Err(vantage_core::Error::usage(format!(
                "unknown kernguard audit check: {id}"
            )));
        }
    }
    Ok(CHECKS
        .iter()
        .filter(|(id, _, _)| only.is_empty() || only.iter().any(|o| o == id))
        .map(|(id, _, f)| CheckResult::run(ENGINE, id, || f(opts)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vfs_caps_parsing() {
        let mut v2 = Vec::new();
        v2.extend_from_slice(&(0x0200_0000u32 | 1).to_le_bytes());
        v2.extend_from_slice(&(1u32 << 13).to_le_bytes());
        v2.extend_from_slice(&0u32.to_le_bytes());
        v2.extend_from_slice(&(1u32 << 7).to_le_bytes());
        v2.extend_from_slice(&0u32.to_le_bytes());
        let c = parse_vfs_caps(&v2).unwrap();
        assert!(c.effective);
        assert_eq!(c.permitted, (1 << 13) | (1u64 << 39));
        assert_eq!(c.rootid, None);
        let mut v3 = v2.clone();
        v3[3] = 0x03;
        v3.extend_from_slice(&1000u32.to_le_bytes());
        assert_eq!(parse_vfs_caps(&v3).unwrap().rootid, Some(1000));
        assert!(parse_vfs_caps(&[0, 0, 0, 9]).is_none());
        assert!(parse_vfs_caps(&v2[..10]).is_none());
    }

    #[test]
    fn want_semantics() {
        assert!(Want::Min(1).ok(2) && !Want::Min(1).ok(0));
        assert!(Want::Eq(2).ok(2) && !Want::Eq(2).ok(1));
        assert!(Want::Ne(1).ok(0) && !Want::Ne(1).ok(1));
    }

    #[test]
    fn privileged_file_rules() {
        let f = PrivilegedFile {
            path: PathBuf::from("/tmp/.x/bash"),
            dev: 0,
            ino: 0,
            mode: 0o104777,
            uid: 0,
            gid: 0,
            caps: None,
        };
        let titles: Vec<Severity> = file_findings(&f).iter().map(|f| f.severity).collect();
        assert!(titles.contains(&Severity::Critical));
        assert!(titles.contains(&Severity::High));
        let py = PrivilegedFile {
            path: PathBuf::from("/usr/bin/python3.12"),
            dev: 0,
            ino: 0,
            mode: 0o100755,
            uid: 0,
            gid: 0,
            caps: Some(FileCaps {
                permitted: 1 << sys::CAP_SETUID,
                inheritable: 0,
                effective: true,
                rootid: None,
            }),
        };
        assert_eq!(file_findings(&py)[0].severity, Severity::High);
        let ping = PrivilegedFile {
            caps: Some(FileCaps {
                permitted: 1 << 13,
                inheritable: 0,
                effective: true,
                rootid: None,
            }),
            path: PathBuf::from("/usr/bin/ping"),
            ..py
        };
        assert!(file_findings(&ping).is_empty());
    }

    #[test]
    fn live_checks_run() {
        for (id, _, f) in CHECKS {
            if id == "privileged-files" {
                continue;
            }
            let r = CheckResult::run(ENGINE, id, || f(&Options::default()));
            assert!(
                !matches!(r.status, vantage_core::Status::Error(_)),
                "{id}: {:?}",
                r.status
            );
        }
    }
}
