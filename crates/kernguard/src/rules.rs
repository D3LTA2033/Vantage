use crate::events::{Creds, Event, Exec, Module, Watch, syscall_name};
use vantage_core::sys::{CAP_SETUID, cap_names};
use vantage_core::syscalls::{ABI_NATIVE, Arch};
use vantage_core::{Finding, Severity};

const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_POKEUSER: u64 = 6;
const PTRACE_SETREGS: u64 = 13;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;
const PTRACE_SETREGSET: u64 = 0x4205;
const BPF_PROG_LOAD: u64 = 5;

pub const WATCHED: [&str; 9] = [
    "ptrace",
    "process_vm_writev",
    "memfd_create",
    "init_module",
    "finit_module",
    "delete_module",
    "bpf",
    "kexec_load",
    "kexec_file_load",
];

pub fn findings(event: &Event, arch: Arch) -> Vec<Finding> {
    match event {
        Event::Exec(e) => exec(e),
        Event::Creds(e) => creds(e, arch),
        Event::Module(e) => module(e),
        Event::Watch(e) => watch(e, arch),
        Event::Syscall(_) => Vec::new(),
    }
}

fn base(f: Finding, h: &crate::events::Header) -> Finding {
    f.evidence("pid", h.pid)
        .evidence("tgid", h.tgid)
        .evidence("uid", h.uid)
        .evidence("comm", h.comm.as_str())
}

pub fn exec(e: &Exec) -> Vec<Finding> {
    let mut out = Vec::new();
    if e.dname.starts_with("memfd:") {
        out.push(
            Finding::new(Severity::High, "fileless execution from memfd")
                .detail("the executed file is an anonymous memfd, not a file on disk"),
        );
    } else if e.nlink == 0 {
        out.push(
            Finding::new(Severity::High, "execution of an unlinked file")
                .detail("the executed inode has no directory entry left, so the binary cannot be recovered from the filesystem"),
        );
    }
    if ["/tmp/", "/dev/shm/", "/var/tmp/"]
        .iter()
        .any(|p| e.filename.starts_with(p))
    {
        out.push(Finding::new(
            Severity::Low,
            "execution from world-writable directory",
        ));
    }
    out.into_iter()
        .map(|f| {
            base(f, &e.h)
                .evidence("filename", e.filename.as_str())
                .evidence("file", e.dname.as_str())
                .evidence("ppid", e.ppid)
        })
        .collect()
}

pub fn creds(e: &Creds, arch: Arch) -> Vec<Finding> {
    let uid_gain = (e.new_euid == 0 && e.old_euid != 0)
        || (e.new_uid == 0 && e.old_uid != 0)
        || (e.new_fsuid == 0 && e.old_fsuid != 0);
    let cap_gain = e.new_cap_eff & !e.old_cap_eff;
    if !uid_gain && (cap_gain == 0 || e.new_userns_level > 0) {
        return Vec::new();
    }
    let name = syscall_name(Some(arch), e.abi, e.syscall);
    let base_name = name.map(|n| match n.strip_suffix("32") {
        Some(b) if b.starts_with("set") => b,
        _ => n,
    });
    let had_setuid = e.old_cap_eff & (1 << CAP_SETUID) != 0;
    let (sev, title, detail): (Severity, String, &str) = {
        match base_name {
            Some("execve" | "execveat") => (
                Severity::Info,
                "privileges gained by executing a setuid or file-capability binary".into(),
                "normal for sudo, su, passwd and similar programs",
            ),
            Some(n @ ("setuid" | "setreuid" | "setresuid" | "setfsuid")) => {
                if had_setuid || e.old_uid == 0 || e.old_suid == 0 || e.old_euid == 0 {
                    (
                        Severity::Info,
                        format!("privileges restored via {n}()"),
                        "the process held CAP_SETUID or had uid 0 as its real or saved uid",
                    )
                } else {
                    (
                        Severity::Critical,
                        format!("uid 0 obtained via {n}() without CAP_SETUID or a saved uid of 0"),
                        "the kernel should have refused this transition; credentials were tampered with",
                    )
                }
            }
            Some("capset") => {
                if cap_gain & !e.old_cap_prm == 0 && !uid_gain {
                    (
                        Severity::Info,
                        "capabilities raised within the permitted set".into(),
                        "capset() moved permitted capabilities into the effective set",
                    )
                } else {
                    (
                        Severity::Critical,
                        "capset() raised capabilities outside the permitted set".into(),
                        "the kernel only allows this for privileged callers; credentials were tampered with",
                    )
                }
            }
            Some(n) => (
                Severity::Critical,
                format!("credentials elevated during {n}()"),
                "commit_creds() raised privileges inside a syscall that never changes credentials; this matches kernel exploit payloads such as commit_creds(prepare_kernel_cred(0))",
            ),
            None if e.syscall < 0 => (
                Severity::Critical,
                "credentials elevated outside a syscall".into(),
                "commit_creds() raised privileges in a user task that was not executing a syscall",
            ),
            None => (
                Severity::Medium,
                format!("credentials elevated during unknown syscall {}", e.syscall),
                "the syscall number is not in the table vantage was built with for this ABI; inspect the process",
            ),
        }
    };
    let f = base(Finding::new(sev, title).detail(detail), &e.h)
        .evidence(
            "syscall",
            name.map_or_else(|| e.syscall.to_string(), str::to_owned),
        )
        .evidence("uid_change", format!("{} -> {}", e.old_uid, e.new_uid))
        .evidence("euid_change", format!("{} -> {}", e.old_euid, e.new_euid))
        .evidence(
            "fsuid_change",
            format!("{} -> {}", e.old_fsuid, e.new_fsuid),
        )
        .evidence("caps_gained", cap_names(cap_gain))
        .evidence("userns_level", e.new_userns_level);
    vec![with_abi(f, arch, e.abi)]
}

fn with_abi(f: Finding, arch: Arch, abi: u32) -> Finding {
    if abi == ABI_NATIVE {
        return f;
    }
    let shown = arch
        .abi(abi)
        .map_or_else(|| format!("unknown ({abi})"), |a| a.as_str().to_owned());
    f.evidence("abi", shown)
}

pub fn module(e: &Module) -> Vec<Finding> {
    let mut flags = Vec::new();
    let mut sev = Severity::Medium;
    for (bit, letter, s) in [
        (0, "P", Severity::Medium),
        (12, "O", Severity::High),
        (13, "E", Severity::High),
        (1, "F", Severity::Critical),
    ] {
        if e.taints & (1 << bit) != 0 {
            flags.push(letter);
            sev = sev.max(s);
        }
    }
    vec![base(
        Finding::new(sev, format!("kernel module {} loaded", e.name))
            .detail("modules run with full kernel privileges; unsigned or out-of-tree modules deserve scrutiny"),
        &e.h,
    )
    .evidence("module", e.name.as_str())
    .evidence("taints", flags)]
}

pub fn watch(e: &Watch, arch: Arch) -> Vec<Finding> {
    let Some(name) = syscall_name(Some(arch), e.abi, e.nr) else {
        return Vec::new();
    };
    let a = e.args;
    let f = match name {
        "ptrace" => match a[0] {
            PTRACE_ATTACH | PTRACE_SEIZE => Finding::new(Severity::Medium, format!("ptrace attach to pid {}", a[1]))
                .detail("debuggers do this; so does process injection")
                .evidence("target_pid", a[1]),
            PTRACE_POKETEXT | PTRACE_POKEDATA | PTRACE_POKEUSER => {
                Finding::new(Severity::High, format!("ptrace write into pid {}", a[1])).evidence("target_pid", a[1])
            }
            PTRACE_SETREGS | PTRACE_SETREGSET => {
                Finding::new(Severity::High, format!("ptrace register write in pid {}", a[1]))
                    .evidence("target_pid", a[1])
            }
            _ => return Vec::new(),
        },
        "process_vm_writev" => {
            Finding::new(Severity::High, format!("memory write into pid {}", a[0])).evidence("target_pid", a[0])
        }
        "memfd_create" => Finding::new(Severity::Info, "anonymous memory file created").evidence("name", e.path.as_str()),
        "init_module" => Finding::new(Severity::High, "kernel module loaded from a memory buffer")
            .detail("init_module() takes the image from memory, so no module file needs to exist on disk"),
        "finit_module" => Finding::new(Severity::Medium, "kernel module load requested").evidence("fd", a[0]),
        "delete_module" => Finding::new(Severity::Low, "kernel module unload requested").evidence("module", e.path.as_str()),
        "bpf" if a[0] == BPF_PROG_LOAD => Finding::new(Severity::Medium, "BPF program loaded")
            .detail("BPF programs can observe and alter kernel behaviour; BPF rootkits load this way"),
        "kexec_load" | "kexec_file_load" => Finding::new(Severity::High, "kexec image load")
            .detail("a new kernel image is being staged to replace the running kernel"),
        _ => return Vec::new(),
    };
    vec![with_abi(
        base(f, &e.h).evidence("syscall", name),
        arch,
        e.abi,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Header;

    fn h() -> Header {
        Header {
            pid: 10,
            tgid: 10,
            uid: 1000,
            ts: 0,
            comm: "x".into(),
        }
    }

    fn creds_ev(syscall: &str, old: u32, new: u32) -> Creds {
        Creds {
            h: h(),
            syscall: i64::from(Arch::X86_64.number(syscall).unwrap()),
            old_uid: old,
            old_euid: old,
            old_suid: old,
            old_fsuid: old,
            new_uid: new,
            new_euid: new,
            new_suid: new,
            new_fsuid: new,
            old_cap_eff: 0,
            old_cap_prm: 0,
            new_cap_eff: if new == 0 { 0x1ff_ffff_ffff } else { 0 },
            new_userns_level: 0,
            abi: 0,
        }
    }

    #[test]
    fn setuid_exec_is_info() {
        let f = creds(&creds_ev("execve", 1000, 0), Arch::X86_64);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn exploit_pattern_is_critical() {
        let f = creds(&creds_ev("ioctl", 1000, 0), Arch::X86_64);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].title.contains("ioctl"));
        let mut e = creds_ev("ioctl", 1000, 0);
        e.syscall = -1;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Critical);
    }

    #[test]
    fn setuid_rules() {
        let mut e = creds_ev("setresuid", 1000, 0);
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Critical);
        e.old_suid = 0;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Info);
        let mut e = creds_ev("setuid", 1000, 0);
        e.old_cap_eff = 1 << CAP_SETUID;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Info);
    }

    #[test]
    fn userns_caps_ignored_and_capset() {
        let mut e = creds_ev("unshare", 1000, 1000);
        e.new_cap_eff = 0x1ff_ffff_ffff;
        e.new_userns_level = 1;
        assert!(creds(&e, Arch::X86_64).is_empty());
        let mut e = creds_ev("capset", 1000, 1000);
        e.old_cap_prm = 1 << 10;
        e.new_cap_eff = 1 << 10;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Info);
        e.new_cap_eff = 1 << 21;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Critical);
        let mut e = creds_ev("ioctl", 0, 0);
        e.old_cap_eff = 1;
        e.new_cap_eff = 1;
        assert!(creds(&e, Arch::X86_64).is_empty());
    }

    #[test]
    fn aarch64_numbers_classify() {
        let mut e = creds_ev("execve", 1000, 0);
        e.syscall = i64::from(Arch::Aarch64.number("execve").unwrap());
        assert_eq!(creds(&e, Arch::Aarch64)[0].severity, Severity::Info);
        e.abi = 1;
        let f = creds(&e, Arch::Aarch64);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(
            f[0].evidence_value("syscall").and_then(|v| v.as_str()),
            Some("fcntl64")
        );
        e.syscall = i64::from(Arch::Arm.number("execve").unwrap());
        let f = creds(&e, Arch::Aarch64);
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(
            f[0].evidence_value("abi").and_then(|v| v.as_str()),
            Some("arm")
        );
    }

    #[test]
    fn compat_numbers_classify() {
        let mut e = creds_ev("execve", 1000, 0);
        e.abi = 1;
        e.syscall = i64::from(Arch::I386.number("setuid32").unwrap());
        let f = creds(&e, Arch::X86_64);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].title.contains("setuid()"), "{}", f[0].title);
        e.old_cap_eff = 1 << CAP_SETUID;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Info);
        e.abi = 2;
        e.syscall = i64::from(Arch::X32.number("ptrace").unwrap());
        let f = creds(&e, Arch::X86_64);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(
            f[0].evidence_value("abi").and_then(|v| v.as_str()),
            Some("x32")
        );
        e.abi = 0;
        e.syscall = 999;
        assert_eq!(creds(&e, Arch::X86_64)[0].severity, Severity::Medium);
        assert!(creds_ev("execve", 1000, 0).abi == 0);
        assert!(
            creds(&creds_ev("execve", 1000, 0), Arch::X86_64)[0]
                .evidence_value("abi")
                .is_none()
        );
    }

    #[test]
    fn exec_rules() {
        let mut e = Exec {
            h: h(),
            ppid: 1,
            euid: 1000,
            nlink: 1,
            filename: "/usr/bin/ls".into(),
            dname: "ls".into(),
        };
        assert!(exec(&e).is_empty());
        e.dname = "memfd:payload".into();
        e.nlink = 0;
        e.filename = "/proc/self/fd/3".into();
        let f = exec(&e);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        e.dname = "x".into();
        e.filename = "/tmp/x".into();
        let titles: Vec<String> = exec(&e).into_iter().map(|f| f.title).collect();
        assert_eq!(
            titles,
            vec![
                "execution of an unlinked file",
                "execution from world-writable directory"
            ]
        );
    }

    #[test]
    fn watch_rules() {
        let nr = |n: &str| i64::from(Arch::X86_64.number(n).unwrap());
        let mk = |n: &str, a0: u64| Watch {
            h: h(),
            nr: nr(n),
            abi: 0,
            args: [a0, 4242, 0, 0, 0, 0],
            path: String::new(),
        };
        assert_eq!(
            watch(&mk("ptrace", PTRACE_ATTACH), Arch::X86_64)[0].severity,
            Severity::Medium
        );
        assert_eq!(
            watch(&mk("ptrace", PTRACE_POKETEXT), Arch::X86_64)[0].severity,
            Severity::High
        );
        assert!(watch(&mk("ptrace", 0), Arch::X86_64).is_empty());
        assert_eq!(
            watch(&mk("bpf", BPF_PROG_LOAD), Arch::X86_64)[0].severity,
            Severity::Medium
        );
        assert!(watch(&mk("bpf", 0), Arch::X86_64).is_empty());
        assert_eq!(
            watch(&mk("init_module", 0), Arch::X86_64)[0].severity,
            Severity::High
        );
        assert!(watch(&mk("read", 0), Arch::X86_64).is_empty());
        for name in WATCHED {
            assert!(Arch::X86_64.number(name).is_some(), "{name}");
            assert!(Arch::Aarch64.number(name).is_some(), "{name}");
        }

        let compat = Watch {
            nr: i64::from(Arch::I386.number("ptrace").unwrap()),
            abi: 1,
            ..mk("read", PTRACE_ATTACH)
        };
        let f = watch(&compat, Arch::X86_64);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(
            f[0].evidence_value("abi").and_then(|v| v.as_str()),
            Some("i386")
        );
        let msync = Watch { abi: 0, ..compat };
        assert!(watch(&msync, Arch::X86_64).is_empty());
    }

    #[test]
    fn module_rules() {
        let m = Module {
            h: h(),
            taints: (1 << 12) | (1 << 13),
            name: "rk".into(),
        };
        assert_eq!(module(&m)[0].severity, Severity::High);
        let m = Module { taints: 0, ..m };
        assert_eq!(module(&m)[0].severity, Severity::Medium);
    }
}
