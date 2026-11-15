use crate::json::{self, Value};
use crate::text;
use std::io;
use std::path::PathBuf;

pub const CAPABILITIES: [&str; 41] = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_SYS_MODULE: u32 = 16;
pub const CAP_SYS_RAWIO: u32 = 17;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;

pub fn cap_names(mask: u64) -> Vec<String> {
    (0..64)
        .filter(|bit| mask & (1u64 << bit) != 0)
        .map(|bit| match CAPABILITIES.get(bit as usize) {
            Some(name) => (*name).to_owned(),
            None => format!("cap_{bit}"),
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    pub fn parse(release: &str) -> Option<Self> {
        let mut parts = release.split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(KernelVersion {
            major,
            minor,
            patch,
        })
    }

    pub fn at_least(self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }
}

#[derive(Debug, Clone)]
pub struct Uname {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

pub fn uname() -> Uname {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    let field = |f: &[libc::c_char]| {
        let bytes: Vec<u8> = f.iter().map(|&c| c as u8).collect();
        text::from_cstr_bytes(&bytes)
    };
    Uname {
        sysname: field(&u.sysname),
        nodename: field(&u.nodename),
        release: field(&u.release),
        version: field(&u.version),
        machine: field(&u.machine),
    }
}

pub fn kernel_version() -> Option<KernelVersion> {
    KernelVersion::parse(&uname().release)
}

pub fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn sysctl_path(name: &str) -> PathBuf {
    PathBuf::from("/proc/sys").join(name.replace('.', "/"))
}

pub fn sysctl(name: &str) -> io::Result<Option<String>> {
    match std::fs::read_to_string(sysctl_path(name)) {
        Ok(s) => Ok(Some(s.trim().to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn sysctl_int(name: &str) -> io::Result<Option<i64>> {
    Ok(sysctl(name)?.and_then(|s| s.split_whitespace().next()?.parse().ok()))
}

pub fn effective_caps() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    crate::proc::status_field(&status, "CapEff")
        .and_then(|v| u64::from_str_radix(v, 16).ok())
        .unwrap_or(0)
}

pub fn has_cap(cap: u32) -> bool {
    effective_caps() & (1u64 << cap) != 0
}

pub fn pid_max() -> u32 {
    sysctl_int("kernel.pid_max")
        .ok()
        .flatten()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(32768)
}

pub fn lockdown() -> Option<String> {
    let raw = std::fs::read_to_string("/sys/kernel/security/lockdown").ok()?;
    raw.split_whitespace()
        .find(|w| w.starts_with('[') && w.ends_with(']'))
        .map(|w| w.trim_matches(['[', ']']).to_owned())
}

#[derive(Debug, Clone)]
pub struct Host {
    pub hostname: String,
    pub kernel: String,
    pub machine: String,
    pub euid: u32,
    pub cap_effective: u64,
}

impl Host {
    pub fn current() -> Self {
        let u = uname();
        Host {
            hostname: u.nodename,
            kernel: u.release,
            machine: u.machine,
            euid: euid(),
            cap_effective: effective_caps(),
        }
    }

    pub fn to_json(&self) -> Value {
        json::obj([
            ("hostname", self.hostname.clone().into()),
            ("kernel", self.kernel.clone().into()),
            ("machine", self.machine.clone().into()),
            ("euid", self.euid.into()),
            ("cap_effective", format!("{:#x}", self.cap_effective).into()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_parse() {
        let v = KernelVersion::parse("7.2.2-zen1-1-zen").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (7, 2, 2));
        let v = KernelVersion::parse("5.15.0-91-generic").unwrap();
        assert!(v.at_least(5, 15) && !v.at_least(5, 16));
        let v = KernelVersion::parse("6.1-rc3").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (6, 1, 0));
        assert!(KernelVersion::parse("garbage").is_none());
    }

    #[test]
    fn cap_name_decoding() {
        assert_eq!(cap_names(0), Vec::<String>::new());
        assert_eq!(
            cap_names(1 << CAP_SYS_ADMIN | 1),
            vec!["chown", "sys_admin"]
        );
        assert_eq!(cap_names(1 << 50), vec!["cap_50"]);
    }

    #[test]
    fn live_host_info() {
        let u = uname();
        assert_eq!(u.sysname, "Linux");
        assert!(kernel_version().is_some());
        assert!(pid_max() >= 301);
        assert_eq!(sysctl("kernel.ostype").unwrap().as_deref(), Some("Linux"));
        assert_eq!(sysctl("kernel.does_not_exist_vantage").unwrap(), None);
    }
}
