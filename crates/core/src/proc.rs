use crate::text;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const PF_KTHREAD: u64 = 0x0020_0000;

pub fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        (k == key).then(|| v.trim())
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcStatus {
    pub pid: u32,
    pub name: String,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: [u32; 4],
    pub gid: [u32; 4],
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_bnd: u64,
    pub cap_amb: u64,
    pub no_new_privs: bool,
    pub seccomp: u8,
}

fn ids(v: Option<&str>) -> Option<[u32; 4]> {
    let mut out = [0u32; 4];
    let mut it = v?.split_whitespace();
    for slot in &mut out {
        *slot = it.next()?.parse().ok()?;
    }
    Some(out)
}

fn hex(v: Option<&str>) -> u64 {
    v.and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0)
}

impl ProcStatus {
    pub fn parse(pid: u32, status: &str) -> Option<Self> {
        let f = |k| status_field(status, k);
        Some(ProcStatus {
            pid,
            name: text::from_bytes(f("Name")?.as_bytes()),
            tgid: f("Tgid")?.parse().ok()?,
            ppid: f("PPid")?.parse().ok()?,
            uid: ids(f("Uid"))?,
            gid: ids(f("Gid"))?,
            cap_inh: hex(f("CapInh")),
            cap_prm: hex(f("CapPrm")),
            cap_eff: hex(f("CapEff")),
            cap_bnd: hex(f("CapBnd")),
            cap_amb: hex(f("CapAmb")),
            no_new_privs: f("NoNewPrivs") == Some("1"),
            seccomp: f("Seccomp").and_then(|s| s.parse().ok()).unwrap_or(0),
        })
    }

    pub fn read(pid: u32) -> io::Result<Self> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        Self::parse(pid, &s)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed status"))
    }
}

pub fn parse_pid(name: &[u8]) -> Option<u32> {
    if name.is_empty() || name.len() > 10 || !name.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(name).ok()?.parse().ok()
}

pub fn list_pids() -> io::Result<Vec<u32>> {
    let mut pids: Vec<u32> = std::fs::read_dir("/proc")?
        .filter_map(|e| parse_pid(e.ok()?.file_name().as_bytes()))
        .collect();
    pids.sort_unstable();
    Ok(pids)
}

pub fn exe(pid: u32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

pub fn cmdline(pid: u32) -> io::Result<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    let parts: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(text::from_bytes)
        .collect();
    Ok(parts.join(" "))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub flags: u64,
    pub start_time: u64,
}

impl ProcStat {
    pub fn parse(stat: &str) -> Option<Self> {
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        let comm = text::from_bytes(stat.get(open + 1..close)?.as_bytes());
        let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
        Some(ProcStat {
            comm,
            state: rest.first()?.chars().next()?,
            ppid: rest.get(1)?.parse().ok()?,
            flags: rest.get(6)?.parse().ok()?,
            start_time: rest.get(19)?.parse().ok()?,
        })
    }

    pub fn read(pid: u32) -> io::Result<Self> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        Self::parse(&s).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed stat"))
    }

    pub fn is_kernel_thread(&self) -> bool {
        self.flags & PF_KTHREAD != 0
    }
}

pub fn is_world_writable_dir(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_dir() && m.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4242\nPPid:\t1\nUid:\t1000\t0\t0\t1000\nGid:\t100\t100\t100\t100\nCapInh:\t0000000000000000\nCapPrm:\t0000000000200000\nCapEff:\t0000000000200000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";

    #[test]
    fn status_parse() {
        let s = ProcStatus::parse(4242, STATUS).unwrap();
        assert_eq!(s.name, "bash");
        assert_eq!(s.tgid, 4242);
        assert_eq!(s.ppid, 1);
        assert_eq!(s.uid, [1000, 0, 0, 1000]);
        assert_eq!(s.cap_eff, 1 << 21);
        assert_eq!(s.cap_bnd, 0x1ff_ffff_ffff);
        assert!(s.no_new_privs);
        assert_eq!(s.seccomp, 2);
        assert!(ProcStatus::parse(1, "Name:\tx\n").is_none());
    }

    #[test]
    fn stat_parse_handles_hostile_comm() {
        let line = "77 (a) b (c) S 1 77 77 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 12345 0 0";
        let s = ProcStat::parse(line).unwrap();
        assert_eq!(s.comm, "a) b (c");
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 1);
        assert_eq!(s.flags, 4194560);
        assert_eq!(s.start_time, 12345);
        let kthread = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0";
        assert!(ProcStat::parse(kthread).unwrap().is_kernel_thread());
    }

    #[test]
    fn pid_names() {
        assert_eq!(parse_pid(b"123"), Some(123));
        assert_eq!(parse_pid(b"self"), None);
        assert_eq!(parse_pid(b""), None);
        assert_eq!(parse_pid(b"99999999999"), None);
    }

    #[test]
    fn live_self() {
        let me = std::process::id();
        assert!(list_pids().unwrap().contains(&me));
        let s = ProcStatus::read(me).unwrap();
        assert_eq!(s.tgid, me);
        assert!(!ProcStat::read(me).unwrap().is_kernel_thread());
        assert!(exe(me).is_ok());
    }
}
