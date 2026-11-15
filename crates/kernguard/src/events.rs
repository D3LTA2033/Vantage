use vantage_core::json::{self, Value};
use vantage_core::syscalls::Arch;
use vantage_core::text;

pub const EV_EXEC: u32 = 1;
pub const EV_CREDS: u32 = 2;
pub const EV_SYSCALL: u32 = 3;
pub const EV_MODULE: u32 = 4;
pub const EV_WATCH: u32 = 5;

pub const HDR_SIZE: usize = 40;
pub const EXEC_SIZE: usize = 376;
pub const CREDS_SIZE: usize = 112;
pub const SYSCALL_SIZE: usize = 376;
pub const WATCH_SIZE: usize = 360;
pub const MODULE_SIZE: usize = 104;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub ts: u64,
    pub comm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exec {
    pub h: Header,
    pub ppid: u32,
    pub euid: u32,
    pub nlink: u32,
    pub filename: String,
    pub dname: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Creds {
    pub h: Header,
    pub syscall: i64,
    pub old_uid: u32,
    pub old_euid: u32,
    pub old_suid: u32,
    pub old_fsuid: u32,
    pub new_uid: u32,
    pub new_euid: u32,
    pub new_suid: u32,
    pub new_fsuid: u32,
    pub old_cap_eff: u64,
    pub old_cap_prm: u64,
    pub new_cap_eff: u64,
    pub new_userns_level: u32,
    pub abi: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syscall {
    pub h: Header,
    pub nr: i64,
    pub abi: u32,
    pub args: [u64; 6],
    pub ret: i64,
    pub duration_ns: u64,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    pub h: Header,
    pub nr: i64,
    pub abi: u32,
    pub args: [u64; 6],
    pub path: String,
}

pub fn syscall_name(arch: Option<Arch>, abi: u32, nr: i64) -> Option<&'static str> {
    arch?.abi(abi)?.name(u64::try_from(nr).ok()?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub h: Header,
    pub taints: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Exec(Exec),
    Creds(Creds),
    Syscall(Syscall),
    Module(Module),
    Watch(Watch),
}

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u32(&self, off: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(
            self.0.get(off..off + 4)?.try_into().ok()?,
        ))
    }

    fn u64(&self, off: usize) -> Option<u64> {
        Some(u64::from_ne_bytes(
            self.0.get(off..off + 8)?.try_into().ok()?,
        ))
    }

    fn i64(&self, off: usize) -> Option<i64> {
        self.u64(off).map(|v| v as i64)
    }

    fn str(&self, off: usize, len: usize) -> Option<String> {
        Some(text::from_cstr_bytes(self.0.get(off..off + len)?))
    }

    fn args(&self, off: usize) -> Option<[u64; 6]> {
        let mut a = [0u64; 6];
        for (i, slot) in a.iter_mut().enumerate() {
            *slot = self.u64(off + i * 8)?;
        }
        Some(a)
    }
}

pub fn parse(data: &[u8]) -> Option<Event> {
    let b = Bytes(data);
    let kind = b.u32(0)?;
    let h = Header {
        pid: b.u32(4)?,
        tgid: b.u32(8)?,
        uid: b.u32(12)?,
        ts: b.u64(16)?,
        comm: b.str(24, 16)?,
    };
    let expected = match kind {
        EV_EXEC => EXEC_SIZE,
        EV_CREDS => CREDS_SIZE,
        EV_SYSCALL => SYSCALL_SIZE,
        EV_MODULE => MODULE_SIZE,
        EV_WATCH => WATCH_SIZE,
        _ => return None,
    };
    if data.len() < expected {
        return None;
    }
    Some(match kind {
        EV_EXEC => Event::Exec(Exec {
            h,
            ppid: b.u32(40)?,
            euid: b.u32(44)?,
            nlink: b.u32(48)?,
            filename: b.str(56, 256)?,
            dname: b.str(312, 64)?,
        }),
        EV_CREDS => Event::Creds(Creds {
            h,
            syscall: b.i64(40)?,
            old_uid: b.u32(48)?,
            old_euid: b.u32(52)?,
            old_suid: b.u32(56)?,
            old_fsuid: b.u32(60)?,
            new_uid: b.u32(64)?,
            new_euid: b.u32(68)?,
            new_suid: b.u32(72)?,
            new_fsuid: b.u32(76)?,
            old_cap_eff: b.u64(80)?,
            old_cap_prm: b.u64(88)?,
            new_cap_eff: b.u64(96)?,
            new_userns_level: b.u32(104)?,
            abi: b.u32(108)?,
        }),
        EV_SYSCALL => Event::Syscall(Syscall {
            h,
            nr: b.i64(40)?,
            abi: b.u32(368)?,
            args: b.args(48)?,
            ret: b.i64(96)?,
            duration_ns: b.u64(104)?,
            path: b.str(112, 256)?,
        }),
        EV_WATCH => Event::Watch(Watch {
            h,
            nr: b.i64(40)?,
            abi: b.u32(352)?,
            args: b.args(48)?,
            path: b.str(96, 256)?,
        }),
        _ => Event::Module(Module {
            h,
            taints: b.u64(40)?,
            name: b.str(48, 56)?,
        }),
    })
}

impl Event {
    pub fn header(&self) -> &Header {
        match self {
            Event::Exec(e) => &e.h,
            Event::Creds(e) => &e.h,
            Event::Syscall(e) => &e.h,
            Event::Module(e) => &e.h,
            Event::Watch(e) => &e.h,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Event::Exec(_) => "exec",
            Event::Creds(_) => "creds",
            Event::Syscall(_) => "syscall",
            Event::Module(_) => "module_load",
            Event::Watch(_) => "watched_syscall",
        }
    }

    pub fn to_json(&self, arch: Option<Arch>) -> Value {
        let syscall =
            |abi: u32, nr: i64| syscall_name(arch, abi, nr).map_or(Value::from(nr), Value::from);
        let abi_name = |abi: u32| {
            arch.and_then(|a| a.abi(abi))
                .map_or(Value::from(abi), |a| a.as_str().into())
        };
        let h = self.header();
        let mut pairs: Vec<(String, Value)> = vec![
            ("type".into(), self.kind().into()),
            ("pid".into(), h.pid.into()),
            ("tgid".into(), h.tgid.into()),
            ("uid".into(), h.uid.into()),
            ("comm".into(), h.comm.clone().into()),
            ("boot_ns".into(), h.ts.into()),
        ];
        let hex_args =
            |a: &[u64; 6]| Value::Array(a.iter().map(|v| Value::from(format!("{v:#x}"))).collect());
        let mut add = |k: &str, v: Value| pairs.push((k.to_owned(), v));
        match self {
            Event::Exec(e) => {
                add("ppid", e.ppid.into());
                add("euid", e.euid.into());
                add("filename", e.filename.clone().into());
                add("file", e.dname.clone().into());
                add("nlink", e.nlink.into());
            }
            Event::Creds(e) => {
                add("syscall", syscall(e.abi, e.syscall));
                add("abi", abi_name(e.abi));
                add(
                    "old",
                    json::obj([
                        ("uid", e.old_uid.into()),
                        ("euid", e.old_euid.into()),
                        ("suid", e.old_suid.into()),
                        ("fsuid", e.old_fsuid.into()),
                        ("cap_effective", format!("{:#x}", e.old_cap_eff).into()),
                        ("cap_permitted", format!("{:#x}", e.old_cap_prm).into()),
                    ]),
                );
                add(
                    "new",
                    json::obj([
                        ("uid", e.new_uid.into()),
                        ("euid", e.new_euid.into()),
                        ("suid", e.new_suid.into()),
                        ("fsuid", e.new_fsuid.into()),
                        ("cap_effective", format!("{:#x}", e.new_cap_eff).into()),
                        ("userns_level", e.new_userns_level.into()),
                    ]),
                );
            }
            Event::Syscall(e) => {
                add("syscall", syscall(e.abi, e.nr));
                add("abi", abi_name(e.abi));
                add("args", hex_args(&e.args));
                add("path", (!e.path.is_empty()).then(|| e.path.clone()).into());
                add("ret", e.ret.into());
                add("duration_ns", e.duration_ns.into());
            }
            Event::Watch(e) => {
                add("syscall", syscall(e.abi, e.nr));
                add("abi", abi_name(e.abi));
                add("args", hex_args(&e.args));
                add("path", (!e.path.is_empty()).then(|| e.path.clone()).into());
            }
            Event::Module(e) => {
                add("module", e.name.clone().into());
                add("taints", format!("{:#x}", e.taints).into());
            }
        }
        Value::Object(pairs)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn header_bytes(kind: u32, size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size];
        b[0..4].copy_from_slice(&kind.to_ne_bytes());
        b[4..8].copy_from_slice(&100u32.to_ne_bytes());
        b[8..12].copy_from_slice(&99u32.to_ne_bytes());
        b[12..16].copy_from_slice(&1000u32.to_ne_bytes());
        b[16..24].copy_from_slice(&123456u64.to_ne_bytes());
        b[24..28].copy_from_slice(b"bash");
        b
    }

    #[test]
    fn exec_layout() {
        let mut b = header_bytes(EV_EXEC, EXEC_SIZE);
        b[40..44].copy_from_slice(&1u32.to_ne_bytes());
        b[44..48].copy_from_slice(&0u32.to_ne_bytes());
        b[56..66].copy_from_slice(b"/dev/fd/3\0");
        b[312..322].copy_from_slice(b"memfd:x\0\0\0");
        let Some(Event::Exec(e)) = parse(&b) else {
            panic!()
        };
        assert_eq!(
            (e.h.pid, e.h.tgid, e.h.uid, e.h.ts),
            (100, 99, 1000, 123456)
        );
        assert_eq!(e.h.comm, "bash");
        assert_eq!(e.ppid, 1);
        assert_eq!(e.filename, "/dev/fd/3");
        assert_eq!(e.dname, "memfd:x");
    }

    #[test]
    fn creds_layout() {
        let mut b = header_bytes(EV_CREDS, CREDS_SIZE);
        b[40..48].copy_from_slice(&59i64.to_ne_bytes());
        b[52..56].copy_from_slice(&1000u32.to_ne_bytes());
        b[68..72].copy_from_slice(&0u32.to_ne_bytes());
        b[96..104].copy_from_slice(&u64::MAX.to_ne_bytes());
        b[108..112].copy_from_slice(&1u32.to_ne_bytes());
        let Some(Event::Creds(c)) = parse(&b) else {
            panic!()
        };
        assert_eq!(c.syscall, 59);
        assert_eq!(c.old_euid, 1000);
        assert_eq!(c.new_cap_eff, u64::MAX);
        assert_eq!(c.abi, 1);
        let v = Event::Creds(c).to_json(Some(Arch::X86_64));
        assert_eq!(v.get("abi").and_then(Value::as_str), Some("i386"));
        assert_eq!(
            v.get("syscall").and_then(Value::as_str),
            Some("oldolduname")
        );
    }

    #[test]
    fn syscall_and_watch_layout() {
        let mut b = header_bytes(EV_SYSCALL, SYSCALL_SIZE);
        b[40..48].copy_from_slice(&257i64.to_ne_bytes());
        b[56..64].copy_from_slice(&0xdeadu64.to_ne_bytes());
        b[96..104].copy_from_slice(&(-2i64).to_ne_bytes());
        b[104..112].copy_from_slice(&5000u64.to_ne_bytes());
        b[112..123].copy_from_slice(b"/etc/shadow");
        b[368..372].copy_from_slice(&2u32.to_ne_bytes());
        let Some(Event::Syscall(s)) = parse(&b) else {
            panic!()
        };
        assert_eq!(
            (s.nr, s.args[1], s.ret, s.duration_ns, s.abi),
            (257, 0xdead, -2, 5000, 2)
        );
        assert_eq!(s.path, "/etc/shadow");
        assert_eq!(
            syscall_name(Some(Arch::X86_64), s.abi, s.nr),
            Some("openat")
        );
        assert_eq!(syscall_name(Some(Arch::Aarch64), s.abi, s.nr), None);

        let mut w = header_bytes(EV_WATCH, WATCH_SIZE);
        w[40..48].copy_from_slice(&26i64.to_ne_bytes());
        w[48..56].copy_from_slice(&16u64.to_ne_bytes());
        w[352..356].copy_from_slice(&1u32.to_ne_bytes());
        let Some(Event::Watch(w)) = parse(&w) else {
            panic!()
        };
        assert_eq!((w.nr, w.args[0], w.abi), (26, 16, 1));
        assert_eq!(
            syscall_name(Some(Arch::X86_64), w.abi, w.nr),
            Some("ptrace")
        );
        assert_eq!(
            syscall_name(Some(Arch::Aarch64), w.abi, w.nr),
            Some("ptrace")
        );
        assert_eq!(syscall_name(Some(Arch::X86_64), 0, w.nr), Some("msync"));
    }

    #[test]
    fn module_layout_and_rejects() {
        let mut b = header_bytes(EV_MODULE, MODULE_SIZE);
        b[40..48].copy_from_slice(&(1u64 << 13).to_ne_bytes());
        b[48..59].copy_from_slice(b"diamorphine");
        let Some(Event::Module(m)) = parse(&b) else {
            panic!()
        };
        assert_eq!(m.name, "diamorphine");
        assert_eq!(m.taints, 1 << 13);
        assert!(parse(&b[..MODULE_SIZE - 1]).is_none());
        assert!(parse(&header_bytes(99, 400)).is_none());
        assert!(parse(&[0u8; 8]).is_none());
    }
}
