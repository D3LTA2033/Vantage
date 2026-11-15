use std::collections::HashMap;
use std::path::Path;
use vantage_core::syscalls::Arch;

const PATH_ARG_NAMES: [&str; 12] = [
    "filename",
    "pathname",
    "path",
    "oldname",
    "newname",
    "oldpath",
    "newpath",
    "name",
    "uname",
    "specialfile",
    "library",
    "dir_name",
];

const FALLBACK_PATH_ARG: [(&str, u8); 52] = [
    ("open", 1),
    ("creat", 1),
    ("openat", 2),
    ("openat2", 2),
    ("execve", 1),
    ("execveat", 2),
    ("stat", 1),
    ("lstat", 1),
    ("newfstatat", 2),
    ("statx", 2),
    ("access", 1),
    ("faccessat", 2),
    ("faccessat2", 2),
    ("readlink", 1),
    ("readlinkat", 2),
    ("unlink", 1),
    ("unlinkat", 2),
    ("mkdir", 1),
    ("mkdirat", 2),
    ("rmdir", 1),
    ("rename", 1),
    ("renameat", 2),
    ("renameat2", 2),
    ("chmod", 1),
    ("fchmodat", 2),
    ("fchmodat2", 2),
    ("chown", 1),
    ("lchown", 1),
    ("fchownat", 2),
    ("truncate", 1),
    ("chdir", 1),
    ("chroot", 1),
    ("symlink", 1),
    ("symlinkat", 1),
    ("link", 1),
    ("linkat", 2),
    ("mknod", 1),
    ("mknodat", 2),
    ("utimensat", 2),
    ("memfd_create", 1),
    ("delete_module", 1),
    ("statfs", 1),
    ("getxattr", 1),
    ("setxattr", 1),
    ("listxattr", 1),
    ("removexattr", 1),
    ("inotify_add_watch", 2),
    ("umount2", 1),
    ("mount", 2),
    ("swapon", 1),
    ("acct", 1),
    ("pivot_root", 1),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature {
    pub args: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Signatures {
    by_nr: HashMap<u32, Signature>,
    arch: Option<Arch>,
}

pub fn parse_format(text: &str) -> Option<Signature> {
    let mut args = Vec::new();
    let mut started = false;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let decl = rest.split(';').next()?.trim();
        if decl.ends_with("__syscall_nr") {
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        let split = decl.rfind([' ', '*'])?;
        let name = decl[split + 1..].to_owned();
        let ty = decl[..=split].trim().to_owned();
        args.push((ty, name));
    }
    started.then_some(Signature { args })
}

impl Signatures {
    pub fn load(arch: Arch) -> Signatures {
        let mut by_nr = HashMap::new();
        for root in [
            "/sys/kernel/tracing/events/syscalls",
            "/sys/kernel/debug/tracing/events/syscalls",
        ] {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for e in entries.flatten() {
                let dir = e.file_name();
                let Some(name) = dir.to_str().and_then(|d| d.strip_prefix("sys_enter_")) else {
                    continue;
                };
                let Some(nr) = arch.number(name) else {
                    continue;
                };
                let Ok(text) = std::fs::read_to_string(Path::new(root).join(&dir).join("format"))
                else {
                    continue;
                };
                if let Some(sig) = parse_format(&text) {
                    by_nr.insert(nr, sig);
                }
            }
            if !by_nr.is_empty() {
                break;
            }
        }
        Signatures {
            by_nr,
            arch: Some(arch),
        }
    }

    pub fn from_tracefs(&self) -> bool {
        !self.by_nr.is_empty()
    }

    pub fn signature(&self, nr: u32) -> Option<&Signature> {
        self.by_nr.get(&nr)
    }

    pub fn arg_count(&self, nr: u32) -> Option<usize> {
        self.by_nr.get(&nr).map(|s| s.args.len())
    }

    pub fn path_index(&self, nr: u32) -> Option<u8> {
        if let Some(sig) = self.by_nr.get(&nr) {
            return sig
                .args
                .iter()
                .position(|(ty, name)| {
                    ty.contains("char *") && PATH_ARG_NAMES.contains(&name.as_str())
                })
                .map(|i| i as u8 + 1);
        }
        let name = self.arch?.name(u64::from(nr))?;
        FALLBACK_PATH_ARG
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, i)| *i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAT: &str = "name: sys_enter_openat\nID: 700\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;\n\tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;\n\tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;\n\tfield:umode_t mode;\toffset:40;\tsize:8;\tsigned:0;\n\nprint fmt: \"dfd: 0x%08lx\"\n";

    #[test]
    fn format_parsing() {
        let sig = parse_format(OPENAT).unwrap();
        let names: Vec<&str> = sig.args.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, vec!["dfd", "filename", "flags", "mode"]);
        assert_eq!(sig.args[1].0, "const char *");
        assert!(parse_format("garbage").is_none());
    }

    #[test]
    fn path_index_from_tracefs_and_fallback() {
        let arch = Arch::X86_64;
        let mut s = Signatures {
            by_nr: HashMap::new(),
            arch: Some(arch),
        };
        let openat = arch.number("openat").unwrap();
        assert_eq!(s.path_index(openat), Some(2));
        assert_eq!(s.path_index(arch.number("read").unwrap()), None);
        s.by_nr.insert(openat, parse_format(OPENAT).unwrap());
        assert_eq!(s.path_index(openat), Some(2));
        assert_eq!(s.arg_count(openat), Some(4));
        for (name, _) in FALLBACK_PATH_ARG {
            assert!(
                Arch::X86_64.number(name).is_some() || Arch::Aarch64.number(name).is_some(),
                "{name}"
            );
        }
    }
}
