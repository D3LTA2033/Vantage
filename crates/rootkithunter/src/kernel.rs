use crate::Options;
use crate::kallsyms::Kallsyms;
use crate::kcore::Kcore;
use crate::modules::read_proc_modules;
use std::io;
use std::path::Path;
use vantage_core::syscalls::Arch;
use vantage_core::{Error, Finding, IoContext, Outcome, Result, Severity, sys, text};

pub const TAINT_FLAGS: [(char, Severity, &str); 20] = [
    ('P', Severity::Low, "proprietary module loaded"),
    ('F', Severity::High, "module force loaded"),
    (
        'S',
        Severity::Info,
        "running on an out-of-specification system",
    ),
    ('R', Severity::High, "module force unloaded"),
    (
        'M',
        Severity::Info,
        "processor reported a machine check exception",
    ),
    (
        'B',
        Severity::Info,
        "bad page referenced or unexpected page flags",
    ),
    (
        'U',
        Severity::Medium,
        "taint requested by a userspace application",
    ),
    ('D', Severity::Medium, "kernel died recently (OOPS or BUG)"),
    ('A', Severity::Medium, "ACPI table overridden by user"),
    ('W', Severity::Info, "kernel issued a warning"),
    ('C', Severity::Info, "staging driver loaded"),
    (
        'I',
        Severity::Info,
        "workaround for platform firmware bug applied",
    ),
    (
        'O',
        Severity::Low,
        "externally built (out-of-tree) module loaded",
    ),
    ('E', Severity::Medium, "unsigned module loaded"),
    ('L', Severity::Info, "soft lockup occurred"),
    ('K', Severity::Info, "kernel live patched"),
    (
        'X',
        Severity::Info,
        "auxiliary taint defined by the distribution",
    ),
    (
        'T',
        Severity::Info,
        "built with the struct randomization plugin",
    ),
    ('N', Severity::Info, "in-kernel test has been run"),
    (
        'J',
        Severity::Low,
        "userspace used a mutating fwctl debug operation",
    ),
];

pub type TaintFlag = (char, Severity, &'static str);

pub fn decode_taint(value: u64) -> Vec<(u32, Option<TaintFlag>)> {
    (0..64)
        .filter(|bit| value & (1u64 << bit) != 0)
        .map(|bit| (bit, TAINT_FLAGS.get(bit as usize).copied()))
        .collect()
}

pub fn taint(_: &Options) -> Result<Outcome> {
    let value = sys::sysctl_int("kernel.tainted")
        .context("read /proc/sys/kernel/tainted")?
        .ok_or_else(|| Error::unsupported("/proc/sys/kernel/tainted missing"))?
        as u64;
    let mut findings = Vec::new();
    for (bit, flag) in decode_taint(value) {
        let f = match flag {
            Some((c, sev, what)) => Finding::new(sev, format!("kernel taint {c}: {what}"))
                .evidence("flag", c.to_string()),
            None => Finding::new(Severity::Low, format!("unknown kernel taint bit {bit}")),
        };
        findings.push(f.evidence("bit", bit));
    }
    let module_taints: String = read_proc_modules()?
        .iter()
        .map(|m| m.taints.as_str())
        .collect();
    let orphaned: Vec<String> = [('E', 13), ('O', 12), ('F', 1)]
        .iter()
        .filter(|(c, bit)| value & (1 << bit) != 0 && !module_taints.contains(*c))
        .map(|(c, _)| c.to_string())
        .collect();
    if !orphaned.is_empty() {
        findings.push(
            Finding::new(Severity::Medium, "module taint without a listed tainting module")
                .detail("taint flags persist until reboot; the module that set them was unloaded or is hidden from /proc/modules")
                .evidence("flags", orphaned),
        );
    }
    Ok(Outcome::done(format!("kernel.tainted = {value}"), findings))
}

fn syscall_prefixes(arch: Arch) -> &'static [&'static str] {
    match arch {
        Arch::X86_64 => &["__x64_sys_", "sys_ni_syscall"],
        Arch::Aarch64 => &["__arm64_sys_", "sys_ni_syscall"],
        Arch::I386 | Arch::X32 | Arch::Arm => &[],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadEntry {
    pub nr: usize,
    pub ptr: u64,
    pub target: String,
    pub module: Option<String>,
}

pub fn verify_table(
    entries: &[u64],
    ks: &Kallsyms,
    arch: Arch,
    stext: u64,
    etext: u64,
) -> Vec<BadEntry> {
    let prefixes = syscall_prefixes(arch);
    entries
        .iter()
        .enumerate()
        .filter_map(|(nr, &ptr)| {
            let in_text = ptr >= stext && ptr < etext;
            let named = ks
                .at(ptr)
                .iter()
                .any(|s| s.module.is_none() && prefixes.iter().any(|p| s.name.starts_with(p)));
            if in_text && named {
                return None;
            }
            let (target, module) = match ks.containing(ptr) {
                Some((s, off)) => (s.describe(off), s.module.clone()),
                None => (format!("{ptr:#x}"), None),
            };
            Some(BadEntry {
                nr,
                ptr,
                target,
                module,
            })
        })
        .collect()
}

pub fn syscall_table(_: &Options) -> Result<Outcome> {
    let Some(arch) = Arch::native() else {
        return Ok(Outcome::skipped(
            "syscall table layout is only known for x86_64 and aarch64",
        ));
    };
    let ks = Kallsyms::read().context("read /proc/kallsyms")?;
    if !ks.addresses_visible() {
        return Ok(Outcome::skipped(
            "kallsyms addresses are hidden; needs root (CAP_SYSLOG) and kernel.kptr_restrict below 2",
        ));
    }
    let Some(table) = ks.lookup("sys_call_table").map(|s| s.addr) else {
        return Ok(Outcome::skipped(
            "sys_call_table is not in kallsyms (CONFIG_KALLSYMS_ALL disabled)",
        ));
    };
    let (Some(stext), Some(etext)) = (ks.lookup("_stext"), ks.lookup("_etext")) else {
        return Err(Error::parse("kallsyms lacks _stext/_etext"));
    };
    let (stext, etext) = (stext.addr, etext.addr);
    let kcore = match Kcore::open(Path::new("/proc/kcore")) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Outcome::skipped(
                "/proc/kcore missing (CONFIG_PROC_KCORE disabled)",
            ));
        }
        Err(e)
            if e.kind() == io::ErrorKind::PermissionDenied
                || e.raw_os_error() == Some(libc::EPERM) =>
        {
            let lockdown = sys::lockdown();
            let why = if lockdown.as_deref() == Some("confidentiality") {
                "kernel lockdown (confidentiality) blocks /proc/kcore"
            } else {
                "reading /proc/kcore needs root (CAP_SYS_RAWIO)"
            };
            return Ok(Outcome::skipped(why));
        }
        Err(e) => return Err(e).context("open /proc/kcore"),
    };
    let mut count = arch.max_nr() as u64 + 1;
    if let Some(next) = ks.next_after(table) {
        count = count.min((next - table) / 8);
    }
    let raw = kcore
        .read(table, (count * 8) as usize)
        .with_context(|| format!("read sys_call_table at {table:#x} from /proc/kcore"))?;
    let entries: Vec<u64> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_ne_bytes(*c))
        .collect();
    if entries.iter().all(|&e| e == 0) {
        return Err(Error::unsupported(
            "/proc/kcore returned only zeros for sys_call_table",
        ));
    }
    let findings = verify_table(&entries, &ks, arch, stext, etext)
        .into_iter()
        .map(|b| {
            let name = arch.name(b.nr as u64).unwrap_or("?");
            let sev = if b.module.is_some() {
                Severity::Critical
            } else {
                Severity::High
            };
            Finding::new(
                sev,
                format!(
                    "sys_call_table[{}] ({name}) redirected to {}",
                    b.nr, b.target
                ),
            )
            .detail("the entry does not point at a core kernel syscall handler")
            .evidence("nr", b.nr)
            .evidence("syscall", name)
            .evidence("address", format!("{:#x}", b.ptr))
            .evidence("target", b.target)
            .evidence("module", b.module)
        })
        .collect();
    let mut summary = format!("{count} entries of sys_call_table at {table:#x} checked");
    let dispatch_by_switch =
        arch == Arch::X86_64 && sys::kernel_version().is_some_and(|v| v.at_least(6, 9));
    if dispatch_by_switch {
        summary.push_str("; this kernel dispatches x86_64 syscalls through x64_sys_call(), so table edits indicate tampering but do not redirect syscalls");
    }
    Ok(Outcome::done(summary, findings))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub function: String,
    pub function_module: Option<String>,
    pub callback_modules: Vec<String>,
    pub line: String,
}

pub fn parse_enabled_functions(data: &[u8]) -> Vec<Hook> {
    data.split(|&b| b == b'\n')
        .filter_map(|raw| {
            let line = text::from_bytes(raw);
            let mut tokens = line.split_whitespace();
            let function = tokens.next()?.to_owned();
            let second = tokens.next();
            let function_module = second
                .and_then(|t| t.strip_prefix('[')?.strip_suffix(']'))
                .map(str::to_owned);
            let rest_start = line.find(function.as_str())? + function.len();
            let mut rest = line[rest_start..].to_owned();
            if let Some(m) = &function_module {
                rest = rest.replacen(&format!("[{m}]"), "", 1);
            }
            let mut callback_modules = Vec::new();
            let mut s = rest.as_str();
            while let Some(open) = s.find('[') {
                let Some(close) = s[open..].find(']') else {
                    break;
                };
                let name = &s[open + 1..open + close];
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    callback_modules.push(name.to_owned());
                }
                s = &s[open + close + 1..];
            }
            callback_modules.sort();
            callback_modules.dedup();
            Some(Hook {
                function,
                function_module,
                callback_modules,
                line,
            })
        })
        .collect()
}

const SENSITIVE: [&str; 16] = [
    "sys_",
    "getdents",
    "filldir",
    "seq_show",
    "proc_",
    "kill",
    "tcp",
    "udp",
    "packet_rcv",
    "vfs_",
    "find_task",
    "audit",
    "module",
    "kallsyms",
    "bpf",
    "inet_",
];

pub fn ftrace_hooks(_: &Options) -> Result<Outcome> {
    let candidates = [
        "/sys/kernel/tracing/enabled_functions",
        "/sys/kernel/debug/tracing/enabled_functions",
    ];
    let mut data = None;
    for path in candidates {
        match std::fs::read(path) {
            Ok(d) => {
                data = Some((path, d));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(Outcome::skipped("reading tracefs needs root"));
            }
            Err(e) => return Err(e).with_context(|| format!("read {path}")),
        }
    }
    let Some((path, data)) = data else {
        let reason = if Path::new("/sys/kernel/tracing/trace").exists() {
            "tracefs has no enabled_functions (kernel built without dynamic ftrace)"
        } else {
            "tracefs is not mounted at /sys/kernel/tracing or /sys/kernel/debug/tracing"
        };
        return Ok(Outcome::skipped(reason));
    };
    let hooks = parse_enabled_functions(&data);
    let findings: Vec<Finding> = hooks
        .iter()
        .filter(|h| !h.callback_modules.is_empty())
        .map(|h| {
            let sensitive = SENSITIVE.iter().any(|s| h.function.contains(s));
            let sev = if sensitive { Severity::High } else { Severity::Medium };
            Finding::new(sev, format!("{} hooked from module {}", h.function, h.callback_modules.join(",")))
                .detail("an ftrace callback owned by a loadable module is attached to this kernel function; ftrace hooking is the standard technique of modern LKM rootkits")
                .evidence("function", h.function.as_str())
                .evidence("callback_modules", h.callback_modules.clone())
                .evidence("line", h.line.as_str())
        })
        .collect();
    Ok(Outcome::done(
        format!("{} functions with ftrace callbacks in {path}", hooks.len()),
        findings,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KALLSYMS: &[u8] = b"ffffffff81000000 T _stext\nffffffff812a0000 T __x64_sys_read\nffffffff812a0100 T __x64_sys_write\nffffffff812a0200 T __x64_sys_ni_syscall\nffffffff812a0300 T commit_creds\nffffffff81ffffff T _etext\nffffffff82000000 D sys_call_table\nffffffffc0a00000 t hacked_kill\t[diamorphine]\n";

    #[test]
    fn table_verification() {
        let ks = Kallsyms::parse(KALLSYMS);
        let entries = [
            0xffffffff812a0000,
            0xffffffff812a0100,
            0xffffffffc0a00010,
            0xffffffff812a0200,
            0xffffffff812a0300,
            0xffffffff812a0004,
        ];
        let bad = verify_table(
            &entries,
            &ks,
            Arch::X86_64,
            0xffffffff81000000,
            0xffffffff81ffffff,
        );
        let nrs: Vec<usize> = bad.iter().map(|b| b.nr).collect();
        assert_eq!(nrs, vec![2, 4, 5]);
        assert_eq!(bad[0].module.as_deref(), Some("diamorphine"));
        assert_eq!(bad[0].target, "hacked_kill+0x10 [diamorphine]");
        assert_eq!(bad[1].target, "commit_creds");
        assert_eq!(bad[2].target, "__x64_sys_read+0x4");
    }

    #[test]
    fn taint_decoding() {
        let d = decode_taint((1 << 12) | (1 << 13) | (1 << 40));
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].1.unwrap().0, 'O');
        assert_eq!(d[1].1.unwrap().0, 'E');
        assert!(d[2].1.is_none());
        assert!(decode_taint(0).is_empty());
    }

    #[test]
    fn enabled_functions_parsing() {
        let data = b"__x64_sys_kill (1) R I   \ttramp: 0xffffffffc04a6000 (hook_kill+0x0/0x60 [rk]) ->arch_ftrace_ops_list_func+0x0/0x1f0\nnf_hook_slow [nf_tables] (1)    \ttramp: 0xffffffffc0400000 (kprobe_ftrace_handler+0x0/0x1a0) ->kprobe_ftrace_handler+0x0/0x1a0\nvfs_read (2) R  \ttramp: 0x0 ->ftrace_ops_list_func+0x0/0x1f0\n";
        let hooks = parse_enabled_functions(data);
        assert_eq!(hooks.len(), 3);
        assert_eq!(hooks[0].callback_modules, vec!["rk"]);
        assert_eq!(hooks[1].function_module.as_deref(), Some("nf_tables"));
        assert!(hooks[1].callback_modules.is_empty());
        assert!(hooks[2].callback_modules.is_empty());
    }
}
