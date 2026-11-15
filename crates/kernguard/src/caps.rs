use std::path::Path;
use vantage_core::json::{self, Value};
use vantage_core::syscalls::Arch;
use vantage_core::{rawsys, sys};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Yes,
    No,
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Yes => "yes",
            State::No => "no",
            State::Unknown => "unknown",
        }
    }

    fn from(b: bool) -> State {
        if b { State::Yes } else { State::No }
    }
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub name: &'static str,
    pub state: State,
    pub detail: String,
}

impl Capability {
    pub fn to_json(&self) -> Value {
        json::obj([
            ("name", self.name.into()),
            ("state", self.state.as_str().into()),
            ("detail", self.detail.clone().into()),
        ])
    }
}

fn kallsyms_has(syms: Option<&[u8]>, names: &[&str]) -> Vec<Option<bool>> {
    let Some(data) = syms else {
        return vec![None; names.len()];
    };
    let mut found = vec![false; names.len()];
    for line in data.split(|&b| b == b'\n') {
        let mut it = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|t| !t.is_empty());
        let Some(name) = it.nth(2) else { continue };
        for (i, n) in names.iter().enumerate() {
            if name == n.as_bytes() {
                found[i] = true;
            }
        }
    }
    found.into_iter().map(Some).collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn probe() -> Vec<Capability> {
    let mut out = Vec::new();
    let mut push = |name, state, detail: String| {
        out.push(Capability {
            name,
            state,
            detail,
        })
    };

    let u = sys::uname();
    push(
        "architecture",
        State::from(Arch::native().is_some()),
        format!(
            "{} (BPF programs are built for x86_64 and aarch64)",
            u.machine
        ),
    );
    let v = sys::kernel_version();
    push(
        "kernel >= 5.15",
        v.map_or(State::Unknown, |v| State::from(v.at_least(5, 15))),
        u.release.clone(),
    );
    push(
        "ebpf support compiled in",
        State::from(crate::ebpf_enabled()),
        if crate::ebpf_enabled() {
            "built with the ebpf feature".into()
        } else {
            "built without the ebpf feature".into()
        },
    );
    #[cfg(feature = "ebpf")]
    {
        let (maj, min) = crate::bpf::libbpf_version();
        push(
            "libbpf >= 1.0",
            State::from(maj >= 1),
            format!("runtime libbpf {maj}.{min}"),
        );
    }

    let btf = rawsys::read_file(Path::new("/sys/kernel/btf/vmlinux"), 256 << 20).ok();
    push(
        "kernel BTF",
        State::from(btf.is_some()),
        "/sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF)".into(),
    );
    for tp in [
        "sched_process_exec",
        "sched_process_fork",
        "sched_process_exit",
        "module_load",
    ] {
        let state = match &btf {
            Some(b) => State::from(contains(b, format!("btf_trace_{tp}\0").as_bytes())),
            None => State::Unknown,
        };
        push(
            match tp {
                "sched_process_exec" => "tp_btf sched_process_exec",
                "sched_process_fork" => "tp_btf sched_process_fork",
                "sched_process_exit" => "tp_btf sched_process_exit",
                _ => "tp_btf module_load",
            },
            state,
            "BTF-typed tracepoint used by kernguard".into(),
        );
    }

    let ks = rawsys::read_file(Path::new("/proc/kallsyms"), 512 << 20).ok();
    let names = [
        "register_kprobe",
        "commit_creds",
        "bpf_task_pt_regs",
        "bpf_ringbuf_reserve",
    ];
    let found = kallsyms_has(ks.as_deref(), &names);
    let detail = [
        "kprobe infrastructure (CONFIG_KPROBES)",
        "kprobe target for privilege escalation detection",
        "helper used to read the syscall number at commit_creds",
        "BPF ring buffer (5.8+)",
    ];
    for ((name, f), d) in names.iter().zip(found).zip(detail) {
        let state = f.map_or(State::Unknown, State::from);
        push(
            match *name {
                "register_kprobe" => "kprobes",
                "commit_creds" => "commit_creds symbol",
                "bpf_task_pt_regs" => "bpf_task_pt_regs helper",
                _ => "BPF ring buffer",
            },
            state,
            d.into(),
        );
    }

    let lockdown = sys::lockdown();
    push(
        "lockdown permits bpf_probe_read_kernel",
        match lockdown.as_deref() {
            Some("confidentiality") => State::No,
            Some(_) => State::Yes,
            None => State::Yes,
        },
        format!(
            "lockdown: {}",
            lockdown.unwrap_or_else(|| "not available".into())
        ),
    );
    let admin = sys::has_cap(sys::CAP_SYS_ADMIN);
    let split = sys::has_cap(sys::CAP_BPF) && sys::has_cap(sys::CAP_PERFMON);
    push(
        "privileges to load BPF",
        State::from(admin || split),
        format!(
            "euid {}; needs CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN",
            sys::euid()
        ),
    );
    let unpriv = sys::sysctl_int("kernel.unprivileged_bpf_disabled")
        .ok()
        .flatten();
    push(
        "unprivileged BPF disabled",
        unpriv.map_or(State::Unknown, |v| State::from(v >= 1)),
        format!(
            "kernel.unprivileged_bpf_disabled = {}",
            unpriv.map_or("?".into(), |v| v.to_string())
        ),
    );
    let fmt = [
        "/sys/kernel/tracing/events/syscalls",
        "/sys/kernel/debug/tracing/events/syscalls",
    ];
    let tracefs = fmt.iter().any(|p| std::fs::read_dir(p).is_ok());
    push(
        "syscall argument formats",
        if tracefs { State::Yes } else { State::Unknown },
        if tracefs {
            "tracefs syscall formats readable; trace output names arguments".into()
        } else {
            "tracefs not readable (needs root and CONFIG_FTRACE_SYSCALLS); trace falls back to built-in path argument table".into()
        },
    );
    out
}

pub fn ready(caps: &[Capability]) -> bool {
    caps.iter().all(|c| {
        c.state != State::No || matches!(c.name, "unprivileged BPF disabled" | "tp_btf module_load")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kallsyms_lookup() {
        let data = b"ffffffff81000000 T commit_creds\nffffffff81000100 t bpf_task_pt_regs\nffffffff81000200 T not_it\t[mod]\n";
        let r = kallsyms_has(
            Some(data),
            &["commit_creds", "bpf_task_pt_regs", "register_kprobe", "not"],
        );
        assert_eq!(r, vec![Some(true), Some(true), Some(false), Some(false)]);
        assert_eq!(kallsyms_has(None, &["x"]), vec![None]);
    }

    #[test]
    fn probe_reports_every_item() {
        let caps = probe();
        assert!(caps.len() >= 15);
        assert!(caps.iter().any(|c| c.name == "kernel BTF"));
    }
}
