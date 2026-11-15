pub mod files;
pub mod kallsyms;
pub mod kcore;
pub mod kernel;
pub mod modules;
pub mod network;
pub mod processes;

use std::path::PathBuf;
use vantage_core::{CheckResult, Error, Outcome, Result};

pub const ENGINE: &str = "rootkithunter";

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub pid_max: Option<u32>,
    pub extra_dirs: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct Check {
    pub id: &'static str,
    pub description: &'static str,
    pub privileged: bool,
    pub run: fn(&Options) -> Result<Outcome>,
}

pub const CHECKS: &[Check] = &[
    Check {
        id: "hidden-processes",
        description: "processes that answer kill/getpgid probes but are missing from the raw /proc listing",
        privileged: false,
        run: processes::hidden_processes,
    },
    Check {
        id: "userland-hiding",
        description: "directory entries and file contents that differ between libc calls and raw syscalls",
        privileged: false,
        run: files::userland_hiding,
    },
    Check {
        id: "preload",
        description: "/etc/ld.so.preload entries and processes started with LD_PRELOAD or LD_AUDIT",
        privileged: false,
        run: files::preload,
    },
    Check {
        id: "process-executables",
        description: "processes running from memfd, deleted files or world-writable directories",
        privileged: false,
        run: processes::executables,
    },
    Check {
        id: "hidden-modules",
        description: "modules visible in sysfs, BTF or kallsyms but missing from /proc/modules",
        privileged: false,
        run: modules::hidden_modules,
    },
    Check {
        id: "module-audit",
        description: "loaded modules that are force-loaded, unsigned, out-of-tree or not in the installed module tree",
        privileged: false,
        run: modules::audit,
    },
    Check {
        id: "kernel-taint",
        description: "kernel taint flags, including taint left behind by modules no longer listed",
        privileged: false,
        run: kernel::taint,
    },
    Check {
        id: "syscall-table",
        description: "sys_call_table entries read from /proc/kcore that do not point at core kernel syscall handlers",
        privileged: true,
        run: kernel::syscall_table,
    },
    Check {
        id: "ftrace-hooks",
        description: "kernel functions with ftrace callbacks that live in loadable modules",
        privileged: true,
        run: kernel::ftrace_hooks,
    },
    Check {
        id: "hidden-ports",
        description: "TCP/UDP ports that refuse bind() but are missing from /proc/net",
        privileged: false,
        run: network::hidden_ports,
    },
];

pub fn find(id: &str) -> Option<&'static Check> {
    CHECKS.iter().find(|c| c.id == id)
}

pub fn run(opts: &Options, only: &[String]) -> Result<Vec<CheckResult>> {
    for id in only {
        if find(id).is_none() {
            return Err(Error::usage(format!("unknown rootkithunter check: {id}")));
        }
    }
    Ok(CHECKS
        .iter()
        .filter(|c| only.is_empty() || only.iter().any(|o| o == c.id))
        .map(|c| CheckResult::run(ENGINE, c.id, || (c.run)(opts)))
        .collect())
}
