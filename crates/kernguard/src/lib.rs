pub mod audit;
#[cfg(feature = "ebpf")]
pub mod bpf;
pub mod caps;
pub mod events;
pub mod rules;
#[cfg(feature = "ebpf")]
mod runtime;
pub mod signatures;

use std::time::Duration;
use vantage_core::syscalls::Arch;

pub use signatures::Signatures;

pub const ENGINE: &str = "kernguard";

pub const fn ebpf_enabled() -> bool {
    cfg!(feature = "ebpf")
}

#[derive(Debug, Clone)]
pub struct Detector {
    pub name: &'static str,
    pub active: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub events: u64,
    pub dropped: u64,
    pub elapsed: Duration,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct MonitorOptions {
    pub duration: Option<Duration>,
}

#[derive(Debug, Clone)]
pub enum Target {
    Pid(u32),
    Command(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub target: Target,
    pub duration: Option<Duration>,
}

#[derive(Debug)]
pub struct Tracer {
    pub signatures: Signatures,
    pub arch: Arch,
}

pub fn boot_to_unix_ns(boot_ns: u64) -> u64 {
    let read = |clock| {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(clock, &mut ts) };
        ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
    };
    let offset = read(libc::CLOCK_REALTIME) - read(libc::CLOCK_BOOTTIME);
    (boot_ns as i128 + offset).max(0) as u64
}

#[cfg(feature = "ebpf")]
pub use runtime::{monitor, preflight, trace};

#[cfg(not(feature = "ebpf"))]
mod disabled {
    use super::*;
    use crate::events::{Event, Syscall};
    use vantage_core::{Error, Finding, Result};

    fn unavailable() -> Error {
        Error::unsupported("this build has no eBPF support; rebuild with the ebpf feature")
    }

    pub fn preflight() -> Result<Arch> {
        Err(unavailable())
    }

    pub fn monitor(
        _: &MonitorOptions,
        _: impl FnMut(&[Detector]),
        _: impl FnMut(&Event, Vec<Finding>),
    ) -> Result<Stats> {
        Err(unavailable())
    }

    pub fn trace(_: &TraceOptions, _: impl FnMut(&Tracer, &Syscall)) -> Result<Stats> {
        Err(unavailable())
    }
}

#[cfg(not(feature = "ebpf"))]
pub use disabled::{monitor, preflight, trace};
