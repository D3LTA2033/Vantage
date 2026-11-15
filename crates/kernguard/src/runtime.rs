use crate::bpf::{Map, Object, RingBuffer};
use crate::events::{self, Event, Syscall};
use crate::rules;
use crate::signatures::Signatures;
use crate::{Detector, MonitorOptions, Stats, Target, TraceOptions, Tracer};
use std::cell::Cell;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use vantage_core::syscalls::Arch;
use vantage_core::{Error, Finding, Result, rawsys, sys};

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static OBJECT: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/kernguard.bpf.o"
)));

const PROGRAMS: [&str; 7] = [
    "on_exec",
    "on_commit_creds",
    "on_module_load",
    "on_sys_enter",
    "on_sys_exit",
    "on_fork",
    "on_exit",
];
const FLAG_WATCH: u32 = 1;
const FLAG_TRACE: u32 = 2;
const MAX_SYSCALL: u32 = 1024;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    STOP.store(false, Ordering::SeqCst);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

pub fn preflight() -> Result<Arch> {
    let arch = Arch::native()
        .ok_or_else(|| Error::unsupported("kernguard eBPF supports x86_64 and aarch64 only"))?;
    let v = sys::kernel_version().ok_or_else(|| Error::parse("cannot parse kernel release"))?;
    if !v.at_least(5, 15) {
        return Err(Error::unsupported(format!(
            "kernel {}.{} is older than 5.15; kernguard needs BTF tracepoints, the BPF ring buffer and bpf_task_pt_regs()",
            v.major, v.minor
        )));
    }
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Err(Error::unsupported(
            "kernel exposes no BTF at /sys/kernel/btf/vmlinux (needs CONFIG_DEBUG_INFO_BTF=y)",
        ));
    }
    if sys::lockdown().as_deref() == Some("confidentiality") {
        return Err(Error::unsupported(
            "kernel lockdown is in confidentiality mode, which blocks bpf_probe_read_kernel()",
        ));
    }
    let admin = sys::has_cap(sys::CAP_SYS_ADMIN);
    let split = sys::has_cap(sys::CAP_BPF) && sys::has_cap(sys::CAP_PERFMON);
    if !admin && !split {
        return Err(Error::permission(
            "loading the BPF programs needs root (CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN)",
        ));
    }
    let unlimited = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) };
    Ok(arch)
}

fn open(enabled: &[&str]) -> Result<Object> {
    let mut obj = Object::open(&OBJECT.0)?;
    for p in PROGRAMS {
        obj.set_autoload(p, enabled.contains(&p))?;
    }
    obj.load()?;
    obj.map("config")?
        .update(&0u32, &[std::process::id(), 0u32])?;
    Ok(obj)
}

fn poll_loop<F: FnMut(&[u8])>(
    rb: &mut RingBuffer<'_, F>,
    deadline: Option<Instant>,
    mut done: impl FnMut() -> bool,
) -> Result<()> {
    loop {
        if STOP.load(Ordering::SeqCst) || deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        match rb.poll(100) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => return Err(Error::io("poll ring buffer", e)),
        }
        if done() {
            break;
        }
    }
    while matches!(rb.poll(0), Ok(n) if n > 0) {}
    Ok(())
}

pub fn monitor(
    opts: &MonitorOptions,
    mut on_ready: impl FnMut(&[Detector]),
    mut on_event: impl FnMut(&Event, Vec<Finding>),
) -> Result<Stats> {
    let arch = preflight()?;
    install_signal_handlers();
    let modules = Path::new("/proc/modules").exists();
    let mut wanted = vec!["on_exec", "on_commit_creds", "on_sys_enter"];
    if modules {
        wanted.push("on_module_load");
    }
    let obj = open(&wanted)?;
    let sigs = Signatures::load(arch);
    let flags = obj.map("syscall_flags")?;
    for name in rules::WATCHED {
        if let Some(nr) = arch.number(name) {
            let path = u32::from(sigs.path_index(nr).unwrap_or(0));
            flags.update(&nr, &(FLAG_WATCH | (path << 8)))?;
        }
    }
    let mut links = Vec::new();
    let mut detectors = Vec::new();
    for (name, prog) in [
        ("exec", "on_exec"),
        ("privilege-escalation", "on_commit_creds"),
        ("module-load", "on_module_load"),
        ("watched-syscalls", "on_sys_enter"),
    ] {
        if !wanted.contains(&prog) {
            detectors.push(Detector {
                name,
                active: false,
                reason: Some("kernel built without loadable module support".into()),
            });
            continue;
        }
        match obj.attach(prog) {
            Ok(l) => {
                links.push(l);
                detectors.push(Detector {
                    name,
                    active: true,
                    reason: None,
                });
            }
            Err(e) => detectors.push(Detector {
                name,
                active: false,
                reason: Some(e.to_string()),
            }),
        }
    }
    if links.is_empty() {
        return Err(Error::unsupported(
            "no kernguard detector could be attached",
        ));
    }
    on_ready(&detectors);
    let events = obj.map("events")?;
    let count = Cell::new(0u64);
    let start = Instant::now();
    {
        let mut rb = RingBuffer::new(&events, |data: &[u8]| {
            if let Some(ev) = events::parse(data) {
                count.set(count.get() + 1);
                let found = rules::findings(&ev, arch);
                on_event(&ev, found);
            }
        })?;
        poll_loop(&mut rb, opts.duration.map(|d| start + d), || false)?;
    }
    let dropped = obj.map("drops")?.sum_percpu_u64(0)?;
    drop(links);
    Ok(Stats {
        events: count.get(),
        dropped,
        elapsed: start.elapsed(),
        exit_code: None,
    })
}

struct Child {
    pid: libc::pid_t,
    go: Option<std::fs::File>,
}

fn spawn_held(argv: &[String]) -> Result<Child> {
    let args: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).map_err(|_| Error::usage("argument contains NUL")))
        .collect::<Result<_>>()?;
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::io("pipe2", std::io::Error::last_os_error()));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::io("fork", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        unsafe {
            libc::close(fds[1]);
            let mut b = 0u8;
            let n = loop {
                let n = libc::read(fds[0], (&mut b as *mut u8).cast(), 1);
                if n < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                break n;
            };
            if n == 1 {
                libc::execvp(ptrs[0], ptrs.as_ptr());
            }
            libc::_exit(127);
        }
    }
    unsafe { libc::close(fds[0]) };
    let go = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    Ok(Child { pid, go: Some(go) })
}

pub fn trace(opts: &TraceOptions, mut on_syscall: impl FnMut(&Tracer, &Syscall)) -> Result<Stats> {
    let arch = preflight()?;
    install_signal_handlers();
    let obj = open(&["on_sys_enter", "on_sys_exit", "on_fork", "on_exit"])?;
    let tracer = Tracer {
        signatures: Signatures::load(arch),
        arch,
    };
    let flags = obj.map("syscall_flags")?;
    for nr in 0..MAX_SYSCALL {
        let path = u32::from(tracer.signatures.path_index(nr).unwrap_or(0));
        flags.update(&nr, &(FLAG_TRACE | (path << 8)))?;
    }
    let links: Vec<_> = ["on_sys_enter", "on_sys_exit", "on_fork", "on_exit"]
        .iter()
        .map(|p| obj.attach(p))
        .collect::<Result<_>>()?;
    let traced: Map = obj.map("traced")?;
    let mut child = None;
    match &opts.target {
        Target::Pid(pid) => {
            if !rawsys::pid_exists(*pid as i32) {
                return Err(Error::usage(format!("no process with pid {pid}")));
            }
            traced.update(pid, &1u8)?;
        }
        Target::Command(argv) => {
            if argv.is_empty() {
                return Err(Error::usage("no command given"));
            }
            let c = spawn_held(argv)?;
            traced.update(&(c.pid as u32), &1u8)?;
            child = Some(c);
        }
    }
    if let Some(c) = child.as_mut()
        && let Some(mut go) = c.go.take()
    {
        go.write_all(b"g")
            .map_err(|e| Error::io("release traced command", e))?;
    }
    let events_map = obj.map("events")?;
    let count = Cell::new(0u64);
    let mut exit_code = None;
    let start = Instant::now();
    {
        let mut rb = RingBuffer::new(&events_map, |data: &[u8]| {
            if let Some(Event::Syscall(s)) = events::parse(data) {
                count.set(count.get() + 1);
                on_syscall(&tracer, &s);
            }
        })?;
        let target_pid = match &opts.target {
            Target::Pid(p) => Some(*p),
            Target::Command(_) => None,
        };
        poll_loop(&mut rb, opts.duration.map(|d| start + d), || {
            if let Some(c) = &child {
                if exit_code.is_none() {
                    let mut status = 0;
                    let r = unsafe { libc::waitpid(c.pid, &mut status, libc::WNOHANG) };
                    if r == c.pid {
                        exit_code = Some(if libc::WIFEXITED(status) {
                            libc::WEXITSTATUS(status)
                        } else {
                            128 + libc::WTERMSIG(status)
                        });
                    }
                }
                exit_code.is_some() && traced.is_empty::<u32>()
            } else {
                let gone = target_pid.is_some_and(|p| !rawsys::pid_exists(p as i32));
                gone && traced.is_empty::<u32>()
            }
        })?;
    }
    if let (Some(c), None) = (&child, exit_code) {
        let mut status = 0;
        if unsafe { libc::waitpid(c.pid, &mut status, libc::WNOHANG) } == c.pid
            && libc::WIFEXITED(status)
        {
            exit_code = Some(libc::WEXITSTATUS(status));
        }
    }
    let dropped = obj.map("drops")?.sum_percpu_u64(0)?;
    drop(links);
    Ok(Stats {
        events: count.get(),
        dropped,
        elapsed: start.elapsed(),
        exit_code,
    })
}
