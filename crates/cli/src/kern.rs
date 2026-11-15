use crate::Global;
use crate::args::{self, flag, multi, opt};
use crate::render::{Out, evidence_text, table};
use kernguard::events::{Event, Syscall, syscall_name};
use kernguard::{MonitorOptions, Target, TraceOptions, Tracer, audit, caps};
use std::path::PathBuf;
use std::time::Duration;
use vantage_core::json::{self, Value};
use vantage_core::syscalls::ABI_NATIVE;
use vantage_core::{Error, Finding, Report, Result, Severity, sys};

pub const HELP: &str = "usage: vantage kernguard <command>

commands:
  caps                         what this kernel and build support, probed live
  audit                        hardening sysctls, lockdown, privileged processes and files
      --check ID               run only this check (repeatable)
      --path DIR               extra directory to scan for privileged files (repeatable)
  monitor                      live eBPF detection (root)
      --duration SECS          stop after SECS seconds
      --events                 also print every raw event
  trace (--pid PID | -- CMD)   eBPF syscall trace of a process and its children (root)
      --duration SECS          stop after SECS seconds";

pub fn run(argv: &[String], g: &Global) -> Result<i32> {
    let Some((cmd, rest)) = argv.split_first() else {
        println!("{HELP}");
        return Ok(2);
    };
    match cmd.as_str() {
        "caps" => caps_cmd(rest, g),
        "audit" => audit_cmd(rest, g),
        "monitor" => monitor_cmd(rest, g),
        "trace" => trace_cmd(rest, g),
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            Ok(0)
        }
        other => Err(Error::usage(format!(
            "unknown kernguard command {other:?}\n\n{HELP}"
        ))),
    }
}

fn caps_cmd(rest: &[String], g: &Global) -> Result<i32> {
    args::parse(rest, &[], 0)?;
    let mut out = Out::open(g.output.as_deref(), g.json, Severity::Info)?;
    let found = caps::probe();
    let ready = caps::ready(&found);
    if out.json {
        out.value(&json::obj([
            (
                "capabilities",
                Value::Array(found.iter().map(|c| c.to_json()).collect()),
            ),
            ("ebpf_ready", ready.into()),
        ]))?;
    } else {
        let rows: Vec<Vec<String>> = found
            .iter()
            .map(|c| {
                vec![
                    c.name.to_owned(),
                    c.state.as_str().to_owned(),
                    c.detail.clone(),
                ]
            })
            .collect();
        for l in table(&["capability", "state", "detail"], &rows) {
            out.line(&l)?;
        }
        out.line("")?;
        out.line(if ready {
            "monitor/trace: supported"
        } else {
            "monitor/trace: not available (see rows marked no)"
        })?;
    }
    out.flush()?;
    Ok(0)
}

fn audit_cmd(rest: &[String], g: &Global) -> Result<i32> {
    let p = args::parse(rest, &[multi("check"), multi("path")], 0)?;
    let opts = audit::Options {
        extra_paths: p.values("path").iter().map(PathBuf::from).collect(),
    };
    let mut report = Report::new(sys::Host::current());
    report.checks = audit::run(&opts, p.values("check"))?;
    report.finish();
    crate::finish_report(report, g)
}

fn duration(p: &args::Parsed) -> Result<Option<Duration>> {
    p.parse_value::<f64>("duration")?
        .map(|s| {
            if s.is_finite() && s > 0.0 {
                Ok(Duration::from_secs_f64(s))
            } else {
                Err(Error::usage(
                    "--duration must be a positive number of seconds",
                ))
            }
        })
        .transpose()
}

fn clock(boot_ns: u64) -> String {
    let unix = kernguard::boot_to_unix_ns(boot_ns);
    let secs = (unix / 1_000_000_000) as libc::time_t;
    let ms = (unix / 1_000_000) % 1000;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!(
        "{:02}:{:02}:{:02}.{ms:03}",
        tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

fn finding_line(f: &Finding) -> String {
    let ev: Vec<String> = f
        .evidence
        .iter()
        .filter_map(|(k, v)| evidence_text(v).map(|t| format!("{k}={t}")))
        .collect();
    format!("[{}] {}  {}", f.severity.as_str(), f.title, ev.join(" "))
}

fn event_line(e: &Event, arch: Option<vantage_core::syscalls::Arch>) -> String {
    let v = e.to_json(arch);
    let mut parts = Vec::new();
    if let Value::Object(pairs) = v {
        for (k, val) in pairs {
            if k == "boot_ns" || k == "type" {
                continue;
            }
            if let Some(t) = evidence_text(&val) {
                parts.push(format!("{k}={t}"));
            }
        }
    }
    format!("{} {}", e.kind(), parts.join(" "))
}

fn monitor_cmd(rest: &[String], g: &Global) -> Result<i32> {
    let p = args::parse(rest, &[opt("duration"), flag("events")], 0)?;
    let opts = MonitorOptions {
        duration: duration(&p)?,
    };
    let show_events = p.flag("events");
    let min = g.min.unwrap_or(Severity::Low);
    let mut out = Out::open(g.output.as_deref(), g.json, min)?;
    let arch = vantage_core::syscalls::Arch::native();
    let mut worst: Option<Severity> = None;
    let mut write_err = None;
    let stats = kernguard::monitor(
        &opts,
        |detectors| {
            let list: Vec<String> = detectors
                .iter()
                .map(|d| format!("{} {}", d.name, if d.active { "on" } else { "off" }))
                .collect();
            eprintln!("kernguard: {}; ctrl-c to stop", list.join(", "));
            for d in detectors.iter().filter(|d| !d.active) {
                eprintln!(
                    "kernguard: detector {} inactive: {}",
                    d.name,
                    d.reason.as_deref().unwrap_or("unknown reason")
                );
            }
        },
        |event, findings| {
            if write_err.is_some() {
                return;
            }
            let ts = event.header().ts;
            let mut emit = |out: &mut Out| -> Result<()> {
                if show_events {
                    if out.json {
                        out.json_line(&json::obj([
                            ("kind", "event".into()),
                            ("unix_ns", kernguard::boot_to_unix_ns(ts).into()),
                            ("event", event.to_json(arch)),
                        ]))?;
                    } else {
                        out.line(&format!("{} {}", clock(ts), event_line(event, arch)))?;
                    }
                }
                for f in &findings {
                    worst = worst.max(Some(f.severity));
                    if f.severity < out.min {
                        continue;
                    }
                    if out.json {
                        out.json_line(&json::obj([
                            ("kind", "finding".into()),
                            ("unix_ns", kernguard::boot_to_unix_ns(ts).into()),
                            ("finding", f.to_json()),
                            ("event", event.to_json(arch)),
                        ]))?;
                    } else {
                        out.line(&format!("{} {}", clock(ts), finding_line(f)))?;
                    }
                }
                out.flush()
            };
            if let Err(e) = emit(&mut out) {
                write_err = Some(e);
            }
        },
    )?;
    if let Some(e) = write_err {
        return Err(e);
    }
    eprintln!(
        "kernguard: {} events in {:.1}s, {} dropped by the ring buffer",
        stats.events,
        stats.elapsed.as_secs_f64(),
        stats.dropped
    );
    Ok(match (g.fail_on, worst) {
        (Some(t), Some(w)) if w >= t => 1,
        _ => 0,
    })
}

fn format_arg(v: u64, ty: Option<&str>, name: Option<&str>, path: Option<&str>) -> String {
    if let Some(p) = path {
        return format!("{p:?}");
    }
    let ty = ty.unwrap_or("");
    let name = name.unwrap_or("");
    if name == "dfd" && v as i32 == -100 {
        return "AT_FDCWD".into();
    }
    if ty.contains('*') {
        return if v == 0 {
            "NULL".into()
        } else {
            format!("{v:#x}")
        };
    }
    if name.ends_with("flags") || name == "prot" || name == "cmd" {
        return format!("{v:#x}");
    }
    if name == "mode" {
        return format!("0{v:o}");
    }
    let signed = [
        "int",
        "long",
        "pid_t",
        "off_t",
        "loff_t",
        "clockid_t",
        "key_serial_t",
        "timer_t",
    ];
    if signed
        .iter()
        .any(|s| ty == *s || ty.ends_with(&format!(" {s}")))
        && !ty.contains("unsigned")
    {
        return if ty.ends_with("int") || ty.ends_with("pid_t") || ty.ends_with("clockid_t") {
            (v as i32).to_string()
        } else {
            (v as i64).to_string()
        };
    }
    if ty.is_empty() {
        return format!("{v:#x}");
    }
    v.to_string()
}

fn syscall_line(t: &Tracer, s: &Syscall) -> String {
    let native = s.abi == ABI_NATIVE;
    let nr = u32::try_from(s.nr).ok().filter(|_| native);
    let name = syscall_name(Some(t.arch), s.abi, s.nr)
        .map_or_else(|| format!("syscall_{}", s.nr), str::to_owned);
    let name = match t.arch.abi(s.abi) {
        _ if native => name,
        Some(a) => format!("{}:{name}", a.as_str()),
        None => format!("abi{}:{name}", s.abi),
    };
    let path_idx = nr.and_then(|n| t.signatures.path_index(n));
    let count = nr
        .and_then(|n| t.signatures.arg_count(n))
        .unwrap_or(6)
        .min(6);
    let sig = nr.and_then(|n| t.signatures.signature(n));
    let args: Vec<String> = (0..count)
        .map(|i| {
            let path =
                (path_idx == Some(i as u8 + 1) && !s.path.is_empty()).then_some(s.path.as_str());
            let (ty, nm) = sig
                .and_then(|g| g.args.get(i))
                .map_or((None, None), |(t, n)| (Some(t.as_str()), Some(n.as_str())));
            format_arg(s.args[i], ty, nm, path)
        })
        .collect();
    let ret = if (-4095..0).contains(&s.ret) {
        format!("-1 {}", std::io::Error::from_raw_os_error(-s.ret as i32))
    } else if s.ret > 0xffff {
        format!("{:#x}", s.ret)
    } else {
        s.ret.to_string()
    };
    format!(
        "[{}] {}({}) = {ret} <{:.6}>",
        s.h.pid,
        name,
        args.join(", "),
        s.duration_ns as f64 / 1e9
    )
}

fn trace_cmd(rest: &[String], g: &Global) -> Result<i32> {
    let p = args::parse(rest, &[opt("pid"), opt("duration")], 0)?;
    let target = match (p.parse_value::<u32>("pid")?, p.rest.is_empty()) {
        (Some(pid), true) => Target::Pid(pid),
        (None, false) => Target::Command(p.rest.clone()),
        (Some(_), false) => {
            return Err(Error::usage(
                "give either --pid or a command after --, not both",
            ));
        }
        (None, true) => return Err(Error::usage("trace needs --pid PID or -- COMMAND [ARGS]")),
    };
    let opts = TraceOptions {
        target,
        duration: duration(&p)?,
    };
    let mut out = Out::open(g.output.as_deref(), g.json, Severity::Info)?;
    let mut write_err = None;
    let stats = kernguard::trace(&opts, |tracer, s| {
        if write_err.is_some() {
            return;
        }
        let res = if out.json {
            let ev = Event::Syscall(s.clone());
            out.json_line(&ev.to_json(Some(tracer.arch)))
        } else {
            out.line(&syscall_line(tracer, s))
        };
        if let Err(e) = res {
            write_err = Some(e);
        }
    })?;
    out.flush()?;
    if let Some(e) = write_err {
        return Err(e);
    }
    eprintln!(
        "kernguard: {} syscalls traced in {:.1}s, {} events dropped",
        stats.events,
        stats.elapsed.as_secs_f64(),
        stats.dropped
    );
    Ok(stats.exit_code.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_formatting() {
        assert_eq!(
            format_arg((-100i64) as u64, Some("int"), Some("dfd"), None),
            "AT_FDCWD"
        );
        assert_eq!(
            format_arg(0, Some("const char *"), Some("buf"), None),
            "NULL"
        );
        assert_eq!(
            format_arg(0x7fff0000, Some("char *"), Some("buf"), None),
            "0x7fff0000"
        );
        assert_eq!(
            format_arg(0x80000, Some("int"), Some("flags"), None),
            "0x80000"
        );
        assert_eq!(
            format_arg(0o644, Some("umode_t"), Some("mode"), None),
            "0644"
        );
        assert_eq!(format_arg(u64::MAX, Some("int"), Some("fd"), None), "-1");
        assert_eq!(format_arg(3, Some("unsigned int"), Some("fd"), None), "3");
        assert_eq!(format_arg(7, Some("size_t"), Some("count"), None), "7");
        assert_eq!(
            format_arg(1, None, None, Some("/etc/passwd")),
            "\"/etc/passwd\""
        );
        assert_eq!(format_arg(255, None, None, None), "0xff");
    }

    #[test]
    fn compat_trace_lines_name_the_abi() {
        use kernguard::events::Header;
        use vantage_core::syscalls::Arch;
        let t = Tracer {
            signatures: Default::default(),
            arch: Arch::X86_64,
        };
        let mut s = Syscall {
            h: Header {
                pid: 7,
                tgid: 7,
                uid: 0,
                ts: 0,
                comm: "a.out".into(),
            },
            nr: 26,
            abi: 1,
            args: [16, 4242, 0, 0, 0, 0],
            ret: 0,
            duration_ns: 1000,
            path: "/etc/shadow".into(),
        };
        let line = syscall_line(&t, &s);
        assert!(line.starts_with("[7] i386:ptrace(0x10, 0x1092,"), "{line}");
        assert!(!line.contains("shadow"), "{line}");
        s.abi = 2;
        s.nr = 521;
        assert!(syscall_line(&t, &s).starts_with("[7] x32:ptrace("));
        s.abi = 0;
        s.nr = 26;
        assert!(syscall_line(&t, &s).starts_with("[7] msync("));
    }
}
