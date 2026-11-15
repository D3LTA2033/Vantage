use crate::Global;
use crate::args::{self, multi, opt};
use crate::render::{Out, table};
use elfinspector::{Binary, Context};
use kernguard::audit::{self, PrivilegedFile};
use std::path::{Path, PathBuf};
use vantage_core::json::{self, Value};
use vantage_core::{CheckResult, Error, Finding, Outcome, Report, Result, Severity, sys, text};

pub const SCAN_HELP: &str = "usage: vantage scan [options]

runs every snapshot check of all three engines; run as root for full coverage

options:
  --skip ID          skip a check by id (repeatable)
  --pid-max N        highest PID to probe for hidden processes (default kernel.pid_max)
  --dir DIR          extra directory to compare between libc and raw syscalls (repeatable)
  --path DIR         extra directory to scan for privileged files (repeatable)";

pub const ROOTKIT_HELP: &str = "usage: vantage rootkit <command>

commands:
  list               list checks with descriptions
  scan               run rootkit checks
      --check ID     run only this check (repeatable)
      --pid-max N    highest PID to probe (default kernel.pid_max)
      --dir DIR      extra directory to compare between libc and raw syscalls (repeatable)";

pub fn setuid_mitigations(found: &[PrivilegedFile]) -> Result<Outcome> {
    let mut findings = Vec::new();
    let mut analyzed = 0usize;
    let mut not_elf = 0usize;
    for f in found.iter().filter(|f| f.setuid() || f.setgid()) {
        let shown = text::from_path(&f.path);
        let data = match elfinspector::read_file(&f.path, elfinspector::DEFAULT_MAX_SIZE) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let Ok(bin) = Binary::parse(&data) else {
            not_elf += 1;
            continue;
        };
        analyzed += 1;
        let ctx = Context {
            setuid: true,
            host_paths: true,
        };
        for finding in bin.checksec().findings(&ctx) {
            if finding.severity >= Severity::Low {
                findings.push(
                    Finding {
                        title: format!("{shown}: {}", finding.title),
                        ..finding
                    }
                    .evidence("binary", shown.as_str()),
                );
            }
        }
    }
    let mut summary = format!("{analyzed} setuid/setgid ELF binaries analyzed");
    if not_elf > 0 {
        summary.push_str(&format!(", {not_elf} non-ELF files skipped"));
    }
    Ok(Outcome::done(summary, findings))
}

pub fn scan(argv: &[String], g: &Global) -> Result<i32> {
    let p = args::parse(
        argv,
        &[multi("skip"), opt("pid-max"), multi("dir"), multi("path")],
        0,
    )?;
    let skip = p.values("skip");
    let known: Vec<&str> = audit::CHECKS
        .iter()
        .map(|c| c.0)
        .chain(rootkithunter::CHECKS.iter().map(|c| c.id))
        .chain(std::iter::once("setuid-mitigations"))
        .collect();
    for s in skip {
        if !known.contains(&s.as_str()) {
            return Err(Error::usage(format!(
                "unknown check {s:?}; known: {}",
                known.join(", ")
            )));
        }
    }
    let skipped = |id: &str| skip.iter().any(|s| s == id);
    let mut report = Report::new(sys::Host::current());
    let kg_opts = audit::Options {
        extra_paths: p.values("path").iter().map(PathBuf::from).collect(),
    };
    let kg_ids: Vec<String> = ["hardening", "lockdown", "privileged-processes"]
        .iter()
        .filter(|id| !skipped(id))
        .map(|s| (*s).to_owned())
        .collect();
    if !kg_ids.is_empty() {
        report.checks.extend(audit::run(&kg_opts, &kg_ids)?);
    }
    let need_files = !skipped("privileged-files") || !skipped("setuid-mitigations");
    let walk = std::time::Instant::now();
    let (found, scanned) = if need_files {
        audit::find_privileged(&kg_opts.extra_paths)
    } else {
        (Vec::new(), 0)
    };
    let walk = walk.elapsed();
    if !skipped("privileged-files") {
        let mut result = CheckResult::run(kernguard::ENGINE, "privileged-files", || {
            Ok(audit::files_outcome(&found, scanned))
        });
        result.duration += walk;
        report.checks.push(result);
    }
    let rk_opts = rootkithunter::Options {
        pid_max: p.parse_value("pid-max")?,
        extra_dirs: p.values("dir").iter().map(PathBuf::from).collect(),
    };
    let rk_ids: Vec<String> = rootkithunter::CHECKS
        .iter()
        .filter(|c| !skipped(c.id))
        .map(|c| c.id.to_owned())
        .collect();
    if !rk_ids.is_empty() {
        report.checks.extend(rootkithunter::run(&rk_opts, &rk_ids)?);
    }
    if !skipped("setuid-mitigations") {
        report.checks.push(CheckResult::run(
            "elfinspector",
            "setuid-mitigations",
            || setuid_mitigations(&found),
        ));
    }
    report.finish();
    crate::finish_report(report, g)
}

pub fn rootkit(argv: &[String], g: &Global) -> Result<i32> {
    let Some((cmd, rest)) = argv.split_first() else {
        println!("{ROOTKIT_HELP}");
        return Ok(2);
    };
    match cmd.as_str() {
        "list" => {
            args::parse(rest, &[], 0)?;
            let mut out = Out::open(g.output.as_deref(), g.json, Severity::Info)?;
            if out.json {
                out.value(&Value::Array(
                    rootkithunter::CHECKS
                        .iter()
                        .map(|c| {
                            json::obj([
                                ("id", c.id.into()),
                                ("description", c.description.into()),
                                ("needs_root", c.privileged.into()),
                            ])
                        })
                        .collect(),
                ))?;
            } else {
                let rows: Vec<Vec<String>> = rootkithunter::CHECKS
                    .iter()
                    .map(|c| {
                        vec![
                            c.id.to_owned(),
                            if c.privileged { "root" } else { "any" }.to_owned(),
                            c.description.to_owned(),
                        ]
                    })
                    .collect();
                for l in table(&["check", "runs as", "description"], &rows) {
                    out.line(&l)?;
                }
            }
            out.flush()?;
            Ok(0)
        }
        "scan" => {
            let p = args::parse(rest, &[multi("check"), opt("pid-max"), multi("dir")], 0)?;
            let opts = rootkithunter::Options {
                pid_max: p.parse_value("pid-max")?,
                extra_dirs: p.values("dir").iter().map(PathBuf::from).collect(),
            };
            for d in &opts.extra_dirs {
                if !Path::new(d).is_dir() {
                    return Err(Error::usage(format!(
                        "--dir {}: not a directory",
                        d.display()
                    )));
                }
            }
            let mut report = Report::new(sys::Host::current());
            report.checks = rootkithunter::run(&opts, p.values("check"))?;
            report.finish();
            crate::finish_report(report, g)
        }
        "help" | "--help" | "-h" => {
            println!("{ROOTKIT_HELP}");
            Ok(0)
        }
        other => Err(Error::usage(format!(
            "unknown rootkit command {other:?}\n\n{ROOTKIT_HELP}"
        ))),
    }
}
