mod args;
mod elf;
mod kern;
mod render;
mod scan;

use render::Out;
use std::io;
use vantage_core::{Error, Report, Result, Severity};

const HELP: &str = "vantage: Linux host security inspection

usage: vantage [global options] <command> [args]

commands:
  scan          run every snapshot check (kernguard audit, rootkithunter, setuid ELF mitigations)
  kernguard     kernel monitoring: caps, audit, monitor, trace
  elf           ELF analysis: info, checksec, symbols, relocs
  rootkit       rootkit detection: list, scan
  help          this text; `vantage <command> help` for details

global options:
  --json                 machine-readable output
  --output FILE          write output to FILE (created mode 0600, symlinks refused)
  --min-severity LEVEL   hide findings below LEVEL (info, low, medium, high, critical)
  --fail-on LEVEL        exit 1 if any finding is at or above LEVEL
  -V, --version          print version

exit status: 0 success, 1 findings at or above --fail-on, 2 usage error, 3 runtime error;
kernguard trace exits with the traced command's status";

#[derive(Debug, Clone, Default)]
pub struct Global {
    pub json: bool,
    pub output: Option<String>,
    pub fail_on: Option<Severity>,
    pub min: Option<Severity>,
}

fn severity(v: &str) -> Result<Severity> {
    Severity::parse(v).ok_or_else(|| {
        Error::usage(format!(
            "invalid severity {v:?} (info, low, medium, high, critical)"
        ))
    })
}

fn split_globals(args: Vec<String>) -> Result<(Global, Vec<String>, bool)> {
    let mut g = Global::default();
    let mut rest = Vec::new();
    let mut version = false;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            rest.push(a);
            rest.extend(it.by_ref());
            break;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (a.clone(), None),
        };
        let mut value = |inline: Option<String>| -> Result<String> {
            match inline {
                Some(v) => Ok(v),
                None => it
                    .next()
                    .ok_or_else(|| Error::usage(format!("{name} needs a value"))),
            }
        };
        match name.as_str() {
            "--json" if inline.is_none() => g.json = true,
            "--output" => g.output = Some(value(inline)?),
            "--fail-on" => g.fail_on = Some(severity(&value(inline)?)?),
            "--min-severity" => g.min = Some(severity(&value(inline)?)?),
            "-V" | "--version" => version = true,
            _ => rest.push(a),
        }
    }
    Ok((g, rest, version))
}

pub fn finish_report(mut report: Report, g: &Global) -> Result<i32> {
    let worst = report.max_severity();
    let min = g.min.unwrap_or(Severity::Info);
    render::filter(&mut report, min);
    let mut out = Out::open(g.output.as_deref(), g.json, min)?;
    render::report(&mut out, &report)?;
    out.flush()?;
    Ok(match (g.fail_on, worst) {
        (Some(t), Some(w)) if w >= t => 1,
        _ => 0,
    })
}

fn run() -> Result<i32> {
    let (g, args, version) = split_globals(std::env::args().skip(1).collect())?;
    if version {
        println!("vantage {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    let Some((cmd, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(2);
    };
    match cmd.as_str() {
        "scan"
            if rest
                .first()
                .is_some_and(|a| a == "help" || a == "--help" || a == "-h") =>
        {
            println!("{}", scan::SCAN_HELP);
            Ok(0)
        }
        "scan" => scan::scan(rest, &g),
        "kernguard" | "kg" => kern::run(rest, &g),
        "elf" => elf::run(rest, &g),
        "rootkit" | "rk" => scan::rootkit(rest, &g),
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            Ok(0)
        }
        other => Err(Error::usage(format!("unknown command {other:?}\n\n{HELP}"))),
    }
}

fn main() {
    let code = match run() {
        Ok(c) => c,
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::BrokenPipe => 0,
        Err(e) => {
            eprintln!("vantage: {e}");
            match e {
                Error::Usage(_) => 2,
                _ => 3,
            }
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn globals_anywhere_before_double_dash() {
        let (g, rest, ver) = split_globals(v(&[
            "elf",
            "--json",
            "checksec",
            "--fail-on=high",
            "x",
            "--min-severity",
            "low",
        ]))
        .unwrap();
        assert!(g.json && !ver);
        assert_eq!(g.fail_on, Some(Severity::High));
        assert_eq!(g.min, Some(Severity::Low));
        assert_eq!(rest, v(&["elf", "checksec", "x"]));
        let (g, rest, _) = split_globals(v(&["kernguard", "trace", "--", "ls", "--json"])).unwrap();
        assert!(!g.json);
        assert_eq!(rest, v(&["kernguard", "trace", "--", "ls", "--json"]));
        assert!(split_globals(v(&["--fail-on", "bogus"])).is_err());
        assert!(split_globals(v(&["--output"])).is_err());
    }
}
