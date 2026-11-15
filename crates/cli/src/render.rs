use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use vantage_core::json::Value;
use vantage_core::{CheckResult, Error, Finding, Report, Result, Severity, Status};

pub struct Out {
    w: Box<dyn Write>,
    pub json: bool,
    pub min: Severity,
}

impl Out {
    pub fn open(path: Option<&str>, json: bool, min: Severity) -> Result<Out> {
        let w: Box<dyn Write> = match path {
            None | Some("-") => Box::new(io::BufWriter::new(io::stdout())),
            Some(p) => Box::new(io::BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(p)
                    .map_err(|e| Error::io(format!("open {p}"), e))?,
            )),
        };
        Ok(Out { w, json, min })
    }

    pub fn line(&mut self, s: &str) -> Result<()> {
        writeln!(self.w, "{s}").map_err(|e| Error::io("write output", e))
    }

    pub fn value(&mut self, v: &Value) -> Result<()> {
        let text = if self.json {
            v.to_pretty()
        } else {
            v.to_compact()
        };
        self.line(&text)
    }

    pub fn json_line(&mut self, v: &Value) -> Result<()> {
        let text = v.to_compact();
        self.line(&text)?;
        self.flush()
    }

    pub fn flush(&mut self) -> Result<()> {
        self.w.flush().map_err(|e| Error::io("write output", e))
    }
}

pub fn table(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let cols = headers.len();
    let mut width = vec![0usize; cols];
    for (i, h) in headers.iter().enumerate() {
        width[i] = h.chars().count();
    }
    for r in rows {
        for (i, c) in r.iter().enumerate().take(cols) {
            width[i] = width[i].max(c.chars().count());
        }
    }
    let fmt = |cells: Vec<&str>| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(c);
                s.extend(std::iter::repeat_n(' ', width[i] - c.chars().count() + 2));
            }
        }
        s.trim_end().to_owned()
    };
    let mut out = vec![fmt(headers.to_vec())];
    for r in rows {
        out.push(fmt(r.iter().map(String::as_str).collect()));
    }
    out
}

pub fn evidence_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::Str(s) => Some(s.clone()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(evidence_text).collect();
            (!parts.is_empty()).then(|| parts.join(","))
        }
        other => Some(other.to_compact()),
    }
}

pub fn finding_lines(f: &Finding, indent: &str) -> Vec<String> {
    let mut out = vec![format!("{indent}[{}] {}", f.severity.as_str(), f.title)];
    if !f.detail.is_empty() {
        out.push(format!("{indent}    {}", f.detail));
    }
    let ev: Vec<String> = f
        .evidence
        .iter()
        .filter_map(|(k, v)| evidence_text(v).map(|t| format!("{k}={t}")))
        .collect();
    if !ev.is_empty() {
        out.push(format!("{indent}    {}", ev.join(" ")));
    }
    out
}

pub fn filter(report: &mut Report, min: Severity) {
    for c in &mut report.checks {
        c.findings.retain(|f| f.severity >= min);
        if c.status == Status::Findings && c.findings.is_empty() {
            c.status = Status::Ok;
        }
    }
}

fn duration(c: &CheckResult) -> String {
    let ms = c.duration.as_millis();
    if ms >= 1000 {
        format!("{:.1}s", c.duration.as_secs_f64())
    } else {
        format!("{ms}ms")
    }
}

pub fn report(out: &mut Out, report: &Report) -> Result<()> {
    if out.json {
        return out.value(&report.to_json());
    }
    let h = &report.host;
    out.line(&format!(
        "vantage {}  host {}  kernel {}  {}  euid {}",
        env!("CARGO_PKG_VERSION"),
        h.hostname,
        h.kernel,
        h.machine,
        h.euid
    ))?;
    let mut engine = "";
    for c in &report.checks {
        if c.engine != engine {
            engine = c.engine;
            out.line("")?;
            out.line(engine)?;
        }
        let (label, info) = match &c.status {
            Status::Skipped(r) => ("skipped", r.clone()),
            Status::Error(r) => ("error", r.clone()),
            s => (s.as_str(), c.summary.clone()),
        };
        out.line(&format!(
            "  {label:<9} {:<22} {info}  ({})",
            c.id,
            duration(c)
        ))?;
        for f in &c.findings {
            for l in finding_lines(f, "            ") {
                out.line(&l)?;
            }
        }
    }
    let counts = report.counts();
    let (mut ok, mut found, mut skipped, mut errors) = (0, 0, 0, 0);
    for c in &report.checks {
        match c.status {
            Status::Ok => ok += 1,
            Status::Findings => found += 1,
            Status::Skipped(_) => skipped += 1,
            Status::Error(_) => errors += 1,
        }
    }
    out.line("")?;
    out.line(&format!(
        "{} critical, {} high, {} medium, {} low, {} info  |  {} checks: {ok} ok, {found} with findings, {skipped} skipped, {errors} errors",
        counts[4],
        counts[3],
        counts[2],
        counts[1],
        counts[0],
        report.checks.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_alignment() {
        let rows = vec![
            vec!["a".into(), "long value".into(), "x".into()],
            vec!["bbb".into(), "v".into(), "y".into()],
        ];
        let t = table(&["k", "value", "z"], &rows);
        assert_eq!(t[0], "k    value       z");
        assert_eq!(t[1], "a    long value  x");
        assert_eq!(t[2], "bbb  v           y");
    }

    #[test]
    fn finding_render() {
        let f = Finding::new(Severity::High, "t")
            .detail("d")
            .evidence("pid", 5u32)
            .evidence("x", Value::Null);
        assert_eq!(
            finding_lines(&f, ""),
            vec!["[high] t", "    d", "    pid=5"]
        );
    }
}
