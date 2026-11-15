use crate::Result;
use crate::json::{self, Value};
use crate::sys::Host;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<(String, Value)>,
}

impl Finding {
    pub fn new(severity: Severity, title: impl Into<String>) -> Self {
        Finding {
            severity,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn evidence(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.evidence.push((key.into(), value.into()));
        self
    }

    pub fn evidence_value(&self, key: &str) -> Option<&Value> {
        self.evidence.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn to_json(&self) -> Value {
        json::obj([
            ("severity", self.severity.as_str().into()),
            ("title", self.title.clone().into()),
            ("detail", self.detail.clone().into()),
            ("evidence", Value::Object(self.evidence.clone())),
        ])
    }
}

#[derive(Debug)]
pub enum Outcome {
    Done {
        summary: String,
        findings: Vec<Finding>,
    },
    Skipped(String),
}

impl Outcome {
    pub fn done(summary: impl Into<String>, findings: Vec<Finding>) -> Self {
        Outcome::Done {
            summary: summary.into(),
            findings,
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        Outcome::Skipped(reason.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Ok,
    Findings,
    Skipped(String),
    Error(String),
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Findings => "findings",
            Status::Skipped(_) => "skipped",
            Status::Error(_) => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub engine: &'static str,
    pub id: &'static str,
    pub status: Status,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub duration: Duration,
}

impl CheckResult {
    pub fn run(
        engine: &'static str,
        id: &'static str,
        f: impl FnOnce() -> Result<Outcome>,
    ) -> Self {
        let start = Instant::now();
        let outcome = f();
        let duration = start.elapsed();
        let (status, summary, mut findings) = match outcome {
            Ok(Outcome::Done { summary, findings }) => {
                let status = if findings.is_empty() {
                    Status::Ok
                } else {
                    Status::Findings
                };
                (status, summary, findings)
            }
            Ok(Outcome::Skipped(reason)) => (Status::Skipped(reason), String::new(), Vec::new()),
            Err(e) => (Status::Error(e.to_string()), String::new(), Vec::new()),
        };
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        CheckResult {
            engine,
            id,
            status,
            summary,
            findings,
            duration,
        }
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn to_json(&self) -> Value {
        let reason = match &self.status {
            Status::Skipped(r) | Status::Error(r) => Value::from(r.as_str()),
            _ => Value::Null,
        };
        json::obj([
            ("engine", self.engine.into()),
            ("check", self.id.into()),
            ("status", self.status.as_str().into()),
            ("reason", reason),
            ("summary", self.summary.clone().into()),
            ("duration_ms", (self.duration.as_millis() as u64).into()),
            (
                "findings",
                Value::Array(self.findings.iter().map(Finding::to_json).collect()),
            ),
        ])
    }
}

#[derive(Debug)]
pub struct Report {
    pub host: Host,
    pub started: SystemTime,
    pub duration: Duration,
    pub checks: Vec<CheckResult>,
}

impl Report {
    pub fn new(host: Host) -> Self {
        Report {
            host,
            started: SystemTime::now(),
            duration: Duration::ZERO,
            checks: Vec::new(),
        }
    }

    pub fn finish(&mut self) {
        self.duration = self.started.elapsed().unwrap_or_default();
    }

    pub fn findings(&self) -> impl Iterator<Item = (&CheckResult, &Finding)> {
        self.checks
            .iter()
            .flat_map(|c| c.findings.iter().map(move |f| (c, f)))
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.checks
            .iter()
            .filter_map(CheckResult::max_severity)
            .max()
    }

    pub fn counts(&self) -> [usize; 5] {
        let mut counts = [0usize; 5];
        for (_, f) in self.findings() {
            counts[f.severity as usize] += 1;
        }
        counts
    }

    pub fn to_json(&self) -> Value {
        let started = self
            .started
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let counts = self.counts();
        json::obj([
            ("tool", "vantage".into()),
            ("version", env!("CARGO_PKG_VERSION").into()),
            ("host", self.host.to_json()),
            ("started_unix", started.into()),
            ("duration_ms", (self.duration.as_millis() as u64).into()),
            (
                "counts",
                json::obj(
                    Severity::ALL
                        .iter()
                        .map(|s| (s.as_str(), Value::from(counts[*s as usize]))),
                ),
            ),
            (
                "checks",
                Value::Array(self.checks.iter().map(CheckResult::to_json).collect()),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
        for s in Severity::ALL {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        assert_eq!(Severity::parse("bogus"), None);
    }

    #[test]
    fn run_maps_outcomes() {
        let ok = CheckResult::run("e", "a", || Ok(Outcome::done("nothing", vec![])));
        assert_eq!(ok.status, Status::Ok);
        let skip = CheckResult::run("e", "b", || Ok(Outcome::skipped("needs root")));
        assert_eq!(skip.status, Status::Skipped("needs root".into()));
        let err = CheckResult::run("e", "c", || Err(Error::parse("boom")));
        assert!(matches!(err.status, Status::Error(ref m) if m.contains("boom")));
        let found = CheckResult::run("e", "d", || {
            Ok(Outcome::done(
                "2",
                vec![
                    Finding::new(Severity::Low, "x"),
                    Finding::new(Severity::High, "y"),
                ],
            ))
        });
        assert_eq!(found.status, Status::Findings);
        assert_eq!(found.findings[0].severity, Severity::High);
        assert_eq!(found.max_severity(), Some(Severity::High));
    }

    #[test]
    fn report_json_is_parseable() {
        let mut r = Report::new(Host::current());
        r.checks.push(CheckResult::run("e", "d", || {
            Ok(Outcome::done(
                "",
                vec![Finding::new(Severity::Medium, "t").evidence("pid", 1u32)],
            ))
        }));
        r.finish();
        let parsed = Value::parse(&r.to_json().to_pretty()).unwrap();
        assert_eq!(
            parsed
                .get("counts")
                .unwrap()
                .get("medium")
                .unwrap()
                .as_u64(),
            Some(1)
        );
    }
}
