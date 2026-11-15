use crate::Options;
use crate::kallsyms::Kallsyms;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use vantage_core::{Finding, IoContext, Outcome, Result, Severity, rawsys, sys, text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcModule {
    pub name: String,
    pub size: u64,
    pub refcount: Option<i64>,
    pub deps: Vec<String>,
    pub state: String,
    pub taints: String,
}

pub fn parse_proc_modules(data: &[u8]) -> Vec<ProcModule> {
    data.split(|&b| b == b'\n')
        .filter_map(|line| {
            let line = text::from_bytes(line);
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 {
                return None;
            }
            let taints = cols
                .get(6)
                .and_then(|t| t.strip_prefix('(')?.strip_suffix(')'))
                .unwrap_or("")
                .to_owned();
            Some(ProcModule {
                name: cols[0].to_owned(),
                size: cols[1].parse().ok()?,
                refcount: cols[2].parse().ok(),
                deps: cols[3]
                    .split(',')
                    .filter(|d| !d.is_empty() && *d != "-")
                    .map(str::to_owned)
                    .collect(),
                state: cols[4].to_owned(),
                taints,
            })
        })
        .collect()
}

pub fn read_proc_modules() -> Result<Vec<ProcModule>> {
    let data =
        rawsys::read_file(Path::new("/proc/modules"), 16 << 20).context("read /proc/modules")?;
    Ok(parse_proc_modules(&data))
}

pub fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

fn sysfs_modules() -> io::Result<BTreeSet<String>> {
    Ok(rawsys::read_dir(Path::new("/sys/module"))?
        .into_iter()
        .map(|e| text::from_bytes(&e.name))
        .filter(|n| rawsys::Fd::open(&Path::new("/sys/module").join(n).join("initstate")).is_ok())
        .collect())
}

fn btf_modules() -> io::Result<BTreeSet<String>> {
    Ok(rawsys::read_dir(Path::new("/sys/kernel/btf"))?
        .into_iter()
        .map(|e| text::from_bytes(&e.name))
        .filter(|n| n != "vmlinux")
        .collect())
}

pub fn hidden_modules(_: &Options) -> Result<Outcome> {
    let listed: BTreeSet<String> = read_proc_modules()?.into_iter().map(|m| m.name).collect();
    let mut sources: Vec<(&str, BTreeSet<String>)> = Vec::new();
    let mut unavailable = Vec::new();
    match sysfs_modules() {
        Ok(s) => sources.push(("sysfs", s)),
        Err(e) => unavailable.push(format!("/sys/module ({e})")),
    }
    match btf_modules() {
        Ok(s) => sources.push(("btf", s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            unavailable.push("/sys/kernel/btf (CONFIG_DEBUG_INFO_BTF_MODULES off)".into())
        }
        Err(e) => unavailable.push(format!("/sys/kernel/btf ({e})")),
    }
    match Kallsyms::read() {
        Ok(k) => sources.push(("kallsyms", k.modules())),
        Err(e) => unavailable.push(format!("/proc/kallsyms ({e})")),
    }
    let mut findings = Vec::new();
    let mut seen: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (source, names) in &sources {
        for n in names {
            if !listed.contains(n) {
                seen.entry(n.as_str()).or_default().push(source);
            }
        }
    }
    if !seen.is_empty() {
        let relisted: BTreeSet<String> = read_proc_modules()?.into_iter().map(|m| m.name).collect();
        for (name, srcs) in seen {
            if relisted.contains(name) {
                continue;
            }
            findings.push(
                Finding::new(Severity::Critical, format!("module {name} hidden from /proc/modules"))
                    .detail("the module still has kernel objects or symbols but is unlinked from the module list, which is how LKM rootkits hide themselves")
                    .evidence("module", name)
                    .evidence("seen_in", srcs),
            );
        }
    }
    if let Some((_, sysfs)) = sources.iter().find(|(s, _)| *s == "sysfs") {
        for name in listed.difference(sysfs) {
            findings.push(
                Finding::new(Severity::Medium, format!("module {name} missing from /sys/module"))
                    .detail("listed in /proc/modules but its sysfs kobject is gone; partial unlinking is a rootkit hiding step")
                    .evidence("module", name.as_str()),
            );
        }
    }
    let mut summary = format!(
        "{} listed modules cross-checked against {}",
        listed.len(),
        sources
            .iter()
            .map(|(s, n)| format!("{s} ({})", n.len()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !unavailable.is_empty() {
        summary.push_str(&format!("; unavailable: {}", unavailable.join(", ")));
    }
    Ok(Outcome::done(summary, findings))
}

pub fn parse_modules_dep(data: &[u8]) -> BTreeMap<String, String> {
    data.split(|&b| b == b'\n')
        .filter_map(|line| {
            let path = text::from_bytes(line.split(|&b| b == b':').next()?);
            let base = path.rsplit('/').next()?;
            let stem = [".ko.zst", ".ko.xz", ".ko.gz", ".ko"]
                .iter()
                .find_map(|ext| base.strip_suffix(ext))?;
            Some((normalize(stem), path))
        })
        .collect()
}

const TAINT_ISSUES: [(char, Severity, &str); 5] = [
    ('F', Severity::High, "force-loaded"),
    ('E', Severity::Medium, "unsigned"),
    ('O', Severity::Low, "out-of-tree"),
    ('P', Severity::Info, "proprietary"),
    ('C', Severity::Info, "staging"),
];

pub fn audit(_: &Options) -> Result<Outcome> {
    let modules = read_proc_modules()?;
    let release = sys::uname().release;
    let tree = PathBuf::from("/lib/modules").join(&release);
    let dep = match std::fs::read(tree.join("modules.dep")) {
        Ok(d) => Some(parse_modules_dep(&d)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| format!("read {}", tree.join("modules.dep").display()));
        }
    };
    let mut findings = Vec::new();
    for m in &modules {
        let mut issues: Vec<(Severity, String)> = TAINT_ISSUES
            .iter()
            .filter(|(c, _, _)| m.taints.contains(*c))
            .map(|(_, s, d)| (*s, (*d).to_owned()))
            .collect();
        let path = dep
            .as_ref()
            .and_then(|d| d.get(&normalize(&m.name)).cloned());
        if dep.is_some() && path.is_none() {
            issues.push((
                Severity::Medium,
                format!("not in the module tree of {release}"),
            ));
        }
        if m.state != "Live" {
            issues.push((Severity::Info, format!("state {}", m.state)));
        }
        let Some(sev) = issues.iter().map(|(s, _)| *s).max() else {
            continue;
        };
        let names: Vec<&str> = issues.iter().map(|(_, d)| d.as_str()).collect();
        findings.push(
            Finding::new(sev, format!("module {}: {}", m.name, names.join(", ")))
                .evidence("module", m.name.as_str())
                .evidence("taints", m.taints.as_str())
                .evidence("size", m.size)
                .evidence("refcount", m.refcount)
                .evidence("state", m.state.as_str())
                .evidence("path", path),
        );
    }
    let mut summary = format!("{} modules audited", modules.len());
    if dep.is_none() {
        summary.push_str(&format!(
            "; {} missing, so modules were not matched against the installed tree (kernel upgraded without reboot?)",
            tree.join("modules.dep").display()
        ));
    }
    Ok(Outcome::done(summary, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_modules_parsing() {
        let data = b"nvidia_uvm 4931584 0 - Live 0xffffffffc1e00000 (POE)\nsnd_hda_codec 212992 2 snd_hda_codec_realtek,snd_hda_intel, Live 0x0000000000000000\nbroken\nloading 4096 -2 - Loading 0x0 (OE)\n";
        let m = parse_proc_modules(data);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].taints, "POE");
        assert_eq!(m[1].deps, vec!["snd_hda_codec_realtek", "snd_hda_intel"]);
        assert_eq!(m[1].taints, "");
        assert_eq!(m[2].state, "Loading");
        assert_eq!(m[2].refcount, Some(-2));
    }

    #[test]
    fn modules_dep_parsing() {
        let d = parse_modules_dep(b"kernel/fs/xfs/xfs.ko.zst: kernel/lib/libcrc32c.ko.zst\nupdates/dkms/nvidia-uvm.ko: \nextra/foo.ko.xz:\n\n");
        assert_eq!(
            d.get("xfs").map(String::as_str),
            Some("kernel/fs/xfs/xfs.ko.zst")
        );
        assert!(d.contains_key("nvidia_uvm"));
        assert!(d.contains_key("foo"));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn live_cross_check_runs() {
        match hidden_modules(&Options::default()).unwrap() {
            Outcome::Done { findings, .. } => {
                assert!(
                    findings.iter().all(|f| f.severity != Severity::Critical),
                    "{findings:?}"
                )
            }
            Outcome::Skipped(r) => panic!("{r}"),
        }
    }
}
