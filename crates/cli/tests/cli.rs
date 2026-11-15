use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use vantage_core::json::Value;

const HIDER: &str = r#"
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static int hidden(const char *name)
{
    const char *needle = getenv("VANTAGE_TEST_HIDE");
    return needle && *needle && strcmp(name, needle) == 0;
}

struct dirent *readdir(DIR *d)
{
    static struct dirent *(*real)(DIR *);
    if (!real)
        real = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real(d)) && hidden(e->d_name))
        ;
    return e;
}

struct dirent64 *readdir64(DIR *d)
{
    static struct dirent64 *(*real)(DIR *);
    if (!real)
        real = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = real(d)) && hidden(e->d_name))
        ;
    return e;
}
"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vantage")
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn json(out: &Output) -> Value {
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    Value::parse(&text).unwrap_or_else(|e| {
        panic!(
            "bad JSON ({e}):\n{text}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn checks(v: &Value) -> Vec<&Value> {
    v.get("checks")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .collect()
}

fn find_check<'a>(v: &'a Value, id: &str) -> &'a Value {
    checks(v)
        .into_iter()
        .find(|c| c.get("check").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("check {id} missing"))
}

fn titles(check: &Value) -> Vec<String> {
    check
        .get("findings")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|f| f.get("title").and_then(Value::as_str).unwrap().to_owned())
        .collect()
}

fn compile(src: &str, out: &Path, args: &[&str]) {
    let c = out.with_extension("c");
    std::fs::write(&c, src).unwrap();
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let res = Command::new(&cc)
        .args(args)
        .arg("-o")
        .arg(out)
        .arg(&c)
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
}

#[test]
fn version_and_usage_errors() {
    let v = run(&["--version"]);
    assert!(v.status.success());
    assert!(String::from_utf8_lossy(&v.stdout).starts_with("vantage "));
    assert_eq!(run(&["nonsense"]).status.code(), Some(2));
    assert_eq!(run(&["elf", "checksec"]).status.code(), Some(2));
    assert_eq!(run(&["--fail-on", "bogus", "scan"]).status.code(), Some(2));
    assert_eq!(
        run(&["rootkit", "scan", "--check", "nope"]).status.code(),
        Some(2)
    );
    assert_eq!(run(&["help"]).status.code(), Some(0));
}

#[test]
fn elf_commands_on_own_binary() {
    let out = run(&["--json", "elf", "checksec", bin()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    let file = &v.get("files").unwrap().as_array().unwrap()[0];
    let cs = file.get("checksec").unwrap();
    assert_eq!(cs.get("nx").and_then(Value::as_str), Some("enabled"));
    assert!(
        cs.get("kind")
            .and_then(Value::as_str)
            .unwrap()
            .contains("pie")
    );

    let out = run(&["--json", "elf", "info", bin()]);
    let v = json(&out);
    assert_eq!(
        v.get("header").unwrap().get("type").and_then(Value::as_str),
        Some("DYN")
    );

    let out = run(&["--json", "elf", "symbols", "--grep", "main", bin()]);
    let syms = json(&out);
    let main = syms
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s.get("name").and_then(Value::as_str) == Some("main"))
        .expect("main symbol");
    let addr = main
        .get("value")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let out = run(&["elf", "symbols", "--lookup", &addr, bin()]);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .trim_end()
            .ends_with(" main")
    );

    let out = run(&["--json", "elf", "relocs", bin()]);
    assert!(!json(&out).as_array().unwrap().is_empty());

    let missing = run(&["elf", "info", "/nonexistent/vantage"]);
    assert_eq!(missing.status.code(), Some(3));
}

#[test]
fn checksec_fail_on_threshold() {
    let dir = tmp("failon");
    let weak = dir.join("weak");
    compile(
        "int main(void){return 0;}",
        &weak,
        &["-no-pie", "-fno-pie", "-Wl,-z,norelro"],
    );
    let w = weak.to_str().unwrap();
    assert_eq!(
        run(&["--fail-on", "medium", "elf", "checksec", w])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        run(&["--fail-on", "critical", "elf", "checksec", w])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn preload_hiding_is_detected() {
    let dir = tmp("preload");
    let lib = dir.join("libhide.so");
    compile(HIDER, &lib, &["-shared", "-fPIC", "-ldl"]);
    let target = dir.join("target");
    std::fs::create_dir_all(&target).unwrap();
    for n in ["visible_a", "vantage_hidden_file", "visible_b"] {
        std::fs::write(target.join(n), b"x").unwrap();
    }
    let run_hidden = |needle: &str| {
        Command::new(bin())
            .args([
                "--json",
                "rootkit",
                "scan",
                "--check",
                "userland-hiding",
                "--dir",
            ])
            .arg(&target)
            .env("LD_PRELOAD", &lib)
            .env("VANTAGE_TEST_HIDE", needle)
            .output()
            .unwrap()
    };

    let out = run_hidden("vantage_hidden_file");
    let v = json(&out);
    let t = titles(find_check(&v, "userland-hiding"));
    let expect = format!(
        "{}/vantage_hidden_file hidden from libc readdir",
        target.display()
    );
    assert!(t.contains(&expect), "{t:?}");

    let mut sleeper = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = sleeper.id().to_string();
    let out = run_hidden(&pid);
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    let v = json(&out);
    let t = titles(find_check(&v, "userland-hiding"));
    assert!(
        t.contains(&format!("process {pid} hidden from libc readdir")),
        "{t:?}"
    );

    let clean = Command::new(bin())
        .args([
            "--json",
            "rootkit",
            "scan",
            "--check",
            "userland-hiding",
            "--dir",
        ])
        .arg(&target)
        .output()
        .unwrap();
    let v = json(&clean);
    assert!(titles(find_check(&v, "userland-hiding")).is_empty());
}

#[test]
fn preload_environment_is_reported() {
    let mut child = Command::new("sleep")
        .arg("30")
        .env("LD_PRELOAD", "/nonexistent/vantage-marker.so")
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let out = run(&["--json", "rootkit", "scan", "--check", "preload"]);
    let _ = child.kill();
    let _ = child.wait();
    let v = json(&out);
    let c = find_check(&v, "preload");
    let f = c
        .get("findings")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|f| {
            f.get("evidence")
                .and_then(|e| e.get("value"))
                .and_then(Value::as_str)
                == Some("/nonexistent/vantage-marker.so")
        })
        .expect("marker preload finding");
    let procs = f
        .get("evidence")
        .unwrap()
        .get("processes")
        .unwrap()
        .as_array()
        .unwrap();
    assert!(
        procs
            .iter()
            .any(|p| p.as_str().unwrap().starts_with(&format!("{}:", child.id())))
    );
}

#[test]
fn scan_reports_every_check() {
    let out = run(&[
        "--json",
        "scan",
        "--pid-max",
        "2000",
        "--skip",
        "hidden-ports",
        "--skip",
        "privileged-files",
        "--skip",
        "setuid-mitigations",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    let ids: Vec<&str> = checks(&v)
        .iter()
        .map(|c| c.get("check").and_then(Value::as_str).unwrap())
        .collect();
    for id in [
        "hardening",
        "lockdown",
        "privileged-processes",
        "hidden-processes",
        "hidden-modules",
        "kernel-taint",
    ] {
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
    assert!(!ids.contains(&"hidden-ports"));
    for c in checks(&v) {
        let status = c.get("status").and_then(Value::as_str).unwrap();
        assert_ne!(status, "error", "{}", c.to_compact());
        if status == "skipped" {
            assert!(
                c.get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|r| !r.is_empty())
            );
        }
    }
    assert!(v.get("host").unwrap().get("kernel").is_some());
}

#[test]
fn caps_and_unprivileged_monitor() {
    let out = run(&["--json", "kernguard", "caps"]);
    let v = json(&out);
    assert!(
        v.get("capabilities")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() > 10)
    );
    if unsafe { libc::geteuid() } != 0 {
        let out = run(&["kernguard", "monitor", "--duration", "1"]);
        assert_eq!(out.status.code(), Some(3));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("needs root") || err.contains("no eBPF support"),
            "{err}"
        );
    }
}

#[test]
fn output_file_is_private_and_refuses_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("output");
    let report = dir.join("report.json");
    let out = run(&[
        "--json",
        "--output",
        report.to_str().unwrap(),
        "rootkit",
        "scan",
        "--check",
        "kernel-taint",
    ]);
    assert!(out.status.success());
    let mode = std::fs::metadata(&report).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(Value::parse(&std::fs::read_to_string(&report).unwrap()).is_ok());
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(dir.join("elsewhere"), &link).unwrap();
    let out = run(&["--output", link.to_str().unwrap(), "rootkit", "list"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!dir.join("elsewhere").exists());
}
