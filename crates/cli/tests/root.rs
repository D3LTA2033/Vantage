use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use vantage_core::json::Value;

const HELPER: &str = r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "memfd") == 0) {
        int src = open("/bin/true", O_RDONLY);
        int fd = memfd_create("vantage-test", MFD_CLOEXEC);
        char buf[65536];
        ssize_t n;
        while ((n = read(src, buf, sizeof(buf))) > 0)
            if (write(fd, buf, n) != n)
                return 2;
        char *args[] = {"true", NULL};
        char *env[] = {NULL};
        fexecve(fd, args, env);
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "ptrace") == 0) {
        pid_t c = fork();
        if (c == 0) {
            pause();
            _exit(0);
        }
        usleep(100000);
        ptrace(PTRACE_ATTACH, c, 0, 0);
        waitpid(c, 0, 0);
        ptrace(PTRACE_DETACH, c, 0, 0);
        kill(c, SIGKILL);
        waitpid(c, 0, 0);
        return 0;
    }
    return 3;
}
"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vantage")
}

fn dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("root-tests");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn helper() -> PathBuf {
    let out = dir().join("helper");
    let c = out.with_extension("c");
    std::fs::write(&c, HELPER).unwrap();
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let res = Command::new(cc)
        .arg("-o")
        .arg(&out)
        .arg(&c)
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    out
}

fn start_monitor(seconds: &str) -> Child {
    let mut child = Command::new(bin())
        .args([
            "--json",
            "--min-severity",
            "info",
            "kernguard",
            "monitor",
            "--duration",
            seconds,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut lines = BufReader::new(stderr).lines();
    let mut seen = Vec::new();
    let ready = loop {
        match lines.next() {
            Some(Ok(l)) if l.contains("ctrl-c to stop") => break l,
            Some(Ok(l)) => seen.push(l),
            _ => panic!("monitor failed to start:\n{}", seen.join("\n")),
        }
    };
    assert!(!ready.contains(" off"), "a detector is inactive: {ready}");
    std::thread::spawn(move || for _ in lines {});
    child
}

fn monitor_findings(child: Child) -> Vec<Value> {
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| Value::parse(l).unwrap())
        .filter(|v| v.get("kind").and_then(Value::as_str) == Some("finding"))
        .collect()
}

fn title(v: &Value) -> &str {
    v.get("finding")
        .and_then(|f| f.get("title"))
        .and_then(Value::as_str)
        .unwrap()
}

fn evidence<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get("finding")?.get("evidence")?.get(key)
}

#[test]
#[ignore = "needs root: loads eBPF programs"]
fn monitor_detects_memfd_exec_and_ptrace() {
    let helper = helper();
    let child = start_monitor("4");
    Command::new(&helper).arg("memfd").status().unwrap();
    Command::new(&helper).arg("ptrace").status().unwrap();
    let findings = monitor_findings(child);
    assert!(
        findings
            .iter()
            .any(|f| title(f) == "fileless execution from memfd"),
        "{:?}",
        findings.iter().map(title).collect::<Vec<_>>()
    );
    assert!(
        findings
            .iter()
            .any(|f| title(f) == "anonymous memory file created"
                && evidence(f, "name").and_then(Value::as_str) == Some("vantage-test"))
    );
    assert!(
        findings
            .iter()
            .any(|f| title(f).starts_with("ptrace attach to pid"))
    );
}

#[test]
#[ignore = "needs root: loads eBPF programs and creates a setuid binary"]
fn monitor_classifies_setuid_exec() {
    use std::os::unix::fs::PermissionsExt;
    let base = ["/var/tmp", env!("CARGO_TARGET_TMPDIR"), "/tmp"]
        .iter()
        .map(PathBuf::from)
        .find(|d| allows_setuid(d))
        .expect("no directory mounted without nosuid");
    let work = base.join(format!("vantage-suid-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o755)).unwrap();
    let suid = work.join("suid-true");
    std::fs::copy("/bin/true", &suid).unwrap();
    std::fs::set_permissions(&suid, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let child = start_monitor("4");
    let status = Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .arg(&suid)
        .status()
        .expect("setpriv from util-linux");
    assert!(status.success());
    let findings = monitor_findings(child);
    let _ = std::fs::remove_dir_all(&work);
    let hit = findings
        .iter()
        .find(|f| title(f) == "privileges gained by executing a setuid or file-capability binary")
        .unwrap_or_else(|| panic!("{:?}", findings.iter().map(title).collect::<Vec<_>>()));
    assert_eq!(
        evidence(hit, "syscall").and_then(Value::as_str),
        Some("execve")
    );
    assert_eq!(
        evidence(hit, "euid_change").and_then(Value::as_str),
        Some("65534 -> 0")
    );
    assert!(
        findings
            .iter()
            .all(|f| !title(f).starts_with("credentials elevated"))
    );
}

fn allows_setuid(dir: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statvfs(c.as_ptr(), &mut st) == 0 && st.f_flag & libc::ST_NOSUID == 0 }
}

fn trace(args: &[&str]) -> (Vec<Value>, Option<i32>) {
    let out = Command::new(bin())
        .args(["--json", "kernguard", "trace", "--"])
        .args(args)
        .output()
        .unwrap();
    let events = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| Value::parse(l).unwrap())
        .collect();
    (events, out.status.code())
}

#[test]
#[ignore = "needs root: loads eBPF programs"]
fn trace_follows_children_and_decodes_paths() {
    let (events, code) = trace(&["sh", "-c", "cat /etc/hostname > /dev/null; exit 7"]);
    assert_eq!(code, Some(7));
    let opened = events.iter().find(|e| {
        matches!(
            e.get("syscall").and_then(Value::as_str),
            Some("openat" | "open")
        ) && e.get("path").and_then(Value::as_str) == Some("/etc/hostname")
    });
    let opened = opened.expect("openat of /etc/hostname");
    assert!(opened.get("ret").and_then(|r| r.as_u64()).is_some());
    let pids: std::collections::BTreeSet<u64> = events
        .iter()
        .filter_map(|e| e.get("tgid").and_then(Value::as_u64))
        .collect();
    assert!(pids.len() >= 2, "child process not followed: {pids:?}");
}

#[test]
#[ignore = "needs root: reads /proc/kcore and tracefs"]
fn privileged_rootkit_checks_run_clean() {
    let out = Command::new(bin())
        .args([
            "--json",
            "rootkit",
            "scan",
            "--check",
            "syscall-table",
            "--check",
            "ftrace-hooks",
            "--check",
            "hidden-modules",
        ])
        .output()
        .unwrap();
    let v = Value::parse(&String::from_utf8(out.stdout).unwrap()).unwrap();
    for c in v.get("checks").and_then(Value::as_array).unwrap() {
        let id = c.get("check").and_then(Value::as_str).unwrap();
        let status = c.get("status").and_then(Value::as_str).unwrap();
        assert_ne!(status, "error", "{id}: {}", c.to_compact());
        if id == "syscall-table" && Path::new("/proc/kcore").exists() {
            assert_eq!(status, "ok", "{}", c.to_compact());
        }
    }
}
