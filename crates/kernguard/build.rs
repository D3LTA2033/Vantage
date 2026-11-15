use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn pkg_config(args: &[&str]) -> Option<String> {
    let out = Command::new("pkg-config")
        .args(args)
        .arg("libbpf")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=bpf/kernguard.bpf.c");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=BPF_CFLAGS");
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let (define, triple) = match arch.as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        other => panic!(
            "kernguard eBPF programs are built for x86_64 and aarch64 only (target: {other}); build with --no-default-features"
        ),
    };

    match pkg_config(&["--modversion"]) {
        Some(v) => {
            let major: u32 = v
                .split('.')
                .next()
                .and_then(|m| m.parse().ok())
                .unwrap_or(0);
            if major < 1 {
                panic!("libbpf {v} found; kernguard needs libbpf >= 1.0");
            }
        }
        None => println!(
            "cargo:warning=pkg-config could not find libbpf; assuming it is on the default paths"
        ),
    }

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("kernguard.bpf.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let mut cmd = Command::new(&clang);
    cmd.args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
        .arg(format!("-D__TARGET_ARCH_{define}"));
    let multiarch = Path::new("/usr/include").join(triple);
    if multiarch.is_dir() {
        cmd.arg("-idirafter").arg(&multiarch);
    }
    if let Some(cflags) = pkg_config(&["--cflags"]) {
        cmd.args(cflags.split_whitespace());
    }
    if let Ok(extra) = env::var("BPF_CFLAGS") {
        cmd.args(extra.split_whitespace());
    }
    cmd.arg("-c").arg("bpf/kernguard.bpf.c").arg("-o").arg(&out);
    let res = cmd
        .output()
        .unwrap_or_else(|e| panic!("cannot run {clang} to build the BPF object: {e}"));
    if !res.status.success() {
        panic!(
            "BPF compilation failed:\n{}{}",
            String::from_utf8_lossy(&res.stdout),
            String::from_utf8_lossy(&res.stderr)
        );
    }

    match pkg_config(&["--libs"]) {
        Some(libs) => {
            for flag in libs.split_whitespace() {
                if let Some(dir) = flag.strip_prefix("-L") {
                    println!("cargo:rustc-link-search=native={dir}");
                } else if let Some(lib) = flag.strip_prefix("-l") {
                    println!("cargo:rustc-link-lib={lib}");
                }
            }
        }
        None => println!("cargo:rustc-link-lib=bpf"),
    }
}
