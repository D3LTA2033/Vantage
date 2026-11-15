use elfinspector::checksec::{Canary, Entry, Kind, Nx, Relro};
use elfinspector::reader::{Class, Endian};
use elfinspector::{Binary, Context};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use vantage_core::Severity;

const PROGRAM: &str = r#"
#include <stdio.h>
#include <string.h>
__attribute__((noinline)) int vantage_marker(int x) { return x * 3 + 1; }
int main(int argc, char **argv) {
    char buf[32];
    char dst[64];
    if (argc > 1) strcpy(buf, argv[1]); else buf[0] = 0;
    memcpy(dst, buf, strlen(buf) + 1);
    printf("%s %d\n", dst, vantage_marker(argc));
    puts("done");
    return 0;
}
"#;

const OBJECT: &str = r#"
extern int ext_func(int);
extern int ext_data;
int local_var = 5;
int entry_point(int x) { return ext_func(x) + ext_data + local_var; }
"#;

fn tmp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("elf-fixtures")
}

fn build(compiler: &str, name: &str, src: &str, args: &[&str]) -> Vec<u8> {
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    let c = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&c, src).unwrap();
    let res = Command::new(compiler)
        .args(args)
        .arg("-o")
        .arg(&out)
        .arg(&c)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {compiler}: {e}"));
    assert!(
        res.status.success(),
        "{compiler} {args:?} failed:\n{}",
        String::from_utf8_lossy(&res.stderr)
    );
    std::fs::read(out).unwrap()
}

fn cc(name: &str, args: &[&str]) -> Vec<u8> {
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    build(&compiler, name, PROGRAM, args)
}

fn hardened() -> Vec<u8> {
    cc(
        "hardened",
        &[
            "-O2",
            "-fstack-protector-strong",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=2",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
            "-Wl,-z,noexecstack",
        ],
    )
}

fn severities(bin: &Binary<'_>, ctx: Context) -> Vec<(Severity, String)> {
    bin.checksec()
        .findings(&ctx)
        .into_iter()
        .map(|f| (f.severity, f.title))
        .collect()
}

#[test]
fn hardened_binary() {
    let data = hardened();
    let bin = Binary::parse(&data).unwrap();
    let c = bin.checksec();
    assert_eq!(c.kind, Kind::Pie);
    assert_eq!(c.nx, Nx::Enabled);
    assert_eq!(c.relro, Some(Relro::Full));
    assert_eq!(c.canary, Canary::Imported);
    assert!(
        c.fortified.iter().any(|f| f == "__printf_chk"),
        "{:?}",
        c.fortified
    );
    assert!(
        c.fortified
            .iter()
            .any(|f| f == "__strcpy_chk" || f == "__memcpy_chk")
    );
    assert!(!c.stripped);
    assert!(!c.static_linked);
    assert_eq!(c.entry, Entry::Ok);
    assert!(
        c.interpreter
            .as_deref()
            .is_some_and(|i| i.contains("ld-linux"))
    );
    assert!(c.build_id.as_ref().is_none_or(|b| b.len() >= 16));
    let worst = severities(&bin, Context::default())
        .into_iter()
        .map(|(s, _)| s)
        .max();
    assert!(worst.is_none_or(|s| s <= Severity::Info), "{worst:?}");
    assert!(bin.elf.warnings.is_empty(), "{:?}", bin.elf.warnings);
}

#[test]
fn weak_binary() {
    let data = cc(
        "weak",
        &[
            "-O0",
            "-fno-stack-protector",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
            "-fno-pie",
            "-no-pie",
            "-z",
            "execstack",
            "-Wl,-z,norelro",
            "-Wl,-z,lazy",
        ],
    );
    let bin = Binary::parse(&data).unwrap();
    let c = bin.checksec();
    assert_eq!(c.kind, Kind::Executable);
    assert_eq!(c.nx, Nx::Disabled);
    assert_eq!(c.relro, Some(Relro::None));
    assert_eq!(c.canary, Canary::NotFound);
    assert!(c.fortified.is_empty());
    assert!(c.fortifiable.iter().any(|f| f == "strcpy" || f == "printf"));
    let found = severities(&bin, Context::default());
    let titles: BTreeSet<&str> = found.iter().map(|(_, t)| t.as_str()).collect();
    for expect in [
        "executable stack requested",
        "not position independent",
        "no RELRO",
        "no stack protector references",
        "no FORTIFY_SOURCE",
    ] {
        assert!(titles.contains(expect), "missing {expect}: {titles:?}");
    }
    let suid = severities(
        &bin,
        Context {
            setuid: true,
            host_paths: false,
        },
    );
    assert!(
        suid.iter()
            .any(|(s, t)| t == "executable stack requested" && *s == Severity::Critical)
    );
}

#[test]
fn partial_relro() {
    let data = cc("partial", &["-O1", "-Wl,-z,relro,-z,lazy"]);
    let bin = Binary::parse(&data).unwrap();
    assert_eq!(bin.checksec().relro, Some(Relro::Partial));
}

#[test]
fn rpath_and_runpath() {
    let data = cc(
        "rpath",
        &["-Wl,--disable-new-dtags,-rpath,/tmp:$ORIGIN/lib:rel"],
    );
    let bin = Binary::parse(&data).unwrap();
    let c = bin.checksec();
    assert_eq!(c.rpath, vec!["/tmp", "$ORIGIN/lib", "rel"]);
    assert!(c.runpath.is_empty());
    let found = c.findings(&Context {
        setuid: false,
        host_paths: true,
    });
    let sev = |p: &str| {
        found
            .iter()
            .find(|f| f.evidence_value("path").and_then(|v| v.as_str()) == Some(p))
            .map(|f| f.severity)
    };
    assert_eq!(sev("/tmp"), Some(Severity::High));
    assert_eq!(sev("$ORIGIN/lib"), Some(Severity::Low));
    assert_eq!(sev("rel"), Some(Severity::Medium));

    let data = cc(
        "runpath",
        &["-Wl,--enable-new-dtags,-rpath,/nonexistent/vantage:/usr/lib"],
    );
    let c = Binary::parse(&data).unwrap().checksec();
    assert_eq!(c.runpath, vec!["/nonexistent/vantage", "/usr/lib"]);
    assert!(c.rpath.is_empty());
    let found = c.findings(&Context {
        setuid: true,
        host_paths: true,
    });
    let sev = |p: &str| {
        found
            .iter()
            .find(|f| f.evidence_value("path").and_then(|v| v.as_str()) == Some(p))
            .map(|f| f.severity)
    };
    assert_eq!(sev("/usr/lib"), Some(Severity::Info));
    assert_eq!(sev("/nonexistent/vantage"), Some(Severity::Medium));
}

#[test]
fn shared_object_exports_and_versions() {
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let data = build(
        &compiler,
        "libvantage.so",
        "#include <stdio.h>\nint vantage_export(int x) { printf(\"%d\", x); return x; }\nstatic int hidden(void) { return 1; }\nint (*keep)(void) = hidden;\n",
        &[
            "-shared",
            "-fPIC",
            "-O1",
            "-U_FORTIFY_SOURCE",
            "-Wl,-soname,libvantage.so.1",
        ],
    );
    let bin = Binary::parse(&data).unwrap();
    assert_eq!(bin.checksec().kind, Kind::SharedObject);
    assert_eq!(
        bin.dynamic.as_ref().unwrap().soname.as_deref(),
        Some("libvantage.so.1")
    );
    assert!(bin.exports().any(|s| s.name == "vantage_export"));
    let printf = bin
        .imports()
        .find(|s| s.name == "printf")
        .expect("printf import");
    assert!(
        printf
            .version
            .as_deref()
            .is_some_and(|v| v.starts_with("GLIBC_"))
    );
    assert!(printf.display_name().starts_with("printf@GLIBC_"));
}

#[test]
fn static_and_static_pie() {
    let data = cc("static", &["-static", "-O1"]);
    let c = Binary::parse(&data).unwrap().checksec();
    assert_eq!(c.kind, Kind::Executable);
    assert!(c.static_linked);
    assert!(c.interpreter.is_none());
    assert!(!c.fortify_applicable);

    let data = cc("static-pie", &["-static-pie", "-fPIE", "-O1"]);
    let c = Binary::parse(&data).unwrap().checksec();
    assert_eq!(c.kind, Kind::StaticPie);
    assert!(c.static_linked);
}

#[test]
fn address_resolution() {
    let data = hardened();
    let bin = Binary::parse(&data).unwrap();
    let marker = bin
        .symtab
        .iter()
        .find(|s| s.name == "vantage_marker")
        .expect("marker symbol");
    assert!(marker.size > 1);
    let idx = bin.address_index();
    let (s, off) = idx.resolve(marker.value + 1).unwrap();
    assert_eq!((s.name.as_str(), off), ("vantage_marker", 1));
    let (s, off) = idx.resolve(marker.value).unwrap();
    assert_eq!((s.name.as_str(), off), ("vantage_marker", 0));
}

#[test]
fn plt_relocations_name_imports() {
    let data = cc("lazy", &["-O1", "-fno-stack-protector", "-Wl,-z,lazy"]);
    let mut bin = Binary::parse(&data).unwrap();
    let machine = bin.elf.header.machine;
    let relocs = bin.relocations();
    let puts = relocs
        .iter()
        .find(|r| r.symbol.as_deref().is_some_and(|s| s.starts_with("puts@")))
        .expect("relocation against puts");
    assert!(
        ["JUMP_SLOT", "GLOB_DAT"].contains(&puts.type_name(machine).as_str()),
        "{}",
        puts.type_name(machine)
    );
}

fn strip_section_headers(data: &[u8]) -> Vec<u8> {
    let mut d = data.to_vec();
    assert_eq!(d[4], 2, "test expects ELF64");
    let le = d[5] == 1;
    let put16 = |d: &mut Vec<u8>, off: usize, v: u16| {
        let b = if le { v.to_le_bytes() } else { v.to_be_bytes() };
        d[off..off + 2].copy_from_slice(&b);
    };
    d[40..48].fill(0);
    put16(&mut d, 60, 0);
    put16(&mut d, 62, 0);
    d
}

#[test]
fn section_less_binary_matches_section_view() {
    let data = cc("sstrip", &["-O1", "-Wl,-z,lazy", "-Wl,--hash-style=gnu"]);
    let mut full = Binary::parse(&data).unwrap();
    let stripped_data = strip_section_headers(&data);
    let mut bare = Binary::parse(&stripped_data).unwrap();
    assert!(bare.elf.sections.is_empty());
    assert!(!full.elf.sections.is_empty());

    let names = |b: &Binary<'_>| -> Vec<(String, Option<Arc<str>>)> {
        b.dynsyms
            .iter()
            .map(|s| (s.name.clone(), s.version.clone()))
            .collect()
    };
    assert_eq!(names(&full), names(&bare));

    let key = |b: &mut Binary<'_>| -> BTreeSet<(u64, u32, Option<Arc<str>>)> {
        b.relocations()
            .into_iter()
            .map(|r| (r.offset, r.kind, r.symbol))
            .collect()
    };
    let a = key(&mut full);
    let b = key(&mut bare);
    assert!(!a.is_empty());
    assert_eq!(a, b);

    let c_full = full.checksec();
    let c_bare = bare.checksec();
    assert_eq!(c_full.relro, c_bare.relro);
    assert_eq!(c_full.nx, c_bare.nx);
    assert_eq!(c_full.kind, c_bare.kind);
    assert_eq!(c_full.canary, c_bare.canary);
    assert_eq!(c_full.fortified, c_bare.fortified);
    assert!(c_bare.stripped);
}

#[test]
fn patched_segment_flags_are_detected() {
    let data = hardened();
    let bin = Binary::parse(&data).unwrap();
    let text = bin
        .elf
        .segments
        .iter()
        .find(|s| s.kind == 1 && s.flags & 1 != 0 && s.contains_vaddr(bin.elf.header.entry))
        .expect("text segment")
        .clone();
    let mut patched = data.clone();
    let off = bin.elf.header.phoff as usize + text.index * bin.elf.header.phentsize as usize + 4;
    patched[off..off + 4].copy_from_slice(&7u32.to_le_bytes());
    let b2 = Binary::parse(&patched).unwrap();
    let c = b2.checksec();
    assert_eq!(c.wx_segments, vec![text.index]);
    assert_eq!(c.entry, Entry::Writable);

    let data_seg = bin
        .elf
        .segments
        .iter()
        .find(|s| s.kind == 1 && s.flags & 1 == 0 && s.memsz > 1)
        .expect("non-executable load segment");
    let mut nonexec = data.clone();
    nonexec[24..32].copy_from_slice(&(data_seg.vaddr + 1).to_le_bytes());
    let c = Binary::parse(&nonexec).unwrap().checksec();
    assert_eq!(c.entry, Entry::NonExecutable);

    let mut moved = data.clone();
    moved[24..32].copy_from_slice(&0x7fff_dead_0000u64.to_le_bytes());
    let c = Binary::parse(&moved).unwrap().checksec();
    assert_eq!(c.entry, Entry::OutsideLoad);
}

#[test]
fn aarch64_object() {
    let data = build(
        "clang",
        "obj-aarch64.o",
        OBJECT,
        &[
            "--target=aarch64-linux-gnu",
            "-c",
            "-O2",
            "-fno-pic",
            "-mbranch-protection=standard",
        ],
    );
    let mut bin = Binary::parse(&data).unwrap();
    assert_eq!(bin.elf.header.machine_name(), "AARCH64");
    let c = bin.checksec();
    assert_eq!(c.kind, Kind::Relocatable);
    assert_eq!(c.nx, Nx::Enabled);
    assert_eq!((c.bti, c.pac), (Some(true), Some(true)));
    let relocs = bin.relocations();
    let types: BTreeSet<String> = relocs.iter().map(|r| r.type_name(183)).collect();
    assert!(
        types.contains("CALL26") || types.contains("JUMP26"),
        "{types:?}"
    );
    assert!(types.contains("ADR_PREL_PG_HI21"), "{types:?}");
    assert!(
        relocs
            .iter()
            .any(|r| r.symbol.as_deref() == Some("ext_func"))
    );
    assert!(relocs.iter().all(|r| r.addend.is_some()));
}

#[test]
fn i386_object_uses_rel() {
    let data = build(
        "clang",
        "obj-i386.o",
        OBJECT,
        &["--target=i386-linux-gnu", "-c", "-O2", "-fno-pic"],
    );
    let mut bin = Binary::parse(&data).unwrap();
    assert_eq!(bin.elf.header.class, Class::Elf32);
    assert_eq!(bin.elf.header.machine_name(), "386");
    let relocs = bin.relocations();
    let call = relocs
        .iter()
        .find(|r| r.symbol.as_deref() == Some("ext_func"))
        .expect("call relocation");
    assert!(["PC32", "PLT32"].contains(&call.type_name(3).as_str()));
    assert!(call.addend.is_none());
    assert!(
        bin.symtab
            .iter()
            .any(|s| s.name == "entry_point" && s.kind_name() == "FUNC")
    );
}

#[test]
fn arm_object() {
    let data = build(
        "clang",
        "obj-arm.o",
        OBJECT,
        &["--target=armv7-linux-gnueabihf", "-c", "-O2", "-fno-pic"],
    );
    let mut bin = Binary::parse(&data).unwrap();
    assert_eq!(bin.elf.header.class, Class::Elf32);
    let relocs = bin.relocations();
    let types: BTreeSet<String> = relocs.iter().map(|r| r.type_name(40)).collect();
    assert!(
        types.contains("CALL") || types.contains("JUMP24"),
        "{types:?}"
    );
}

#[test]
fn big_endian_ppc64_object() {
    let data = build(
        "clang",
        "obj-ppc64.o",
        OBJECT,
        &["--target=powerpc64-linux-gnu", "-c", "-O2"],
    );
    let mut bin = Binary::parse(&data).unwrap();
    assert_eq!(bin.elf.header.endian, Endian::Big);
    assert_eq!(bin.elf.header.machine_name(), "PPC64");
    assert!(bin.symtab.iter().any(|s| s.name == "entry_point"));
    assert!(
        bin.symtab
            .iter()
            .any(|s| s.name == "local_var" && s.size == 4)
    );
    assert!(bin.elf.section_by_name(".text").is_some());
    assert!(!bin.relocations().is_empty());
}

#[test]
fn cet_markers_on_x86_object() {
    if !cfg!(target_arch = "x86_64") {
        return;
    }
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let on = build(
        &compiler,
        "cet-on.o",
        OBJECT,
        &["-c", "-fcf-protection=full"],
    );
    let c = Binary::parse(&on).unwrap().checksec();
    assert_eq!((c.ibt, c.shstk), (Some(true), Some(true)));
    let off = build(
        &compiler,
        "cet-off.o",
        OBJECT,
        &["-c", "-fcf-protection=none"],
    );
    let c = Binary::parse(&off).unwrap().checksec();
    assert_eq!((c.ibt, c.shstk), (Some(false), Some(false)));
}

#[test]
fn rejects_non_elf() {
    assert!(Binary::parse(b"").is_err());
    assert!(Binary::parse(b"#!/bin/sh\necho hi\n").is_err());
    assert!(Binary::parse(b"\x7fELF\x03\x01\x01").is_err());
    assert!(Binary::parse(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0").is_err());
}

fn exercise(data: &[u8]) {
    if let Ok(mut bin) = Binary::parse(data) {
        let c = bin.checksec();
        let _ = c.findings(&Context::default());
        let _ = bin.relocations();
        let idx = bin.address_index();
        let _ = idx.resolve(bin.elf.header.entry);
        let _ = elfinspector::report::info(&bin);
    }
}

#[test]
fn truncation_never_panics() {
    let data = hardened();
    let step = (data.len() / 600).max(1);
    for len in (0..data.len()).step_by(step) {
        exercise(&data[..len]);
    }
}

#[test]
fn random_mutation_never_panics() {
    let data = cc("mutate", &["-O1", "-Wl,-z,lazy"]);
    let obj = build(
        "clang",
        "mutate-arm.o",
        OBJECT,
        &["--target=armv7-linux-gnueabihf", "-c"],
    );
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for base in [&data, &obj] {
        let hot = base.len().min(4096);
        for _ in 0..1500 {
            let mut m = base.to_vec();
            for _ in 0..(1 + next() % 8) {
                let pos = if next() % 4 == 0 {
                    (next() % m.len() as u64) as usize
                } else {
                    (next() % hot as u64) as usize
                };
                let mode = next() % 3;
                m[pos] = match mode {
                    0 => next() as u8,
                    1 => 0xff,
                    _ => 0,
                };
            }
            exercise(&m);
        }
    }
}
