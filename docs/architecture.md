# Architecture

Vantage is a Cargo workspace with one shared library, three engines and a CLI. The engines do not depend on each other. Only the CLI combines them.

```mermaid
graph TD
    cli["vantage (crates/cli)"]
    kg["kernguard"]
    elf["elfinspector"]
    rk["rootkithunter"]
    core["vantage-core"]
    bpf["bpf/kernguard.bpf.c"]
    libbpf[("system libbpf")]

    cli --> kg
    cli --> elf
    cli --> rk
    kg --> core
    elf --> core
    rk --> core
    kg -. "include_bytes! at build time" .-> bpf
    kg -. "FFI, ebpf feature only" .-> libbpf
```

| crate | role | unsafe code |
|---|---|---|
| `vantage-core` | report model, JSON encoder/parser, raw syscalls, procfs and sysctl helpers, syscall number tables | raw syscall wrappers, `uname` |
| `elfinspector` | ELF parser and mitigation analysis | none (`#![forbid(unsafe_code)]`) |
| `rootkithunter` | rootkit and hiding detection | socket/bind probes |
| `kernguard` | eBPF monitoring and tracing, kernel hardening audit | libbpf FFI, fork/exec for `trace`, xattr reads |
| `vantage` | argument parsing, output, exit codes | none of its own beyond `localtime_r` |

The only crates.io dependency is `libc`. The eBPF loader links the system libbpf (1.0 or newer) through hand-written bindings for the few functions it uses.

## Report model

Every snapshot check returns an `Outcome`: either `Done { summary, findings }` or `Skipped(reason)`. `CheckResult::run` adds timing and turns errors into an `error` status. A check that cannot run because of missing privileges or kernel features says so in its reason. It never reports `ok` for something it did not look at.

```mermaid
graph LR
    check["check fn"] -->|"Ok(Done)"| ok["ok / findings"]
    check -->|"Ok(Skipped)"| skip["skipped + reason"]
    check -->|"Err"| err["error + message"]
    ok --> report["Report"]
    skip --> report
    err --> report
    report --> human["text"]
    report --> json["JSON"]
```

Strings read from the system (file names, process names, symbol names, kernel strings) pass through `text::from_bytes`. That function escapes control characters and invalid UTF-8 as `\xNN` before anything is stored, so hostile names cannot inject terminal escape sequences or produce invalid JSON.

## KernGuard

```mermaid
graph LR
    subgraph kernel
        exec["tp_btf/sched_process_exec"]
        creds["kprobe/commit_creds"]
        mod["tp_btf/module_load"]
        enter["raw_tp/sys_enter"]
        exit["raw_tp/sys_exit"]
        fork["tp_btf/sched_process_fork"]
        pexit["tp_btf/sched_process_exit"]
        rb[("ring buffer 4 MiB")]
        maps[("syscall_flags, traced, inflight")]
    end
    exec --> rb
    creds --> rb
    mod --> rb
    enter --> rb
    enter --> maps
    exit --> maps
    exit --> rb
    fork --> maps
    pexit --> maps
    rb --> parse["events::parse"]
    parse --> rules["rules::findings"]
    rules --> out["CLI output"]
```

The BPF object is compiled by `build.rs` with `clang -target bpf` and embedded in the binary. It does not include `vmlinux.h`. Kernel structures are declared with only the fields that are read, marked `preserve_access_index`, and libbpf relocates the field offsets against `/sys/kernel/btf/vmlinux` at load time (CO-RE). The same object therefore runs on any kernel from 5.15 on with BTF, on x86_64 and arm64.

Program sets per mode:

- `monitor` loads `on_exec`, `on_commit_creds`, `on_module_load` and `on_sys_enter`. `syscall_flags` marks only the watched syscalls, so all other syscalls return after one array lookup.
- `trace` loads `on_sys_enter`, `on_sys_exit`, `on_fork` and `on_exit`. The `traced` map starts with the target PID. `on_fork` adds children, and `on_exit` removes processes and stale in-flight entries.

Event layouts are fixed C structs. The C side checks sizes and offsets with `_Static_assert`. The Rust side decodes the bytes at explicit offsets and never transmutes. A per-CPU `drops` counter records ring buffer reservation failures, and the count is printed when the session ends.

Privilege escalation classification happens in userspace (`rules::creds`). The kprobe emits an event only when `commit_creds` raises the uid, euid or fsuid to 0 or adds effective capabilities. The event carries the syscall number of the calling task, read with `bpf_task_pt_regs`. The rules use that syscall to tell a setuid `execve` or a permitted `setresuid` apart from a credential change inside an unrelated syscall such as `ioctl`, which is what kernel exploit payloads produce.

`trace -- CMD` forks a child that blocks on a pipe until its PID is in the `traced` map. Only then does it call `execvp`, so the first syscall of the new program is already traced.

## RootkitHunter

Most checks compare two or more independent views of the same kernel state. A rootkit has to fake every view the same way to stay hidden.

```mermaid
graph TD
    subgraph processes
        p1["libc readdir(/proc)"]
        p2["raw getdents64(/proc) + every /proc/PID/task"]
        p3["raw kill(pid,0) and getpgid(pid) for 1..pid_max"]
    end
    p2 -. "differs from p1: userland hook in this process" .-> p1
    p3 -. "differs from p2: kernel-level hiding" .-> p2

    subgraph modules
        m1["/proc/modules"]
        m2["/sys/module/*/initstate"]
        m3["/sys/kernel/btf/*"]
        m4["[module] tags in /proc/kallsyms"]
    end
    m2 & m3 & m4 -. "name missing from m1: hidden module" .-> m1

    subgraph ports
        n1["/proc/net/{tcp,tcp6,udp,udp6}"]
        n2["bind() on every port, v4 and v6"]
    end
    n2 -. "EADDRINUSE but not listed: hidden socket" .-> n1
```

Raw syscalls (`vantage_core::rawsys`) use inline assembly on x86_64 (`syscall`) and aarch64 (`svc 0`), so a library preloaded into vantage cannot intercept them. On other architectures they fall back to `libc::syscall`, which a preloaded library could hook. Every difference is re-read before it is reported, which keeps short-lived processes, files and sockets out of the findings.

`syscall-table` reads `sys_call_table` from `/proc/kcore`. A small reader takes the program headers to map kernel virtual addresses to file offsets. Each entry is resolved against `/proc/kallsyms` and must point at an arch syscall handler (`__x64_sys_*`, `__arm64_sys_*`, `sys_ni_syscall`) inside `_stext.._etext`.

## ELFInspector

```mermaid
graph LR
    bytes["file bytes"] --> elf["Elf: header, phdrs, shdrs"]
    elf --> dyn["Dynamic: PT_DYNAMIC first, .dynamic as fallback"]
    elf --> st["symtab"]
    dyn --> ds["dynsym: SHT_DYNSYM, or DT_SYMTAB counted via DT_HASH / DT_GNU_HASH / relocations"]
    ds --> ver["GNU symbol versions"]
    elf --> notes["notes: build-id, GNU properties"]
    dyn --> rel["REL / RELA / RELR"]
    elf & dyn & st & ds & notes --> cs["Checksec"]
    cs --> f["findings"]
```

The parser borrows the input slice. Every read goes through a bounds-checked `Reader` that handles both classes and both byte orders. Malformed tables become warnings rather than errors where the loader would still run the file. Dynamic information comes from `PT_DYNAMIC`, the same source the loader uses. When section headers are stripped, dynamic symbols and relocations are recovered from the dynamic segment. A test checks that both paths give identical results.
