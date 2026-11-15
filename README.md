# Vantage

Host security inspection for Linux, written in Rust with a CO-RE eBPF program in C.

It has three parts that share a small core library:

- **KernGuard**: live eBPF monitoring of exec, privilege changes, module loads and suspicious syscalls; an eBPF syscall tracer; an audit of kernel hardening settings, privileged processes and privileged files.
- **ELFInspector**: an ELF parser (32/64-bit, both byte orders) with symbols, GNU symbol versions, REL/RELA/RELR relocations, notes, and exploit mitigation checks (NX, PIE, RELRO, stack protector, FORTIFY, RPATH/RUNPATH, TEXTREL, W+X, CET, BTI/PAC).
- **RootkitHunter**: finds hidden processes, modules, sockets and files by comparing independent views of the same kernel state, and checks the syscall table and ftrace hooks.

Every check reports `ok`, `findings`, `skipped` with a reason, or `error`. Nothing is reported as clean if it was not actually checked. [docs/detections.md](docs/detections.md) lists what each check does, what it needs and what gets past it. [docs/architecture.md](docs/architecture.md) covers how the pieces fit together.

## Requirements

- Linux, x86_64 or aarch64. Other architectures build without eBPF (`--no-default-features`).
- Rust 1.88 or newer. Distribution packages are often older; [rustup](https://rustup.rs) works everywhere.
- For the eBPF part: clang, libbpf 1.0 or newer with headers, pkg-config.
- At runtime, `monitor` and `trace` need kernel 5.15+ with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and root. `vantage kernguard caps` tells you whether the running kernel qualifies.

Arch:

```sh
pacman -S --needed rust clang libbpf pkgconf
```

Debian / Ubuntu (24.04 or newer, for libbpf 1.x), with Rust from rustup:

```sh
apt install clang libbpf-dev pkg-config
```

## Build and install

```sh
git clone https://github.com/D3LTA2033/Vantage
cd Vantage
cargo build --release
sudo install -Dm755 target/release/vantage /usr/local/bin/vantage
```

Without eBPF (no clang or libbpf needed for the build; `monitor` and `trace` then exit with an error that says so):

```sh
cargo build --release --no-default-features
```

## Usage

```sh
sudo vantage scan                          # every snapshot check of all three engines
sudo vantage --json --output report.json scan
vantage --fail-on high scan                # exit 1 if anything is high or critical

vantage kernguard caps                     # what this kernel and build support
sudo vantage kernguard audit
sudo vantage kernguard monitor             # live detection, ctrl-c to stop
sudo vantage kernguard monitor --events --json
sudo vantage kernguard trace -- curl -s https://example.com
sudo vantage kernguard trace --pid 1234 --duration 10

vantage elf checksec /usr/bin/*
vantage elf info ./binary
vantage elf symbols --imports ./binary
vantage elf symbols --lookup 0x11a9 ./binary
vantage elf relocs ./binary

vantage rootkit list
sudo vantage rootkit scan
vantage rootkit scan --check hidden-processes --check userland-hiding --dir /srv
```

Most checks also run as a normal user, with less coverage. What changes with root:

| without root | with root |
|---|---|
| `syscall-table`, `ftrace-hooks` are skipped | read `/proc/kcore`, `/proc/kallsyms` addresses and tracefs |
| other users' processes are skipped by `preload` and `process-executables` | all processes |
| privileged ports are not probed by `hidden-ports` | all ports |
| `monitor`, `trace` refuse to start | eBPF programs load |

Global options: `--json`, `--output FILE` (created with mode 0600, symlinks refused), `--min-severity LEVEL`, `--fail-on LEVEL`. Exit status: 0 success, 1 findings at or above `--fail-on`, 2 usage error, 3 runtime error. `kernguard trace -- CMD` exits with the command's status.

`monitor` prints findings at `low` and above by default. Use `--min-severity info` to also see setuid executions and memfd creation.

## Example

On an Arch desktop, as a normal user:

```
$ vantage rootkit scan --check hidden-processes --check hidden-modules --check syscall-table
vantage 0.1.0  host mcss  kernel 7.2.2-zen1-1-zen  x86_64  euid 1000

rootkithunter
  ok        hidden-processes       probed PIDs 1..=4194304 against 1342 visible task IDs  (3.6s)
  ok        hidden-modules         162 listed modules cross-checked against sysfs (162), btf (162), kallsyms (162)  (486ms)
  skipped   syscall-table          kallsyms addresses are hidden; needs root (CAP_SYSLOG) and kernel.kptr_restrict below 2  (436ms)

0 critical, 0 high, 0 medium, 0 low, 0 info  |  3 checks: 2 ok, 0 with findings, 1 skipped, 0 errors
```

## Tests and benchmarks

```sh
cargo test --workspace
```

The tests use real binaries: the ELF tests compile fixtures with `cc` and `clang` (including aarch64, i386, ARM and big-endian ppc64 objects), and one CLI test builds an `LD_PRELOAD` library that hides a file and a live PID through `readdir`, then checks that vantage reports both. The parser is also fed a real binary truncated at hundreds of points and a few thousand randomly mutated copies, and must not panic on any of them.

Tests that load eBPF programs or read `/proc/kcore` are marked `#[ignore]` and need root:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test --workspace -- --ignored
```

They check that `monitor` reports a memfd execution, a ptrace attach and a setuid execution (classified by its syscall), that `trace` follows forked children and decodes path arguments, and that the kcore and ftrace checks run cleanly. CI runs them on x86_64 and aarch64 runners.

```sh
cargo bench --workspace
```

The benchmarks use a small built-in timing loop rather than an external framework. They cover ELF parsing and lookups, PID probing, `/proc` listing, kallsyms parsing, bind probes and event decoding.

## Layout

```
crates/core            report model, JSON, raw syscalls, procfs/sysctl helpers, syscall tables
crates/elfinspector    ELF parser and mitigation analysis
crates/rootkithunter   rootkit checks
crates/kernguard       eBPF loader and rules, audit, capability probe
crates/kernguard/bpf   kernguard.bpf.c
crates/cli             the vantage binary
docs/                  architecture and detection notes
```

The only crates.io dependency is `libc`. The eBPF program is built by `build.rs` and embedded in the binary, so there is nothing to install next to it.

## Limits

- Detection runs on the same kernel it inspects. A rootkit with full kernel control can fake every view vantage reads. The checks raise the cost of hiding; they do not make it impossible.
- KernGuard only sees what happens while it runs, and root can detach its programs.
- Privilege escalation detection hooks `commit_creds`. Exploits that edit credentials in place are not seen.
- Process, module and socket checks see the current PID and network namespace.
- aarch64 is covered by the CI workflow on GitHub's arm64 runners. It has not been run on other aarch64 hardware.

## Credits
@mcs.s Main Programmer

## License

MIT, see [LICENSE](LICENSE).
