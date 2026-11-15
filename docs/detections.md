# Detections

For each check: what it looks at, what it needs, when it is wrong, and what gets past it. Severities are the defaults in the code.

## KernGuard: live monitoring (`vantage kernguard monitor`)

Requires root (CAP_BPF + CAP_PERFMON, or CAP_SYS_ADMIN), kernel 5.15 or newer with BTF, and lockdown not set to `confidentiality`. `vantage kernguard caps` reports each of these individually. If a program fails to attach, the detector is printed as `off` with the reason, and monitoring continues with the rest.

### exec (`tp_btf/sched_process_exec`)

| finding | severity | logic |
|---|---|---|
| fileless execution from memfd | high | the executed file's dentry name starts with `memfd:` |
| execution of an unlinked file | high | the executed inode has `i_nlink == 0` |
| execution from world-writable directory | low | path starts with `/tmp/`, `/dev/shm/` or `/var/tmp/` |

The checks read the inode the kernel actually executes, so renames, `/proc/self/fd` paths and `fexecve` do not hide the memfd. For scripts the kernel has already switched to the interpreter, so the check sees the interpreter.

### privilege escalation (`kprobe/commit_creds`)

An event is emitted when new credentials raise uid, euid or fsuid to 0, or add effective capabilities. Capability gains inside a non-initial user namespace are ignored, because they do not grant anything on the host. The event records the syscall the task is executing and the ABI it used, and the syscall is looked up in that ABI's table: x86_64, i386 or x32 on x86_64, aarch64 or 32-bit arm on arm64. The i386 and arm `setuid32`-style variants count as their base syscall.

| syscall at the time | result |
|---|---|
| `execve`, `execveat` | info: setuid or file-capability binary (sudo, su, passwd) |
| `setuid`, `setreuid`, `setresuid`, `setfsuid` | info if the task had CAP_SETUID or uid 0 as real, effective or saved uid. Otherwise critical: the kernel should have refused the change. |
| `capset` | info if the new capabilities were already permitted, otherwise critical |
| any other syscall | critical: credentials raised inside a syscall that never changes them, the pattern of `commit_creds(prepare_kernel_cred(0))` exploit payloads |
| no syscall | critical |
| number not in the table for its ABI | medium: cannot be classified, for example a syscall newer than vantage |

Not covered: exploits that overwrite `struct cred` fields in place instead of calling `commit_creds` (for example DirtyCred-style credential swaps, or direct writes through an arbitrary-write primitive). Kernel threads are skipped.

### module load (`tp_btf/module_load`)

Every module load is reported with its name and taint bits. Severity is medium, high if the module is unsigned (E) or out-of-tree (O), and critical if it was force-loaded (F).

### watched syscalls (`raw_tp/sys_enter`)

| syscall | condition | severity |
|---|---|---|
| `ptrace` | ATTACH, SEIZE | medium |
| `ptrace` | POKETEXT, POKEDATA, POKEUSER, SETREGS, SETREGSET | high |
| `process_vm_writev` | always | high |
| `init_module` | always (image comes from memory, no file) | high |
| `finit_module` | always | medium |
| `delete_module` | always | low |
| `bpf` | `BPF_PROG_LOAD` | medium |
| `kexec_load`, `kexec_file_load` | always | high |
| `memfd_create` | always, with the memfd name | info |

These syscalls are watched under every ABI the kernel accepts, each with its own numbers: i386 and x32 on x86_64, 32-bit arm on arm64. The ABI is taken from the x32 bit of the syscall number, `TS_COMPAT` on x86_64 and the AArch32 bit of `pstate` on arm64, so a 64-bit program that issues `int 0x80` is decoded as i386, with its arguments read from the i386 registers. Findings for a non-native ABI carry an `abi` evidence field.

Vantage's own process is excluded in the kernel.

### general limits

- Only what happens while the monitor runs is seen.
- When the 4 MiB ring buffer is full, events are lost. The loss is counted and printed at exit, never hidden.
- Root can detach BPF programs. KernGuard does not protect itself against an attacker who already has root.

## KernGuard: tracing (`vantage kernguard trace`)

Records every syscall of a PID, or of a command started by vantage, plus all of its descendants: number, six raw arguments, return value, duration, and the path argument as a string. Argument names and types come from tracefs (`events/syscalls/sys_enter_*/format`) when it is readable. Otherwise a built-in table identifies the path argument of the common file syscalls. Syscalls of threads that already existed when `--pid` attached are traced from their next syscall on. Compat syscalls (i386, x32, 32-bit arm) are printed with their ABI and name, for example `i386:openat(...)`, and with raw arguments only, because some compat syscalls split 64-bit arguments across two registers and the tracefs signatures describe the native layout.

## KernGuard: audit (`vantage kernguard audit`)

| check | what | notes |
|---|---|---|
| hardening | 18 sysctls (kptr_restrict, dmesg_restrict, unprivileged_bpf_disabled, bpf_jit_harden, perf_event_paranoid, yama.ptrace_scope, kexec_load_disabled, sysrq, protected_{symlinks,hardlinks,fifos,regular}, suid_dumpable, randomize_va_space, mmap_min_addr, unprivileged_userfaultfd, ldisc_autoload, io_uring_disabled) plus unprivileged user namespaces | sysctls that are absent or unreadable are listed in the summary, not guessed |
| lockdown | lockdown mode, `module.sig_enforce`, `kernel.modules_disabled`, UEFI Secure Boot state from efivars | |
| privileged-processes | non-root processes with root-equivalent capabilities (dac_override, dac_read_search, fowner, chown, setuid, setgid, sys_module, sys_rawio, sys_ptrace, sys_admin, setfcap, bpf), ambient capabilities, setuid-root processes | processes in a child user namespace are skipped when their namespace link is readable. Without root it often is not, and the evidence says `unknown` |
| privileged-files | setuid/setgid files and file capabilities under the standard binary and library directories and under `/tmp`, `/var/tmp`, `/dev/shm` | critical if writable by group/others. High if located in a world-writable place, or setuid-root in a directory non-root users can modify. High for dangerous file capabilities on an interpreter, low on other binaries |

## RootkitHunter (`vantage rootkit scan`)

| check | method | needs root | false positives | evasion / limits |
|---|---|---|---|---|
| hidden-processes | `kill(pid, 0)` and `getpgid(pid)` via raw syscalls for every PID up to `kernel.pid_max`, compared with raw `getdents64` of `/proc` and of every `/proc/PID/task` | no | none expected; candidates are re-listed and re-probed | a rootkit that also hooks `kill`/`getpgid` for its PIDs; only the current PID namespace is visible |
| userland-hiding | `readdir()` through libc vs raw `getdents64` on `/proc`, `/etc`, `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/lib/modules/<release>` and `--dir` paths; libc `read()` vs raw `read()` of `/proc/modules`, `/proc/net/{tcp,tcp6,udp,udp6}`, `/etc/ld.so.preload` | no | entries must persist across three raw reads and be missing from two libc reads | only meaningful for a dynamically linked build, since the hook has to load into vantage; skipped and explained for static builds |
| preload | `/etc/ld.so.preload` read with raw syscalls; `LD_PRELOAD`/`LD_AUDIT` in `/proc/PID/environ`, grouped by value | for other users' processes | legitimate preloads (gtk-nocsd, sandboxes, debuggers) are reported too; the finding names the library so it can be judged | environment can be rewritten by the process after start |
| process-executables | `/proc/PID/exe` pointing at a memfd, a deleted file or a world-writable directory | for other users' processes | deleted executables after package upgrades; grouped into one low finding | |
| hidden-modules | names from `/sys/module/*` (with `initstate`), `/sys/kernel/btf/*` and `[module]` tags in `/proc/kallsyms` missing from `/proc/modules` | no | | the kallsyms tags come from the same module list as `/proc/modules` and only catch filtering of the `/proc/modules` output. A module that unlinks itself from the list and deletes its kobject (the Diamorphine approach) is caught only through its `/sys/kernel/btf` entry, which exists only if the module was built with BTF |
| module-audit | taint letters per module in `/proc/modules`; module name missing from `/lib/modules/<release>/modules.dep` | no | DKMS modules are in modules.dep after `depmod`; the tree check is skipped with a note when the running kernel's tree is not installed | |
| kernel-taint | decodes `kernel.tainted`; flags E/O/F taint with no listed module carrying it | no | taint persists after legitimate unloads | |
| syscall-table | reads `sys_call_table` from `/proc/kcore`; each entry must resolve to an arch syscall handler inside `_stext.._etext` | yes (CAP_SYS_RAWIO, readable kallsyms addresses) | | an entry swapped for another real syscall handler is not caught. x86_64 kernels 6.9 and newer dispatch through `x64_sys_call()`, so table edits there indicate tampering but do not redirect syscalls. ia32/compat tables are not checked |
| ftrace-hooks | `enabled_functions` in tracefs: kernel functions whose ftrace callback lives in a loadable module | yes | security agents built as modules that use ftrace | kprobe-based hooks show as `kprobe_ftrace_handler` (core kernel) and are not attributed to a module |
| hidden-ports | `bind()` to every TCP/UDP port on 0.0.0.0 and `[::]` (V6ONLY); `EADDRINUSE` on a port absent from `/proc/net/*` is re-checked twice | no; ports below `ip_unprivileged_port_start` need CAP_NET_BIND_SERVICE and are counted as not probed | | current network namespace only; raw and SCTP sockets are not covered |

## ELFInspector (`vantage elf checksec`)

| property | how it is decided |
|---|---|
| kind | `e_type`, `PT_INTERP`, `DF_1_PIE`, `DT_SONAME` (separates PIE, static-pie and shared objects) |
| NX | `PT_GNU_STACK` flags; for object files the `.note.GNU-stack` section. Missing marker is reported separately because the default then depends on arch and kernel |
| RELRO | `PT_GNU_RELRO`; full when `DT_BIND_NOW`, `DF_BIND_NOW` or `DF_1_NOW` is set |
| canary | references to `__stack_chk_fail`, `__stack_chk_fail_local`, `__stack_chk_guard`, `__intel_security_cookie`. No reference means either no `-fstack-protector` or no function that needed one. Stripped static binaries report `unknown` |
| FORTIFY | imported `__*_chk` functions vs imported unchecked counterparts; not applicable to static binaries |
| RPATH/RUNPATH | each component: empty or relative (searched relative to the working directory), `$ORIGIN`, world-writable or non-root-owned directories on this host |
| TEXTREL | `DT_TEXTREL` or `DF_TEXTREL` |
| W+X | `PT_LOAD` segments, or allocated sections in object files, that are both writable and executable |
| entry point | must lie in an executable, non-writable `PT_LOAD` segment |
| CET / BTI / PAC | `GNU_PROPERTY_X86_FEATURE_1_AND` and `GNU_PROPERTY_AARCH64_FEATURE_1_AND` notes |
| packer | UPX section names or the `UPX!` marker in the first 4 KiB |

Most severities go up one level for setuid/setgid binaries, because those cross a privilege boundary. `vantage scan` runs these checks on every setuid/setgid ELF file found by `privileged-files`. Each file is opened without following symlinks and without blocking, and is read only if it is still the same regular file (device and inode) the walk found. Files replaced in between, for example by a symlink or a FIFO in `/tmp`, are counted in the summary and skipped.
