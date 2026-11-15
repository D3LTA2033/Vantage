use kernguard::events::{self, EV_EXEC, EXEC_SIZE};
use kernguard::rules;
use vantage_core::bench::Bench;
use vantage_core::syscalls::Arch;

fn main() {
    let b = Bench::from_args();
    let mut exec = vec![0u8; EXEC_SIZE];
    exec[0..4].copy_from_slice(&EV_EXEC.to_ne_bytes());
    exec[24..28].copy_from_slice(b"bash");
    exec[48..52].copy_from_slice(&1u32.to_ne_bytes());
    exec[56..69].copy_from_slice(b"/usr/bin/bash");
    exec[312..316].copy_from_slice(b"bash");
    b.run("parse exec event", || events::parse(&exec).unwrap());
    let ev = events::parse(&exec).unwrap();
    b.run("classify exec event", || {
        rules::findings(&ev, Arch::X86_64).len()
    });
    b.run("syscall name lookup", || Arch::X86_64.name(257));
}
