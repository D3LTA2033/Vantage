use rootkithunter::kallsyms::Kallsyms;
use rootkithunter::network::{Proto, probe_bind};
use rootkithunter::processes::{probe, raw_visible_ids, sweep};
use std::path::Path;
use vantage_core::bench::Bench;
use vantage_core::rawsys;

fn main() {
    let b = Bench::from_args();
    b.run("probe one absent pid (kill + getpgid)", || {
        probe(i32::MAX as u32 - 1)
    });
    let (_, visible) = raw_visible_ids().unwrap();
    b.run("sweep 65536 pids, all threads", || {
        sweep(1, 65536, &visible).len()
    });
    b.run("getdents64 /proc (raw)", || {
        rawsys::read_dir(Path::new("/proc")).unwrap().len()
    });
    b.run("readdir /proc (libc)", || {
        std::fs::read_dir("/proc").unwrap().count()
    });
    b.run("visible pids + tids", || raw_visible_ids().unwrap().1.len());
    let ks = rawsys::read_file(Path::new("/proc/kallsyms"), 512 << 20).unwrap();
    b.run(&format!("parse kallsyms ({} KiB)", ks.len() / 1024), || {
        Kallsyms::parse(&ks).syms.len()
    });
    b.run("bind probe one TCP port", || {
        probe_bind(Proto::Tcp, false, 47_999)
    });
}
