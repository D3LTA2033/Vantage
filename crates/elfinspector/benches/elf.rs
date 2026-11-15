use elfinspector::{Binary, Context};
use std::path::Path;
use vantage_core::bench::Bench;

fn main() {
    let b = Bench::from_args();
    let own = std::fs::read("/proc/self/exe").expect("read own executable");
    let libc = [
        "/usr/lib/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
    ]
    .iter()
    .find(|p| Path::new(p).exists())
    .map(|p| std::fs::read(p).expect("read libc"));

    let mut targets = vec![("bench binary", own)];
    if let Some(l) = libc {
        targets.push(("libc", l));
    }
    for (name, data) in &targets {
        b.run(&format!("parse {name} ({} KiB)", data.len() / 1024), || {
            Binary::parse(data).unwrap()
        });
        let bin = Binary::parse(data).unwrap();
        b.run(&format!("checksec + findings {name}"), || {
            bin.checksec().findings(&Context::default())
        });
        b.run(&format!("relocations {name}"), || {
            Binary::parse(data).unwrap().relocations().len()
        });
        let idx = bin.address_index();
        let addrs: Vec<u64> = bin
            .symtab
            .iter()
            .chain(bin.dynsyms.iter())
            .map(|s| s.value + 1)
            .collect();
        if !addrs.is_empty() {
            let mut i = 0usize;
            b.run(
                &format!("address lookup {name} ({} symbols)", idx.len()),
                || {
                    i = (i + 7919) % addrs.len();
                    idx.resolve(addrs[i])
                },
            );
        }
    }
}
