use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use vantage_core::{rawsys, text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sym {
    pub addr: u64,
    pub kind: u8,
    pub name: String,
    pub module: Option<String>,
}

impl Sym {
    pub fn describe(&self, offset: u64) -> String {
        let mut s = if offset == 0 {
            self.name.clone()
        } else {
            format!("{}+{offset:#x}", self.name)
        };
        if let Some(m) = &self.module {
            s.push_str(&format!(" [{m}]"));
        }
        s
    }
}

#[derive(Debug, Clone, Default)]
pub struct Kallsyms {
    pub syms: Vec<Sym>,
}

impl Kallsyms {
    pub fn parse(data: &[u8]) -> Kallsyms {
        let mut syms: Vec<Sym> = data
            .split(|&b| b == b'\n')
            .filter_map(|line| {
                let mut it = line
                    .split(|b| *b == b' ' || *b == b'\t')
                    .filter(|t| !t.is_empty());
                let addr = u64::from_str_radix(std::str::from_utf8(it.next()?).ok()?, 16).ok()?;
                let kind = *it.next()?.first()?;
                let name = text::from_bytes(it.next()?);
                let module = it
                    .next()
                    .and_then(|m| m.strip_prefix(b"[")?.strip_suffix(b"]"))
                    .map(text::from_bytes);
                Some(Sym {
                    addr,
                    kind,
                    name,
                    module,
                })
            })
            .collect();
        syms.sort_by_key(|s| s.addr);
        Kallsyms { syms }
    }

    pub fn read() -> io::Result<Kallsyms> {
        Ok(Self::parse(&rawsys::read_file(
            Path::new("/proc/kallsyms"),
            512 << 20,
        )?))
    }

    pub fn addresses_visible(&self) -> bool {
        self.syms.iter().any(|s| s.addr != 0)
    }

    pub fn lookup(&self, name: &str) -> Option<&Sym> {
        self.syms
            .iter()
            .find(|s| s.name == name && s.module.is_none())
    }

    pub fn at(&self, addr: u64) -> &[Sym] {
        let lo = self.syms.partition_point(|s| s.addr < addr);
        let hi = self.syms.partition_point(|s| s.addr <= addr);
        &self.syms[lo..hi]
    }

    pub fn containing(&self, addr: u64) -> Option<(&Sym, u64)> {
        let idx = self.syms.partition_point(|s| s.addr <= addr);
        let s = self.syms[..idx].last()?;
        Some((s, addr - s.addr))
    }

    pub fn next_after(&self, addr: u64) -> Option<u64> {
        let idx = self.syms.partition_point(|s| s.addr <= addr);
        self.syms.get(idx).map(|s| s.addr)
    }

    pub fn modules(&self) -> BTreeSet<String> {
        self.syms
            .iter()
            .filter_map(|s| s.module.as_deref())
            .filter(|m| *m != "bpf" && !m.starts_with("__builtin__"))
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"ffffffff81000000 T _stext\nffffffff81000000 T _text\nffffffff812a0000 T __x64_sys_read\nffffffff812a0100 T __x64_sys_write\nffffffff81ffffff T _etext\nffffffff82000000 D sys_call_table\nffffffff82001000 D next_data\nffffffffc0a00000 t hacked_kill\t[diamorphine]\nffffffffc0b00000 t bpf_prog_x\t[bpf]\nffffffffc0c00000 t ftrace_tramp\t[__builtin__ftrace]\n";

    #[test]
    fn parse_and_query() {
        let k = Kallsyms::parse(SAMPLE);
        assert!(k.addresses_visible());
        assert_eq!(k.lookup("sys_call_table").unwrap().addr, 0xffffffff82000000);
        assert_eq!(k.at(0xffffffff81000000).len(), 2);
        let (s, off) = k.containing(0xffffffffc0a00010).unwrap();
        assert_eq!(s.describe(off), "hacked_kill+0x10 [diamorphine]");
        assert_eq!(k.next_after(0xffffffff82000000), Some(0xffffffff82001000));
        assert_eq!(k.modules(), BTreeSet::from(["diamorphine".to_owned()]));
        assert!(k.lookup("hacked_kill").is_none());
    }

    #[test]
    fn zeroed_addresses() {
        let k = Kallsyms::parse(b"0000000000000000 T _stext\n0000000000000000 t x\t[m]\n");
        assert!(!k.addresses_visible());
        assert_eq!(k.modules().len(), 1);
    }

    #[test]
    fn live_kallsyms_readable() {
        let k = Kallsyms::read().unwrap();
        assert!(k.syms.len() > 1000);
        assert!(k.syms.iter().any(|s| s.name == "_stext"));
    }
}
