use crate::consts::*;
use crate::dynamic::Dynamic;
use crate::elf::Elf;
use crate::names;
use crate::reader::{Class, Reader};
use crate::symbols::Symbol;
use vantage_core::Result;

const MAX_RELOCATIONS: usize = 10_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    pub table: String,
    pub offset: u64,
    pub kind: u32,
    pub sym_index: u32,
    pub symbol: Option<String>,
    pub addend: Option<i64>,
}

impl Relocation {
    pub fn type_name(&self, machine: u16) -> String {
        names::reloc_name(machine, self.kind)
            .map(str::to_owned)
            .unwrap_or_else(|| self.kind.to_string())
    }
}

pub fn relative_type(machine: u16) -> u32 {
    match machine {
        EM_X86_64 | EM_386 => 8,
        EM_AARCH64 => 1027,
        EM_ARM => 23,
        EM_RISCV => 3,
        _ => 0,
    }
}

#[derive(Clone, Copy)]
enum Format {
    Rel,
    Rela,
    Relr,
}

struct Ctx<'r, 's> {
    r: Reader<'r>,
    machine: u16,
    syms: &'s [Symbol],
    out: Vec<Relocation>,
    truncated: bool,
}

impl Ctx<'_, '_> {
    fn push(&mut self, rel: Relocation) -> bool {
        if self.out.len() >= MAX_RELOCATIONS {
            self.truncated = true;
            return false;
        }
        self.out.push(rel);
        true
    }

    fn decode(&mut self, table: &str, data: &[u8], format: Format, entsize: u64) {
        let r = self.r.with_data(data);
        let ws = r.word_size();
        match format {
            Format::Relr => self.decode_relr(table, &r),
            Format::Rel | Format::Rela => {
                let min = if matches!(format, Format::Rela) {
                    3 * ws
                } else {
                    2 * ws
                };
                let entsize = if entsize < min { min } else { entsize };
                let mut off = 0u64;
                while off + min <= r.len() {
                    let (Ok(offset), Ok(info)) = (r.word(off), r.word(off + ws)) else {
                        break;
                    };
                    let addend = match format {
                        Format::Rela => r.sword(off + 2 * ws).ok(),
                        _ => None,
                    };
                    let (sym_index, kind) = match r.class {
                        Class::Elf32 => ((info >> 8) as u32, (info & 0xff) as u32),
                        Class::Elf64 => ((info >> 32) as u32, info as u32),
                    };
                    let symbol = (sym_index != 0)
                        .then(|| self.syms.get(sym_index as usize))
                        .flatten()
                        .map(Symbol::display_name);
                    if !self.push(Relocation {
                        table: table.to_owned(),
                        offset,
                        kind,
                        sym_index,
                        symbol,
                        addend,
                    }) {
                        return;
                    }
                    off += entsize;
                }
            }
        }
    }

    fn decode_relr(&mut self, table: &str, r: &Reader<'_>) {
        let ws = r.word_size();
        let bits = ws * 8 - 1;
        let kind = relative_type(self.machine);
        let mut base = 0u64;
        let mut off = 0u64;
        while off + ws <= r.len() {
            let Ok(entry) = r.word(off) else { break };
            off += ws;
            if entry & 1 == 0 {
                if !self.push_relative(table, entry, kind) {
                    return;
                }
                base = entry.wrapping_add(ws);
            } else {
                let mut bitmap = entry >> 1;
                let mut addr = base;
                while bitmap != 0 {
                    if bitmap & 1 != 0 && !self.push_relative(table, addr, kind) {
                        return;
                    }
                    bitmap >>= 1;
                    addr = addr.wrapping_add(ws);
                }
                base = base.wrapping_add(bits * ws);
            }
        }
    }

    fn push_relative(&mut self, table: &str, offset: u64, kind: u32) -> bool {
        self.push(Relocation {
            table: table.to_owned(),
            offset,
            kind,
            sym_index: 0,
            symbol: None,
            addend: None,
        })
    }
}

struct Table {
    addr: u64,
    size: u64,
    entsize: u64,
    format: Format,
    name: &'static str,
}

fn dynamic_tables(d: &Dynamic<'_>) -> Vec<Table> {
    let mut tables = Vec::new();
    let jmprel = d.get(DT_JMPREL).zip(d.get(DT_PLTRELSZ));
    for (addr_tag, size_tag, ent_tag, format, name) in [
        (DT_RELA, DT_RELASZ, DT_RELAENT, Format::Rela, "DT_RELA"),
        (DT_REL, DT_RELSZ, DT_RELENT, Format::Rel, "DT_REL"),
        (DT_RELR, DT_RELRSZ, DT_RELRENT, Format::Relr, "DT_RELR"),
    ] {
        if let (Some(addr), Some(mut size)) = (d.get(addr_tag), d.get(size_tag)) {
            if let Some((j, _)) = jmprel
                && j > addr
                && j < addr.saturating_add(size)
            {
                size = j - addr;
            }
            tables.push(Table {
                addr,
                size,
                entsize: d.get(ent_tag).unwrap_or(0),
                format,
                name,
            });
        }
    }
    if let Some((addr, size)) = jmprel {
        let format = if d.get(DT_PLTREL) == Some(DT_REL as u64) {
            Format::Rel
        } else {
            Format::Rela
        };
        tables.push(Table {
            addr,
            size,
            entsize: 0,
            format,
            name: "DT_JMPREL",
        });
    }
    tables
}

pub fn max_dynamic_symbol(elf: &Elf<'_>, d: &Dynamic<'_>) -> Option<u64> {
    let mut ctx = Ctx {
        r: elf.r,
        machine: elf.header.machine,
        syms: &[],
        out: Vec::new(),
        truncated: false,
    };
    for t in dynamic_tables(d) {
        if matches!(t.format, Format::Relr) {
            continue;
        }
        if let Some(data) = elf.bytes_at_vaddr(t.addr, t.size) {
            ctx.decode(t.name, data, t.format, t.entsize);
        }
    }
    ctx.out
        .iter()
        .map(|r| u64::from(r.sym_index))
        .filter(|&i| i != 0)
        .max()
}

pub fn relocations(
    elf: &mut Elf<'_>,
    dynamic: Option<&Dynamic<'_>>,
    dynsyms: &[Symbol],
    statics: &[Symbol],
) -> Result<Vec<Relocation>> {
    let has_sections = elf
        .sections
        .iter()
        .any(|s| matches!(s.kind, SHT_REL | SHT_RELA | SHT_RELR));
    let mut ctx = Ctx {
        r: elf.r,
        machine: elf.header.machine,
        syms: &[],
        out: Vec::new(),
        truncated: false,
    };
    if has_sections {
        for s in elf.sections.clone() {
            let format = match s.kind {
                SHT_REL => Format::Rel,
                SHT_RELA => Format::Rela,
                SHT_RELR => Format::Relr,
                _ => continue,
            };
            ctx.syms = match elf.sections.get(s.link as usize).map(|l| l.kind) {
                Some(SHT_DYNSYM) => dynsyms,
                Some(SHT_SYMTAB) => statics,
                _ => &[],
            };
            match elf.section_data(&s) {
                Ok(data) => ctx.decode(&s.name, data, format, s.entsize),
                Err(e) => elf.warn(format!("relocation section {} unreadable: {e}", s.name)),
            }
        }
    } else if let Some(d) = dynamic {
        ctx.syms = dynsyms;
        for t in dynamic_tables(d) {
            match elf.bytes_at_vaddr(t.addr, t.size) {
                Some(data) => ctx.decode(t.name, data, t.format, t.entsize),
                None => elf.warn(format!(
                    "{} at {:#x} size {:#x} does not map to file contents",
                    t.name, t.addr, t.size
                )),
            }
        }
    }
    if ctx.truncated {
        elf.warn(format!(
            "relocation output truncated at {MAX_RELOCATIONS} entries"
        ));
    }
    Ok(ctx.out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::Endian;

    fn relr(words: &[u64]) -> Vec<u64> {
        let data: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let r = Reader {
            data: &data,
            endian: Endian::Little,
            class: Class::Elf64,
        };
        let mut ctx = Ctx {
            r,
            machine: EM_X86_64,
            syms: &[],
            out: Vec::new(),
            truncated: false,
        };
        ctx.decode("t", &data, Format::Relr, 8);
        ctx.out.iter().map(|r| r.offset).collect()
    }

    #[test]
    fn relr_address_and_bitmap() {
        assert_eq!(relr(&[0x1000]), vec![0x1000]);
        assert_eq!(relr(&[0x1000, 0b111]), vec![0x1000, 0x1008, 0x1010]);
        assert_eq!(
            relr(&[0x1000, 1 | (1 << 63)]),
            vec![0x1000, 0x1000 + 8 + 62 * 8]
        );
        let two_bitmaps = relr(&[0x2000, 0b11, 0b11]);
        assert_eq!(two_bitmaps, vec![0x2000, 0x2008, 0x2008 + 63 * 8]);
    }
}
