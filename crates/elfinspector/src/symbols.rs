use crate::consts::*;
use crate::dynamic::Dynamic;
use crate::elf::{Elf, Section};
use crate::reader::{Class, Reader, StrTab};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use vantage_core::{Error, Result, text};

const MAX_SYMBOLS: u64 = 4_000_000;
const MAX_VERSION_RECORDS: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolTable {
    Static,
    Dynamic,
}

impl SymbolTable {
    pub fn as_str(self) -> &'static str {
        match self {
            SymbolTable::Static => "symtab",
            SymbolTable::Dynamic => "dynsym",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub index: usize,
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub kind: u8,
    pub bind: u8,
    pub visibility: u8,
    pub shndx: u32,
    pub version: Option<Arc<str>>,
    pub version_hidden: bool,
    pub table: SymbolTable,
}

impl Symbol {
    pub fn is_undefined(&self) -> bool {
        self.shndx == SHN_UNDEF && self.index != 0
    }

    pub fn is_defined(&self) -> bool {
        self.shndx != SHN_UNDEF
    }

    pub fn is_export(&self) -> bool {
        self.is_defined() && self.index != 0 && self.bind != STB_LOCAL
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            STT_NOTYPE => "NOTYPE",
            STT_OBJECT => "OBJECT",
            STT_FUNC => "FUNC",
            STT_SECTION => "SECTION",
            STT_FILE => "FILE",
            STT_COMMON => "COMMON",
            STT_TLS => "TLS",
            STT_GNU_IFUNC => "IFUNC",
            _ => "OTHER",
        }
    }

    pub fn bind_name(&self) -> &'static str {
        match self.bind {
            STB_LOCAL => "LOCAL",
            STB_GLOBAL => "GLOBAL",
            STB_WEAK => "WEAK",
            STB_GNU_UNIQUE => "UNIQUE",
            _ => "OTHER",
        }
    }

    pub fn visibility_name(&self) -> &'static str {
        match self.visibility & 3 {
            0 => "DEFAULT",
            1 => "INTERNAL",
            2 => "HIDDEN",
            _ => "PROTECTED",
        }
    }

    pub fn shndx_name(&self) -> String {
        match self.shndx {
            SHN_UNDEF => "UND".into(),
            SHN_ABS => "ABS".into(),
            SHN_COMMON => "COM".into(),
            n => n.to_string(),
        }
    }

    pub fn display_name(&self) -> String {
        match &self.version {
            Some(v) if self.is_undefined() || self.version_hidden => format!("{}@{v}", self.name),
            Some(v) => format!("{}@@{v}", self.name),
            None => self.name.clone(),
        }
    }
}

fn sym_size(class: Class) -> u64 {
    match class {
        Class::Elf32 => 16,
        Class::Elf64 => 24,
    }
}

fn read_symbols(
    r: &Reader<'_>,
    data: &[u8],
    count: u64,
    entsize: u64,
    strtab: &[u8],
    shndx_table: Option<&[u8]>,
    table: SymbolTable,
) -> Result<(Vec<Symbol>, Option<String>)> {
    let min = sym_size(r.class);
    let entsize = if entsize == 0 { min } else { entsize };
    if entsize < min {
        return Err(Error::parse(format!(
            "symbol entry size {entsize} too small"
        )));
    }
    if count > MAX_SYMBOLS {
        return Err(Error::parse(format!("symbol count {count} exceeds limit")));
    }
    let tr = r.with_data(data);
    let xr = shndx_table.map(|d| r.with_data(d));
    let mut strs = StrTab::new(strtab);
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let off = i * entsize;
        if off + min > tr.len() {
            break;
        }
        let (name_off, value, size, info, other, shndx) = match r.class {
            Class::Elf32 => (
                tr.u32(off)?,
                tr.word(off + 4)?,
                tr.word(off + 8)?,
                tr.u8(off + 12)?,
                tr.u8(off + 13)?,
                tr.u16(off + 14)?,
            ),
            Class::Elf64 => (
                tr.u32(off)?,
                tr.u64(off + 8)?,
                tr.u64(off + 16)?,
                tr.u8(off + 4)?,
                tr.u8(off + 5)?,
                tr.u16(off + 6)?,
            ),
        };
        let mut shndx = u32::from(shndx);
        if shndx == SHN_XINDEX
            && let Some(x) = &xr
        {
            shndx = x.u32(i * 4).unwrap_or(shndx);
        }
        let name = strs
            .get(u64::from(name_off))
            .map(text::from_bytes)
            .unwrap_or_default();
        out.push(Symbol {
            index: i as usize,
            name,
            value,
            size,
            kind: info & 0xf,
            bind: info >> 4,
            visibility: other & 3,
            shndx,
            version: None,
            version_hidden: false,
            table,
        });
    }
    Ok((out, strs.limit_warning(table.as_str())))
}

fn table_from_section(
    elf: &Elf<'_>,
    sec: &Section,
    table: SymbolTable,
) -> Result<(Vec<Symbol>, Option<String>)> {
    let data = elf.section_data(sec)?;
    let strtab = elf
        .sections
        .get(sec.link as usize)
        .filter(|s| s.kind == SHT_STRTAB)
        .map(|s| elf.section_data(s))
        .transpose()?
        .unwrap_or(&[]);
    let shndx = elf
        .sections
        .iter()
        .find(|s| s.kind == SHT_SYMTAB_SHNDX && s.link as usize == sec.index)
        .and_then(|s| elf.section_data(s).ok());
    let entsize = if sec.entsize == 0 {
        sym_size(elf.r.class)
    } else {
        sec.entsize
    };
    read_symbols(
        &elf.r,
        data,
        data.len() as u64 / entsize,
        entsize,
        strtab,
        shndx,
        table,
    )
}

pub fn static_symbols(elf: &mut Elf<'_>) -> Result<Vec<Symbol>> {
    let Some(sec) = elf.sections.iter().find(|s| s.kind == SHT_SYMTAB).cloned() else {
        return Ok(Vec::new());
    };
    let (syms, warning) = table_from_section(elf, &sec, SymbolTable::Static)?;
    if let Some(w) = warning {
        elf.warn(w);
    }
    Ok(syms)
}

pub fn dynamic_symbols(elf: &mut Elf<'_>, dynamic: Option<&Dynamic<'_>>) -> Result<Vec<Symbol>> {
    let (mut syms, warning) =
        if let Some(sec) = elf.sections.iter().find(|s| s.kind == SHT_DYNSYM).cloned() {
            table_from_section(elf, &sec, SymbolTable::Dynamic)?
        } else if let Some(d) = dynamic {
            symbols_from_dynamic(elf, d)?
        } else {
            (Vec::new(), None)
        };
    if let Some(w) = warning {
        elf.warn(w);
    }
    if let Some(d) = dynamic {
        apply_versions(elf, d, &mut syms);
    }
    Ok(syms)
}

fn symbols_from_dynamic(
    elf: &mut Elf<'_>,
    d: &Dynamic<'_>,
) -> Result<(Vec<Symbol>, Option<String>)> {
    let Some(symtab) = d.get(DT_SYMTAB) else {
        return Ok((Vec::new(), None));
    };
    let entsize = d.get(DT_SYMENT).unwrap_or(sym_size(elf.r.class));
    let count = match symbol_count(elf, d) {
        Some(c) => c,
        None => {
            elf.warn("dynamic symbol count unknown (no DT_HASH or DT_GNU_HASH); dynsym not read");
            return Ok((Vec::new(), None));
        }
    };
    let Some(data) = elf.bytes_from_vaddr(symtab) else {
        elf.warn("DT_SYMTAB does not map to file contents");
        return Ok((Vec::new(), None));
    };
    read_symbols(
        &elf.r,
        data,
        count,
        entsize,
        d.strtab,
        None,
        SymbolTable::Dynamic,
    )
}

fn symbol_count(elf: &Elf<'_>, d: &Dynamic<'_>) -> Option<u64> {
    if let Some(hash) = d.get(DT_HASH) {
        let data = elf.bytes_at_vaddr(hash, 8)?;
        return Some(u64::from(elf.reader_for(data).u32(4).ok()?));
    }
    let (count, exact) = gnu_hash_count(elf, d)?;
    if exact {
        return Some(count);
    }
    let from_relocs = crate::relocs::max_dynamic_symbol(elf, d).map_or(0, |m| m + 1);
    Some(count.max(from_relocs).max(layout_count(elf, d)))
}

fn layout_count(elf: &Elf<'_>, d: &Dynamic<'_>) -> u64 {
    let (Some(symtab), Some(strtab)) = (d.get(DT_SYMTAB), d.get(DT_STRTAB)) else {
        return 0;
    };
    let entsize = d.get(DT_SYMENT).unwrap_or(sym_size(elf.r.class));
    if strtab <= symtab || entsize < sym_size(elf.r.class) {
        return 0;
    }
    let max = ((strtab - symtab) / entsize).min(MAX_SYMBOLS);
    let Some(data) = elf.bytes_at_vaddr(symtab, max * entsize) else {
        return 0;
    };
    let r = elf.reader_for(data);
    let strsz = d.get(DT_STRSZ).unwrap_or(d.strtab.len() as u64);
    let info_off = match elf.r.class {
        Class::Elf32 => 12,
        Class::Elf64 => 4,
    };
    for i in 0..max {
        let off = i * entsize;
        let (Ok(name), Ok(info)) = (r.u32(off), r.u8(off + info_off)) else {
            return i;
        };
        let valid_kind = matches!(info & 0xf, 0..=6 | 10);
        let valid_bind = matches!(info >> 4, 0..=2 | 10);
        if u64::from(name) >= strsz
            || !valid_kind
            || !valid_bind
            || (i == 0 && (name != 0 || info != 0))
        {
            return i;
        }
    }
    max
}

fn gnu_hash_count(elf: &Elf<'_>, d: &Dynamic<'_>) -> Option<(u64, bool)> {
    let gnu = d.get(DT_GNU_HASH)?;
    let data = elf.bytes_from_vaddr(gnu)?;
    let r = elf.reader_for(data);
    let nbuckets = u64::from(r.u32(0).ok()?);
    let symoffset = u64::from(r.u32(4).ok()?);
    let bloom_size = u64::from(r.u32(8).ok()?);
    let buckets = 16u64.checked_add(bloom_size.checked_mul(r.word_size())?)?;
    let chains = buckets.checked_add(nbuckets.checked_mul(4)?)?;
    let mut max = 0u64;
    for i in 0..nbuckets {
        max = max.max(u64::from(r.u32(buckets + i * 4).ok()?));
    }
    if max < symoffset {
        return Some((symoffset, false));
    }
    let mut idx = max;
    loop {
        let entry = r.u32(chains + (idx - symoffset) * 4).ok()?;
        if entry & 1 != 0 {
            return Some((idx + 1, true));
        }
        idx += 1;
        if idx > MAX_SYMBOLS {
            return None;
        }
    }
}

fn region<'a>(elf: &Elf<'a>, tag_addr: Option<u64>, section_kind: u32) -> Option<&'a [u8]> {
    if let Some(addr) = tag_addr
        && let Some(d) = elf.bytes_from_vaddr(addr)
    {
        return Some(d);
    }
    let s = elf.sections.iter().find(|s| s.kind == section_kind)?;
    elf.section_data(s).ok()
}

struct VersionNames<'a> {
    strs: StrTab<'a>,
    records: usize,
    stopped: bool,
    names: HashMap<u16, Arc<str>>,
}

impl VersionNames<'_> {
    fn record(&mut self) -> bool {
        if self.records == 0 {
            self.stopped = true;
            return false;
        }
        self.records -= 1;
        true
    }

    fn insert(&mut self, index: u16, name: u32) {
        if let Entry::Vacant(e) = self.names.entry(index & VERSYM_VERSION)
            && let Some(n) = self.strs.get(u64::from(name))
        {
            e.insert(Arc::from(text::from_bytes(n)));
        }
    }
}

fn apply_versions(elf: &mut Elf<'_>, d: &Dynamic<'_>, syms: &mut [Symbol]) {
    let Some(versym) = region(elf, d.get(DT_VERSYM), SHT_GNU_VERSYM) else {
        return;
    };
    let mut v = VersionNames {
        strs: StrTab::new(d.strtab),
        records: MAX_VERSION_RECORDS,
        stopped: false,
        names: HashMap::new(),
    };
    if let Some(data) = region(elf, d.get(DT_VERNEED), SHT_GNU_VERNEED) {
        let count = d.get(DT_VERNEEDNUM).unwrap_or(u64::MAX);
        read_verneed(&elf.reader_for(data), count, &mut v);
    }
    if let Some(data) = region(elf, d.get(DT_VERDEF), SHT_GNU_VERDEF) {
        let count = d.get(DT_VERDEFNUM).unwrap_or(u64::MAX);
        read_verdef(&elf.reader_for(data), count, &mut v);
    }
    if v.stopped {
        elf.warn(format!(
            "version tables: stopped after {MAX_VERSION_RECORDS} records"
        ));
    }
    if let Some(w) = v.strs.limit_warning("version names") {
        elf.warn(w);
    }
    let r = elf.reader_for(versym);
    for s in syms.iter_mut() {
        let Ok(idx) = r.u16(s.index as u64 * 2) else {
            break;
        };
        let hidden = idx & VERSYM_HIDDEN != 0;
        let idx = idx & VERSYM_VERSION;
        if idx <= 1 {
            continue;
        }
        if let Some(name) = v.names.get(&idx) {
            s.version = Some(Arc::clone(name));
            s.version_hidden = hidden;
        }
    }
}

const VERNEED_SIZE: u32 = 16;
const VERNAUX_SIZE: u32 = 16;
const VERDEF_SIZE: u32 = 20;

fn read_verneed(r: &Reader<'_>, count: u64, v: &mut VersionNames<'_>) {
    let mut off = 0u64;
    for _ in 0..count {
        if !v.record() {
            return;
        }
        let (Ok(cnt), Ok(aux), Ok(next)) = (r.u16(off + 2), r.u32(off + 8), r.u32(off + 12)) else {
            return;
        };
        let mut aoff = off + u64::from(aux);
        for _ in 0..cnt {
            if !v.record() {
                return;
            }
            let (Ok(other), Ok(name), Ok(anext)) =
                (r.u16(aoff + 6), r.u32(aoff + 8), r.u32(aoff + 12))
            else {
                break;
            };
            v.insert(other, name);
            if anext < VERNAUX_SIZE {
                break;
            }
            aoff += u64::from(anext);
        }
        if next < VERNEED_SIZE {
            return;
        }
        off += u64::from(next);
    }
}

fn read_verdef(r: &Reader<'_>, count: u64, v: &mut VersionNames<'_>) {
    let mut off = 0u64;
    for _ in 0..count {
        if !v.record() {
            return;
        }
        let (Ok(flags), Ok(ndx), Ok(aux), Ok(next)) = (
            r.u16(off + 2),
            r.u16(off + 4),
            r.u32(off + 12),
            r.u32(off + 16),
        ) else {
            return;
        };
        if flags & 1 == 0
            && let Ok(name) = r.u32(off + u64::from(aux))
        {
            v.insert(ndx, name);
        }
        if next < VERDEF_SIZE {
            return;
        }
        off += u64::from(next);
    }
}

#[derive(Debug, Clone)]
pub struct AddressIndex<'s> {
    sorted: Vec<&'s Symbol>,
}

impl<'s> AddressIndex<'s> {
    pub fn new(tables: impl IntoIterator<Item = &'s Symbol>) -> Self {
        let mut sorted: Vec<&Symbol> = tables
            .into_iter()
            .filter(|s| {
                s.is_defined()
                    && s.shndx != SHN_ABS
                    && matches!(s.kind, STT_FUNC | STT_OBJECT | STT_NOTYPE | STT_GNU_IFUNC)
                    && !s.name.is_empty()
            })
            .collect();
        sorted.sort_by(|a, b| a.value.cmp(&b.value).then(b.size.cmp(&a.size)));
        sorted.dedup_by(|a, b| a.value == b.value && a.name == b.name);
        AddressIndex { sorted }
    }

    pub fn resolve(&self, addr: u64) -> Option<(&'s Symbol, u64)> {
        let below = &self.sorted[..self.sorted.partition_point(|s| s.value <= addr)];
        for s in below.iter().rev().take(64) {
            let off = addr - s.value;
            if s.size > 0 && off < s.size {
                return Some((s, off));
            }
        }
        let s = below.last()?;
        (s.size == 0).then(|| (*s, addr - s.value))
    }

    pub fn len(&self) -> usize {
        self.sorted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::Endian;

    #[test]
    fn shared_long_name_is_read_within_budget() {
        let mut strtab = vec![b'A'; 1 << 20];
        strtab.push(0);
        let entries = vec![0u8; 24 * 1000];
        let r = Reader {
            data: &entries,
            endian: Endian::Little,
            class: Class::Elf64,
        };
        let (syms, warning) =
            read_symbols(&r, &entries, 1000, 24, &strtab, None, SymbolTable::Static).unwrap();
        assert_eq!(syms.len(), 1000);
        let total: usize = syms.iter().map(|s| s.name.len()).sum();
        assert!(total <= strtab.len() * 4 + (1 << 16), "{total}");
        assert!(warning.is_some_and(|w| w.starts_with("symtab: names reference")));
    }

    #[test]
    fn version_chains_must_move_forward() {
        let mut data = vec![0u8; 32];
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[8..12].copy_from_slice(&16u32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16 + 6..16 + 8].copy_from_slice(&2u16.to_le_bytes());
        data[16 + 8..16 + 12].copy_from_slice(&1u32.to_le_bytes());
        data[16 + 12..16 + 16].copy_from_slice(&8u32.to_le_bytes());
        let r = Reader {
            data: &data,
            endian: Endian::Little,
            class: Class::Elf64,
        };
        let mut v = VersionNames {
            strs: StrTab::new(b"\0GLIBC_2.34\0"),
            records: MAX_VERSION_RECORDS,
            stopped: false,
            names: HashMap::new(),
        };
        read_verneed(&r, u64::MAX, &mut v);
        assert_eq!(v.names.get(&2).map(|s| &**s), Some("GLIBC_2.34"));
        assert_eq!(v.records, MAX_VERSION_RECORDS - 2);

        let mut looping = data.clone();
        looping[12..16].copy_from_slice(&4u32.to_le_bytes());
        let r = Reader {
            data: &looping,
            ..r
        };
        let mut v = VersionNames {
            strs: StrTab::new(b"\0GLIBC_2.34\0"),
            records: MAX_VERSION_RECORDS,
            stopped: false,
            names: HashMap::new(),
        };
        read_verneed(&r, u64::MAX, &mut v);
        assert_eq!(v.records, MAX_VERSION_RECORDS - 2);
    }
}
