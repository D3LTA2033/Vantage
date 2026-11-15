#![forbid(unsafe_code)]

pub mod checksec;
pub mod consts;
pub mod dynamic;
pub mod elf;
pub mod names;
pub mod notes;
pub mod reader;
pub mod relocs;
pub mod report;
pub mod symbols;

use std::io::Read;
use std::path::Path;
use vantage_core::{Error, IoContext, Result, text};

pub use checksec::{Checksec, Context};
pub use dynamic::Dynamic;
pub use elf::{Elf, Header, Section, Segment};
pub use notes::Note;
pub use relocs::Relocation;
pub use symbols::{AddressIndex, Symbol, SymbolTable};

pub const DEFAULT_MAX_SIZE: u64 = 1 << 30;

#[derive(Debug)]
pub struct Binary<'a> {
    pub elf: Elf<'a>,
    pub dynamic: Option<Dynamic<'a>>,
    pub symtab: Vec<Symbol>,
    pub dynsyms: Vec<Symbol>,
    pub notes: Vec<Note>,
}

impl<'a> Binary<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut elf = Elf::parse(data)?;
        let dynamic = Dynamic::parse(&mut elf).unwrap_or_else(|e| {
            elf.warn(format!("dynamic section unusable: {e}"));
            None
        });
        let symtab = symbols::static_symbols(&elf).unwrap_or_else(|e| {
            elf.warn(format!("symbol table unusable: {e}"));
            Vec::new()
        });
        let dynsyms = symbols::dynamic_symbols(&mut elf, dynamic.as_ref()).unwrap_or_else(|e| {
            elf.warn(format!("dynamic symbol table unusable: {e}"));
            Vec::new()
        });
        let notes = notes::notes(&elf);
        Ok(Binary {
            elf,
            dynamic,
            symtab,
            dynsyms,
            notes,
        })
    }

    pub fn checksec(&self) -> Checksec {
        Checksec::analyze(self)
    }

    pub fn relocations(&mut self) -> Vec<Relocation> {
        relocs::relocations(
            &mut self.elf,
            self.dynamic.as_ref(),
            &self.dynsyms,
            &self.symtab,
        )
        .unwrap_or_else(|e| {
            self.elf.warn(format!("relocations unusable: {e}"));
            Vec::new()
        })
    }

    pub fn address_index(&self) -> AddressIndex<'_> {
        AddressIndex::new(self.symtab.iter().chain(self.dynsyms.iter()))
    }

    pub fn imports(&self) -> impl Iterator<Item = &Symbol> {
        self.dynsyms.iter().filter(|s| s.is_undefined())
    }

    pub fn exports(&self) -> impl Iterator<Item = &Symbol> {
        self.dynsyms
            .iter()
            .filter(|s| s.is_defined() && s.index != 0 && s.bind != consts::STB_LOCAL)
    }
}

pub fn read_file(path: &Path, max_size: u64) -> Result<Vec<u8>> {
    let shown = text::from_path(path);
    let file = std::fs::File::open(path).with_context(|| format!("open {shown}"))?;
    let meta = file.metadata().with_context(|| format!("stat {shown}"))?;
    if !meta.is_file() {
        return Err(Error::usage(format!("{shown}: not a regular file")));
    }
    if meta.len() > max_size {
        return Err(Error::usage(format!(
            "{shown}: {} bytes exceeds the {max_size} byte limit",
            meta.len()
        )));
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take(max_size + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("read {shown}"))?;
    if data.len() as u64 > max_size {
        return Err(Error::usage(format!(
            "{shown}: grew past the size limit while reading"
        )));
    }
    Ok(data)
}
