use crate::consts::*;
use crate::names;
use crate::reader::{Class, Endian, Reader, cstr_at};
use vantage_core::{Error, Result, text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub class: Class,
    pub endian: Endian,
    pub ident_version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    pub kind: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u32,
    pub shentsize: u16,
    pub shnum: u32,
    pub shstrndx: u32,
}

impl Header {
    pub fn kind_name(&self) -> String {
        match self.kind {
            ET_NONE => "NONE".into(),
            ET_REL => "REL".into(),
            ET_EXEC => "EXEC".into(),
            ET_DYN => "DYN".into(),
            ET_CORE => "CORE".into(),
            k => format!("{k:#06x}"),
        }
    }

    pub fn machine_name(&self) -> String {
        names::lookup(names::MACHINES, u32::from(self.machine))
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{:#x}", self.machine))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub index: usize,
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl Segment {
    pub fn type_name(&self) -> String {
        names::lookup(names::SEGMENT_TYPES, self.kind)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{:#x}", self.kind))
    }

    pub fn flags_string(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.flags & PF_R != 0 { 'R' } else { '-' });
        s.push(if self.flags & PF_W != 0 { 'W' } else { '-' });
        s.push(if self.flags & PF_X != 0 { 'X' } else { '-' });
        s
    }

    pub fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr - self.vaddr < self.memsz
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub index: usize,
    pub name: String,
    pub name_offset: u32,
    pub kind: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
}

impl Section {
    pub fn type_name(&self) -> String {
        names::lookup(names::SECTION_TYPES, self.kind)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{:#x}", self.kind))
    }

    pub fn flags_string(&self) -> String {
        let mut s = String::new();
        for (bit, c) in [(SHF_WRITE, 'W'), (SHF_ALLOC, 'A'), (SHF_EXECINSTR, 'X')] {
            if self.flags & bit != 0 {
                s.push(c);
            }
        }
        s
    }
}

#[derive(Debug)]
pub struct Elf<'a> {
    pub r: Reader<'a>,
    pub header: Header,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 16 || &data[..4] != b"\x7fELF" {
            return Err(Error::parse("not an ELF file"));
        }
        let class = match data[4] {
            1 => Class::Elf32,
            2 => Class::Elf64,
            c => return Err(Error::parse(format!("invalid EI_CLASS {c}"))),
        };
        let endian = match data[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            d => return Err(Error::parse(format!("invalid EI_DATA {d}"))),
        };
        let r = Reader {
            data,
            endian,
            class,
        };
        let header = parse_header(&r)?;
        let mut elf = Elf {
            r,
            header,
            segments: Vec::new(),
            sections: Vec::new(),
            warnings: Vec::new(),
        };
        if elf.header.ident_version != 1 || elf.header.version != 1 {
            elf.warn(format!(
                "unexpected ELF version (ident {}, header {})",
                elf.header.ident_version, elf.header.version
            ));
        }
        elf.apply_extended_numbering();
        match elf.parse_segments() {
            Ok(s) => elf.segments = s,
            Err(e) => elf.warn(format!("program headers unusable: {e}")),
        }
        match elf.parse_sections() {
            Ok(s) => elf.sections = s,
            Err(e) => elf.warn(format!("section headers unusable: {e}")),
        }
        elf.resolve_section_names();
        Ok(elf)
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    fn section_header_size(&self) -> u64 {
        match self.r.class {
            Class::Elf32 => 40,
            Class::Elf64 => 64,
        }
    }

    fn apply_extended_numbering(&mut self) {
        let h = &self.header;
        let needs = h.shoff != 0
            && (h.shnum == 0 || h.shstrndx == SHN_XINDEX || h.phnum == u32::from(PN_XNUM));
        if !needs {
            return;
        }
        let Ok(s0) = self.read_section(0) else {
            self.warn("extended numbering requested but section 0 is unreadable");
            return;
        };
        if self.header.shnum == 0 {
            self.header.shnum = u32::try_from(s0.size).unwrap_or(u32::MAX);
        }
        if self.header.shstrndx == SHN_XINDEX {
            self.header.shstrndx = s0.link;
        }
        if self.header.phnum == u32::from(PN_XNUM) {
            self.header.phnum = s0.info;
        }
    }

    fn parse_segments(&self) -> Result<Vec<Segment>> {
        let h = &self.header;
        if h.phnum == 0 {
            return Ok(Vec::new());
        }
        let min = match self.r.class {
            Class::Elf32 => 32,
            Class::Elf64 => 56,
        };
        if u64::from(h.phentsize) < min {
            return Err(Error::parse(format!(
                "e_phentsize {} too small",
                h.phentsize
            )));
        }
        let total = u64::from(h.phnum) * u64::from(h.phentsize);
        self.r.bytes(h.phoff, total)?;
        (0..h.phnum as usize)
            .map(|i| {
                let off = h.phoff + i as u64 * u64::from(h.phentsize);
                let r = &self.r;
                Ok(match r.class {
                    Class::Elf32 => Segment {
                        index: i,
                        kind: r.u32(off)?,
                        offset: r.word(off + 4)?,
                        vaddr: r.word(off + 8)?,
                        paddr: r.word(off + 12)?,
                        filesz: r.word(off + 16)?,
                        memsz: r.word(off + 20)?,
                        flags: r.u32(off + 24)?,
                        align: r.word(off + 28)?,
                    },
                    Class::Elf64 => Segment {
                        index: i,
                        kind: r.u32(off)?,
                        flags: r.u32(off + 4)?,
                        offset: r.u64(off + 8)?,
                        vaddr: r.u64(off + 16)?,
                        paddr: r.u64(off + 24)?,
                        filesz: r.u64(off + 32)?,
                        memsz: r.u64(off + 40)?,
                        align: r.u64(off + 48)?,
                    },
                })
            })
            .collect()
    }

    fn read_section(&self, i: usize) -> Result<Section> {
        let h = &self.header;
        let entsize = if h.shentsize == 0 {
            self.section_header_size()
        } else {
            u64::from(h.shentsize)
        };
        let off = (i as u64)
            .checked_mul(entsize)
            .and_then(|o| o.checked_add(h.shoff))
            .ok_or_else(|| Error::parse("section header offset overflow"))?;
        let r = &self.r;
        Ok(match r.class {
            Class::Elf32 => Section {
                index: i,
                name: String::new(),
                name_offset: r.u32(off)?,
                kind: r.u32(off + 4)?,
                flags: r.word(off + 8)?,
                addr: r.word(off + 12)?,
                offset: r.word(off + 16)?,
                size: r.word(off + 20)?,
                link: r.u32(off + 24)?,
                info: r.u32(off + 28)?,
                align: r.word(off + 32)?,
                entsize: r.word(off + 36)?,
            },
            Class::Elf64 => Section {
                index: i,
                name: String::new(),
                name_offset: r.u32(off)?,
                kind: r.u32(off + 4)?,
                flags: r.u64(off + 8)?,
                addr: r.u64(off + 16)?,
                offset: r.u64(off + 24)?,
                size: r.u64(off + 32)?,
                link: r.u32(off + 40)?,
                info: r.u32(off + 44)?,
                align: r.u64(off + 48)?,
                entsize: r.u64(off + 56)?,
            },
        })
    }

    fn parse_sections(&self) -> Result<Vec<Section>> {
        let h = &self.header;
        if h.shoff == 0 || h.shnum == 0 {
            return Ok(Vec::new());
        }
        if u64::from(h.shentsize) < self.section_header_size() {
            return Err(Error::parse(format!(
                "e_shentsize {} too small",
                h.shentsize
            )));
        }
        let total = u64::from(h.shnum) * u64::from(h.shentsize);
        self.r.bytes(h.shoff, total)?;
        (0..h.shnum as usize)
            .map(|i| self.read_section(i))
            .collect()
    }

    fn resolve_section_names(&mut self) {
        if self.sections.is_empty() {
            return;
        }
        let idx = self.header.shstrndx as usize;
        let table = match self.sections.get(idx) {
            Some(s) if s.kind == SHT_STRTAB => self.section_data(s).ok(),
            _ => None,
        };
        let Some(table) = table else {
            if idx != 0 {
                self.warn(format!("section name table index {idx} is invalid"));
            }
            return;
        };
        for s in &mut self.sections {
            if let Some(name) = cstr_at(table, u64::from(s.name_offset)) {
                s.name = text::from_bytes(name);
            }
        }
    }

    pub fn section_data(&self, s: &Section) -> Result<&'a [u8]> {
        if s.kind == SHT_NOBITS || s.kind == SHT_NULL {
            return Ok(&[]);
        }
        self.r.bytes(s.offset, s.size)
    }

    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn segments_of(&self, kind: u32) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(move |s| s.kind == kind)
    }

    pub fn segment(&self, kind: u32) -> Option<&Segment> {
        self.segments_of(kind).next()
    }

    pub fn segment_data(&self, s: &Segment) -> Result<&'a [u8]> {
        self.r.bytes(s.offset, s.filesz)
    }

    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<(u64, u64)> {
        for s in self.segments_of(PT_LOAD) {
            if vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz {
                let delta = vaddr - s.vaddr;
                return Some((s.offset.checked_add(delta)?, s.filesz - delta));
            }
        }
        if self.segments.iter().any(|s| s.kind == PT_LOAD) {
            return None;
        }
        for s in &self.sections {
            if s.flags & SHF_ALLOC != 0
                && s.kind != SHT_NOBITS
                && vaddr >= s.addr
                && vaddr - s.addr < s.size
            {
                let delta = vaddr - s.addr;
                return Some((s.offset.checked_add(delta)?, s.size - delta));
            }
        }
        None
    }

    pub fn bytes_at_vaddr(&self, vaddr: u64, len: u64) -> Option<&'a [u8]> {
        let (off, avail) = self.vaddr_to_offset(vaddr)?;
        if len > avail {
            return None;
        }
        self.r.bytes(off, len).ok()
    }

    pub fn bytes_from_vaddr(&self, vaddr: u64) -> Option<&'a [u8]> {
        let (off, avail) = self.vaddr_to_offset(vaddr)?;
        self.r.bytes(off, avail).ok()
    }

    pub fn interpreter(&self) -> Option<String> {
        let seg = self.segment(PT_INTERP)?;
        let data = self.segment_data(seg).ok()?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        Some(text::from_bytes(&data[..end]))
    }

    pub fn load_segment_at(&self, vaddr: u64) -> Option<&Segment> {
        self.segments_of(PT_LOAD).find(|s| s.contains_vaddr(vaddr))
    }

    pub fn reader_for(&self, data: &'a [u8]) -> Reader<'a> {
        self.r.with_data(data)
    }
}

fn parse_header(r: &Reader<'_>) -> Result<Header> {
    let d = r.data;
    let (entry, phoff, shoff, rest) = match r.class {
        Class::Elf32 => (r.word(24)?, r.word(28)?, r.word(32)?, 36),
        Class::Elf64 => (r.word(24)?, r.word(32)?, r.word(40)?, 48),
    };
    Ok(Header {
        class: r.class,
        endian: r.endian,
        ident_version: d[6],
        os_abi: d[7],
        abi_version: d[8],
        kind: r.u16(16)?,
        machine: r.u16(18)?,
        version: r.u32(20)?,
        entry,
        phoff,
        shoff,
        flags: r.u32(rest)?,
        ehsize: r.u16(rest + 4)?,
        phentsize: r.u16(rest + 6)?,
        phnum: u32::from(r.u16(rest + 8)?),
        shentsize: r.u16(rest + 10)?,
        shnum: u32::from(r.u16(rest + 12)?),
        shstrndx: u32::from(r.u16(rest + 14)?),
    })
}
