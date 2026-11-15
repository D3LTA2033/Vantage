use crate::consts::*;
use crate::elf::Elf;
use crate::names;
use crate::reader::StrTab;
use vantage_core::{Result, text};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynEntry {
    pub tag: i64,
    pub val: u64,
}

impl DynEntry {
    pub fn tag_name(&self) -> String {
        u64::try_from(self.tag)
            .ok()
            .and_then(|t| names::lookup(names::DYNAMIC_TAGS, t))
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{:#x}", self.tag))
    }

    pub fn is_string(&self) -> bool {
        matches!(self.tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Dynamic<'a> {
    pub entries: Vec<DynEntry>,
    pub source: &'static str,
    pub strtab: &'a [u8],
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub flags: u64,
    pub flags_1: u64,
}

impl<'a> Dynamic<'a> {
    pub fn get(&self, tag: i64) -> Option<u64> {
        self.entries.iter().find(|e| e.tag == tag).map(|e| e.val)
    }

    pub fn has(&self, tag: i64) -> bool {
        self.entries.iter().any(|e| e.tag == tag)
    }

    pub fn strings(&self) -> StrTab<'a> {
        StrTab::new(self.strtab)
    }

    pub fn bind_now(&self) -> bool {
        self.has(DT_BIND_NOW) || self.flags & DF_BIND_NOW != 0 || self.flags_1 & DF_1_NOW != 0
    }

    pub fn textrel(&self) -> bool {
        self.has(DT_TEXTREL) || self.flags & DF_TEXTREL != 0
    }

    pub fn parse(elf: &mut Elf<'a>) -> Result<Option<Dynamic<'a>>> {
        let seg = elf.segment(PT_DYNAMIC).cloned();
        let sec = elf.sections.iter().find(|s| s.kind == SHT_DYNAMIC).cloned();
        let (data, source) = match (&seg, &sec) {
            (Some(p), s) => {
                if let Some(s) = s
                    && s.offset != p.offset
                {
                    elf.warn(format!(
                            "dynamic section at {:#x} disagrees with PT_DYNAMIC at {:#x}; using PT_DYNAMIC",
                            s.offset, p.offset
                        ));
                }
                (elf.segment_data(p)?, "PT_DYNAMIC")
            }
            (None, Some(s)) => (elf.section_data(s)?, ".dynamic"),
            (None, None) => return Ok(None),
        };
        let r = elf.reader_for(data);
        let ent = 2 * r.word_size();
        let mut entries = Vec::new();
        let mut off = 0u64;
        while off + ent <= r.len() {
            let tag = r.sword(off)?;
            let val = r.word(off + r.word_size())?;
            if tag == DT_NULL {
                break;
            }
            entries.push(DynEntry { tag, val });
            off += ent;
        }
        let mut dynamic = Dynamic {
            entries,
            source,
            ..Default::default()
        };
        dynamic.strtab = dynamic.locate_strtab(elf, sec.as_ref().map(|s| s.link));
        if dynamic.strtab.is_empty() && dynamic.has(DT_STRTAB) {
            elf.warn("DT_STRTAB does not map to file contents");
        }
        let mut strs = dynamic.strings();
        for e in &dynamic.entries {
            let mut s = || strs.get(e.val).map(text::from_bytes);
            match e.tag {
                DT_NEEDED => {
                    let name = s().unwrap_or_else(|| format!("<bad offset {:#x}>", e.val));
                    dynamic.needed.push(name);
                }
                DT_SONAME => dynamic.soname = s(),
                DT_RPATH => dynamic.rpath.extend(s().into_iter().flat_map(split_path)),
                DT_RUNPATH => dynamic.runpath.extend(s().into_iter().flat_map(split_path)),
                DT_FLAGS => dynamic.flags |= e.val,
                DT_FLAGS_1 => dynamic.flags_1 |= e.val,
                _ => {}
            }
        }
        if let Some(w) = strs.limit_warning("dynamic entries") {
            elf.warn(w);
        }
        Ok(Some(dynamic))
    }

    fn locate_strtab(&self, elf: &Elf<'a>, section_link: Option<u32>) -> &'a [u8] {
        if let Some(addr) = self.get(DT_STRTAB) {
            let size = self.get(DT_STRSZ);
            let found = match size {
                Some(sz) => elf.bytes_at_vaddr(addr, sz),
                None => elf.bytes_from_vaddr(addr),
            };
            if let Some(t) = found {
                return t;
            }
        }
        section_link
            .and_then(|l| elf.sections.get(l as usize))
            .filter(|s| s.kind == SHT_STRTAB)
            .and_then(|s| elf.section_data(s).ok())
            .unwrap_or(&[])
    }
}

fn split_path(s: String) -> Vec<String> {
    s.split(':').map(str::to_owned).collect()
}
