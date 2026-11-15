use crate::consts::*;
use crate::elf::Elf;
use crate::reader::{Class, Reader};
use std::fmt::Write;
use vantage_core::text;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub owner: String,
    pub kind: u32,
    pub desc: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GnuProperties {
    pub x86_feature_1: Option<u32>,
    pub aarch64_feature_1: Option<u32>,
}

fn align_up(v: u64, a: u64) -> Option<u64> {
    v.checked_add(a - 1).map(|x| x & !(a - 1))
}

pub fn parse_notes(r: &Reader<'_>, data: &[u8], align: u64, out: &mut Vec<Note>) {
    let align = if align == 8 { 8 } else { 4 };
    let r = r.with_data(data);
    let mut off = 0u64;
    while off + 12 <= r.len() {
        let (Ok(namesz), Ok(descsz), Ok(kind)) = (r.u32(off), r.u32(off + 4), r.u32(off + 8))
        else {
            return;
        };
        let name_off = off + 12;
        let Some(desc_off) = align_up(name_off + u64::from(namesz), align) else {
            return;
        };
        let Ok(name) = r.bytes(name_off, u64::from(namesz)) else {
            return;
        };
        let Ok(desc) = r.bytes(desc_off, u64::from(descsz)) else {
            return;
        };
        out.push(Note {
            owner: text::from_cstr_bytes(name),
            kind,
            desc: desc.to_vec(),
        });
        let Some(next) = align_up(desc_off + u64::from(descsz), align) else {
            return;
        };
        off = next;
    }
}

pub fn notes(elf: &Elf<'_>) -> Vec<Note> {
    let mut out = Vec::new();
    let note_segments: Vec<_> = elf.segments_of(PT_NOTE).collect();
    if !note_segments.is_empty() {
        for s in note_segments {
            if let Ok(d) = elf.segment_data(s) {
                parse_notes(&elf.r, d, s.align, &mut out);
            }
        }
    } else {
        for s in elf.sections.iter().filter(|s| s.kind == SHT_NOTE) {
            if let Ok(d) = elf.section_data(s) {
                parse_notes(&elf.r, d, s.align, &mut out);
            }
        }
    }
    out
}

pub fn build_id(notes: &[Note]) -> Option<String> {
    let n = notes
        .iter()
        .find(|n| n.owner == "GNU" && n.kind == NT_GNU_BUILD_ID)?;
    let mut s = String::with_capacity(n.desc.len() * 2);
    for b in &n.desc {
        let _ = write!(s, "{b:02x}");
    }
    Some(s)
}

pub fn gnu_properties(r: &Reader<'_>, notes: &[Note]) -> GnuProperties {
    let mut props = GnuProperties::default();
    let pad = match r.class {
        Class::Elf32 => 4,
        Class::Elf64 => 8,
    };
    for n in notes
        .iter()
        .filter(|n| n.owner == "GNU" && n.kind == NT_GNU_PROPERTY_TYPE_0)
    {
        let d = r.with_data(&n.desc);
        let mut off = 0u64;
        while off + 8 <= d.len() {
            let (Ok(kind), Ok(size)) = (d.u32(off), d.u32(off + 4)) else {
                break;
            };
            let value = if size >= 4 { d.u32(off + 8).ok() } else { None };
            match kind {
                GNU_PROPERTY_X86_FEATURE_1_AND => props.x86_feature_1 = value,
                GNU_PROPERTY_AARCH64_FEATURE_1_AND => props.aarch64_feature_1 = value,
                _ => {}
            }
            let Some(next) = align_up(off + 8 + u64::from(size), pad) else {
                break;
            };
            off = next;
        }
    }
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::Endian;

    #[test]
    fn note_parsing_with_alignment() {
        let mut data = Vec::new();
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"GNU\0");
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(b"GNU\0");
        data.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        let r = Reader {
            data: &data,
            endian: Endian::Little,
            class: Class::Elf64,
        };
        let mut out = Vec::new();
        parse_notes(&r, &data, 4, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(build_id(&out).as_deref(), Some("deadbeef"));
        assert_eq!(gnu_properties(&r, &out).x86_feature_1, Some(3));
    }

    #[test]
    fn truncated_notes_stop_cleanly() {
        let data = [8u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, b'G'];
        let r = Reader {
            data: &data,
            endian: Endian::Little,
            class: Class::Elf64,
        };
        let mut out = Vec::new();
        parse_notes(&r, &data, 4, &mut out);
        assert!(out.is_empty());
    }
}
