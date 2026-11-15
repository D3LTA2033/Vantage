use crate::checksec::{Canary, Checksec, Entry, Nx, Relro};
use crate::consts::*;
use crate::reader::{Class, Endian};
use crate::relocs::Relocation;
use crate::symbols::Symbol;
use crate::{Binary, Header};
use std::fmt::Write;
use vantage_core::json::{self, Value};

pub fn hex(v: u64) -> Value {
    Value::Str(format!("{v:#x}"))
}

pub fn header(h: &Header) -> Value {
    json::obj([
        (
            "class",
            match h.class {
                Class::Elf32 => "ELF32",
                Class::Elf64 => "ELF64",
            }
            .into(),
        ),
        (
            "endian",
            match h.endian {
                Endian::Little => "little",
                Endian::Big => "big",
            }
            .into(),
        ),
        ("os_abi", h.os_abi.into()),
        ("type", h.kind_name().into()),
        ("machine", h.machine_name().into()),
        ("entry", hex(h.entry)),
        ("flags", hex(u64::from(h.flags))),
        ("phoff", hex(h.phoff)),
        ("phnum", h.phnum.into()),
        ("shoff", hex(h.shoff)),
        ("shnum", h.shnum.into()),
        ("shstrndx", h.shstrndx.into()),
    ])
}

pub fn info(bin: &Binary<'_>) -> Value {
    let elf = &bin.elf;
    let segments = elf
        .segments
        .iter()
        .map(|s| {
            json::obj([
                ("index", s.index.into()),
                ("type", s.type_name().into()),
                ("flags", s.flags_string().into()),
                ("offset", hex(s.offset)),
                ("vaddr", hex(s.vaddr)),
                ("filesz", s.filesz.into()),
                ("memsz", s.memsz.into()),
                ("align", s.align.into()),
            ])
        })
        .collect();
    let sections = elf
        .sections
        .iter()
        .map(|s| {
            json::obj([
                ("index", s.index.into()),
                ("name", s.name.clone().into()),
                ("type", s.type_name().into()),
                ("flags", s.flags_string().into()),
                ("addr", hex(s.addr)),
                ("offset", hex(s.offset)),
                ("size", s.size.into()),
                ("link", s.link.into()),
                ("info", s.info.into()),
                ("entsize", s.entsize.into()),
            ])
        })
        .collect();
    let dynamic = bin.dynamic.as_ref().map(|d| {
        json::obj([
            ("source", d.source.into()),
            ("needed", d.needed.clone().into()),
            ("soname", d.soname.clone().into()),
            ("rpath", d.rpath.clone().into()),
            ("runpath", d.runpath.clone().into()),
            ("flags", hex(d.flags)),
            ("flags_1", hex(d.flags_1)),
            (
                "entries",
                Value::Array(
                    d.entries
                        .iter()
                        .map(|e| {
                            let value = match e.tag {
                                DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH => {
                                    d.string(e.val).map_or_else(|| hex(e.val), Value::Str)
                                }
                                _ => hex(e.val),
                            };
                            json::obj([("tag", e.tag_name().into()), ("value", value)])
                        })
                        .collect(),
                ),
            ),
        ])
    });
    let notes = bin
        .notes
        .iter()
        .map(|n| {
            let mut desc = String::new();
            for b in n.desc.iter().take(64) {
                let _ = write!(desc, "{b:02x}");
            }
            json::obj([
                ("owner", n.owner.clone().into()),
                ("type", n.kind.into()),
                ("size", n.desc.len().into()),
                ("desc", desc.into()),
            ])
        })
        .collect();
    json::obj([
        ("header", header(&elf.header)),
        ("interpreter", elf.interpreter().into()),
        ("segments", Value::Array(segments)),
        ("sections", Value::Array(sections)),
        ("dynamic", dynamic.into()),
        ("notes", Value::Array(notes)),
        ("symtab_count", bin.symtab.len().into()),
        ("dynsym_count", bin.dynsyms.len().into()),
        ("warnings", elf.warnings.clone().into()),
    ])
}

pub fn symbol(s: &Symbol) -> Value {
    json::obj([
        ("table", s.table.as_str().into()),
        ("index", s.index.into()),
        ("name", s.name.clone().into()),
        ("version", s.version.clone().into()),
        ("value", hex(s.value)),
        ("size", s.size.into()),
        ("type", s.kind_name().into()),
        ("bind", s.bind_name().into()),
        ("visibility", s.visibility_name().into()),
        ("section", s.shndx_name().into()),
    ])
}

pub fn relocation(r: &Relocation, machine: u16) -> Value {
    json::obj([
        ("table", r.table.clone().into()),
        ("offset", hex(r.offset)),
        ("type", r.type_name(machine).into()),
        ("symbol", r.symbol.clone().into()),
        ("addend", r.addend.into()),
    ])
}

pub fn nx_str(nx: Nx) -> &'static str {
    match nx {
        Nx::Enabled => "enabled",
        Nx::Disabled => "disabled",
        Nx::Missing => "no-gnu-stack",
    }
}

pub fn relro_str(r: Option<Relro>) -> &'static str {
    match r {
        None => "n/a",
        Some(Relro::None) => "none",
        Some(Relro::Partial) => "partial",
        Some(Relro::Full) => "full",
    }
}

pub fn canary_str(c: Canary) -> &'static str {
    match c {
        Canary::Imported => "yes",
        Canary::Defined => "symbol-defined",
        Canary::NotFound => "no",
        Canary::Unknown => "unknown",
    }
}

pub fn entry_str(e: Entry) -> &'static str {
    match e {
        Entry::Ok => "ok",
        Entry::NotApplicable => "n/a",
        Entry::OutsideLoad => "outside-load-segments",
        Entry::NonExecutable => "non-executable-segment",
        Entry::Writable => "writable-segment",
    }
}

pub fn checksec(c: &Checksec) -> Value {
    json::obj([
        ("kind", c.kind.as_str().into()),
        ("nx", nx_str(c.nx).into()),
        ("relro", relro_str(c.relro).into()),
        ("canary", canary_str(c.canary).into()),
        (
            "fortify",
            if c.fortify_applicable {
                json::obj([
                    ("fortified", c.fortified.clone().into()),
                    ("fortifiable", c.fortifiable.clone().into()),
                ])
            } else {
                Value::Null
            },
        ),
        ("rpath", c.rpath.clone().into()),
        ("runpath", c.runpath.clone().into()),
        ("textrel", c.textrel.into()),
        ("wx_segments", c.wx_segments.clone().into()),
        ("wx_sections", c.wx_sections.clone().into()),
        ("ibt", c.ibt.into()),
        ("shstk", c.shstk.into()),
        ("bti", c.bti.into()),
        ("pac", c.pac.into()),
        ("stripped", c.stripped.into()),
        ("static", c.static_linked.into()),
        ("interpreter", c.interpreter.clone().into()),
        ("build_id", c.build_id.clone().into()),
        ("entry", entry_str(c.entry).into()),
        ("packer", c.packer.clone().into()),
    ])
}
