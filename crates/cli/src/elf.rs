use crate::Global;
use crate::args::{self, flag, multi};
use crate::render::{self, Out, finding_lines, table};
use elfinspector::checksec::{Checksec, Kind};
use elfinspector::{Binary, Context, Relocation, Symbol, report};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use vantage_core::json::{self, Value};
use vantage_core::{Error, Result, Severity, text};

pub const HELP: &str = "usage: vantage elf <command> FILE...

commands:
  info FILE                  headers, segments, sections, dynamic entries, notes
  checksec FILE...           exploit mitigations and risky linkage
  symbols FILE               symbol tables
      --dynamic | --static   restrict to .dynsym or .symtab
      --imports | --exports  undefined or exported dynamic symbols only
      --grep TEXT            name contains TEXT
      --lookup ADDR          resolve ADDR (repeatable) to symbol+offset
  relocs FILE                REL, RELA and RELR relocations with resolved symbols";

fn load(path: &str) -> Result<Vec<u8>> {
    elfinspector::read_file(Path::new(path), elfinspector::DEFAULT_MAX_SIZE)
}

pub fn run(argv: &[String], g: &Global) -> Result<i32> {
    let Some((cmd, rest)) = argv.split_first() else {
        println!("{HELP}");
        return Ok(2);
    };
    let mut out = Out::open(g.output.as_deref(), g.json, g.min.unwrap_or(Severity::Info))?;
    let code = match cmd.as_str() {
        "info" => info(rest, &mut out)?,
        "checksec" => checksec(rest, &mut out, g)?,
        "symbols" => symbols(rest, &mut out)?,
        "relocs" => relocs(rest, &mut out)?,
        "help" | "--help" | "-h" => {
            out.line(HELP)?;
            0
        }
        other => {
            return Err(Error::usage(format!(
                "unknown elf command {other:?}\n\n{HELP}"
            )));
        }
    };
    out.flush()?;
    Ok(code)
}

fn one_file(rest: &[String], specs: &[args::Spec]) -> Result<(args::Parsed, String)> {
    let p = args::parse(rest, specs, 1)?;
    let file = p
        .positional
        .first()
        .cloned()
        .ok_or_else(|| Error::usage("missing FILE"))?;
    Ok((p, file))
}

fn info(rest: &[String], out: &mut Out) -> Result<i32> {
    let (_, file) = one_file(rest, &[])?;
    let data = load(&file)?;
    let bin = Binary::parse(&data)?;
    if out.json {
        let mut v = report::info(&bin);
        if let Value::Object(pairs) = &mut v {
            pairs.insert(0, ("path".into(), file.clone().into()));
        }
        out.value(&v)?;
        return Ok(0);
    }
    let elf = &bin.elf;
    let h = &elf.header;
    let class = match h.class {
        elfinspector::reader::Class::Elf32 => "ELF32",
        elfinspector::reader::Class::Elf64 => "ELF64",
    };
    let endian = match h.endian {
        elfinspector::reader::Endian::Little => "little-endian",
        elfinspector::reader::Endian::Big => "big-endian",
    };
    out.line(&format!(
        "{}: {class} {endian} {} {} (os/abi {})",
        text::from_bytes(file.as_bytes()),
        h.kind_name(),
        h.machine_name(),
        h.os_abi
    ))?;
    let mut kv: Vec<(String, String)> = vec![("entry".into(), format!("{:#x}", h.entry))];
    if let Some(i) = elf.interpreter() {
        kv.push(("interpreter".into(), i));
    }
    if let Some(d) = &bin.dynamic {
        if !d.needed.is_empty() {
            kv.push(("needed".into(), d.needed.join(", ")));
        }
        if let Some(s) = &d.soname {
            kv.push(("soname".into(), s.clone()));
        }
        if !d.rpath.is_empty() {
            kv.push(("rpath".into(), d.rpath.join(":")));
        }
        if !d.runpath.is_empty() {
            kv.push(("runpath".into(), d.runpath.join(":")));
        }
    }
    if let Some(b) = elfinspector::notes::build_id(&bin.notes) {
        kv.push(("build-id".into(), b));
    }
    kv.push((
        "symbols".into(),
        format!(
            "{} in .symtab, {} in .dynsym",
            bin.symtab.len(),
            bin.dynsyms.len()
        ),
    ));
    for (k, v) in kv {
        out.line(&format!("{k:<12}{v}"))?;
    }
    if !elf.segments.is_empty() {
        out.line("")?;
        out.line("program headers")?;
        let rows: Vec<Vec<String>> = elf
            .segments
            .iter()
            .map(|s| {
                vec![
                    s.index.to_string(),
                    s.type_name(),
                    s.flags_string(),
                    format!("{:#x}", s.offset),
                    format!("{:#x}", s.vaddr),
                    format!("{:#x}", s.filesz),
                    format!("{:#x}", s.memsz),
                    format!("{:#x}", s.align),
                ]
            })
            .collect();
        for l in table(
            &[
                "idx", "type", "flags", "offset", "vaddr", "filesz", "memsz", "align",
            ],
            &rows,
        ) {
            out.line(&format!("  {l}"))?;
        }
    }
    if !elf.sections.is_empty() {
        out.line("")?;
        out.line("section headers")?;
        let rows: Vec<Vec<String>> = elf
            .sections
            .iter()
            .map(|s| {
                vec![
                    s.index.to_string(),
                    s.name.clone(),
                    s.type_name(),
                    s.flags_string(),
                    format!("{:#x}", s.addr),
                    format!("{:#x}", s.offset),
                    format!("{:#x}", s.size),
                ]
            })
            .collect();
        for l in table(
            &["idx", "name", "type", "flags", "addr", "offset", "size"],
            &rows,
        ) {
            out.line(&format!("  {l}"))?;
        }
    }
    if let Some(d) = &bin.dynamic {
        out.line("")?;
        out.line(&format!("dynamic ({})", d.source))?;
        let mut strs = d.strings();
        let rows: Vec<Vec<String>> = d
            .entries
            .iter()
            .map(|e| {
                let v = e
                    .is_string()
                    .then(|| strs.get(e.val))
                    .flatten()
                    .map_or_else(|| format!("{:#x}", e.val), text::from_bytes);
                vec![e.tag_name(), v]
            })
            .collect();
        for l in table(&["tag", "value"], &rows) {
            out.line(&format!("  {l}"))?;
        }
    }
    if !bin.notes.is_empty() {
        out.line("")?;
        out.line("notes")?;
        let rows: Vec<Vec<String>> = bin
            .notes
            .iter()
            .map(|n| {
                vec![
                    n.owner.clone(),
                    n.kind.to_string(),
                    n.desc.len().to_string(),
                ]
            })
            .collect();
        for l in table(&["owner", "type", "size"], &rows) {
            out.line(&format!("  {l}"))?;
        }
    }
    if !elf.warnings.is_empty() {
        out.line("")?;
        out.line("warnings")?;
        for w in &elf.warnings {
            out.line(&format!("  {w}"))?;
        }
    }
    Ok(0)
}

fn tri(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "n/a",
    }
}

pub fn summary_row(path: &str, c: &Checksec, setuid: bool) -> Vec<String> {
    let pie = match c.kind {
        Kind::Pie | Kind::StaticPie => "yes",
        Kind::Executable => "no",
        _ => "n/a",
    };
    let fortify = if !c.fortify_applicable {
        "n/a".to_owned()
    } else {
        format!(
            "{}/{}",
            c.fortified.len(),
            c.fortified.len() + c.fortifiable.len()
        )
    };
    let cfi = match (c.ibt, c.shstk, c.bti, c.pac) {
        (Some(i), Some(s), _, _) => format!("ibt:{} shstk:{}", tri(Some(i)), tri(Some(s))),
        (_, _, Some(b), Some(p)) => format!("bti:{} pac:{}", tri(Some(b)), tri(Some(p))),
        _ => "n/a".into(),
    };
    let rpath = if c.rpath.is_empty() && c.runpath.is_empty() {
        "-".to_owned()
    } else {
        [c.rpath.as_slice(), c.runpath.as_slice()]
            .concat()
            .join(":")
    };
    vec![
        format!("{path}{}", if setuid { " [suid]" } else { "" }),
        c.kind.as_str().into(),
        report::nx_str(c.nx).into(),
        pie.into(),
        report::relro_str(c.relro).into(),
        report::canary_str(c.canary).into(),
        fortify,
        cfi,
        rpath,
    ]
}

pub const SUMMARY_HEADERS: [&str; 9] = [
    "file", "kind", "nx", "pie", "relro", "canary", "fortify", "cfi", "rpath",
];

fn checksec(rest: &[String], out: &mut Out, g: &Global) -> Result<i32> {
    let p = args::parse(rest, &[flag("setuid")], usize::MAX)?;
    if p.positional.is_empty() {
        return Err(Error::usage("missing FILE"));
    }
    let mut rows = Vec::new();
    let mut blocks = Vec::new();
    let mut json_files = Vec::new();
    let mut worst: Option<Severity> = None;
    let mut failed = false;
    for path in &p.positional {
        let shown = text::from_bytes(path.as_bytes());
        let setuid = p.flag("setuid")
            || std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o6000 != 0);
        let result = load(path).and_then(|data| {
            let bin = Binary::parse(&data)?;
            let c = bin.checksec();
            let findings = c.findings(&Context {
                setuid,
                host_paths: true,
            });
            Ok((c, findings, bin.elf.warnings.clone()))
        });
        match result {
            Ok((c, findings, warnings)) => {
                worst = worst.max(findings.iter().map(|f| f.severity).max());
                let shown_findings: Vec<_> = findings
                    .into_iter()
                    .filter(|f| f.severity >= out.min)
                    .collect();
                if out.json {
                    json_files.push(json::obj([
                        ("path", shown.clone().into()),
                        ("setuid", setuid.into()),
                        ("checksec", report::checksec(&c)),
                        (
                            "findings",
                            Value::Array(shown_findings.iter().map(|f| f.to_json()).collect()),
                        ),
                        ("warnings", warnings.into()),
                    ]));
                } else {
                    rows.push(summary_row(&shown, &c, setuid));
                    if !shown_findings.is_empty() || !warnings.is_empty() {
                        let mut lines = vec![shown.clone()];
                        for f in &shown_findings {
                            lines.extend(finding_lines(f, "  "));
                        }
                        for w in warnings {
                            lines.push(format!("  [warning] {w}"));
                        }
                        blocks.push(lines);
                    }
                }
            }
            Err(e) => {
                failed = true;
                if out.json {
                    json_files.push(json::obj([
                        ("path", shown.into()),
                        ("error", e.to_string().into()),
                    ]));
                } else {
                    eprintln!("vantage: {shown}: {e}");
                }
            }
        }
    }
    if out.json {
        out.value(&json::obj([("files", Value::Array(json_files))]))?;
    } else {
        for l in table(&SUMMARY_HEADERS, &rows) {
            out.line(&l)?;
        }
        for b in blocks {
            out.line("")?;
            for l in b {
                out.line(&l)?;
            }
        }
    }
    if failed {
        return Ok(3);
    }
    Ok(match (g.fail_on, worst) {
        (Some(t), Some(w)) if w >= t => 1,
        _ => 0,
    })
}

fn sym_cells(s: &Symbol) -> [String; 6] {
    [
        format!("{:#x}", s.value),
        s.size.to_string(),
        s.kind_name().into(),
        s.bind_name().into(),
        s.visibility_name().into(),
        s.shndx_name(),
    ]
}

fn parse_addr(s: &str) -> Result<u64> {
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    r.map_err(|_| Error::usage(format!("invalid address {s:?}")))
}

fn symbols(rest: &[String], out: &mut Out) -> Result<i32> {
    let (p, file) = one_file(
        rest,
        &[
            flag("dynamic"),
            flag("static"),
            flag("imports"),
            flag("exports"),
            args::opt("grep"),
            multi("lookup"),
        ],
    )?;
    let data = load(&file)?;
    let bin = Binary::parse(&data)?;
    if !p.values("lookup").is_empty() {
        let idx = bin.address_index();
        let mut results = Vec::new();
        for a in p.values("lookup") {
            let addr = parse_addr(a)?;
            let hit = idx.resolve(addr).map(|(s, off)| {
                if off == 0 {
                    s.display_name()
                } else {
                    format!("{}+{off:#x}", s.display_name())
                }
            });
            results.push((addr, hit));
        }
        if out.json {
            out.value(&Value::Array(
                results
                    .into_iter()
                    .map(|(a, h)| {
                        json::obj([("address", format!("{a:#x}").into()), ("symbol", h.into())])
                    })
                    .collect(),
            ))?;
        } else {
            for (a, h) in results {
                out.line(&format!("{a:#018x}  {}", h.as_deref().unwrap_or("??")))?;
            }
        }
        return Ok(0);
    }
    let grep = p.value("grep");
    let mut sel: Vec<&Symbol> = Vec::new();
    let want_static = !p.flag("dynamic") && !p.flag("imports") && !p.flag("exports");
    let want_dynamic = !p.flag("static");
    if want_dynamic {
        sel.extend(bin.dynsyms.iter().filter(|s| {
            s.index != 0
                && (!p.flag("imports") || s.is_undefined())
                && (!p.flag("exports") || s.is_export())
        }));
    }
    if want_static {
        sel.extend(bin.symtab.iter().filter(|s| s.index != 0));
    }
    if let Some(g) = grep {
        sel.retain(|s| s.name.contains(g));
    }
    if out.json {
        out.array(sel.iter().map(|s| report::symbol(s)))?;
        return Ok(0);
    }
    let headers = ["value", "size", "type", "bind", "vis", "ndx", "name"];
    for group in sel.chunk_by(|a, b| a.table == b.table) {
        let width = render::widths(&headers, group.iter().map(|s| sym_cells(s)));
        out.line(&format!(
            "{} ({} symbols)",
            group[0].table.as_str(),
            group.len()
        ))?;
        out.line(&format!("  {}", render::row(&width, &headers)))?;
        for s in group {
            let [value, size, kind, bind, vis, ndx] = sym_cells(s);
            let cells = [value, size, kind, bind, vis, ndx, s.display_name()];
            out.line(&format!("  {}", render::row(&width, &cells)))?;
        }
        out.line("")?;
    }
    Ok(0)
}

fn relocs(rest: &[String], out: &mut Out) -> Result<i32> {
    let (_, file) = one_file(rest, &[])?;
    let data = load(&file)?;
    let mut bin = Binary::parse(&data)?;
    let machine = bin.elf.header.machine;
    let relocs = bin.relocations();
    if out.json {
        out.array(relocs.iter().map(|r| report::relocation(r, machine)))?;
        return Ok(0);
    }
    let headers = ["table", "offset", "type", "symbol/addend"];
    let cells = |r: &Relocation| {
        [
            r.table.to_string(),
            format!("{:#x}", r.offset),
            r.type_name(machine),
        ]
    };
    let width = render::widths(&headers, relocs.iter().map(cells));
    out.line(&render::row(&width, &headers))?;
    for r in &relocs {
        let target = match (&r.symbol, r.addend) {
            (Some(s), Some(a)) if a != 0 => format!("{s} {a:+#x}"),
            (Some(s), _) => s.to_string(),
            (None, Some(a)) => format!("{a:#x}"),
            (None, None) => String::new(),
        };
        let [table, offset, kind] = cells(r);
        out.line(&render::row(&width, &[table, offset, kind, target]))?;
    }
    for w in &bin.elf.warnings {
        eprintln!("vantage: warning: {w}");
    }
    Ok(0)
}
