use crate::Binary;
use crate::consts::*;
use crate::notes::gnu_properties;
use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use vantage_core::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Relocatable,
    Executable,
    Pie,
    StaticPie,
    SharedObject,
    Core,
    Other,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Relocatable => "relocatable",
            Kind::Executable => "executable",
            Kind::Pie => "pie-executable",
            Kind::StaticPie => "static-pie-executable",
            Kind::SharedObject => "shared-object",
            Kind::Core => "core",
            Kind::Other => "other",
        }
    }

    fn is_program(self) -> bool {
        matches!(self, Kind::Executable | Kind::Pie | Kind::StaticPie)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nx {
    Enabled,
    Disabled,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relro {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canary {
    Imported,
    Defined,
    NotFound,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Ok,
    NotApplicable,
    OutsideLoad,
    NonExecutable,
    Writable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksec {
    pub kind: Kind,
    pub nx: Nx,
    pub relro: Option<Relro>,
    pub canary: Canary,
    pub fortify_applicable: bool,
    pub fortified: Vec<String>,
    pub fortifiable: Vec<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub textrel: bool,
    pub wx_segments: Vec<usize>,
    pub wx_sections: Vec<String>,
    pub ibt: Option<bool>,
    pub shstk: Option<bool>,
    pub bti: Option<bool>,
    pub pac: Option<bool>,
    pub stripped: bool,
    pub static_linked: bool,
    pub interpreter: Option<String>,
    pub build_id: Option<String>,
    pub entry: Entry,
    pub packer: Option<String>,
}

const CANARY_SYMBOLS: [&str; 4] = [
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__stack_chk_guard",
    "__intel_security_cookie",
];

pub const FORTIFY: [(&str, &str); 72] = [
    ("memcpy", "__memcpy_chk"),
    ("memmove", "__memmove_chk"),
    ("mempcpy", "__mempcpy_chk"),
    ("memset", "__memset_chk"),
    ("stpcpy", "__stpcpy_chk"),
    ("stpncpy", "__stpncpy_chk"),
    ("strcat", "__strcat_chk"),
    ("strcpy", "__strcpy_chk"),
    ("strncat", "__strncat_chk"),
    ("strncpy", "__strncpy_chk"),
    ("strlcpy", "__strlcpy_chk"),
    ("strlcat", "__strlcat_chk"),
    ("sprintf", "__sprintf_chk"),
    ("snprintf", "__snprintf_chk"),
    ("vsprintf", "__vsprintf_chk"),
    ("vsnprintf", "__vsnprintf_chk"),
    ("printf", "__printf_chk"),
    ("fprintf", "__fprintf_chk"),
    ("dprintf", "__dprintf_chk"),
    ("vprintf", "__vprintf_chk"),
    ("vfprintf", "__vfprintf_chk"),
    ("vdprintf", "__vdprintf_chk"),
    ("asprintf", "__asprintf_chk"),
    ("vasprintf", "__vasprintf_chk"),
    ("obstack_printf", "__obstack_printf_chk"),
    ("obstack_vprintf", "__obstack_vprintf_chk"),
    ("syslog", "__syslog_chk"),
    ("vsyslog", "__vsyslog_chk"),
    ("gets", "__gets_chk"),
    ("fgets", "__fgets_chk"),
    ("fgets_unlocked", "__fgets_unlocked_chk"),
    ("fread", "__fread_chk"),
    ("fread_unlocked", "__fread_unlocked_chk"),
    ("read", "__read_chk"),
    ("pread", "__pread_chk"),
    ("pread64", "__pread64_chk"),
    ("readlink", "__readlink_chk"),
    ("readlinkat", "__readlinkat_chk"),
    ("getcwd", "__getcwd_chk"),
    ("getwd", "__getwd_chk"),
    ("realpath", "__realpath_chk"),
    ("recv", "__recv_chk"),
    ("recvfrom", "__recvfrom_chk"),
    ("confstr", "__confstr_chk"),
    ("getgroups", "__getgroups_chk"),
    ("ttyname_r", "__ttyname_r_chk"),
    ("getlogin_r", "__getlogin_r_chk"),
    ("gethostname", "__gethostname_chk"),
    ("getdomainname", "__getdomainname_chk"),
    ("ptsname_r", "__ptsname_r_chk"),
    ("wctomb", "__wctomb_chk"),
    ("wcrtomb", "__wcrtomb_chk"),
    ("mbstowcs", "__mbstowcs_chk"),
    ("wcstombs", "__wcstombs_chk"),
    ("mbsrtowcs", "__mbsrtowcs_chk"),
    ("wcsrtombs", "__wcsrtombs_chk"),
    ("wcscpy", "__wcscpy_chk"),
    ("wcsncpy", "__wcsncpy_chk"),
    ("wcscat", "__wcscat_chk"),
    ("wcsncat", "__wcsncat_chk"),
    ("wmemcpy", "__wmemcpy_chk"),
    ("wmemmove", "__wmemmove_chk"),
    ("wmemset", "__wmemset_chk"),
    ("poll", "__poll_chk"),
    ("ppoll", "__ppoll_chk"),
    ("explicit_bzero", "__explicit_bzero_chk"),
    ("longjmp", "__longjmp_chk"),
    ("siglongjmp", "__longjmp_chk"),
    ("open", "__open_2"),
    ("open64", "__open64_2"),
    ("openat", "__openat_2"),
    ("openat64", "__openat64_2"),
];

impl Checksec {
    pub fn analyze(bin: &Binary<'_>) -> Checksec {
        let elf = &bin.elf;
        let h = &elf.header;
        let interpreter = elf.interpreter();
        let flags_1 = bin.dynamic.as_ref().map_or(0, |d| d.flags_1);
        let kind = match h.kind {
            ET_REL => Kind::Relocatable,
            ET_EXEC => Kind::Executable,
            ET_CORE => Kind::Core,
            ET_DYN if flags_1 & DF_1_PIE != 0 && interpreter.is_none() => Kind::StaticPie,
            ET_DYN if flags_1 & DF_1_PIE != 0 => Kind::Pie,
            ET_DYN
                if interpreter.is_some()
                    && bin.dynamic.as_ref().is_none_or(|d| d.soname.is_none()) =>
            {
                Kind::Pie
            }
            ET_DYN => Kind::SharedObject,
            _ => Kind::Other,
        };

        let nx = if kind == Kind::Relocatable {
            match elf.section_by_name(".note.GNU-stack") {
                Some(s) if s.flags & SHF_EXECINSTR != 0 => Nx::Disabled,
                Some(_) => Nx::Enabled,
                None => Nx::Missing,
            }
        } else {
            match elf.segment(PT_GNU_STACK) {
                Some(s) if s.flags & PF_X != 0 => Nx::Disabled,
                Some(_) => Nx::Enabled,
                None => Nx::Missing,
            }
        };

        let relro = match kind {
            Kind::Relocatable | Kind::Core | Kind::Other => None,
            _ if elf.segment(PT_GNU_RELRO).is_none() => Some(Relro::None),
            _ if bin.dynamic.as_ref().is_some_and(|d| d.bind_now()) => Some(Relro::Full),
            _ if bin.dynamic.is_none() => Some(Relro::Full),
            _ => Some(Relro::Partial),
        };

        let all_syms = || bin.dynsyms.iter().chain(bin.symtab.iter());
        let stripped = !elf.sections.iter().any(|s| s.kind == SHT_SYMTAB);
        let needed = bin.dynamic.as_ref().is_some_and(|d| !d.needed.is_empty());
        let static_linked = kind.is_program() && interpreter.is_none() && !needed;

        let canary_hits: Vec<_> = all_syms()
            .filter(|s| CANARY_SYMBOLS.contains(&s.name.as_str()))
            .collect();
        let canary = if canary_hits.iter().any(|s| s.is_undefined()) {
            Canary::Imported
        } else if !canary_hits.is_empty() {
            Canary::Defined
        } else if stripped && bin.dynsyms.is_empty() {
            Canary::Unknown
        } else {
            Canary::NotFound
        };

        let imports: BTreeSet<&str> = all_syms()
            .filter(|s| s.is_undefined())
            .map(|s| s.name.as_str())
            .collect();
        let fortify_applicable = !static_linked && kind != Kind::Core;
        let mut fortified = BTreeSet::new();
        let mut fortifiable = BTreeSet::new();
        for (base, chk) in FORTIFY {
            if imports.contains(chk) {
                fortified.insert(chk.to_owned());
            }
            if imports.contains(base) && !imports.contains(chk) {
                fortifiable.insert(base.to_owned());
            }
        }

        let wx_segments = elf
            .segments_of(PT_LOAD)
            .filter(|s| s.flags & PF_W != 0 && s.flags & PF_X != 0)
            .map(|s| s.index)
            .collect();
        let wx_sections = elf
            .sections
            .iter()
            .filter(|s| {
                s.flags & (SHF_WRITE | SHF_EXECINSTR | SHF_ALLOC)
                    == SHF_WRITE | SHF_EXECINSTR | SHF_ALLOC
            })
            .map(|s| s.name.clone())
            .collect();

        let props = gnu_properties(&elf.r, &bin.notes);
        let (mut ibt, mut shstk, mut bti, mut pac) = (None, None, None, None);
        match h.machine {
            EM_X86_64 | EM_386 => {
                let f = props.x86_feature_1.unwrap_or(0);
                ibt = Some(f & GNU_PROPERTY_X86_FEATURE_1_IBT != 0);
                shstk = Some(f & GNU_PROPERTY_X86_FEATURE_1_SHSTK != 0);
            }
            EM_AARCH64 => {
                let f = props.aarch64_feature_1.unwrap_or(0);
                bti = Some(f & GNU_PROPERTY_AARCH64_FEATURE_1_BTI != 0);
                pac = Some(f & GNU_PROPERTY_AARCH64_FEATURE_1_PAC != 0);
            }
            _ => {}
        }

        let entry = if !kind.is_program() || h.entry == 0 {
            Entry::NotApplicable
        } else {
            match elf.load_segment_at(h.entry) {
                None => Entry::OutsideLoad,
                Some(s) if s.flags & PF_X == 0 => Entry::NonExecutable,
                Some(s) if s.flags & PF_W != 0 => Entry::Writable,
                Some(_) => Entry::Ok,
            }
        };

        let head = &elf.r.data[..elf.r.data.len().min(4096)];
        let upx_sections = elf
            .sections
            .iter()
            .any(|s| s.name == "UPX0" || s.name == "UPX1");
        let packer =
            (upx_sections || head.windows(4).any(|w| w == b"UPX!")).then(|| "UPX".to_owned());

        let (rpath, runpath, textrel) = match &bin.dynamic {
            Some(d) => (d.rpath.clone(), d.runpath.clone(), d.textrel()),
            None => (Vec::new(), Vec::new(), false),
        };

        Checksec {
            kind,
            nx,
            relro,
            canary,
            fortify_applicable,
            fortified: fortified.into_iter().collect(),
            fortifiable: fortifiable.into_iter().collect(),
            rpath,
            runpath,
            textrel,
            wx_segments,
            wx_sections,
            ibt,
            shstk,
            bti,
            pac,
            stripped,
            static_linked,
            interpreter,
            build_id: crate::notes::build_id(&bin.notes),
            entry,
            packer,
        }
    }

    pub fn findings(&self, ctx: &Context) -> Vec<Finding> {
        let mut out = Vec::new();
        let raise = |s: Severity| {
            if ctx.setuid {
                match s {
                    Severity::Info => Severity::Info,
                    Severity::Low => Severity::Medium,
                    Severity::Medium => Severity::High,
                    _ => Severity::Critical,
                }
            } else {
                s
            }
        };
        let program_like = self.kind != Kind::Core && self.kind != Kind::Other;

        match self.nx {
            Nx::Disabled => out.push(
                Finding::new(raise(Severity::High), "executable stack requested")
                    .detail("PT_GNU_STACK (or .note.GNU-stack) carries the execute flag, so the stack is mapped executable"),
            ),
            Nx::Missing if program_like => out.push(
                Finding::new(
                    if self.kind == Kind::Relocatable { Severity::Low } else { raise(Severity::Medium) },
                    "no GNU stack marker",
                )
                .detail("without PT_GNU_STACK the stack permissions fall back to the architecture and kernel default, which is executable on several configurations"),
            ),
            _ => {}
        }
        for idx in &self.wx_segments {
            out.push(
                Finding::new(raise(Severity::High), "writable and executable segment")
                    .detail("a PT_LOAD segment is mapped both writable and executable")
                    .evidence("segment", *idx),
            );
        }
        for name in &self.wx_sections {
            out.push(
                Finding::new(Severity::Medium, "writable and executable section")
                    .evidence("section", name.as_str()),
            );
        }
        match self.entry {
            Entry::OutsideLoad => out.push(Finding::new(
                Severity::High,
                "entry point outside loadable segments",
            )),
            Entry::NonExecutable => out.push(Finding::new(
                Severity::High,
                "entry point in non-executable segment",
            )),
            Entry::Writable => out.push(
                Finding::new(Severity::High, "entry point in writable segment")
                    .detail("typical of self-modifying or packed code"),
            ),
            _ => {}
        }
        if self.kind == Kind::Executable {
            out.push(
                Finding::new(raise(Severity::Medium), "not position independent")
                    .detail("ET_EXEC binaries load at a fixed address, so ASLR does not randomize their code"),
            );
        }
        match self.relro {
            Some(Relro::None) => out
                .push(Finding::new(raise(Severity::Medium), "no RELRO").detail(
                "relocation targets including the GOT stay writable for the life of the process",
            )),
            Some(Relro::Partial) => {
                out.push(Finding::new(raise(Severity::Low), "partial RELRO").detail(
                    "lazy binding keeps the PLT GOT writable; link with -z now for full RELRO",
                ))
            }
            _ => {}
        }
        if self.canary == Canary::NotFound && self.kind != Kind::Core {
            out.push(
                Finding::new(raise(Severity::Low), "no stack protector references")
                    .detail("no __stack_chk_fail or guard symbol; either built without -fstack-protector or no function needed one"),
            );
        }
        if self.fortify_applicable && self.fortified.is_empty() && !self.fortifiable.is_empty() {
            out.push(
                Finding::new(raise(Severity::Low), "no FORTIFY_SOURCE")
                    .detail(
                        "imports functions with checked variants but none of the checked variants",
                    )
                    .evidence("fortifiable", self.fortifiable.clone()),
            );
        }
        for (tag, list) in [("DT_RPATH", &self.rpath), ("DT_RUNPATH", &self.runpath)] {
            for p in list {
                let (sev, why) = classify_search_path(p, ctx.host_paths);
                out.push(
                    Finding::new(raise(sev), format!("{tag} entry {p:?}"))
                        .detail(why)
                        .evidence("tag", tag)
                        .evidence("path", p.as_str()),
                );
            }
        }
        if self.textrel {
            out.push(
                Finding::new(raise(Severity::Medium), "text relocations")
                    .detail("the loader must make code pages writable to apply relocations"),
            );
        }
        if let Some(p) = &self.packer {
            out.push(
                Finding::new(Severity::Medium, format!("packed with {p}"))
                    .detail("on-disk code is an unpacking stub; analysis results describe the stub, not the payload"),
            );
        }
        if self.kind.is_program() || self.kind == Kind::SharedObject {
            if self.ibt == Some(false) || self.shstk == Some(false) {
                out.push(
                    Finding::new(Severity::Info, "CET not fully marked")
                        .evidence("ibt", self.ibt.unwrap_or(false))
                        .evidence("shstk", self.shstk.unwrap_or(false)),
                );
            }
            if self.bti == Some(false) || self.pac == Some(false) {
                out.push(
                    Finding::new(Severity::Info, "BTI/PAC not marked")
                        .evidence("bti", self.bti.unwrap_or(false))
                        .evidence("pac", self.pac.unwrap_or(false)),
                );
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    pub setuid: bool,
    pub host_paths: bool,
}

fn classify_search_path(p: &str, host_paths: bool) -> (Severity, String) {
    if p.is_empty() {
        return (
            Severity::Medium,
            "empty component; the loader searches the current working directory".into(),
        );
    }
    if p.starts_with("$ORIGIN") || p.starts_with("${ORIGIN}") {
        return (
            Severity::Low,
            "relative to the binary's own directory; safe only if that directory is not writable by others".into(),
        );
    }
    if !p.starts_with('/') {
        return (
            Severity::Medium,
            "relative path; resolved against the current working directory".into(),
        );
    }
    if host_paths {
        match std::fs::metadata(Path::new(p)) {
            Ok(m) if m.permissions().mode() & 0o002 != 0 => {
                return (
                    Severity::High,
                    "directory is world-writable; any user can plant a library that this binary loads".into(),
                );
            }
            Ok(m) if m.uid() != 0 => {
                return (
                    Severity::Medium,
                    format!(
                        "directory is owned by uid {}, who can plant libraries this binary loads",
                        m.uid()
                    ),
                );
            }
            Ok(_) => return (Severity::Info, "root-owned library search path".into()),
            Err(_) => {
                return (
                    Severity::Low,
                    "directory does not exist; whoever can create it controls library loading"
                        .into(),
                );
            }
        }
    }
    (Severity::Low, "custom library search path".into())
}
