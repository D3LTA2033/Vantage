pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_NULL: u32 = 0;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_RELR: u32 = 19;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;

pub const SHN_UNDEF: u32 = 0;
pub const SHN_LORESERVE: u32 = 0xff00;
pub const SHN_ABS: u32 = 0xfff1;
pub const SHN_COMMON: u32 = 0xfff2;
pub const SHN_XINDEX: u32 = 0xffff;
pub const PN_XNUM: u16 = 0xffff;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_GNU_UNIQUE: u8 = 10;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_RELRSZ: i64 = 35;
pub const DT_RELR: i64 = 36;
pub const DT_RELRENT: i64 = 37;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;
pub const DT_VERSYM: i64 = 0x6fff_fff0;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;
pub const DT_VERDEF: i64 = 0x6fff_fffc;
pub const DT_VERDEFNUM: i64 = 0x6fff_fffd;
pub const DT_VERNEED: i64 = 0x6fff_fffe;
pub const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

pub const DF_TEXTREL: u64 = 0x4;
pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_1_NOW: u64 = 0x1;
pub const DF_1_PIE: u64 = 0x0800_0000;

pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
pub const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1;
pub const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 2;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 2;

pub const VERSYM_HIDDEN: u16 = 0x8000;
pub const VERSYM_VERSION: u16 = 0x7fff;
