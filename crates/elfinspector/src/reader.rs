use vantage_core::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

impl Class {
    pub fn word_size(self) -> u64 {
        match self {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub endian: Endian,
    pub class: Class,
}

impl<'a> Reader<'a> {
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn bytes(&self, off: u64, len: u64) -> Result<&'a [u8]> {
        let end = off
            .checked_add(len)
            .ok_or_else(|| Error::parse(format!("offset overflow at {off:#x}+{len:#x}")))?;
        if end > self.len() {
            return Err(Error::parse(format!(
                "truncated: need {len:#x} bytes at {off:#x}, file is {:#x}",
                self.len()
            )));
        }
        Ok(&self.data[off as usize..end as usize])
    }

    fn array<const N: usize>(&self, off: u64) -> Result<[u8; N]> {
        let b = self.bytes(off, N as u64)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn u8(&self, off: u64) -> Result<u8> {
        Ok(self.array::<1>(off)?[0])
    }

    pub fn u16(&self, off: u64) -> Result<u16> {
        let a = self.array(off)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(a),
            Endian::Big => u16::from_be_bytes(a),
        })
    }

    pub fn u32(&self, off: u64) -> Result<u32> {
        let a = self.array(off)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(a),
            Endian::Big => u32::from_be_bytes(a),
        })
    }

    pub fn u64(&self, off: u64) -> Result<u64> {
        let a = self.array(off)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(a),
            Endian::Big => u64::from_be_bytes(a),
        })
    }

    pub fn word(&self, off: u64) -> Result<u64> {
        match self.class {
            Class::Elf32 => self.u32(off).map(u64::from),
            Class::Elf64 => self.u64(off),
        }
    }

    pub fn sword(&self, off: u64) -> Result<i64> {
        match self.class {
            Class::Elf32 => self.u32(off).map(|v| i64::from(v as i32)),
            Class::Elf64 => self.u64(off).map(|v| v as i64),
        }
    }

    pub fn word_size(&self) -> u64 {
        self.class.word_size()
    }

    pub fn with_data(&self, data: &'a [u8]) -> Reader<'a> {
        Reader {
            data,
            endian: self.endian,
            class: self.class,
        }
    }
}

pub fn cstr_at(table: &[u8], off: u64) -> Option<&[u8]> {
    let start = usize::try_from(off).ok()?;
    let rest = table.get(start..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endianness() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let le = Reader {
            data: &data,
            endian: Endian::Little,
            class: Class::Elf64,
        };
        let be = Reader {
            endian: Endian::Big,
            ..le
        };
        assert_eq!(le.u16(0).unwrap(), 0x0201);
        assert_eq!(be.u16(0).unwrap(), 0x0102);
        assert_eq!(le.u32(4).unwrap(), 0x0807_0605);
        assert_eq!(be.u64(0).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(
            Reader {
                class: Class::Elf32,
                ..be
            }
            .word(0)
            .unwrap(),
            0x0102_0304
        );
    }

    #[test]
    fn bounds() {
        let data = [0u8; 4];
        let r = Reader {
            data: &data,
            endian: Endian::Little,
            class: Class::Elf32,
        };
        assert!(r.u32(0).is_ok());
        assert!(r.u32(1).is_err());
        assert!(r.u64(0).is_err());
        assert!(r.bytes(u64::MAX, 2).is_err());
        assert!(r.bytes(4, 0).is_ok());
        assert!(r.bytes(5, 0).is_err());
    }

    #[test]
    fn cstr() {
        let t = b"\0libc.so.6\0abc";
        assert_eq!(cstr_at(t, 1), Some(&b"libc.so.6"[..]));
        assert_eq!(cstr_at(t, 0), Some(&b""[..]));
        assert_eq!(cstr_at(t, 11), None);
        assert_eq!(cstr_at(t, 100), None);
    }
}
