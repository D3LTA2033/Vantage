use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Load {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
}

#[derive(Debug)]
pub struct Kcore {
    file: File,
    pub loads: Vec<Load>,
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

fn u16_at(b: &[u8], off: usize) -> io::Result<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_ne_bytes([s[0], s[1]]))
        .ok_or_else(|| invalid("truncated"))
}

fn u32_at(b: &[u8], off: usize) -> io::Result<u32> {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or_else(|| invalid("truncated"))
}

fn u64_at(b: &[u8], off: usize) -> io::Result<u64> {
    b.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_ne_bytes)
        .ok_or_else(|| invalid("truncated"))
}

pub fn parse_header(ehdr: &[u8]) -> io::Result<(u64, u16, u16)> {
    let native = if cfg!(target_endian = "little") { 1 } else { 2 };
    if ehdr.len() < 64 || &ehdr[..4] != b"\x7fELF" || ehdr[4] != 2 || ehdr[5] != native {
        return Err(invalid("not a native-endian ELF64 core image"));
    }
    if u16_at(ehdr, 16)? != 4 {
        return Err(invalid("not an ET_CORE image"));
    }
    Ok((u64_at(ehdr, 32)?, u16_at(ehdr, 54)?, u16_at(ehdr, 56)?))
}

pub fn parse_loads(phdrs: &[u8], entsize: u16, count: u16) -> io::Result<Vec<Load>> {
    if entsize < 56 {
        return Err(invalid("program header entries too small"));
    }
    let mut out = Vec::new();
    for i in 0..count as usize {
        let base = i * entsize as usize;
        if u32_at(phdrs, base)? != 1 {
            continue;
        }
        out.push(Load {
            offset: u64_at(phdrs, base + 8)?,
            vaddr: u64_at(phdrs, base + 16)?,
            filesz: u64_at(phdrs, base + 32)?,
        });
    }
    Ok(out)
}

impl Kcore {
    pub fn open(path: &Path) -> io::Result<Kcore> {
        let file = File::open(path)?;
        let mut ehdr = [0u8; 64];
        file.read_exact_at(&mut ehdr, 0)?;
        let (phoff, entsize, count) = parse_header(&ehdr)?;
        let mut phdrs = vec![0u8; entsize as usize * count as usize];
        file.read_exact_at(&mut phdrs, phoff)?;
        let loads = parse_loads(&phdrs, entsize, count)?;
        Ok(Kcore { file, loads })
    }

    pub fn translate(&self, vaddr: u64, len: u64) -> Option<u64> {
        self.loads.iter().find_map(|l| {
            let delta = vaddr.checked_sub(l.vaddr)?;
            (delta.checked_add(len)? <= l.filesz).then(|| l.offset + delta)
        })
    }

    pub fn read(&self, vaddr: u64, len: usize) -> io::Result<Vec<u8>> {
        let off = self
            .translate(vaddr, len as u64)
            .ok_or_else(|| invalid("address not covered by any /proc/kcore segment"))?;
        let mut buf = vec![0u8; len];
        self.file.read_exact_at(&mut buf, off)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_core(vaddr: u64, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 64 + 56 * 2];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = if cfg!(target_endian = "little") { 1 } else { 2 };
        f[6] = 1;
        f[16..18].copy_from_slice(&4u16.to_ne_bytes());
        f[32..40].copy_from_slice(&64u64.to_ne_bytes());
        f[54..56].copy_from_slice(&56u16.to_ne_bytes());
        f[56..58].copy_from_slice(&2u16.to_ne_bytes());
        let note = 64;
        f[note..note + 4].copy_from_slice(&4u32.to_ne_bytes());
        let load = 64 + 56;
        let data_off = f.len() as u64;
        f[load..load + 4].copy_from_slice(&1u32.to_ne_bytes());
        f[load + 8..load + 16].copy_from_slice(&data_off.to_ne_bytes());
        f[load + 16..load + 24].copy_from_slice(&vaddr.to_ne_bytes());
        f[load + 32..load + 40].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn reads_through_load_segment() {
        let path = std::env::temp_dir().join(format!("vantage-kcore-{}", std::process::id()));
        let payload: Vec<u8> = (0u8..64).collect();
        std::fs::write(&path, synthetic_core(0xffff_ffff_8200_0000, &payload)).unwrap();
        let k = Kcore::open(&path).unwrap();
        assert_eq!(k.loads.len(), 1);
        assert_eq!(
            k.read(0xffff_ffff_8200_0010, 4).unwrap(),
            vec![16, 17, 18, 19]
        );
        assert!(k.read(0xffff_ffff_8200_003e, 4).is_err());
        assert!(k.read(0x1000, 1).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_non_core() {
        assert!(parse_header(&[0u8; 64]).is_err());
        let mut truncated = [0u8; 10];
        truncated[..4].copy_from_slice(&1u32.to_ne_bytes());
        assert!(parse_loads(&truncated, 56, 1).is_err());
        assert_eq!(parse_loads(&[0u8; 56], 56, 1).unwrap(), vec![]);
        assert!(parse_loads(&[0u8; 56], 32, 1).is_err());
    }
}
