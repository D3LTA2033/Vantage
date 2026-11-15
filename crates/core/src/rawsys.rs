use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[cfg(target_arch = "x86_64")]
unsafe fn syscall6(nr: libc::c_long, a: [usize; 6]) -> isize {
    let ret: isize;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a[0],
            in("rsi") a[1],
            in("rdx") a[2],
            in("r10") a[3],
            in("r8") a[4],
            in("r9") a[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
unsafe fn syscall6(nr: libc::c_long, a: [usize; 6]) -> isize {
    let ret: isize;
    unsafe {
        std::arch::asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a[0] as isize => ret,
            in("x1") a[1],
            in("x2") a[2],
            in("x3") a[3],
            in("x4") a[4],
            in("x5") a[5],
            options(nostack),
        );
    }
    ret
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn syscall6(nr: libc::c_long, a: [usize; 6]) -> isize {
    let r = unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    if r == -1 {
        -(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO) as isize)
    } else {
        r as isize
    }
}

pub const fn is_direct() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

fn check(ret: isize) -> io::Result<usize> {
    if (-4095..0).contains(&ret) {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as usize)
    }
}

#[derive(Debug)]
pub struct Fd(i32);

impl Fd {
    pub fn open(path: &Path) -> io::Result<Fd> {
        Self::open_flags(path, libc::O_RDONLY)
    }

    pub fn open_dir(path: &Path) -> io::Result<Fd> {
        Self::open_flags(path, libc::O_RDONLY | libc::O_DIRECTORY)
    }

    fn open_flags(path: &Path, flags: i32) -> io::Result<Fd> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let flags = (flags | libc::O_CLOEXEC | libc::O_NOCTTY) as usize;
        let ret = unsafe {
            syscall6(
                libc::SYS_openat,
                [libc::AT_FDCWD as usize, c.as_ptr() as usize, flags, 0, 0, 0],
            )
        };
        check(ret).map(|fd| Fd(fd as i32))
    }

    pub fn raw(&self) -> i32 {
        self.0
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            syscall6(
                libc::SYS_read,
                [
                    self.0 as usize,
                    buf.as_mut_ptr() as usize,
                    buf.len(),
                    0,
                    0,
                    0,
                ],
            )
        };
        check(ret)
    }

    #[cfg(target_pointer_width = "64")]
    pub fn pread(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let ret = unsafe {
            syscall6(
                libc::SYS_pread64,
                [
                    self.0 as usize,
                    buf.as_mut_ptr() as usize,
                    buf.len(),
                    offset as usize,
                    0,
                    0,
                ],
            )
        };
        check(ret)
    }

    #[cfg(not(target_pointer_width = "64"))]
    pub fn pread(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let offset =
            i64::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let ret = unsafe { libc::pread64(self.0, buf.as_mut_ptr().cast(), buf.len(), offset) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    pub fn getdents64(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            syscall6(
                libc::SYS_getdents64,
                [
                    self.0 as usize,
                    buf.as_mut_ptr() as usize,
                    buf.len(),
                    0,
                    0,
                    0,
                ],
            )
        };
        check(ret)
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe {
            syscall6(libc::SYS_close, [self.0 as usize, 0, 0, 0, 0, 0]);
        }
    }
}

pub fn read_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let fd = Fd::open(path)?;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = match fd.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file larger than {limit} bytes"),
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub kind: u8,
    pub name: Vec<u8>,
}

pub fn read_dir(path: &Path) -> io::Result<Vec<DirEntry>> {
    let fd = Fd::open_dir(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::new();
    loop {
        let n = match fd.getdents64(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(out);
        }
        parse_dirents(&buf[..n], &mut out)?;
    }
}

pub fn parse_dirents(buf: &[u8], out: &mut Vec<DirEntry>) -> io::Result<()> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed linux_dirent64");
    let mut off = 0usize;
    while off < buf.len() {
        let rec = buf.get(off..off + 19).ok_or_else(bad)?;
        let ino = u64::from_ne_bytes(rec[0..8].try_into().map_err(|_| bad())?);
        let reclen = u16::from_ne_bytes([rec[16], rec[17]]) as usize;
        let kind = rec[18];
        if reclen < 20 {
            return Err(bad());
        }
        let record = buf.get(off..off + reclen).ok_or_else(bad)?;
        let name_bytes = &record[19..];
        let end = name_bytes.iter().position(|&b| b == 0).ok_or_else(bad)?;
        let name = &name_bytes[..end];
        if name != b"." && name != b".." {
            out.push(DirEntry {
                ino,
                kind,
                name: name.to_vec(),
            });
        }
        off += reclen;
    }
    Ok(())
}

pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
    let ret = unsafe { syscall6(libc::SYS_kill, [pid as usize, sig as usize, 0, 0, 0, 0]) };
    check(ret).map(|_| ())
}

pub fn getpgid(pid: i32) -> io::Result<i32> {
    let ret = unsafe { syscall6(libc::SYS_getpgid, [pid as usize, 0, 0, 0, 0, 0]) };
    check(ret).map(|v| v as i32)
}

pub fn getsid(pid: i32) -> io::Result<i32> {
    let ret = unsafe { syscall6(libc::SYS_getsid, [pid as usize, 0, 0, 0, 0, 0]) };
    check(ret).map(|v| v as i32)
}

pub fn pid_exists(pid: i32) -> bool {
    match kill(pid, 0) {
        Ok(()) => true,
        Err(e) => e.raw_os_error() == Some(libc::EPERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn raw_read_matches_std() {
        let status = read_file(Path::new("/proc/self/status"), 1 << 20).unwrap();
        assert!(status.starts_with(b"Name:"));
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert_eq!(
            read_file(&path, 1 << 20).unwrap(),
            std::fs::read(&path).unwrap()
        );
    }

    #[test]
    fn read_limit_enforced() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/syscalls.rs");
        assert!(read_file(&p, 16).is_err());
    }

    #[test]
    fn raw_readdir_matches_std() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let raw: BTreeSet<Vec<u8>> = read_dir(&dir)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        let std: BTreeSet<Vec<u8>> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().as_bytes().to_vec())
            .collect();
        assert_eq!(raw, std);
    }

    #[test]
    fn errors_are_errno() {
        let e = Fd::open(Path::new("/nonexistent/vantage")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
        let e = read_dir(Path::new("/proc/self/status")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR));
    }

    #[test]
    fn process_probes() {
        let me = std::process::id() as i32;
        assert!(pid_exists(me));
        assert_eq!(getsid(me).unwrap(), unsafe { libc::getsid(0) });
        assert_eq!(getpgid(me).unwrap(), unsafe { libc::getpgid(0) });
        assert!(!pid_exists(i32::MAX));
    }

    #[test]
    fn dirent_parser_rejects_bad_records() {
        let mut out = Vec::new();
        assert!(parse_dirents(&[0u8; 10], &mut out).is_err());
        let mut rec = vec![0u8; 24];
        rec[16] = 24;
        rec[19] = b'a';
        rec[20] = b'b';
        assert!(parse_dirents(&rec, &mut out).is_ok());
        assert_eq!(out[0].name, b"ab");
        rec[16] = 200;
        assert!(parse_dirents(&rec, &mut Vec::new()).is_err());
        let mut no_nul = vec![1u8; 24];
        no_nul[16] = 24;
        no_nul[17] = 0;
        assert!(parse_dirents(&no_nul, &mut Vec::new()).is_err());
    }
}
