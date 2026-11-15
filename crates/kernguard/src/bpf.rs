use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::marker::PhantomData;
use std::ptr::NonNull;
use vantage_core::{Error, Result};

#[repr(C)]
#[derive(Debug)]
pub struct BpfObject {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct BpfProgram {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct BpfLink {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct RingBufferRaw {
    _private: [u8; 0],
}

type SampleFn = unsafe extern "C" fn(ctx: *mut c_void, data: *mut c_void, size: usize) -> c_int;

#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_mem(buf: *const c_void, size: usize, opts: *const c_void)
    -> *mut BpfObject;
    fn bpf_object__load(obj: *mut BpfObject) -> c_int;
    fn bpf_object__close(obj: *mut BpfObject);
    fn bpf_object__find_program_by_name(
        obj: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    fn bpf_object__find_map_fd_by_name(obj: *const BpfObject, name: *const c_char) -> c_int;
    fn bpf_program__set_autoload(prog: *mut BpfProgram, autoload: bool) -> c_int;
    fn bpf_program__attach(prog: *const BpfProgram) -> *mut BpfLink;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn bpf_map_get_next_key(fd: c_int, key: *const c_void, next: *mut c_void) -> c_int;
    fn ring_buffer__new(
        fd: c_int,
        cb: SampleFn,
        ctx: *mut c_void,
        opts: *const c_void,
    ) -> *mut RingBufferRaw;
    fn ring_buffer__poll(rb: *mut RingBufferRaw, timeout_ms: c_int) -> c_int;
    fn ring_buffer__free(rb: *mut RingBufferRaw);
    fn libbpf_num_possible_cpus() -> c_int;
    fn libbpf_major_version() -> u32;
    fn libbpf_minor_version() -> u32;
}

pub fn libbpf_version() -> (u32, u32) {
    unsafe { (libbpf_major_version(), libbpf_minor_version()) }
}

fn last_errno() -> io::Error {
    io::Error::last_os_error()
}

fn neg(rc: c_int) -> io::Error {
    io::Error::from_raw_os_error(-rc)
}

fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::usage(format!("name contains NUL: {s:?}")))
}

#[derive(Debug)]
pub struct Object {
    ptr: NonNull<BpfObject>,
    _image: &'static [u8],
}

impl Object {
    pub fn open(image: &'static [u8]) -> Result<Object> {
        let ptr =
            unsafe { bpf_object__open_mem(image.as_ptr().cast(), image.len(), std::ptr::null()) };
        let ptr = NonNull::new(ptr).ok_or_else(|| Error::io("open BPF object", last_errno()))?;
        Ok(Object { ptr, _image: image })
    }

    fn program(&self, name: &str) -> Result<NonNull<BpfProgram>> {
        let c = cstring(name)?;
        let p = unsafe { bpf_object__find_program_by_name(self.ptr.as_ptr(), c.as_ptr()) };
        NonNull::new(p).ok_or_else(|| Error::parse(format!("BPF program {name} not in object")))
    }

    pub fn set_autoload(&mut self, name: &str, on: bool) -> Result<()> {
        let p = self.program(name)?;
        let rc = unsafe { bpf_program__set_autoload(p.as_ptr(), on) };
        if rc < 0 {
            return Err(Error::io(format!("set autoload for {name}"), neg(rc)));
        }
        Ok(())
    }

    pub fn load(&mut self) -> Result<()> {
        let rc = unsafe { bpf_object__load(self.ptr.as_ptr()) };
        if rc < 0 {
            return Err(Error::io(
                "load BPF programs (the libbpf log above has the verifier output)",
                neg(rc),
            ));
        }
        Ok(())
    }

    pub fn attach(&self, name: &str) -> Result<Link> {
        let p = self.program(name)?;
        let l = unsafe { bpf_program__attach(p.as_ptr()) };
        NonNull::new(l)
            .map(|ptr| Link { ptr })
            .ok_or_else(|| Error::io(format!("attach {name}"), last_errno()))
    }

    pub fn map(&self, name: &str) -> Result<Map> {
        let c = cstring(name)?;
        let fd = unsafe { bpf_object__find_map_fd_by_name(self.ptr.as_ptr(), c.as_ptr()) };
        if fd < 0 {
            return Err(Error::io(format!("find map {name}"), neg(fd)));
        }
        Ok(Map {
            fd,
            name: name.to_owned(),
        })
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe { bpf_object__close(self.ptr.as_ptr()) };
    }
}

#[derive(Debug)]
pub struct Link {
    ptr: NonNull<BpfLink>,
}

impl Drop for Link {
    fn drop(&mut self) {
        unsafe { bpf_link__destroy(self.ptr.as_ptr()) };
    }
}

#[derive(Debug, Clone)]
pub struct Map {
    fd: c_int,
    name: String,
}

pub trait Pod: Copy {}
impl Pod for u8 {}
impl Pod for u32 {}
impl Pod for u64 {}
impl Pod for [u32; 2] {}

impl Map {
    pub fn update<K: Pod, V: Pod>(&self, key: &K, value: &V) -> Result<()> {
        let rc = unsafe {
            bpf_map_update_elem(
                self.fd,
                (key as *const K).cast(),
                (value as *const V).cast(),
                0,
            )
        };
        if rc < 0 {
            return Err(Error::io(format!("update map {}", self.name), neg(rc)));
        }
        Ok(())
    }

    pub fn is_empty<K: Pod + Default>(&self) -> bool {
        let mut next = K::default();
        let rc = unsafe {
            bpf_map_get_next_key(self.fd, std::ptr::null(), (&mut next as *mut K).cast())
        };
        rc < 0
    }

    pub fn sum_percpu_u64(&self, key: u32) -> Result<u64> {
        let cpus = unsafe { libbpf_num_possible_cpus() };
        if cpus <= 0 {
            return Err(Error::io("count possible CPUs", neg(cpus)));
        }
        let mut values = vec![0u64; cpus as usize];
        let rc = unsafe {
            bpf_map_lookup_elem(
                self.fd,
                (&key as *const u32).cast(),
                values.as_mut_ptr().cast(),
            )
        };
        if rc < 0 {
            return Err(Error::io(format!("read map {}", self.name), neg(rc)));
        }
        Ok(values.iter().sum())
    }
}

pub struct RingBuffer<'a, F: FnMut(&[u8])> {
    ptr: NonNull<RingBufferRaw>,
    _callback: Box<F>,
    _map: PhantomData<&'a Map>,
}

impl<F: FnMut(&[u8])> std::fmt::Debug for RingBuffer<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RingBuffer")
    }
}

unsafe extern "C" fn trampoline<F: FnMut(&[u8])>(
    ctx: *mut c_void,
    data: *mut c_void,
    size: usize,
) -> c_int {
    let callback = unsafe { &mut *ctx.cast::<F>() };
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) };
    callback(bytes);
    0
}

impl<'a, F: FnMut(&[u8])> RingBuffer<'a, F> {
    pub fn new(map: &'a Map, callback: F) -> Result<Self> {
        let mut boxed = Box::new(callback);
        let ctx: *mut F = &mut *boxed;
        let ptr =
            unsafe { ring_buffer__new(map.fd, trampoline::<F>, ctx.cast(), std::ptr::null()) };
        let ptr = NonNull::new(ptr).ok_or_else(|| Error::io("create ring buffer", last_errno()))?;
        Ok(RingBuffer {
            ptr,
            _callback: boxed,
            _map: PhantomData,
        })
    }

    pub fn poll(&mut self, timeout_ms: i32) -> io::Result<usize> {
        let rc = unsafe { ring_buffer__poll(self.ptr.as_ptr(), timeout_ms) };
        if rc < 0 {
            Err(neg(rc))
        } else {
            Ok(rc as usize)
        }
    }
}

impl<F: FnMut(&[u8])> Drop for RingBuffer<'_, F> {
    fn drop(&mut self) {
        unsafe { ring_buffer__free(self.ptr.as_ptr()) };
    }
}
