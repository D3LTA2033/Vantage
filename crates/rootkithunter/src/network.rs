use crate::Options;
use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use vantage_core::{Finding, IoContext, Outcome, Result, Severity, rawsys, sys};

pub fn decode_addr(s: &str) -> Option<String> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match addr.len() {
        8 => {
            let v = u32::from_str_radix(addr, 16).ok()?;
            Some(format!("{}:{port}", Ipv4Addr::from(v.to_ne_bytes())))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let w = u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok()?;
                chunk.copy_from_slice(&w.to_ne_bytes());
            }
            Some(format!("[{}]:{port}", Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn state_name(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

pub fn describe_socket_key(key: &[u8]) -> String {
    let s = String::from_utf8_lossy(key);
    let parts: Vec<&str> = s.split(' ').collect();
    if parts.len() != 4 {
        return s.into_owned();
    }
    let local = decode_addr(parts[0]).unwrap_or_else(|| parts[0].to_owned());
    let remote = decode_addr(parts[1]).unwrap_or_else(|| parts[1].to_owned());
    format!(
        "{local} -> {remote} {} inode {}",
        state_name(parts[2]),
        parts[3]
    )
}

pub fn parse_local_ports(data: &[u8]) -> BTreeSet<u16> {
    data.split(|&b| b == b'\n')
        .skip(1)
        .filter_map(|line| {
            let local = line
                .split(|b| b.is_ascii_whitespace())
                .filter(|t| !t.is_empty())
                .nth(1)?;
            let colon = local.iter().rposition(|&b| b == b':')?;
            let port = std::str::from_utf8(&local[colon + 1..]).ok()?;
            u16::from_str_radix(port, 16).ok()
        })
        .collect()
}

fn ports_in(files: &[&str]) -> Result<BTreeSet<u16>> {
    let mut out = BTreeSet::new();
    for f in files {
        match rawsys::read_file(Path::new(f), 64 << 20) {
            Ok(d) => out.extend(parse_local_ports(&d)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("read {f}")),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn files(self) -> [&'static str; 2] {
        match self {
            Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
            Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    Free,
    InUse,
    Denied,
    Unsupported,
}

struct Socket(i32);

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_int(fd: i32, level: i32, opt: i32, value: i32) {
    unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&value as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

pub fn probe_bind(proto: Proto, v6: bool, port: u16) -> Bind {
    let ty = match proto {
        Proto::Tcp => libc::SOCK_STREAM,
        Proto::Udp => libc::SOCK_DGRAM,
    } | libc::SOCK_CLOEXEC;
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = unsafe { libc::socket(family, ty, 0) };
    if fd < 0 {
        return Bind::Unsupported;
    }
    let sock = Socket(fd);
    if proto == Proto::Tcp {
        set_int(sock.0, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
    }
    let rc = if v6 {
        set_int(sock.0, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1);
        let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_port = port.to_be();
        unsafe {
            libc::bind(
                sock.0,
                (&sa as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    } else {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        unsafe {
            libc::bind(
                sock.0,
                (&sa as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    };
    if rc == 0 {
        return Bind::Free;
    }
    match errno() {
        libc::EADDRINUSE => Bind::InUse,
        libc::EACCES | libc::EPERM => Bind::Denied,
        _ => Bind::Unsupported,
    }
}

pub fn hidden_ports(_: &Options) -> Result<Outcome> {
    let mut findings = Vec::new();
    let mut denied = 0usize;
    let mut families = Vec::new();
    let mut probed = 0usize;
    for proto in [Proto::Tcp, Proto::Udp] {
        let listed = ports_in(&proto.files())?;
        let mut candidates = Vec::new();
        for v6 in [false, true] {
            if probe_bind(proto, v6, 0) == Bind::Unsupported {
                continue;
            }
            families.push(format!("{}{}", proto.name(), if v6 { "6" } else { "4" }));
            for port in 1..=u16::MAX {
                if listed.contains(&port) {
                    continue;
                }
                probed += 1;
                match probe_bind(proto, v6, port) {
                    Bind::InUse => candidates.push((v6, port)),
                    Bind::Denied => denied += 1,
                    _ => {}
                }
            }
        }
        if candidates.is_empty() {
            continue;
        }
        let relisted = ports_in(&proto.files())?;
        for (v6, port) in candidates {
            if relisted.contains(&port) || probe_bind(proto, v6, port) != Bind::InUse {
                continue;
            }
            if ports_in(&proto.files())?.contains(&port) {
                continue;
            }
            findings.push(
                Finding::new(
                    Severity::Critical,
                    format!("{} port {port} in use but hidden", proto.name()),
                )
                .detail("bind() reports the port as taken, yet no socket with this local port appears in /proc/net; kernel rootkits hide sockets by filtering the seq_file show functions")
                .evidence("protocol", proto.name())
                .evidence("port", port)
                .evidence("family", if v6 { "ipv6" } else { "ipv4" }),
            );
        }
    }
    let mut summary = format!(
        "{probed} bind probes across {} in the current network namespace",
        families.join("/")
    );
    if denied > 0 {
        let start = sys::sysctl_int("net.ipv4.ip_unprivileged_port_start")
            .ok()
            .flatten()
            .unwrap_or(1024);
        summary.push_str(&format!(
            "; {denied} probes below port {start} refused without CAP_NET_BIND_SERVICE"
        ));
    }
    Ok(Outcome::done(summary, findings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn address_decoding() {
        if cfg!(target_endian = "little") {
            assert_eq!(
                decode_addr("0100007F:0277").as_deref(),
                Some("127.0.0.1:631")
            );
            assert_eq!(
                decode_addr("00000000000000000000000001000000:0016").as_deref(),
                Some("[::1]:22")
            );
        }
        assert_eq!(decode_addr("zz:1"), None);
        assert_eq!(decode_addr("00000000"), None);
    }

    #[test]
    fn local_port_parsing() {
        let data = b"  sl  local_address rem_address   st\n   0: 0100007F:0277 00000000:0000 0A\n   1: 00000000:0016 00000000:0000 0A\n";
        assert_eq!(parse_local_ports(data), BTreeSet::from([631, 22]));
    }

    #[test]
    fn bind_probe_sees_real_listeners() {
        let l = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(probe_bind(Proto::Tcp, false, port), Bind::InUse);
        assert!(ports_in(&Proto::Tcp.files()).unwrap().contains(&port));
        drop(l);
        assert_eq!(probe_bind(Proto::Tcp, false, port), Bind::Free);

        let u = UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = u.local_addr().unwrap().port();
        assert_eq!(probe_bind(Proto::Udp, false, port), Bind::InUse);
        assert!(ports_in(&Proto::Udp.files()).unwrap().contains(&port));
    }
}
