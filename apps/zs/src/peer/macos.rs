use std::net::{IpAddr, SocketAddr};

const PROC_UID_ONLY: u32 = 4;
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const SOCKINFO_TCP: i32 = 2;
const TSI_S_ESTABLISHED: i32 = 4;

#[repr(C)]
struct ProcFileInfo {
    openflags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guardflags: u32,
}

#[repr(C)]
struct InSockInfo {
    fport: i32,
    lport: i32,
    gencnt: u64,
    flags: u32,
    flow: u32,
    vflag: u8,
    ip_ttl: u8,
    reserved: u32,
    faddr: [u8; 16],
    laddr: [u8; 16],
    v4: [u8; 1],
    v6: [u8; 12],
}

#[repr(C)]
struct TcpSockInfo {
    ini: InSockInfo,
    state: i32,
    timer: [i32; 4],
    mss: i32,
    flags: u32,
    reserved: u32,
    tp: u64,
    padding: [u8; 408],
}

#[repr(C)]
struct SocketInfo {
    stat: [u8; 136],
    so: u64,
    pcb: u64,
    socket_type: i32,
    protocol: i32,
    family: i32,
    options: i16,
    linger: i16,
    state: i16,
    qlen: i16,
    incqlen: i16,
    qlimit: i16,
    timeo: i16,
    error: u16,
    oobmark: u32,
    rcv: [u8; 24],
    snd: [u8; 24],
    soi_kind: i32,
    reserved: u32,
    proto: TcpSockInfo,
}

#[repr(C)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

const _: () = assert!(std::mem::size_of::<ProcFileInfo>() == 24);
const _: () = assert!(std::mem::size_of::<InSockInfo>() == 80);
const _: () = assert!(std::mem::size_of::<TcpSockInfo>() == 528);
const _: () = assert!(std::mem::size_of::<SocketInfo>() == 768);
const _: () = assert!(std::mem::size_of::<SocketFdInfo>() == 792);

pub(super) fn same_user(peer: SocketAddr, local: SocketAddr) -> std::io::Result<bool> {
    let peer_addr = addr16(peer.ip());
    let local_addr = addr16(local.ip());
    for pid in user_pids()? {
        for fd in socket_fds(pid)? {
            let Some(info) = socket_info(pid, fd)? else {
                continue;
            };
            if info.psi.soi_kind != SOCKINFO_TCP || info.psi.proto.state != TSI_S_ESTABLISHED {
                continue;
            }
            let ini = &info.psi.proto.ini;
            if u16::from_be(ini.lport as u16) != peer.port()
                || u16::from_be(ini.fport as u16) != local.port()
            {
                continue;
            }
            if ini.laddr == peer_addr && ini.faddr == local_addr {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn addr16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[12..].copy_from_slice(&v4.octets());
            bytes
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_error(code: i32) -> std::io::Error {
    if code == 0 {
        std::io::Error::other("a process lookup answered nothing")
    } else {
        std::io::Error::from_raw_os_error(code)
    }
}

fn user_pids() -> std::io::Result<Vec<libc::c_int>> {
    let uid = unsafe { libc::geteuid() };
    let needed = unsafe { libc::proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut pids = vec![0 as libc::c_int; needed as usize / 4 + 16];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            (pids.len() * std::mem::size_of::<libc::c_int>()) as libc::c_int,
        )
    };
    if bytes <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    pids.truncate(bytes as usize / 4);
    Ok(pids.into_iter().filter(|pid| *pid > 0).collect())
}

fn socket_fds(pid: libc::c_int) -> std::io::Result<Vec<libc::c_int>> {
    let info_size = std::mem::size_of::<libc::proc_fdinfo>();
    clear_errno();
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return match errno() {
            libc::ESRCH => Ok(Vec::new()),
            code => Err(os_error(code)),
        };
    }
    let capacity = needed as usize / info_size + 16;
    let mut entries = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        capacity
    ];
    clear_errno();
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            (entries.len() * info_size) as libc::c_int,
        )
    };
    if bytes <= 0 {
        return match errno() {
            0 | libc::ESRCH => Ok(Vec::new()),
            code => Err(os_error(code)),
        };
    }
    entries.truncate(bytes as usize / info_size);
    Ok(entries
        .into_iter()
        .filter(|entry| entry.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
        .map(|entry| entry.proc_fd)
        .collect())
}

fn socket_info(pid: libc::c_int, fd: libc::c_int) -> std::io::Result<Option<SocketFdInfo>> {
    let size = std::mem::size_of::<SocketFdInfo>();
    let mut info = std::mem::MaybeUninit::<SocketFdInfo>::zeroed();
    clear_errno();
    let bytes = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if bytes <= 0 {
        return match errno() {
            libc::ESRCH | libc::EBADF => Ok(None),
            code => Err(os_error(code)),
        };
    }
    if bytes as usize != size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the socket info is not the expected size",
        ));
    }
    Ok(Some(unsafe { info.assume_init() }))
}
