use std::net::{IpAddr, SocketAddr};

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const INET_DIAG_NOCOOKIE: u32 = u32::MAX;
const TCP_ESTABLISHED: u8 = 1;

#[repr(C)]
struct NlMsgHdr {
    len: u32,
    msg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
struct InetDiagSockId {
    sport: u16,
    dport: u16,
    src: [u32; 4],
    dst: [u32; 4],
    if_: u32,
    cookie: [u32; 2],
}

#[repr(C)]
struct InetDiagReqV2 {
    family: u8,
    protocol: u8,
    ext: u8,
    pad: u8,
    states: u32,
    id: InetDiagSockId,
}

#[repr(C)]
struct InetDiagMsg {
    family: u8,
    state: u8,
    timer: u8,
    retrans: u8,
    id: InetDiagSockId,
    expires: u32,
    rqueue: u32,
    wqueue: u32,
    uid: u32,
    inode: u32,
}

const _: () = assert!(std::mem::size_of::<NlMsgHdr>() == 16);
const _: () = assert!(std::mem::size_of::<InetDiagSockId>() == 48);
const _: () = assert!(std::mem::size_of::<InetDiagReqV2>() == 56);
const _: () = assert!(std::mem::size_of::<InetDiagMsg>() == 72);

struct Socket(libc::c_int);

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

pub(super) fn same_user(peer: SocketAddr, local: SocketAddr) -> std::io::Result<bool> {
    let family = match peer {
        SocketAddr::V4(_) => libc::AF_INET as u8,
        SocketAddr::V6(_) => libc::AF_INET6 as u8,
    };
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let socket = Socket(fd);
    let request = InetDiagReqV2 {
        family,
        protocol: libc::IPPROTO_TCP as u8,
        ext: 0,
        pad: 0,
        states: !0u32,
        id: InetDiagSockId {
            sport: peer.port().to_be(),
            dport: local.port().to_be(),
            src: addr32(peer.ip()),
            dst: addr32(local.ip()),
            if_: 0,
            cookie: [INET_DIAG_NOCOOKIE; 2],
        },
    };
    let header = NlMsgHdr {
        len: (std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<InetDiagReqV2>()) as u32,
        msg_type: SOCK_DIAG_BY_FAMILY,
        flags: NLM_F_REQUEST,
        seq: 1,
        pid: 0,
    };
    let mut message = [0u8; std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<InetDiagReqV2>()];
    unsafe {
        std::ptr::write_unaligned(message.as_mut_ptr().cast::<NlMsgHdr>(), header);
        std::ptr::write_unaligned(
            message
                .as_mut_ptr()
                .add(std::mem::size_of::<NlMsgHdr>())
                .cast::<InetDiagReqV2>(),
            request,
        );
    }
    let sent = unsafe { libc::send(socket.0, message.as_ptr().cast(), message.len(), 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut answer = [0u8; 4096];
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut sender_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let received = unsafe {
        libc::recvfrom(
            socket.0,
            answer.as_mut_ptr().cast(),
            answer.len(),
            0,
            (&mut sender as *mut libc::sockaddr_nl).cast(),
            &mut sender_len,
        )
    };
    if received <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if sender.nl_family != libc::AF_NETLINK as libc::sa_family_t || sender.nl_pid != 0 {
        return Err(std::io::Error::other(
            "the diag answer is not from the kernel",
        ));
    }
    let received = received as usize;
    if received < std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<InetDiagMsg>() {
        return Err(std::io::Error::other("the diag answer is too short"));
    }
    let header = unsafe { std::ptr::read_unaligned(answer.as_ptr().cast::<NlMsgHdr>()) };
    if header.msg_type == NLMSG_ERROR {
        return Err(std::io::Error::other("the diag answer is an error"));
    }
    if header.msg_type != SOCK_DIAG_BY_FAMILY || header.seq != 1 {
        return Err(std::io::Error::other(
            "the diag answer is not the request's",
        ));
    }
    let msg = unsafe {
        std::ptr::read_unaligned(
            answer
                .as_ptr()
                .add(std::mem::size_of::<NlMsgHdr>())
                .cast::<InetDiagMsg>(),
        )
    };
    Ok(msg.state == TCP_ESTABLISHED && msg.uid == unsafe { libc::geteuid() })
}

fn addr32(ip: IpAddr) -> [u32; 4] {
    let mut words = [0u32; 4];
    match ip {
        IpAddr::V4(v4) => {
            words[0] = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            for (index, chunk) in bytes.chunks_exact(4).enumerate() {
                words[index] = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        }
    }
    words
}
