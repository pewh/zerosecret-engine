use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrError {
    Invalid,
    HostBits,
    Mapped,
}

fn bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn width(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn mask(width: u8, prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    (u128::MAX << (128 - prefix)) >> (128 - width)
}

impl Cidr {
    pub fn is_everything(&self) -> bool {
        self.prefix == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        bits(ip) & mask(width(ip), self.prefix) == bits(self.addr)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, CidrError> {
        let (addr, prefix) = text.split_once('/').ok_or(CidrError::Invalid)?;
        let addr: IpAddr = addr.parse().map_err(|_| CidrError::Invalid)?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CidrError::Invalid);
        }
        let prefix: u8 = prefix.parse().map_err(|_| CidrError::Invalid)?;
        let width = width(addr);
        if prefix > width {
            return Err(CidrError::Invalid);
        }
        if matches!(addr, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
            return Err(CidrError::Mapped);
        }
        if bits(addr) & !mask(width, prefix) != 0 {
            return Err(CidrError::HostBits);
        }
        Ok(Self { addr, prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::{Cidr, CidrError};
    use std::net::IpAddr;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn it_parses_v4_and_v6() {
        assert!("10.0.0.0/8".parse::<Cidr>().is_ok());
        assert!("172.17.0.0/16".parse::<Cidr>().is_ok());
        assert!("fd00::/8".parse::<Cidr>().is_ok());
        assert!("10.1.2.3/32".parse::<Cidr>().is_ok());
        assert!("::1/128".parse::<Cidr>().is_ok());
    }

    #[test]
    fn it_refuses_what_is_not_a_cidr() {
        for text in [
            "",
            "10.0.0.0",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/-1",
            "10.0.0.0/8/8",
            "host/8",
        ] {
            assert_eq!(text.parse::<Cidr>(), Err(CidrError::Invalid), "{text}");
        }
    }

    #[test]
    fn it_refuses_an_ipv4_mapped_v6_entry() {
        for text in [
            "::ffff:10.0.0.0/104",
            "::ffff:0.0.0.0/96",
            "::ffff:10.0.0.1/128",
        ] {
            assert_eq!(text.parse::<Cidr>(), Err(CidrError::Mapped), "{text}");
        }
    }

    #[test]
    fn it_refuses_host_bits() {
        for text in ["10.0.0.1/8", "172.17.0.1/16", "fd00::1/8", "10.0.0.1/0"] {
            assert_eq!(text.parse::<Cidr>(), Err(CidrError::HostBits), "{text}");
        }
    }

    #[test]
    fn it_reports_a_prefix_of_zero() {
        assert!("0.0.0.0/0".parse::<Cidr>().unwrap().is_everything());
        assert!("::/0".parse::<Cidr>().unwrap().is_everything());
        assert!(!"10.0.0.0/8".parse::<Cidr>().unwrap().is_everything());
    }

    #[test]
    fn it_contains_by_prefix() {
        let net: Cidr = "172.17.0.0/16".parse().unwrap();
        assert!(net.contains(ip("172.17.0.2")));
        assert!(net.contains(ip("172.17.255.255")));
        assert!(!net.contains(ip("172.18.0.1")));
        assert!(!net.contains(ip("fd00::1")));

        let host: Cidr = "10.0.0.7/32".parse().unwrap();
        assert!(host.contains(ip("10.0.0.7")));
        assert!(!host.contains(ip("10.0.0.8")));

        let v6: Cidr = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("10.0.0.1")));
    }

    #[test]
    fn an_ipv4_mapped_address_is_compared_as_ipv4() {
        let net: Cidr = "172.17.0.0/16".parse().unwrap();
        assert!(net.contains(ip("::ffff:172.17.0.2")));
        assert!(!net.contains(ip("::ffff:172.18.0.2")));
    }
}
