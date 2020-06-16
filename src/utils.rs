use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Result;

/// Reads an IPv4 or IPv6 address from `r` depending on `is_ipv4`.
/// Returns the parsed `IpAddr` and the number of bytes read, which is either 4 or 16.
pub fn read_ip_addr_from<R: Read>(r: &mut R, is_ipv4: bool) -> Result<(IpAddr, usize)> {
    if is_ipv4 {
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf)?;
        Ok((IpAddr::V4(Ipv4Addr::from(buf)), 4))
    } else {
        let mut buf = [0u8; 16];
        r.read_exact(&mut buf)?;
        Ok((IpAddr::V6(Ipv6Addr::from(buf)), 16))
    }
}
