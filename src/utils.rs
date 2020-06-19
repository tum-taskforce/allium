use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Result;
use std::fs::File;

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

pub(crate) fn read_hostkey(path: &str) -> Result<Vec<u8>> {
    let mut file = BufReader::new(File::open(path)?);
    let key = file
        .lines()
        .map(|line| line.unwrap())
        .skip(1)
        .take_while(|line| !line.starts_with('-'))
        .collect::<String>();
    Ok(base64::decode(&key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::RsaKeyPair;

    #[test]
    fn test_read_hostkey() -> Result<()> {
        let data = read_hostkey("testkey.pem")?;
        let hostkey = RsaKeyPair::from_pkcs8(&data)?;
        Ok(())
    }
}
