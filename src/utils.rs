use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Result;
use bytes::{Buf, BufMut, BytesMut};
use std::fs::File;

pub(crate) trait FromBytes {
    fn read_from(buf: &mut BytesMut) -> Result<Self>
    where
        Self: Sized;
}

pub(crate) trait ToBytes {
    fn size(&self) -> usize;
    fn write_to(&self, buf: &mut BytesMut);
}

impl FromBytes for Ipv4Addr {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let mut octets = [0u8; 4];
        buf.copy_to_slice(&mut octets);
        Ok(Ipv4Addr::from(octets))
    }
}

impl FromBytes for Ipv6Addr {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let mut octets = [0u8; 16];
        buf.copy_to_slice(&mut octets);
        Ok(Ipv6Addr::from(octets))
    }
}

pub fn get_ip_addr(buf: &mut BytesMut, is_ipv6: bool) -> IpAddr {
    if !is_ipv6 {
        IpAddr::V4(Ipv4Addr::read_from(buf).unwrap())
    } else {
        IpAddr::V6(Ipv6Addr::read_from(buf).unwrap())
    }
}

impl ToBytes for IpAddr {
    fn size(&self) -> usize {
        match self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            IpAddr::V4(ip) => buf.put(ip.octets().as_ref()),
            IpAddr::V6(ip) => buf.put(ip.octets().as_ref()),
        }
    }
}

pub(crate) fn read_hostkey(path: &str) -> Result<Vec<u8>> {
    let file = BufReader::new(File::open(path)?);
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
        let _hostkey = RsaKeyPair::from_pkcs8(&data)?;
        Ok(())
    }
}
