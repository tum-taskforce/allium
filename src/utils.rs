use bytes::{Buf, BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) trait FromBytes {
    fn read_from(buf: &mut BytesMut) -> Self
    where
        Self: Sized;
}

pub(crate) trait TryFromBytes<E> {
    fn try_read_from(buf: &mut BytesMut) -> std::result::Result<Self, E>
    where
        Self: Sized;
}

impl<T, E> TryFromBytes<E> for T
where
    std::result::Result<T, E>: FromBytes,
{
    fn try_read_from(buf: &mut BytesMut) -> std::result::Result<Self, E>
    where
        Self: Sized,
    {
        std::result::Result::<T, E>::read_from(buf)
    }
}

pub(crate) trait ToBytes {
    fn size(&self) -> usize;
    fn write_to(&self, buf: &mut BytesMut);
}

impl FromBytes for Ipv4Addr {
    fn read_from(buf: &mut BytesMut) -> Self {
        let mut octets = [0u8; 4];
        buf.copy_to_slice(&mut octets);
        Ipv4Addr::from(octets)
    }
}

impl FromBytes for Ipv6Addr {
    fn read_from(buf: &mut BytesMut) -> Self {
        let mut octets = [0u8; 16];
        buf.copy_to_slice(&mut octets);
        Ipv6Addr::from(octets)
    }
}

pub fn get_ip_addr(buf: &mut BytesMut, is_ipv6: bool) -> IpAddr {
    if !is_ipv6 {
        IpAddr::V4(Ipv4Addr::read_from(buf))
    } else {
        IpAddr::V6(Ipv6Addr::read_from(buf))
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
