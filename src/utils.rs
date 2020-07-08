use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Result;
use anyhow::anyhow;
use anyhow::Context;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::{aead, agreement, rand};
use std::fs::File;

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

// TODO maybe think of better solution
impl ToBytes for () {
    fn size(&self) -> usize { 0 }
    fn write_to(&self, buf: &mut BytesMut) { }
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

pub(crate) fn generate_ephemeral_key_pair(
    rng: &rand::SystemRandom,
) -> Result<(
    agreement::EphemeralPrivateKey,
    agreement::UnparsedPublicKey<Bytes>,
)> {
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng).unwrap();
    let public_key = private_key.compute_public_key().unwrap();
    // TODO maybe avoid allocating here
    let key =
        agreement::UnparsedPublicKey::new(&agreement::X25519, public_key.as_ref().to_vec().into());
    Ok((private_key, key))
}

pub(crate) fn derive_secret(
    private_key: agreement::EphemeralPrivateKey,
    peer_key: &agreement::UnparsedPublicKey<Bytes>,
) -> Result<aead::LessSafeKey> {
    // TODO use proper key derivation function
    agreement::agree_ephemeral(
        private_key,
        peer_key,
        anyhow!("Key exchange failed"),
        |key_material| {
            let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key_material[..16])
                .context("Could not construct unbound key from keying material")?;
            Ok(aead::LessSafeKey::new(unbound))
        },
    )
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
