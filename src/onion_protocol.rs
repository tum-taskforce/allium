use std::io::Read;
use std::net::IpAddr;

use anyhow::{anyhow, Context};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::Result;
use crate::{CircuitId, TunnelId};
use async_std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use ring::rand::SecureRandom;
use ring::{aead, agreement, digest, rand, signature};

type BE = byteorder::BigEndian;

const ONION_CREATE_REQUEST: u8 = 0x0;
const ONION_CREATE_RESPONSE: u8 = 0x1;
const ONION_RELAY: u8 = 0x3;

const ONION_RELAY_EXTEND: u8 = 0x10;
const ONION_RELAY_DATA: u8 = 0x11;

const ONION_RELAY_EXTENDED: u8 = 0x20;

/// Length in bytes of the digest included in relay messages.
/// Must not be greater than `digest::SHA256_OUTPUT_LEN` (= 32)
pub(crate) const RELAY_DIGEST_LEN: usize = 12;
const SIGNATURE_LEN: usize = 512;
const KEY_LEN: usize = 32;

pub(crate) const ONION_MESSAGE_SIZE: usize = 1024;
const RELAY_MESSAGE_MAX_SIZE: usize = ONION_MESSAGE_SIZE - 4 - RELAY_DIGEST_LEN;
const RELAY_DATA_MAX_SIZE: usize = RELAY_MESSAGE_MAX_SIZE - 8;

pub(crate) type Key = agreement::UnparsedPublicKey<Bytes>;

pub(crate) struct SignKey<'a> {
    key: &'a Key,
    key_pair: &'a signature::RsaKeyPair,
    rng: &'a rand::SystemRandom,
}

pub(crate) struct VerifyKey {
    key: Key,
    signature: Bytes,
}

/// A message exchanged between onion peers.
/// Initiates the creation of a new circuit to the recipient by performing a Diffie-Hellman key
/// exchange. This message contains the sender's ephemeral public key.
///
/// Header Format:
/// ```text
/// message_type: u8
/// padding: u8
/// circuit_id: u16
/// key
/// ```
pub(crate) struct CircuitCreate {
    pub(crate) circuit_id: CircuitId,
    pub(crate) key: Key,
}

/// A message exchanged between onion peers.
/// Confirms the creation of a new circuit, initiated by a `CreateRequest`. Contains the peer's
/// ephemeral public key, which the initiator can use to generate a shared secret.
///
/// Header Format:
/// ```text
/// message_type: u8
/// padding: u8
/// circuit_id: u16
/// signed_key
/// ```
pub(crate) struct CircuitCreated<K> {
    pub(crate) circuit_id: CircuitId,
    pub(crate) key: K,
}

/// A message exchanged between onion peers.
/// Wraps an encrypted relay message.
/// Can be decrypted using `CircuitOpaque::decrypt`.
///
/// Header Format:
/// ```text
/// message_type: u8
/// padding: u8
/// circuit_id: u16
/// payload
/// ```
pub(crate) struct CircuitOpaque {
    pub(crate) circuit_id: CircuitId,
    pub(crate) payload: BytesMut,
}

/// A fully decrypted relay message.
///
/// Header Format:
/// ```text
/// size: u16
/// type: u8
/// ```
///
/// Can be encrypted using `OpaqueRelayMessage::encrypt`.
pub(crate) enum TunnelRequest {
    /// Format:
    /// ```text
    /// ipv6_flag: u8
    /// tunnel_id: u32
    /// dest.addr(): [u8; 4] or [u8; 16] (depending on ipv6_flag)
    /// dest.port(): u16
    /// key
    /// ```
    Extend(TunnelId, /* dest */ SocketAddr, /* key */ Key),
    /// Format:
    /// ```text
    /// _padding: u8
    /// tunnel_id: u32
    /// data
    /// ```
    Data(TunnelId, /* data */ Bytes),
}

pub(crate) enum TunnelResponse<K> {
    Extended(TunnelId, /* peer_key */ K),
}

pub(crate) trait FromBytes {
    fn read_from(buf: &mut BytesMut) -> Result<Self>
    where
        Self: Sized;

    fn read_with_digest_from(buf: &mut BytesMut) -> Result<Self>
    where
        Self: Sized,
    {
        let digest = digest::digest(&digest::SHA256, &buf[RELAY_DIGEST_LEN..]);
        if &digest.as_ref()[..RELAY_DIGEST_LEN] == &buf[..RELAY_DIGEST_LEN] {
            buf.split_to(RELAY_DIGEST_LEN);
            Self::read_from(buf)
        } else {
            Err(anyhow!("Computed hash did not match the message hash"))
        }
    }
}

pub(crate) trait ToBytes {
    fn size(&self) -> usize;
    fn write_to(&self, buf: &mut BytesMut);

    fn write_with_digest_to(&self, buf: &mut BytesMut, rng: &rand::SystemRandom) {
        let digest_start = buf.len();
        let digest_end = digest_start + RELAY_DIGEST_LEN;
        buf.resize(digest_end, 0);
        self.write_padded_to(buf, rng, RELAY_MESSAGE_MAX_SIZE);
        let digest = digest::digest(&digest::SHA256, &buf[digest_end..]);
        buf[digest_start..digest_end].copy_from_slice(&digest.as_ref()[..RELAY_DIGEST_LEN]);
    }

    fn write_padded_to(&self, buf: &mut BytesMut, rng: &rand::SystemRandom, pad_size: usize) {
        self.write_to(buf);
        let msg_len = buf.len();
        buf.resize(pad_size, 0);
        rng.fill(&mut buf.as_mut()[msg_len..]).unwrap();
    }
}

impl FromBytes for CircuitCreate {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let message_type = buf.get_u8();
        match message_type {
            ONION_CREATE_REQUEST => {
                buf.get_u8();
                let circuit_id = buf.get_u16();
                let key_bytes = buf.split_to(KEY_LEN).freeze();
                let key = Key::new(&agreement::X25519, key_bytes);
                Ok(CircuitCreate { circuit_id, key })
            }
            _ => Err(anyhow!(
                "Expected CircuitCreate message but got {}",
                message_type
            )),
        }
    }
}

impl ToBytes for CircuitCreate {
    fn size(&self) -> usize {
        ONION_MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(ONION_CREATE_REQUEST);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        buf.put(self.key.bytes().as_ref());
    }
}

impl FromBytes for CircuitCreated<VerifyKey> {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let message_type = buf.get_u8();
        match message_type {
            ONION_CREATE_RESPONSE => {
                buf.get_u8();
                let circuit_id = buf.get_u16();
                let key = VerifyKey::read_from(buf)?;
                Ok(CircuitCreated { circuit_id, key })
            }
            _ => Err(anyhow!(
                "Expected CircuitCreated message but got {}",
                message_type
            )),
        }
    }
}

impl ToBytes for CircuitCreated<SignKey<'_>> {
    fn size(&self) -> usize {
        ONION_MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(ONION_CREATE_RESPONSE);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        self.key.write_to(buf);
    }
}

impl FromBytes for CircuitOpaque {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let message_type = buf.get_u8();
        match message_type {
            ONION_RELAY => {
                buf.get_u8();
                let circuit_id = buf.get_u16();
                let payload = buf.split_off(0);
                Ok(CircuitOpaque {
                    circuit_id,
                    payload,
                })
            }
            _ => Err(anyhow!(
                "Expected CircuitOpaque message but got {}",
                message_type
            )),
        }
    }
}

impl ToBytes for CircuitOpaque {
    fn size(&self) -> usize {
        ONION_MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(ONION_RELAY);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        buf.put(self.payload.as_ref())
    }
}

impl CircuitOpaque {
    pub(crate) fn decrypt(
        &mut self,
        rng: &rand::SystemRandom,
        decrypt_keys: impl Iterator<Item=aead::LessSafeKey>,
    ) -> Result<()> {
        for key in decrypt_keys {
            let mut nonce_buf = [0u8; 12];
            rng.fill(&mut nonce_buf);
            let nonce = aead::Nonce::assume_unique_for_key(nonce_buf);
            let plaintext = key.open_in_place(nonce, aead::Aad::empty(), self.payload.as_mut())?;
            let plaintext_len = plaintext.len();
            self.payload.truncate(plaintext_len)
        }
        Ok(())
    }

    pub(crate) fn encrypt(
        &mut self,
        rng: &rand::SystemRandom,
        encrypt_keys: impl Iterator<Item=aead::LessSafeKey>,
    ) -> Result<()> {
        for key in encrypt_keys {
            let mut nonce_buf = [0u8; 12];
            rng.fill(&mut nonce_buf);
            let nonce = aead::Nonce::assume_unique_for_key(nonce_buf);
            let tag = key
                .seal_in_place_separate_tag(nonce, aead::Aad::empty(), self.payload.as_mut())
                .context("Failed to encrypt message")?;
            self.payload.extend_from_slice(tag.as_ref())
        }
        Ok(())
    }
}

impl FromBytes for TunnelRequest {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            ONION_RELAY_EXTEND => {
                let ipv6_flag = buf.get_u8();
                let tunnel_id = buf.get_u32();
                let dest_ip = get_ip_addr(buf, ipv6_flag == 1);
                let dest_port = buf.get_u16();
                let dest = SocketAddr::new(dest_ip, dest_port);
                let key_bytes = buf.split_to(KEY_LEN).freeze();
                let key = Key::new(&agreement::X25519, key_bytes);
                Ok(TunnelRequest::Extend(tunnel_id, dest, key))
            }
            ONION_RELAY_DATA => {
                buf.get_u8();
                let tunnel_id = buf.get_u32();
                let data = buf.split_to(size - 8).freeze();
                Ok(TunnelRequest::Data(tunnel_id, data))
            }
            _ => Err(anyhow!("Unknown TunnelRequest type {}", message_type)),
        }
    }
}

impl ToBytes for TunnelRequest {
    fn size(&self) -> usize {
        match self {
            TunnelRequest::Extend(_, dest, key) => {
                // size (2), type (1), ip flag (1), tunnel id (4), ip addr, dest port (2), secret
                2 + 1 + 1 + 4 + dest.ip().size() + 2 + key.bytes().len()
            }
            TunnelRequest::Data(_, data) => {
                // size (2), type (1), padding (1), tunnel_id (4), data
                2 + 1 + 1 + 4 + data.len()
            }
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            TunnelRequest::Extend(tunnel_id, dest, key) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(ONION_RELAY_EXTEND);
                buf.put_u8(if dest.is_ipv6() { 1 } else { 0 });
                buf.put_u32(*tunnel_id);
                dest.ip().write_to(buf);
                buf.put_u16(dest.port());
                buf.put(key.bytes().as_ref());
            }
            TunnelRequest::Data(tunnel_id, data) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(ONION_RELAY_DATA);
                buf.put_u8(0);
                buf.put_u32(*tunnel_id);
                buf.put(data.as_ref());
            }
        }
    }
}

impl FromBytes for TunnelResponse<VerifyKey> {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            ONION_RELAY_EXTENDED => {
                buf.get_u8();
                let tunnel_id = buf.get_u32();
                let peer_key = VerifyKey::read_from(buf)?;
                Ok(TunnelResponse::Extended(tunnel_id, peer_key))
            }
            _ => Err(anyhow!("Unknown TunnelResponse type {}", message_type)),
        }
    }
}

impl ToBytes for TunnelResponse<SignKey<'_>> {
    fn size(&self) -> usize {
        match self {
            TunnelResponse::Extended(_, peer_key) => {
                // size (2), type (1), padding (1), tunnel_id (4), peer_key
                2 + 1 + 1 + 4 + peer_key.size()
            }
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            TunnelResponse::Extended(tunnel_id, peer_key) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(ONION_RELAY_EXTENDED);
                buf.put_u8(0);
                buf.put_u32(*tunnel_id);
                peer_key.write_to(buf);
            }
        }
    }
}

impl FromBytes for VerifyKey {
    fn read_from(buf: &mut BytesMut) -> Result<Self> {
        let signature = buf.split_to(SIGNATURE_LEN).freeze();
        let key_bytes = buf.split_to(KEY_LEN).freeze();
        let key = Key::new(&agreement::X25519, key_bytes);
        Ok(VerifyKey { key, signature })
    }
}

impl VerifyKey {
    pub(crate) fn verify(self, public_key: &signature::UnparsedPublicKey<Bytes>) -> Result<Key> {
        match public_key.verify(self.key.bytes().as_ref(), self.signature.as_ref()) {
            Ok(_) => Ok(self.key),
            Err(_) => Err(anyhow!("Could not verify key signature")),
        }
    }
}

impl ToBytes for SignKey<'_> {
    fn size(&self) -> usize {
        SIGNATURE_LEN + KEY_LEN
    }

    fn write_to(&self, buf: &mut BytesMut) {
        let sig_start = buf.len();
        let sig_end = sig_start + SIGNATURE_LEN;
        buf.resize(sig_end, 0);
        buf.put(self.key.bytes().as_ref());
        self.key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                self.rng,
                self.key.bytes().as_ref(),
                &mut buf[sig_start..sig_end],
            )
            .unwrap();
    }
}

impl<'a> SignKey<'a> {
    pub(crate) fn sign(
        key: &'a Key,
        key_pair: &'a signature::RsaKeyPair,
        rng: &'a rand::SystemRandom,
    ) -> Self {
        SignKey { key, key_pair, rng }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::read_hostkey;
    use ring::rand::SecureRandom;
    use ring::signature::KeyPair;

    #[test]
    fn test_circuit_create() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let public_key = private_key.compute_public_key()?;
        let key = Key::new(&agreement::X25519, public_key.as_ref().to_vec().into());

        let circuit_id = 0;
        let msg = CircuitCreate { circuit_id, key };
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, &rng, ONION_MESSAGE_SIZE);
        let read_msg = CircuitCreate::read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        let key2_bytes: &[u8] = &read_msg.key.bytes().as_ref();
        assert_eq!(&public_key.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_circuit_created() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let key_pair = signature::RsaKeyPair::from_pkcs8(&read_hostkey("testkey.pem")?)?;
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let public_key = private_key.compute_public_key()?;
        let key = Key::new(&agreement::X25519, public_key.as_ref().to_vec().into());
        let key = SignKey::sign(&key, &key_pair, &rng);

        let circuit_id = 0;
        let msg = CircuitCreated { circuit_id, key };
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, &rng, ONION_MESSAGE_SIZE);
        let read_msg = CircuitCreated::read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        let rsa_public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key_pair.public_key().as_ref().to_vec().into(),
        );
        let key2 = read_msg.key.verify(&rsa_public_key)?;
        let key2_bytes: &[u8] = &key2.bytes().as_ref();
        assert_eq!(&public_key.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_tunnel_extend() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let public_key = private_key.compute_public_key()?;
        let key = Key::new(&agreement::X25519, public_key.as_ref().to_vec().into());

        let mut aes_key_bytes = [0u8; 16];
        rng.fill(&mut aes_key_bytes); // TODO not sure about this
        let aes_key = aead::UnboundKey::new(&aead::AES_128_GCM, &aes_key_bytes)?;
        let aes_key = aead::LessSafeKey::new(aes_key);

        let tunnel_id = 123;
        let dest = "127.0.0.1:4201".parse().unwrap();
        let tunnel_msg = TunnelRequest::Extend(tunnel_id, dest, key);
        let mut buf = BytesMut::with_capacity(tunnel_msg.size());
        tunnel_msg.write_with_digest_to(&mut buf, &rng);

        let circuit_id = 0;
        let mut msg = CircuitOpaque {
            circuit_id,
            payload: buf,
        };
        msg.encrypt(&rng, &[&aes_key])?;
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, &rng, ONION_MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(&rng, &[&aes_key])?;
        let read_tunnel_msg =
            TunnelRequest::read_with_digest_from(&mut read_msg.payload, RELAY_DIGEST_LEN)?;
        if let TunnelRequest::Extend(tunnel_id2, dest2, key2) = read_tunnel_msg {
            assert_eq!(tunnel_id, tunnel_id2);
            assert_eq!(dest, dest2);
            let key2_bytes: &[u8] = &key2.bytes().as_ref();
            assert_eq!(&public_key.as_ref(), &key2_bytes);
        }
        Ok(())
    }

    #[test]
    fn test_tunnel_extended() -> Result<()> {
        Ok(())
    }

    #[test]
    fn test_tunnel_data() -> Result<()> {
        Ok(())
    }
}
