use anyhow::{anyhow, Context};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::utils::{get_ip_addr, FromBytes, ToBytes, TryFromBytes};
use crate::Result;
use crate::{CircuitId, TunnelId};
use ring::rand::SecureRandom;
use ring::{aead, agreement, digest, rand, signature};
use std::net::SocketAddr;
use thiserror::Error;

const CIRCUIT_CREATE: u8 = 0x0;
const CIRCUIT_CREATED: u8 = 0x1;
const CIRCUIT_OPAQUE: u8 = 0x3;
const CIRCUIT_TEARDOWN: u8 = 0xff;

const TUNNEL_EXTEND: u8 = 0x10;
const TUNNEL_TRUNCATE: u8 = 0x11;
const TUNNEL_BEGIN: u8 = 0x12;
const TUNNEL_END: u8 = 0x13;

const TUNNEL_DATA: u8 = 0x30;

const TUNNEL_EXTENDED: u8 = 0x20;
const TUNNEL_TRUNCATED: u8 = 0x21;

pub(crate) const TUNNEL_EXTENDED_ERROR_NONE: u8 = 0x00;
pub(crate) const TUNNEL_EXTENDED_ERROR_PEER_UNREACHABLE: u8 = 0x01;

pub(crate) const TUNNEL_TRUNCATED_ERROR_NONE: u8 = 0x00;
pub(crate) const TUNNEL_TRUNCATED_ERROR_OUT_CIRCUIT_EXISTS: u8 = 0x01;

/// Length in bytes of the digest included in relay messages.
/// Must not be greater than `digest::SHA256_OUTPUT_LEN` (= 32)
pub(crate) const DIGEST_LEN: usize = 12;
const SIGNATURE_LEN: usize = 512;
const KEY_LEN: usize = 32;

pub(crate) const MESSAGE_SIZE: usize = 1024;

#[derive(Error, Debug)]
pub(crate) enum CircuitProtocolError {
    #[error("Teardown while expecting {expected}")]
    Teardown { expected: u8 },
    #[error("Unknown tunnel message id: expected {expected} got {actual}")]
    Unknown { expected: u8, actual: u8 },
}

pub(crate) type CircuitProtocolResult<T> = std::result::Result<T, CircuitProtocolError>;

#[derive(Error, Debug)]
pub(crate) enum TunnelProtocolError {
    #[error("Unknown tunnel message id: {actual}")]
    Unknown { actual: u8 },
    #[error("Computed hash did not match the message hash")]
    Digest,
}

pub(crate) type TunnelProtocolResult<T> = std::result::Result<T, TunnelProtocolError>;

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
pub(crate) struct CircuitOpaque<P> {
    pub(crate) circuit_id: CircuitId,
    pub(crate) payload: P,
}

pub(crate) struct CircuitOpaquePayload<'a, M> {
    pub(crate) msg: &'a M,
    pub(crate) rng: &'a rand::SystemRandom,
    pub(crate) encrypt_keys: &'a [aead::LessSafeKey],
}

pub(crate) struct CircuitOpaqueBytes {
    pub(crate) bytes: BytesMut,
    nonce: [u8; aead::NONCE_LEN],
}

/// A message exchanged between onion peers.
/// Signals that the sending peer broke down the circuit and is no longer servicing the connection.
///
/// Header Format:
/// ```text
/// message_type: u8
/// padding: u8
/// circuit_id: u16
/// ```
pub(crate) struct CircuitTeardown {
    pub(crate) circuit_id: CircuitId,
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
    Truncate(TunnelId),
    Begin(TunnelId),
    End(TunnelId),
    /// Format:
    /// ```text
    /// _padding: u8
    /// tunnel_id: u32
    /// data
    /// ```
    Data(TunnelId, /* data */ Bytes),
}

pub(crate) enum TunnelResponse<K> {
    Extended(TunnelId, /* error_code */ u8, /* peer_key */ K),
    Truncated(TunnelId, /* error_code */ u8),
}

pub(crate) trait TryFromBytesExt: TryFromBytes<TunnelProtocolError> {
    fn read_with_digest_from(buf: &mut BytesMut) -> TunnelProtocolResult<Self>
    where
        Self: Sized,
    {
        let digest = digest::digest(&digest::SHA256, &buf[DIGEST_LEN..]);
        if &digest.as_ref()[..DIGEST_LEN] == &buf[..DIGEST_LEN] {
            buf.advance(DIGEST_LEN);
            Self::try_read_from(buf)
        } else {
            Err(TunnelProtocolError::Digest)
        }
    }
}

impl<T> TryFromBytesExt for T where T: TryFromBytes<TunnelProtocolError> {}

pub(crate) trait ToBytesExt: ToBytes {
    fn write_with_digest_to(&self, buf: &mut BytesMut, rng: &rand::SystemRandom, pad_size: usize) {
        let digest_start = buf.len();
        let payload_start = digest_start + DIGEST_LEN;
        buf.resize(payload_start, 0);
        let mut payload_buf = buf.split_off(payload_start);
        self.write_padded_to(&mut payload_buf, rng, pad_size - DIGEST_LEN);
        // digest must include padding as size is unknown during verification
        let digest = digest::digest(&digest::SHA256, &payload_buf[..]);
        buf[digest_start..payload_start].copy_from_slice(&digest.as_ref()[..DIGEST_LEN]);
        buf.unsplit(payload_buf);
    }

    fn write_padded_to(&self, buf: &mut BytesMut, rng: &rand::SystemRandom, pad_size: usize) {
        self.write_to(buf);
        let msg_len = buf.len();
        assert!(
            msg_len <= pad_size,
            "msg_len ({}) > pad_size ({})",
            msg_len,
            pad_size
        );
        buf.resize(pad_size, 0);
        rng.fill(&mut buf.as_mut()[msg_len..]).unwrap();
    }
}

impl<T: ToBytes> ToBytesExt for T {}

/* == CircuitCreate == */

impl FromBytes for CircuitProtocolResult<CircuitCreate> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let message_type = buf.get_u8();
        match message_type {
            CIRCUIT_CREATE => {
                buf.get_u8();
                let circuit_id = buf.get_u16();
                let key_bytes = buf.split_to(KEY_LEN).freeze();
                let key = Key::new(&agreement::X25519, key_bytes);
                Ok(CircuitCreate { circuit_id, key })
            }
            CIRCUIT_TEARDOWN => Err(CircuitProtocolError::Teardown {
                expected: CIRCUIT_CREATE,
            }),
            _ => Err(CircuitProtocolError::Unknown {
                expected: CIRCUIT_CREATE,
                actual: message_type,
            }),
        }
    }
}

impl ToBytes for CircuitCreate {
    fn size(&self) -> usize {
        MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(CIRCUIT_CREATE);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        buf.put(self.key.bytes().as_ref());
    }
}

/* == CircuitCreated == */

impl FromBytes for CircuitProtocolResult<CircuitCreated<VerifyKey>> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let message_type = buf.get_u8();
        match message_type {
            CIRCUIT_CREATED => {
                buf.get_u8();
                let circuit_id = buf.get_u16();
                let key = VerifyKey::read_from(buf);
                Ok(CircuitCreated { circuit_id, key })
            }
            CIRCUIT_TEARDOWN => Err(CircuitProtocolError::Teardown {
                expected: CIRCUIT_CREATED,
            }),
            _ => Err(CircuitProtocolError::Unknown {
                expected: CIRCUIT_CREATED,
                actual: message_type,
            }),
        }
    }
}

impl ToBytes for CircuitCreated<SignKey<'_>> {
    fn size(&self) -> usize {
        MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(CIRCUIT_CREATED);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        self.key.write_to(buf);
    }
}

/* == CircuitOpaque == */

impl CircuitOpaque<CircuitOpaqueBytes> {
    pub(crate) fn decrypt<'k>(
        &mut self,
        decrypt_keys: impl Iterator<Item = &'k aead::LessSafeKey>,
    ) -> Result<()> {
        for key in decrypt_keys {
            let nonce = aead::Nonce::assume_unique_for_key(self.payload.nonce.clone());
            let _plaintext = key
                .open_in_place_no_tag(nonce, aead::Aad::empty(), self.payload.bytes.as_mut())
                .context("Failed to decrypt message")?;
        }
        Ok(())
    }

    pub(crate) fn encrypt<'k>(
        &mut self,
        encrypt_keys: impl Iterator<Item = &'k aead::LessSafeKey>,
    ) -> Result<()> {
        for key in encrypt_keys {
            let nonce = aead::Nonce::assume_unique_for_key(self.payload.nonce.clone());
            let _tag = key
                .seal_in_place_separate_tag(nonce, aead::Aad::empty(), self.payload.bytes.as_mut())
                .context("Failed to encrypt message")?;
        }
        Ok(())
    }
}

impl FromBytes for CircuitProtocolResult<CircuitOpaque<CircuitOpaqueBytes>> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let message_type = buf.get_u8();
        match message_type {
            CIRCUIT_OPAQUE => {
                buf.get_u8();
                let circuit_id = buf.get_u16();
                let mut nonce = [0u8; aead::NONCE_LEN];
                buf.split_to(aead::NONCE_LEN).copy_to_slice(&mut nonce);
                let payload = buf.split_off(0);
                Ok(CircuitOpaque {
                    circuit_id,
                    payload: CircuitOpaqueBytes {
                        bytes: payload,
                        nonce,
                    },
                })
            }
            CIRCUIT_TEARDOWN => Err(CircuitProtocolError::Teardown {
                expected: CIRCUIT_OPAQUE,
            }),
            _ => Err(CircuitProtocolError::Unknown {
                expected: CIRCUIT_OPAQUE,
                actual: message_type,
            }),
        }
    }
}

impl ToBytes for CircuitOpaque<CircuitOpaqueBytes> {
    fn size(&self) -> usize {
        MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(CIRCUIT_OPAQUE);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        buf.put(self.payload.nonce.as_ref());
        buf.put(self.payload.bytes.as_ref())
    }
}

impl<'a, M: ToBytes> CircuitOpaque<CircuitOpaquePayload<'a, M>> {
    fn encrypt(&self, buf: &mut BytesMut, nonce: [u8; aead::NONCE_LEN]) -> Result<()> {
        for key in self.payload.encrypt_keys.iter() {
            let nonce = aead::Nonce::assume_unique_for_key(nonce.clone());
            let _tag = key
                .seal_in_place_separate_tag(nonce, aead::Aad::empty(), buf.as_mut())
                .context("Failed to encrypt message")?;
        }
        Ok(())
    }
}

impl<'a, M: ToBytes> ToBytes for CircuitOpaque<CircuitOpaquePayload<'a, M>> {
    fn size(&self) -> usize {
        MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(CIRCUIT_OPAQUE);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
        let mut nonce = [0u8; aead::NONCE_LEN];
        self.payload.rng.fill(&mut nonce).unwrap(); // TODO maybe use counter instead
        buf.extend_from_slice(&nonce);
        let mut payload_buf = buf.split_off(buf.len());
        self.payload.msg.write_with_digest_to(
            &mut payload_buf,
            self.payload.rng,
            MESSAGE_SIZE - 4 - aead::NONCE_LEN,
        );
        self.encrypt(&mut payload_buf, nonce).unwrap();
        buf.unsplit(payload_buf);
    }
}

/* == CircuitTeardown== */

impl ToBytes for CircuitTeardown {
    fn size(&self) -> usize {
        MESSAGE_SIZE
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(CIRCUIT_TEARDOWN);
        buf.put_u8(0);
        buf.put_u16(self.circuit_id);
    }
}

/* == TunnelRequest == */

impl FromBytes for TunnelProtocolResult<TunnelRequest> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            TUNNEL_EXTEND => {
                let ipv6_flag = buf.get_u8();
                let tunnel_id = buf.get_u32();
                let dest_ip = get_ip_addr(buf, ipv6_flag == 1);
                let dest_port = buf.get_u16();
                let dest = SocketAddr::new(dest_ip, dest_port);
                let key_bytes = buf.split_to(KEY_LEN).freeze();
                let key = Key::new(&agreement::X25519, key_bytes);
                Ok(TunnelRequest::Extend(tunnel_id, dest, key))
            }
            TUNNEL_DATA => {
                buf.get_u8();
                let tunnel_id = buf.get_u32();
                let data = buf.split_to(size - 8).freeze();
                Ok(TunnelRequest::Data(tunnel_id, data))
            }
            _ => Err(TunnelProtocolError::Unknown {
                actual: message_type,
            }),
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
            TunnelRequest::Truncate(_) => {
                // size (2), type (1), padding (1), tunnel_id (4)
                2 + 1 + 1 + 4
            }
            TunnelRequest::Begin(_) => {
                // size (2), type (1), padding (1), tunnel_id (4)
                2 + 1 + 1 + 4
            }
            TunnelRequest::End(_) => {
                // size (2), type (1), padding (1), tunnel_id (4)
                2 + 1 + 1 + 4
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
                buf.put_u8(TUNNEL_EXTEND);
                buf.put_u8(if dest.is_ipv6() { 1 } else { 0 });
                buf.put_u32(*tunnel_id);
                dest.ip().write_to(buf);
                buf.put_u16(dest.port());
                buf.put(key.bytes().as_ref());
            }
            TunnelRequest::Truncate(tunnel_id) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_TRUNCATE);
                buf.put_u8(0);
                buf.put_u32(*tunnel_id);
            }
            TunnelRequest::Begin(tunnel_id) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_BEGIN);
                buf.put_u8(0);
                buf.put_u32(*tunnel_id);
            }
            TunnelRequest::End(tunnel_id) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_END);
                buf.put_u8(0);
                buf.put_u32(*tunnel_id);
            }
            TunnelRequest::Data(tunnel_id, data) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_DATA);
                buf.put_u8(0);
                buf.put_u32(*tunnel_id);
                buf.put(data.as_ref());
            }
        }
    }
}

/* == TunnelResponse == */

impl FromBytes for TunnelProtocolResult<TunnelResponse<VerifyKey>> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            TUNNEL_EXTENDED => {
                let error_code = buf.get_u8();
                let tunnel_id = buf.get_u32();
                let peer_key = VerifyKey::read_from(buf);
                Ok(TunnelResponse::Extended(tunnel_id, error_code, peer_key))
            }
            _ => Err(TunnelProtocolError::Unknown {
                actual: message_type,
            }),
        }
    }
}

impl<K: ToBytes> ToBytes for TunnelResponse<K> {
    fn size(&self) -> usize {
        match self {
            TunnelResponse::Extended(_, _, peer_key) => {
                // size (2), type (1), error_code (1), tunnel_id (4), peer_key
                2 + 1 + 1 + 4 + peer_key.size()
            }
            TunnelResponse::Truncated(_, _) => {
                // size (2), type (1), error_code(1), tunnel_id (4)
                2 + 1 + 1 + 4
            }
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            TunnelResponse::Extended(tunnel_id, error_code, key) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_EXTENDED);
                buf.put_u8(*error_code);
                buf.put_u32(*tunnel_id);
                key.write_to(buf);
            }
            TunnelResponse::Truncated(tunnel_id, error_code) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_TRUNCATED);
                buf.put_u8(*error_code);
                buf.put_u32(*tunnel_id);
            }
        }
    }
}

/* == Keys == */

impl FromBytes for VerifyKey {
    fn read_from(buf: &mut BytesMut) -> Self {
        let signature = buf.split_to(SIGNATURE_LEN).freeze();
        let key_bytes = buf.split_to(KEY_LEN).freeze();
        let key = Key::new(&agreement::X25519, key_bytes);
        VerifyKey { key, signature }
    }
}

impl ToBytes for VerifyKey {
    fn size(&self) -> usize {
        SIGNATURE_LEN + KEY_LEN
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put(self.signature.as_ref());
        buf.put(self.key.bytes().as_ref());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::read_hostkey;
    use ring::rand::SecureRandom;
    use ring::signature::KeyPair;

    #[test]
    fn test_circuit_create() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let key = generate_ephemeral_key(&rng)?;
        let key_bytes = key.bytes().clone();

        let circuit_id = 0;
        let msg = CircuitCreate { circuit_id, key };
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, &rng, MESSAGE_SIZE);
        let read_msg = CircuitCreate::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        let key2_bytes: &[u8] = &read_msg.key.bytes().as_ref();
        assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_circuit_created() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let key = generate_ephemeral_key(&rng)?;
        let key_bytes = key.bytes().clone();

        let (rsa_private, rsa_public) = read_rsa_testkey()?;
        let key = SignKey::sign(&key, &rsa_private, &rng);

        let circuit_id = 0;
        let msg = CircuitCreated { circuit_id, key };
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, &rng, MESSAGE_SIZE);
        let read_msg = CircuitCreated::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        let key2 = read_msg.key.verify(&rsa_public)?;
        let key2_bytes: &[u8] = &key2.bytes().as_ref();
        assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_tunnel_extend() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let key = generate_ephemeral_key(&rng)?;
        let key_bytes = key.bytes().clone();

        let aes_keys = generate_aes_keys(&rng)?;

        let tunnel_id = 123;
        let dest = "127.0.0.1:4201".parse().unwrap();
        let tunnel_msg = TunnelRequest::Extend(tunnel_id, dest, key);
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                rng: &rng,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, &rng, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        let read_tunnel_msg = TunnelRequest::read_with_digest_from(&mut read_msg.payload.bytes)?;
        if let TunnelRequest::Extend(tunnel_id2, dest2, key2) = read_tunnel_msg {
            assert_eq!(tunnel_id, tunnel_id2);
            assert_eq!(dest, dest2);
            let key2_bytes: &[u8] = &key2.bytes().as_ref();
            assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        }
        Ok(())
    }

    #[test]
    fn test_tunnel_extended() -> Result<()> {
        let rng = rand::SystemRandom::new();
        let key = generate_ephemeral_key(&rng)?;
        let key_bytes = key.bytes().clone();

        let (rsa_private, rsa_public) = read_rsa_testkey()?;
        let key = SignKey::sign(&key, &rsa_private, &rng);

        let aes_keys = generate_aes_keys(&rng)?;

        let tunnel_id = 123;
        let error_code = TUNNEL_EXTENDED_ERROR_NONE;
        let tunnel_msg = TunnelResponse::Extended(tunnel_id, error_code, key);
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                rng: &rng,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, &rng, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        let read_tunnel_msg = TunnelResponse::read_with_digest_from(&mut read_msg.payload.bytes)?;
        match read_tunnel_msg {
            TunnelResponse::Extended(tunnel_id2, error_code2, key2) => {
                assert_eq!(tunnel_id, tunnel_id2);
                assert_eq!(error_code, error_code2);
                let key2 = key2.verify(&rsa_public)?;
                let key2_bytes: &[u8] = &key2.bytes().as_ref();
                assert_eq!(&key_bytes.as_ref(), &key2_bytes);
            }
        }
        Ok(())
    }

    #[test]
    fn test_tunnel_data() -> Result<()> {
        Ok(())
    }

    fn generate_ephemeral_key(rng: &rand::SystemRandom) -> Result<Key> {
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)?;
        let public_key = private_key.compute_public_key()?;
        let key = Key::new(&agreement::X25519, public_key.as_ref().to_vec().into());
        Ok(key)
    }

    fn read_rsa_testkey() -> Result<(signature::RsaKeyPair, signature::UnparsedPublicKey<Bytes>)> {
        let key_pair = signature::RsaKeyPair::from_pkcs8(&read_hostkey("testkey.pem")?)?;
        let rsa_public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key_pair.public_key().as_ref().to_vec().into(),
        );
        Ok((key_pair, rsa_public_key))
    }

    fn generate_aes_keys(rng: &rand::SystemRandom) -> Result<[aead::LessSafeKey; 1]> {
        let mut aes_key_bytes = [0u8; 16];
        rng.fill(&mut aes_key_bytes)?; // TODO not sure about this
        let aes_key =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &aes_key_bytes)?);
        Ok([aes_key])
    }
}
