use crate::onion::crypto::{self, EphemeralPublicKey, SessionKey};
use crate::utils::{self, FromBytes, ToBytes, TryFromBytes};
use crate::{CircuitId, TunnelId};
use crate::{Result, RsaPrivateKey, RsaPublicKey};
use anyhow::{anyhow, Context};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
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
const TUNNEL_KEEPALIVE: u8 = 0x40;

const TUNNEL_EXTENDED: u8 = 0x20;
const TUNNEL_TRUNCATED: u8 = 0x21;
const TUNNEL_ERROR: u8 = 0x2f;

/// Length in bytes of the digest included in relay messages.
/// Must not be greater than `digest::SHA256_OUTPUT_LEN` (= 32)
pub(crate) const DIGEST_LEN: usize = 12;
const SIGNATURE_LEN: usize = 512;
const KEY_LEN: usize = crypto::KEY_LEN;

pub(crate) const MESSAGE_SIZE: usize = 1024;
pub(crate) const MAX_DATA_SIZE: usize = MESSAGE_SIZE - 4 - crypto::NONCE_LEN - DIGEST_LEN - 8;

#[derive(Error, Debug)]
pub(crate) enum CircuitProtocolError {
    #[error("Teardown while expecting {expected}")]
    Teardown { expected: u8 },
    #[error("Unknown tunnel message id: expected {expected} got {actual}")]
    Unknown { expected: u8, actual: u8 },
}

pub(crate) type CircuitProtocolResult<T> = std::result::Result<T, CircuitProtocolError>;

#[derive(Error, Debug)]
pub(crate) enum TunnelProtocolError<E: fmt::Debug> {
    #[error("Peer responded with an error code")]
    Peer(E),
    #[error("Unknown tunnel message id: {actual}")]
    Unknown { actual: u8 },
    #[error("Computed hash did not match the message hash")]
    Digest,
}

pub(crate) type TunnelProtocolResult<T, E> = std::result::Result<T, TunnelProtocolError<E>>;

pub(crate) type Key = EphemeralPublicKey;

pub(crate) struct SignKey<'a> {
    key: &'a Key,
    key_pair: &'a RsaPrivateKey,
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
    pub(crate) encrypt_keys: &'a [SessionKey],
}

pub(crate) struct CircuitOpaqueBytes {
    pub(crate) bytes: BytesMut,
    nonce: [u8; crypto::NONCE_LEN],
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
    /// dest.addr(): [u8; 4] or [u8; 16] (depending on ipv6_flag)
    /// dest.port(): u16
    /// key
    /// ```
    Extend(/* dest */ SocketAddr, /* key */ Key),
    Truncate,
    Begin(TunnelId),
    End(TunnelId),
    /// Format:
    /// ```text
    /// _padding: u8
    /// tunnel_id: u32
    /// data
    /// ```
    Data(TunnelId, /* data */ Bytes),
    KeepAlive,
}

const ERR_BRANCHING: u8 = 0x01;
const ERR_UNREACHABLE: u8 = 0x02;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum TunnelExtendedError {
    /// The `EXTENDED` call is rejected, because there already is an outgoing circuit from the targeted
    /// hop and tunnel branching is not allowed.
    BranchingDetected = ERR_BRANCHING,
    /// The `EXTENDED` call was unsuccessful since the new peer was unreachable.
    PeerUnreachable = ERR_UNREACHABLE,
    Unknown,
}

pub(crate) struct TunnelResponseExtended<K> {
    pub(crate) peer_key: K,
}

const ERR_NO_NEXT_HOP: u8 = 0x01;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum TunnelTruncatedError {
    /// The `TRUNCATED` call is rejected, because there is no outgoing circuit from the targeted hop
    /// that could be truncated.
    NoNextHop = ERR_NO_NEXT_HOP,
    Unknown,
}

pub(crate) struct TunnelResponseTruncated;

pub(crate) trait TryFromBytesExt<E: fmt::Debug>:
    TryFromBytes<TunnelProtocolError<E>>
{
    fn read_with_digest_from(buf: &mut BytesMut) -> TunnelProtocolResult<Self, E>
    where
        Self: Sized,
    {
        let digest = crypto::digest(&buf[DIGEST_LEN..]);
        if digest.as_ref()[..DIGEST_LEN] == buf[..DIGEST_LEN] {
            buf.advance(DIGEST_LEN);
            Self::try_read_from(buf)
        } else {
            Err(TunnelProtocolError::Digest)
        }
    }
}

impl<T, E: fmt::Debug> TryFromBytesExt<E> for T where T: TryFromBytes<TunnelProtocolError<E>> {}

pub(crate) trait ToBytesExt: ToBytes {
    fn write_with_digest_to(&self, buf: &mut BytesMut, pad_size: usize) {
        let digest_start = buf.len();
        let payload_start = digest_start + DIGEST_LEN;
        buf.resize(payload_start, 0);
        let mut payload_buf = buf.split_off(payload_start);
        self.write_padded_to(&mut payload_buf, pad_size - DIGEST_LEN);
        // digest must include padding as size is unknown during verification
        let digest = crypto::digest(&payload_buf[..]);
        buf[digest_start..payload_start].copy_from_slice(&digest.as_ref()[..DIGEST_LEN]);
        buf.unsplit(payload_buf);
    }

    fn write_padded_to(&self, buf: &mut BytesMut, pad_size: usize) {
        self.write_to(buf);
        let msg_len = buf.len();
        assert!(
            msg_len <= pad_size,
            "msg_len ({}) > pad_size ({})",
            msg_len,
            pad_size
        );
        buf.resize(pad_size, 0);
        crypto::fill_random(&mut buf.as_mut()[msg_len..]);
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
                let key = Key::new(key_bytes);
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
        decrypt_keys: impl Iterator<Item = &'k SessionKey>,
    ) -> Result<()> {
        for key in decrypt_keys {
            key.decrypt(self.payload.nonce, self.payload.bytes.as_mut())
                .context("Failed to decrypt message")?;
        }
        Ok(())
    }

    pub(crate) fn encrypt<'k>(
        &mut self,
        encrypt_keys: impl Iterator<Item = &'k SessionKey>,
    ) -> Result<()> {
        for key in encrypt_keys {
            key.encrypt(self.payload.nonce, self.payload.bytes.as_mut())
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
                let mut nonce = [0u8; crypto::NONCE_LEN];
                buf.split_to(crypto::NONCE_LEN).copy_to_slice(&mut nonce);
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
    fn encrypt(&self, buf: &mut BytesMut, nonce: [u8; crypto::NONCE_LEN]) -> Result<()> {
        for key in self.payload.encrypt_keys.iter() {
            key.encrypt(nonce, buf.as_mut())
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
        let mut nonce = [0u8; crypto::NONCE_LEN];
        crypto::fill_random(&mut nonce); // TODO maybe use counter instead
        buf.extend_from_slice(&nonce);
        let mut payload_buf = buf.split_off(buf.len());
        self.payload
            .msg
            .write_with_digest_to(&mut payload_buf, MESSAGE_SIZE - 4 - crypto::NONCE_LEN);
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

impl FromBytes for TunnelProtocolResult<TunnelRequest, ()> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            TUNNEL_EXTEND => {
                let ipv6_flag = buf.get_u8();
                let dest_ip = utils::get_ip_addr(buf, ipv6_flag == 1);
                let dest_port = buf.get_u16();
                let dest = SocketAddr::new(dest_ip, dest_port);
                let key_bytes = buf.split_to(KEY_LEN).freeze();
                let key = Key::new(key_bytes);
                Ok(TunnelRequest::Extend(dest, key))
            }
            TUNNEL_TRUNCATE => Ok(TunnelRequest::Truncate),
            TUNNEL_BEGIN => {
                buf.get_u8();
                let tunnel_id = buf.get_u32();
                Ok(TunnelRequest::Begin(tunnel_id))
            }
            TUNNEL_END => {
                buf.get_u8();
                let tunnel_id = buf.get_u32();
                Ok(TunnelRequest::End(tunnel_id))
            }
            TUNNEL_DATA => {
                buf.get_u8();
                let tunnel_id = buf.get_u32();
                let data = buf.split_to(size - 8).freeze();
                Ok(TunnelRequest::Data(tunnel_id, data))
            }
            TUNNEL_KEEPALIVE => Ok(TunnelRequest::KeepAlive),
            _ => Err(TunnelProtocolError::Unknown {
                actual: message_type,
            }),
        }
    }
}

impl ToBytes for TunnelRequest {
    fn size(&self) -> usize {
        match self {
            TunnelRequest::Extend(dest, key) => {
                // size (2), type (1), ip flag (1), ip addr, dest port (2), secret
                2 + 1 + 1 + dest.ip().size() + 2 + key.bytes().len()
            }
            TunnelRequest::Truncate => {
                // size (2), type (1)
                2 + 1
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
            TunnelRequest::KeepAlive => {
                // size (2), type (1)
                2 + 1
            }
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            TunnelRequest::Extend(dest, key) => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_EXTEND);
                buf.put_u8(if dest.is_ipv6() { 1 } else { 0 });
                dest.ip().write_to(buf);
                buf.put_u16(dest.port());
                buf.put(key.bytes().as_ref());
            }
            TunnelRequest::Truncate => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_TRUNCATE);
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
            TunnelRequest::KeepAlive => {
                buf.put_u16(self.size() as u16);
                buf.put_u8(TUNNEL_KEEPALIVE);
            }
        }
    }
}

/* == TunnelResponseExtended == */

impl FromBytes for TunnelProtocolResult<TunnelResponseExtended<VerifyKey>, TunnelExtendedError> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let _size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            TUNNEL_EXTENDED => {
                let peer_key = VerifyKey::read_from(buf);
                Ok(TunnelResponseExtended { peer_key })
            }
            TUNNEL_ERROR => {
                let error_code = buf.get_u8();
                match error_code {
                    ERR_BRANCHING => Err(TunnelProtocolError::Peer(
                        TunnelExtendedError::BranchingDetected,
                    )),
                    ERR_UNREACHABLE => Err(TunnelProtocolError::Peer(
                        TunnelExtendedError::PeerUnreachable,
                    )),
                    _ => Err(TunnelProtocolError::Peer(TunnelExtendedError::Unknown)),
                }
            }
            _ => Err(TunnelProtocolError::Unknown {
                actual: message_type,
            }),
        }
    }
}

impl<K: ToBytes> ToBytes for TunnelResponseExtended<K> {
    fn size(&self) -> usize {
        // size (2), type (1), peer_key
        2 + 1 + self.peer_key.size()
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.size() as u16);
        buf.put_u8(TUNNEL_EXTENDED);
        self.peer_key.write_to(buf);
    }
}

impl ToBytes for TunnelExtendedError {
    fn size(&self) -> usize {
        // size (2), type (1), error code (1)
        2 + 1 + 1
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.size() as u16);
        buf.put_u8(TUNNEL_ERROR);
        buf.put_u8(*self as u8);
    }
}

/* == TunnelResponseTruncated == */

impl FromBytes for TunnelProtocolResult<TunnelResponseTruncated, TunnelTruncatedError> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let _size = buf.get_u16() as usize;
        let message_type = buf.get_u8();
        match message_type {
            TUNNEL_TRUNCATED => Ok(TunnelResponseTruncated),
            TUNNEL_ERROR => {
                let error_code = buf.get_u8();
                match error_code {
                    ERR_NO_NEXT_HOP => {
                        Err(TunnelProtocolError::Peer(TunnelTruncatedError::NoNextHop))
                    }
                    _ => Err(TunnelProtocolError::Peer(TunnelTruncatedError::Unknown)),
                }
            }
            _ => Err(TunnelProtocolError::Unknown {
                actual: message_type,
            }),
        }
    }
}

impl ToBytes for TunnelResponseTruncated {
    fn size(&self) -> usize {
        // size (2), type (1)
        2 + 1
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.size() as u16);
        buf.put_u8(TUNNEL_TRUNCATED);
    }
}

impl ToBytes for TunnelTruncatedError {
    fn size(&self) -> usize {
        // size (2), type (1), error code (1)
        2 + 1 + 1
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.size() as u16);
        buf.put_u8(TUNNEL_ERROR);
        buf.put_u8(*self as u8);
    }
}

/* == Keys == */

impl FromBytes for VerifyKey {
    fn read_from(buf: &mut BytesMut) -> Self {
        let signature = buf.split_to(SIGNATURE_LEN).freeze();
        let key_bytes = buf.split_to(KEY_LEN).freeze();
        let key = Key::new(key_bytes);
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
    pub(crate) fn verify(self, public_key: &RsaPublicKey) -> Result<Key> {
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
            .sign(self.key.bytes().as_ref(), &mut buf[sig_start..sig_end])
            .unwrap();
    }
}

impl<'a> SignKey<'a> {
    pub(crate) fn sign(key: &'a Key, key_pair: &'a RsaPrivateKey) -> Self {
        SignKey { key, key_pair }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::crypto::{self, EphemeralPrivateKey};
    use crate::onion::tests::read_rsa_keypair;

    #[test]
    fn test_circuit_create() -> Result<()> {
        let key = EphemeralPrivateKey::generate().public_key();
        let key_bytes = key.bytes().clone();

        let circuit_id = 0;
        let msg = CircuitCreate { circuit_id, key };
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        let read_msg = CircuitCreate::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        let key2_bytes: &[u8] = &read_msg.key.bytes().as_ref();
        assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_circuit_created() -> Result<()> {
        let key = EphemeralPrivateKey::generate().public_key();
        let key_bytes = key.bytes().clone();

        let (rsa_private, rsa_public) = read_rsa_keypair("testkey.pem")?;
        let key = SignKey::sign(&key, &rsa_private);

        let circuit_id = 0;
        let msg = CircuitCreated { circuit_id, key };
        let mut buf = BytesMut::with_capacity(msg.size());
        msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        let read_msg = CircuitCreated::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        let key2 = read_msg.key.verify(&rsa_public)?;
        let key2_bytes: &[u8] = &key2.bytes().as_ref();
        assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_tunnel_extend() -> Result<()> {
        let key = EphemeralPrivateKey::generate().public_key();
        let key_bytes = key.bytes().clone();

        let aes_keys = generate_aes_keys()?;

        let dest = "127.0.0.1:4201".parse().unwrap();
        let tunnel_msg = TunnelRequest::Extend(dest, key);
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        let read_tunnel_msg = TunnelRequest::read_with_digest_from(&mut read_msg.payload.bytes)?;
        if let TunnelRequest::Extend(dest2, key2) = read_tunnel_msg {
            //assert_eq!(tunnel_id, tunnel_id2);
            assert_eq!(dest, dest2);
            let key2_bytes: &[u8] = &key2.bytes().as_ref();
            assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        }
        Ok(())
    }

    #[test]
    fn test_tunnel_extended_success() -> Result<()> {
        let key = EphemeralPrivateKey::generate().public_key();
        let key_bytes = key.bytes().clone();

        let (rsa_private, rsa_public) = read_rsa_keypair("testkey.pem")?;
        let key = SignKey::sign(&key, &rsa_private);

        let aes_keys = generate_aes_keys()?;

        let tunnel_msg = TunnelResponseExtended { peer_key: key };
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        let read_tunnel_msg =
            TunnelResponseExtended::read_with_digest_from(&mut read_msg.payload.bytes)?;
        let key2 = read_tunnel_msg.peer_key.verify(&rsa_public)?;
        let key2_bytes: &[u8] = &key2.bytes().as_ref();
        assert_eq!(&key_bytes.as_ref(), &key2_bytes);
        Ok(())
    }

    #[test]
    fn test_tunnel_extended_error() -> Result<()> {
        let aes_keys = generate_aes_keys()?;

        let tunnel_msg = TunnelExtendedError::PeerUnreachable;
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        let read_tunnel_msg =
            TunnelResponseExtended::read_with_digest_from(&mut read_msg.payload.bytes);
        assert!(matches!(
            read_tunnel_msg,
            Err(TunnelProtocolError::Peer(
                TunnelExtendedError::PeerUnreachable
            ))
        ));
        Ok(())
    }

    #[test]
    fn test_tunnel_truncated_success() -> Result<()> {
        let aes_keys = generate_aes_keys()?;

        let tunnel_msg = TunnelResponseTruncated;
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        TunnelResponseTruncated::read_with_digest_from(&mut read_msg.payload.bytes)?;
        Ok(())
    }

    #[test]
    fn test_tunnel_truncated_error() -> Result<()> {
        let aes_keys = generate_aes_keys()?;

        let tunnel_msg = TunnelTruncatedError::NoNextHop;
        let circuit_id = 0;
        let msg = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_msg,
                encrypt_keys: &aes_keys,
            },
        };

        let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
        //msg.write_padded_to(&mut buf, MESSAGE_SIZE);
        msg.write_to(&mut buf);
        assert_eq!(buf.len(), MESSAGE_SIZE);
        let mut read_msg = CircuitOpaque::try_read_from(&mut buf)?;

        assert_eq!(circuit_id, read_msg.circuit_id);
        read_msg.decrypt(aes_keys.iter().rev())?;
        let read_tunnel_msg =
            TunnelResponseTruncated::read_with_digest_from(&mut read_msg.payload.bytes);
        assert!(matches!(
            read_tunnel_msg,
            Err(TunnelProtocolError::Peer(TunnelTruncatedError::NoNextHop))
        ));
        Ok(())
    }

    #[test]
    fn test_tunnel_data() -> Result<()> {
        Ok(())
    }

    fn generate_aes_keys() -> Result<[SessionKey; 1]> {
        let mut aes_key_bytes = [0u8; 16];
        crypto::fill_random(&mut aes_key_bytes);
        Ok([SessionKey::from_bytes(&aes_key_bytes)?])
    }
}
