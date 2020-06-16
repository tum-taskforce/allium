use std::io::{Cursor, Read, Write};
use std::net::IpAddr;

use anyhow::anyhow;
use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::utils::read_ip_addr_from;
use crate::Result;
use crate::{CircuitId, TunnelId};
use async_std::net::SocketAddr;
use ring::{aead, digest};
use std::convert::TryFrom;

type BE = byteorder::BigEndian;

const ONION_CREATE_REQUEST: u8 = 0x0;
const ONION_CREATE_RESPONSE: u8 = 0x1;
const ONION_RELAY: u8 = 0x3;

const ONION_RELAY_EXTEND: u8 = 0x10;
const ONION_RELAY_DATA: u8 = 0x11;

const ONION_RELAY_EXTENDED: u8 = 0x20;

/// Length in bytes of the digest included in relay messages.
/// Must not be greater than `digest::SHA256_OUTPUT_LEN` (= 32)
const RELAY_DIGEST_LEN: usize = 12;

const ONION_MESSAGE_SIZE: usize = 1024;
const RELAY_MESSAGE_MAX_SIZE: usize = ONION_MESSAGE_SIZE - 4 - RELAY_DIGEST_LEN;
const RELAY_DATA_MAX_SIZE: usize = RELAY_MESSAGE_MAX_SIZE - 8;

/// A message exchanged between onion peers.
///
/// Header Format:
/// ```text
/// message_type: u8
/// padding: u8
/// circuit_id: u16
/// ```
pub(crate) enum OnionMessage {
    /// Initiates the creation of a new circuit to the recipient by performing a Diffie-Hellman key
    /// exchange. This message contains the sender's ephemeral public key.
    CreateRequest(CircuitId, /* key */ Vec<u8>),
    /// Confirms the creation of a new circuit, initiated by a `CreateRequest`. Contains the peer's
    /// ephemeral public key, which the initiator can use to generate a shared secret.
    CreateResponse(CircuitId, /* peer_key */ Vec<u8>),
    /// Wraps an encrypted relay message.
    /// Can be decrypted using `OpaqueRelayMessage::decrypt`.
    Relay(CircuitId, /* relay_payload */ Vec<u8>),
    // DestroyRequest,
}

/// A decrypted but opaque relay message.
///
/// Format of the payload:
/// ```text
/// digest: RELAY_DIGEST_LEN
/// decrypted_body
/// ```
///
/// Convert `OnionMessage` to `RelayMessage`:
/// ```text
/// let onion_msg = OnionMessage::Relay(...);
/// let opaque = OpaqueRelayMessage::decrypt(key)?;
/// let relay_msg = opaque.try_into()?;
/// ```
/// The method `try_to_relay_message` may fail in case the computed digest does not match the digest
/// in the message. This means that the message is not to be consumed by the current peer but to be
/// forwarded in the corresponding tunnel.
///
/// Convert `RelayMessage` to `OnionMessage`:
/// ```text
/// let relay_message = RelayMessage::Extend(...);
/// let opaque = OpaqueRelayMessage::from(relay_message);
/// let onion_message = opaque.encrypt(circuit_id, key)?;
/// ```
pub(crate) struct OpaqueRelayMessage {
    relay_payload: Vec<u8>,
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
pub(crate) enum RelayMessage {
    // = Requests =
    /// Format:
    /// ```text
    /// ipv6_flag: u8
    /// tunnel_id: u32
    /// dest.addr(): [u8; 4] or [u8; 16] (depending on ipv6_flag)
    /// dest.port(): u16
    /// key
    /// ```
    Extend(TunnelId, /* dest */ SocketAddr, /* key */ Vec<u8>),
    /// Format:
    /// ```text
    /// _padding: u8
    /// tunnel_id: u32
    /// data
    /// ```
    Data(TunnelId, /* data */ Vec<u8>),
    // Truncate,
    // = Responses =
    // Extended(TunnelId, /* dest_addr */ IpAddr, /* dest_port */ u16),
    // Truncated(TunnelId, RelayTruncated),
}

impl OnionMessage {
    fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let message_type = r.read_u8()?;
        match message_type {
            ONION_CREATE_REQUEST => {
                r.read_u8()?;
                let circuit_id = r.read_u16::<BE>()?;
                let key_len = r.read_u16::<BE>()? as usize;
                let mut key = vec![0u8; key_len];
                r.read_exact(&mut key)?;
                Ok(OnionMessage::CreateRequest(circuit_id, key))
            }
            ONION_CREATE_RESPONSE => {
                r.read_u8()?;
                let circuit_id = r.read_u16::<BE>()?;
                let peer_key_len = r.read_u16::<BE>()? as usize;
                let mut peer_key = vec![0u8; peer_key_len];
                r.read_exact(&mut peer_key)?;
                Ok(OnionMessage::CreateResponse(circuit_id, peer_key))
            }
            ONION_RELAY => {
                r.read_u8()?;
                let circuit_id = r.read_u16::<BE>()?;
                let mut relay_payload = vec![0u8; RELAY_MESSAGE_MAX_SIZE]; // TODO
                r.read_exact(&mut relay_payload)?;
                Ok(OnionMessage::Relay(circuit_id, relay_payload))
            }
            _ => Err(anyhow!("Unknown onion message type: {}", message_type)),
        }
    }

    fn size(&self) -> usize {
        ONION_MESSAGE_SIZE
    }

    fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            OnionMessage::CreateRequest(circuit_id, key) => {
                w.write_u8(ONION_CREATE_REQUEST)?;
                w.write_u8(0)?;
                w.write_u16::<BE>(*circuit_id)?;
                // if secret has constant size, this is not needed
                w.write_u16::<BE>(key.len() as u16)?;
                w.write_all(key)?;
            }
            OnionMessage::CreateResponse(circuit_id, peer_key) => {
                w.write_u8(ONION_CREATE_RESPONSE)?;
                w.write_u8(0)?;
                w.write_u16::<BE>(*circuit_id)?;
                // if secret has constant size, this is not needed
                w.write_u16::<BE>(peer_key.len() as u16)?;
                w.write_all(peer_key)?;
            }
            OnionMessage::Relay(circuit_id, relay_msg) => {
                w.write_u8(ONION_RELAY)?;
                w.write_u8(0)?;
                w.write_u16::<BE>(*circuit_id)?;
                w.write_all(relay_msg)?;
            }
        }
        Ok(())
    }
}

impl RelayMessage {
    fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let size = r.read_u16::<BE>()? as usize;
        let message_type = r.read_u8()?;
        match message_type {
            ONION_RELAY_EXTEND => {
                let ipv6_flag = r.read_u8()?;
                let tunnel_id = r.read_u32::<BE>()?;
                let (dest_ip, dest_ip_len) = read_ip_addr_from(r, ipv6_flag == 0)?;
                let dest_port = r.read_u16::<BE>()?;
                let mut key = vec![0u8; size - 8 - dest_ip_len - 2];
                r.read_exact(&mut key)?;
                Ok(RelayMessage::Extend(
                    tunnel_id,
                    SocketAddr::new(dest_ip, dest_port),
                    key,
                ))
            }
            ONION_RELAY_DATA => {
                r.read_u8()?;
                let tunnel_id = r.read_u32::<BE>()?;
                let mut data = vec![0u8; size - 8];
                r.read_exact(&mut data)?;
                Ok(RelayMessage::Data(tunnel_id, data))
            }
            _ => Err(anyhow!("Unknown relay message type: {}", message_type)),
        }
    }

    fn size(&self) -> usize {
        match self {
            RelayMessage::Extend(_, dest, key) => {
                let addr_size = if dest.is_ipv4() { 4 } else { 16 };
                // size (2), type (1), ip flag (1), tunnel id (4), ip addr, dest port (2), secret
                2 + 1 + 1 + 4 + addr_size + 2 + key.len()
            }
            RelayMessage::Data(_, data) => {
                // size (2), type (1), padding (1), tunnel_id (4) data
                2 + 1 + 1 + 4 + data.len()
            }
        }
    }

    fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            RelayMessage::Extend(tunnel_id, dest, key) => {
                w.write_u16::<BE>(self.size() as u16)?;
                w.write_u8(ONION_RELAY_EXTEND)?;
                let flag = if dest.is_ipv4() { 0 } else { 1 };
                w.write_u8(flag)?;
                w.write_u32::<BE>(*tunnel_id)?;
                match dest.ip() {
                    IpAddr::V4(addr) => w.write_all(&addr.octets())?,
                    IpAddr::V6(addr) => w.write_all(&addr.octets())?,
                }
                w.write_u16::<BE>(dest.port())?;
                w.write_all(key)?;
            }
            RelayMessage::Data(tunnel_id, data) => {
                w.write_u16::<BE>(self.size() as u16)?;
                w.write_u8(ONION_RELAY_DATA)?;
                w.write_u8(0)?;
                w.write_u32::<BE>(*tunnel_id)?;
                w.write_all(data)?;
            }
        }
        Ok(())
    }
}

impl OpaqueRelayMessage {
    fn decrypt(msg: OnionMessage, decrypt_key: aead::LessSafeKey) -> Result<Self> {
        let mut data = if let OnionMessage::Relay(_, data) = msg {
            data
        } else {
            return Err(anyhow!("Message is not a Relay message"));
        };

        let nonce = aead::Nonce::assume_unique_for_key(todo!());
        decrypt_key.open_in_place(nonce, aead::Aad::empty(), &mut data)?;
        Ok(OpaqueRelayMessage {
            relay_payload: data,
        })
    }

    fn encrypt(
        mut self,
        circuit_id: CircuitId,
        encrypt_key: aead::LessSafeKey,
    ) -> Result<OnionMessage> {
        let nonce = aead::Nonce::assume_unique_for_key(todo!());
        encrypt_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut self.relay_payload)?;
        Ok(OnionMessage::Relay(circuit_id, self.relay_payload))
    }
}

impl From<RelayMessage> for OpaqueRelayMessage {
    fn from(msg: RelayMessage) -> Self {
        let buf = Vec::with_capacity(RELAY_DIGEST_LEN + msg.size());
        let mut cursor = Cursor::new(buf);
        cursor.set_position(RELAY_DIGEST_LEN as u64);
        msg.write_to(&mut cursor).unwrap();
        let mut buf = cursor.into_inner();

        let digest = digest::digest(&digest::SHA256, &buf[RELAY_DIGEST_LEN..]);
        buf[..RELAY_DIGEST_LEN].copy_from_slice(&digest.as_ref()[..RELAY_DIGEST_LEN]);
        OpaqueRelayMessage { relay_payload: buf }
    }
}

impl TryFrom<OpaqueRelayMessage> for RelayMessage {
    type Error = (OpaqueRelayMessage, anyhow::Error);

    /// The returned result is of type `Result<RelayMessage, (OpaqueRelayMessage, anyhow::Error)>`
    /// to allow further use of the opaque relay message in case the conversion fails.
    fn try_from(msg: OpaqueRelayMessage) -> std::result::Result<Self, Self::Error> {
        let digest = digest::digest(&digest::SHA256, &msg.relay_payload[RELAY_DIGEST_LEN..]);
        if &digest.as_ref()[..RELAY_DIGEST_LEN] != &msg.relay_payload[..RELAY_DIGEST_LEN] {
            return Err((msg, anyhow!("Computed hash did not match the message hash")));
        }

        let parsed = RelayMessage::read_from(&mut &msg.relay_payload[RELAY_DIGEST_LEN..])
            .map_err(|e| (msg, e))?;
        Ok(parsed)
    }
}
