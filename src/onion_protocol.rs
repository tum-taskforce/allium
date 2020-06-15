use std::io::{Read, Write};
use std::net::IpAddr;

use anyhow::anyhow;
use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::Result;
use crate::{CircuitId, TunnelId};
use ring::{aead, digest};
use std::collections::VecDeque;

type BE = byteorder::BigEndian;

const ONION_CREATE_REQUEST: u8 = 0x0;
const ONION_CREATE_RESPONSE: u8 = 0x1;
const ONION_RELAY: u8 = 0x3;

const ONION_RELAY_EXTEND: u8 = 0x10;
const ONION_RELAY_DATA: u8 = 0x11;

const ONION_RELAY_EXTENDED: u8 = 0x20;

/// Length in bytes of the digest included in relay messages.
/// Must not be greater than `digest::SHA256_OUTPUT_LEN` (= 32)
const RELAY_DIGEST_LEN: usize = 8;

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
    /// Can be decrypted using `OpaqueRelayMessage::decrypt_from_onion_message`.
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
/// let opaque = OpaqueRelayMessage::decrypt_from_onion_message(key)?;
/// let relay_msg = opaque.try_to_relay_message()?;
/// ```
/// The method `try_to_relay_message` may fail in case the computed digest does not match the digest
/// in the message. This means that the message is not to be consumed by the current peer but to be
/// forwarded in the corresponding tunnel.
///
/// Convert `RelayMessage` to `OnionMessage`:
/// ```text
/// let relay_message = RelayMessage::Extend(...);
/// let opaque = OpaqueRelayMessage::from_relay_message(relay_message);
/// let onion_message = opaque.encrypt_to_onion_message(circuit_id, key)?;
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
/// Can be encrypted using `OpaqueRelayMessage::encrypt_to_onion_message`.
pub(crate) enum RelayMessage {
    // = Requests =
    Extend(
        TunnelId,
        /* dest_addr */ IpAddr,
        /* dest_port */ u16,
        /* secret */ Vec<u8>,
    ),
    Data(TunnelId, /* data */ Vec<u8>),
    // Truncate,
    // = Responses =
    // Extended(TunnelId, /* dest_addr */ IpAddr, /* dest_port */ u16),
    // Truncated(TunnelId, RelayTruncated),
}

impl OnionMessgae {
    fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        Ok(todo!())
    }

    fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            OnionMessage::CreateRequest(circuit_id, secret) => {
                w.write_u8(ONION_CREATE_REQUEST);
                w.write_u8();
                w.write_u16::<BE>(*circuit_id)?;
                // if secret has constant size, this is not needed
                w.write_u16::<BE>(secret.len() as u16)?;
                w.write_all(secret)?;
            }
            OnionMessage::CreateResponse(circuit_id, peer_secret) => {
                w.write_u8(ONION_CREATE_RESPONSE);
                w.write_u8();
                w.write_u16::<BE>(*circuit_id)?;
                // if secret has constant size, this is not needed
                w.write_u16::<BE>(secret.len() as u16)?;
                w.write_all(secret)?;
            }
            OnionMessage::Relay(circuit_id, relay_msg) => {
                w.write_u8(ONION_RELAY);
                w.write_u8();
                w.write_u16::<BE>(*circuit_id)?;
                w.write_all(relay_msg)?;
            }
        }
        Ok(())
    }
}

impl RelayMessage {
    fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        Ok(todo!())
    }

    fn size(&self) -> usize {
        match self {
            RelayMessage::Extend(_, dest_addr, _, secret) => {
                let addr_size = if dest_addr.is_ipv4() { 4 } else { 16 };
                // size (2), type (1), ip flag (1), tunnel id (4), ip addr, dest port (2), secret
                2 + 1 + 1 + 4 + addr_size + 2 + secret.len()
            }
            RelayMessage::Data(_, data) => {
                // size (2), type (1), padding (1), tunnel_id (4) data
                2 + 1 + 1 + 4 + data.len()
            }
        }
    }

    fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            RelayMessage::Extend(tunnel_id, dest_addr, dest_port, secret) => {
                w.write_u16::<BE>(self.size() as u16)?;
                w.write_u8(ONION_RELAY_EXTEND)?;
                let flag = if dest_addr.is_ipv4() { 0 } else { 1 };
                w.write_u8(flag)?;
                w.write_u32::<BE>(*tunnel_id)?;
                match dest_addr {
                    IpAddr::V4(addr) => w.write_all(&addr.octets())?,
                    IpAddr::V6(addr) => w.write_all(&addr.octets())?,
                }
                w.write_u16::<BE>(*dest_port)?;
                w.write_all(secret)?;
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
    fn decrypt_from_onion_message(
        msg: OnionMessage,
        decrypt_key: aead::LessSafeKey,
    ) -> Result<Self> {
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

    fn encrypt_to_onion_message(
        mut self,
        circuit_id: CircuitId,
        encrypt_key: aead::LessSafeKey,
    ) -> Result<OnionMessage> {
        let nonce = aead::Nonce::assume_unique_for_key(todo!());
        encrypt_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut self.relay_payload)?;
        Ok(OnionMessage::Relay(circuit_id, self.relay_payload))
    }

    fn try_to_relay_message(&self) -> Result<RelayMessage> {
        let digest = digest::digest(&digest::SHA256, &self.relay_payload[RELAY_DIGEST_LEN..]);
        if digest != &self.relay_payload[..RELAY_DIGEST_LEN] {
            Err(anyhow!("Invalid Relay message"))
        }

        Ok(RelayMessage::read_from(
            &self.relay_payload[RELAY_DIGEST_LEN..],
        )?)
    }

    fn from_relay_message(msg: RelayMessage) -> Self {
        let mut buf = VecDeque::with_capacity(msg.size());
        msg.write_to(&buf)?;

        let digest = digest::digest(&digest::SHA256, &buf);
        buf.extend(digest.as_ref().iter());
        buf.rotate_right(RELAY_DIGEST_LEN);
        return OpaqueRelayMessage {
            relay_payload: buf.into(),
        };
    }
}
