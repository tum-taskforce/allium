use std::net::IpAddr;

use crate::utils::{get_ip_addr, FromBytes, ToBytes};
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use onion::Result;
use std::net::SocketAddr;
use std::fmt;
use serde::export::Formatter;

const ONION_TUNNEL_BUILD: u16 = 560;
const ONION_TUNNEL_READY: u16 = 561;
const ONION_TUNNEL_INCOMING: u16 = 562;
const ONION_TUNNEL_DESTROY: u16 = 563;
const ONION_TUNNEL_DATA: u16 = 564;
const ONION_TUNNEL_ERROR: u16 = 565;
const ONION_TUNNEL_COVER: u16 = 566;

/// Messages received by the onion module.
pub enum OnionRequest {
    /// This message is to be used by the CM/UI module to request the Onion module to build a tunnel
    /// to the given destination in the next period.
    Build(/* dst_addr */ SocketAddr, /* dst_hostkey */ Bytes),
    /// This message is used to instruct the Onion module that a tunnel it created is no longer in
    /// use and can now be destroyed. The tunnel ID should be valid, i.e., it should have been
    /// solicited by the Onion module in a previous ONION TUNNEL READY or ONION TUNNEL INCOMING
    /// message.
    Destroy(/* tunnel_id */ u32),
    /// This message is used to ask Onion to forward data through a tunnel. It is also used by Onion
    /// to deliver data from an incoming tunnel. The tunnel ID in the message corresponds to the
    /// tunnel which is used to forwarding the data; for incoming data it is the tunnel on which the
    /// data is received. For outgoing data, Onion should make a best effort to forward the given
    /// data. However, no guarantee is given: the data could be lost and/or delivered out of order.
    Data(/* tunnel_id */ u32, /* tunnel_data */ Bytes),
    /// This message identifies cover traffic which is sent to a random destination by the Onion
    /// module. The CM/UI module uses this message to fabricate cover traffic, mimicking the
    /// characteristics of real VoIP traffic. Upon receiving this message, the Onion module should
    /// send the given amount of random bytes on the tunnel established to a random destination
    /// in a round. It is illegal to send this message when a tunnel is established and Onion has
    /// replied with ONION TUNNEL READY.
    Cover(/* cover_size */ u16),
}

impl fmt::Debug for OnionRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OnionRequest::Build(dst_addr, _) => {
                f.debug_struct("Build")
                    .field("dst_addr", dst_addr)
                    .finish()
            },
            OnionRequest::Destroy(tunnel_id) => {
                f.debug_struct("Destroy")
                    .field("tunnel_id", tunnel_id)
                    .finish()
            },
            OnionRequest::Data(tunnel_id, data) => {
                f.debug_struct("Data")
                    .field("tunnel_id", tunnel_id)
                    .field("data.len()", &data.len())
                    .finish()
            },
            OnionRequest::Cover(cover_size) => {
                f.debug_struct("Cover")
                    .field("cover_size", cover_size)
                    .finish()
            },
        }
    }
}

impl FromBytes for Result<OnionRequest> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u16();
        return match message_type {
            ONION_TUNNEL_BUILD => {
                let flag = buf.get_u16();
                let dst_port = buf.get_u16();
                let dst_ip = get_ip_addr(buf, (flag & 1) == 1);
                let dst_addr = SocketAddr::new(dst_ip, dst_port);

                let dst_hostkey = buf.split_to(size - 8 - dst_addr.ip().size()).freeze();
                Ok(OnionRequest::Build(dst_addr, dst_hostkey))
            }
            ONION_TUNNEL_DESTROY => {
                let tunnel_id = buf.get_u32();
                Ok(OnionRequest::Destroy(tunnel_id))
            }
            ONION_TUNNEL_DATA => {
                let tunnel_id = buf.get_u32();
                let data = buf.split_to(size - 8).freeze();
                Ok(OnionRequest::Data(tunnel_id, data))
            }
            ONION_TUNNEL_COVER => {
                let cover_size = buf.get_u16();
                buf.get_u16();
                Ok(OnionRequest::Cover(cover_size))
            }
            _ => Err(anyhow!("Unknown onion message type: {}", message_type)),
        };
    }
}

impl OnionRequest {
    pub fn id(&self) -> u16 {
        match self {
            OnionRequest::Build(_, _) => ONION_TUNNEL_BUILD,
            OnionRequest::Destroy(_) => ONION_TUNNEL_DESTROY,
            OnionRequest::Data(_, _) => ONION_TUNNEL_DATA,
            OnionRequest::Cover(_) => ONION_TUNNEL_COVER,
        }
    }
}

/// Messages sent by the onion module.
#[derive(Debug)]
pub enum OnionResponse<'a> {
    /// This message is sent by the Onion module when the requested tunnel is built. The recipient
    /// is allowed to send data in this tunnel after receiving this message. It contains the
    /// identity of the destination peer and a tunnel ID which is assigned by the Onion moduel to
    /// uniquely identify different tunnels.
    Ready(/* tunnel_id */ u32, /* dst_hostkey */ &'a [u8]),
    /// This message is sent by the Onion module on all of its API connections to signal a new
    /// incoming tunnel connection. The new tunnel will be identified by the given tunnel ID.
    /// No response is solicited by Onion for this message. When undesired, the tunnel could be
    /// destroyed by sending an ONION TUNNEL DESTROY message. Incoming data on this tunnel is
    /// duplicated and sent to all API connections which have not yet sent an ONION TUNNEL DESTROY
    /// for this tunnel ID. An incoming tunnel is to be destroyed only if all the API connections
    /// sent a ONION TUNNEL DESTROY for it.
    Incoming(/* tunnel_id */ u32),
    /// This message is used to ask Onion to forward data through a tunnel. It is also used by Onion
    /// to deliver data from an incoming tunnel. The tunnel ID in the message corresponds to the
    /// tunnel which is used to forwarding the data; for incoming data it is the tunnel on which the
    /// data is received. For outgoing data, Onion should make a best effort to forward the given
    /// data. However, no guarantee is given: the data could be lost and/or delivered out of order.
    Data(/* tunnel_id */ u32, /* tunnel_data */ &'a [u8]),
    /// This message is sent by the Onion module to signal an error condition which stems from
    /// servicing an earlier request. The message contains the tunnel ID to signal the failure of an
    /// established tunnel. The reported error condition is not be mistaken with API violations.
    /// Error conditions trigger upon correct usage of API. API violations are to be handled by
    /// terminating the connection to the misbehaving client.
    Error(/* request_type */ u16, /* tunnel_id */ u32),
}

impl ToBytes for OnionResponse<'_> {
    fn size(&self) -> usize {
        match self {
            OnionResponse::Ready(_, dst_hostkey) => 8 + dst_hostkey.len(),
            OnionResponse::Incoming(_) => 8,
            OnionResponse::Data(_, tunnel_data) => 8 + tunnel_data.len(),
            OnionResponse::Error(_, _) => 12,
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            OnionResponse::Ready(tunnel_id, dst_hostkey) => {
                buf.put_u16(self.size() as u16);
                buf.put_u16(ONION_TUNNEL_READY);
                buf.put_u32(*tunnel_id);
                buf.put(*dst_hostkey);
            }
            OnionResponse::Incoming(tunnel_id) => {
                buf.put_u16(self.size() as u16);
                buf.put_u16(ONION_TUNNEL_INCOMING);
                buf.put_u32(*tunnel_id);
            }
            OnionResponse::Data(tunnel_id, tunnel_data) => {
                buf.put_u16(self.size() as u16);
                buf.put_u16(ONION_TUNNEL_DATA);
                buf.put_u32(*tunnel_id);
                buf.put(*tunnel_data);
            }
            OnionResponse::Error(request_type, tunnel_id) => {
                buf.put_u16(self.size() as u16);
                buf.put_u16(ONION_TUNNEL_ERROR);
                buf.put_u16(*request_type);
                buf.put_u16(0);
                buf.put_u32(*tunnel_id);
            }
        }
    }
}

const RPS_QUERY: u16 = 540;
const RPS_PEER: u16 = 541;

const MODULE_DHT: u16 = 650;
const MODULE_GOSSIP: u16 = 500;
const MODULE_NSE: u16 = 520;
const MODULE_ONION: u16 = 560;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Module {
    Dht,
    Gossip,
    Nse,
    Onion,
}

impl Module {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            MODULE_DHT => Ok(Module::Dht),
            MODULE_GOSSIP => Ok(Module::Gossip),
            MODULE_NSE => Ok(Module::Nse),
            MODULE_ONION => Ok(Module::Onion),
            _ => Err(anyhow!("Unknown module id: {}", id)),
        }
    }
}

/// Messages received by the RPS module.
#[derive(Debug)]
pub enum RpsRequest {
    /// This message is used to ask RPS to reply with a random peer.
    Query,
}

impl ToBytes for RpsRequest {
    fn size(&self) -> usize {
        match self {
            RpsRequest::Query => 4,
        }
    }

    fn write_to(&self, buf: &mut BytesMut) {
        match self {
            RpsRequest::Query => {
                buf.put_u16(self.size() as u16);
                buf.put_u16(RPS_QUERY);
            }
        }
    }
}

/// Messages sent by the RPS module.
#[derive(Debug)]
pub enum RpsResponse {
    /// This message is sent by the RPS module as a response to the RPS QUERY message. It contains
    /// the peer identity and the network address of a peer which is selected by RPS at random. In
    /// addition to this it also contains a portmap for the P2P listen ports of the various modules
    /// on the random peer. RPS should sample random peers from the currently online peers.
    /// Therefore the peer sent in this message is very likely to be online, but no guarantee can be
    /// made about its availability.
    Peer(
        /* port */ u16,
        /* portmap */ Vec<(Module, u16)>,
        /* peer_addr */ IpAddr,
        /* peer_hostkey */ Bytes,
    ),
}

impl FromBytes for Result<RpsResponse> {
    fn read_from(buf: &mut BytesMut) -> Self {
        let size = buf.get_u16() as usize;
        let message_type = buf.get_u16();
        return match message_type {
            RPS_PEER => {
                let port = buf.get_u16();
                let portmap_len = buf.get_u8() as usize;
                let flag = buf.get_u8();

                let mut portmap = Vec::with_capacity(portmap_len);
                for _ in 0..portmap_len {
                    let mod_id = buf.get_u16();
                    let port = buf.get_u16();
                    portmap.push((Module::from_id(mod_id)?, port))
                }

                let peer_addr = get_ip_addr(buf, (flag & 1) == 1);
                let peer_hostkey = buf
                    .split_to(size - 8 - portmap_len * 4 - peer_addr.size())
                    .freeze();
                Ok(RpsResponse::Peer(port, portmap, peer_addr, peer_hostkey))
            }
            _ => Err(anyhow!("Unknown RPS message type: {}", message_type)),
        };
    }
}

impl RpsResponse {
    pub fn id(&self) -> u16 {
        match self {
            RpsResponse::Peer(_, _, _, _) => RPS_PEER,
        }
    }
}
