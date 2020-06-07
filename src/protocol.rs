use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::{Write, Read};
use byteorder::{WriteBytesExt, ReadBytesExt};

use super::Result;

type BE = byteorder::BigEndian;

const ONION_TUNNEL_BUILD: u16 = 560;
const ONION_TUNNEL_READY: u16 = 561;
const ONION_TUNNEL_INCOMING: u16 = 562;
const ONION_TUNNEL_DESTROY: u16 = 563;
const ONION_TUNNEL_DATA: u16 = 564;
const ONION_TUNNEL_ERROR: u16 = 565;
const ONION_TUNNEL_COVER: u16 = 566;

/// Messages received by the onion module.
#[derive(Debug)]
pub enum Request {
    /// This message is to be used by the CM/UI module to request the Onion module to build a tunnel
    /// to the given destination in the next period.
    Build(/* onion_port */ u16, /* dst_addr */ IpAddr, /* dst_hostkey */ Vec<u8>),
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
    Data(/* tunnel_id */ u32, /* tunnel_data */ Vec<u8>),
    /// This message identifies cover traffic which is sent to a random destination by the Onion
    /// module. The CM/UI module uses this message to fabricate cover traffic, mimicking the
    /// characteristics of real VoIP traffic. Upon receiving this message, the Onion module should
    /// send the given amount of random bytes on the tunnel established to a random destination
    /// in a round. It is illegal to send this message when a tunnel is established and Onion has
    /// replied with ONION TUNNEL READY.
    Cover(/* cover_size */ u16),
}

impl Request {
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let size = r.read_u16::<BE>()?;
        let message_type = r.read_u16::<BE>()?;
        return match message_type {
            ONION_TUNNEL_BUILD => {
                let flag = r.read_u16::<BE>()?;
                let onion_port = r.read_u16::<BE>()?;
                let ip_addr = if (flag & 1) == 0 {
                    let addr = r.read_u32::<BE>()?;
                    r.read_u32::<BE>()?;
                    IpAddr::V4(Ipv4Addr::from(addr))
                } else {
                    let addr = r.read_u128::<BE>()?;
                    IpAddr::V6(Ipv6Addr::from(addr))
                };

                let mut dst_hostkey = vec![0u8; size as usize - 24];
                r.read_exact(&mut dst_hostkey)?;
                Ok(Request::Build(onion_port, ip_addr, dst_hostkey))
            },
            ONION_TUNNEL_DESTROY => {
                let tunnel_id = r.read_u32::<BE>()?;
                Ok(Request::Destroy(tunnel_id))
            },
            ONION_TUNNEL_DATA => {
                let tunnel_id = r.read_u32::<BE>()?;
                let mut data = vec![0u8; size as usize - 8];
                r.read_exact(&mut data)?;
                Ok(Request::Data(tunnel_id, data))
            },
            ONION_TUNNEL_COVER => {
                let cover_size = r.read_u16::<BE>()?;
                r.read_u16::<BE>()?;
                Ok(Request::Cover(cover_size))
            },
            _ => Err("Unknown message type".into())
        }
    }
}

/// Messages sent by the onion module.
#[derive(Debug)]
pub enum Response<'a> {
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

impl Response<'_> {
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Response::Ready(tunnel_id, dst_hostkey) => {
                w.write_u16::<BE>(8 + dst_hostkey.len() as u16)?;
                w.write_u16::<BE>(ONION_TUNNEL_READY)?;
                w.write_u32::<BE>(*tunnel_id)?;
                w.write_all(dst_hostkey)?;
            },
            Response::Incoming(tunnel_id) => {
                w.write_u16::<BE>(8)?;
                w.write_u16::<BE>(ONION_TUNNEL_INCOMING)?;
                w.write_u32::<BE>(*tunnel_id)?;
            },
            Response::Data(tunnel_id, tunnel_data) => {
                w.write_u16::<BE>(8 + tunnel_data.len() as u16)?;
                w.write_u16::<BE>(ONION_TUNNEL_DATA)?;
                w.write_u32::<BE>(*tunnel_id)?;
                w.write_all(tunnel_data)?;
            },
            Response::Error(request_type, tunnel_id) => {
                w.write_u16::<BE>(12)?;
                w.write_u16::<BE>(ONION_TUNNEL_ERROR)?;
                w.write_u16::<BE>(*request_type)?;
                w.write_u16::<BE>(0)?;
                w.write_u32::<BE>(*tunnel_id)?;
            },
        }
        Ok(())
    }
}