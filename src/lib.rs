#![allow(dead_code)]
#![allow(unused_variables)]
use std::net::IpAddr;

pub mod messages;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Peer {
    addr: IpAddr,
    port: u16,
    hostkey: Vec<u8>,
}

impl Peer {
    pub fn new(addr: IpAddr, port: u16, hostkey: Vec<u8>) -> Self {
        Peer {
            addr,
            port,
            hostkey,
        }
    }
}

pub struct Tunnel {
    id: u32,
}

pub struct Onion {
    p2p_hostname: String,
    p2p_port: u16,
}

impl Onion {
    pub fn new(p2p_hostname: String, p2p_port: u16) -> Self {
        Onion {
            p2p_hostname,
            p2p_port,
        }
    }

    pub async fn build_tunnel(&self, peers: Vec<Peer>) -> Result<()> {
        Ok(())
    }

    pub async fn destroy_tunnel(&self, tunnel_id: u32) -> Result<()> {
        Ok(())
    }

    pub async fn send_data(&self, tunnel_id: u32, data: &[u8]) -> Result<()> {
        Ok(())
    }

    pub async fn listen_p2p(&self) -> Result<()> {
        Ok(())
    }
}
