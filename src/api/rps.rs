use crate::api::config::{PeerConfig, RpsConfig};
use crate::api::protocol::{Module, RpsRequest, RpsResponse};
use crate::api::socket::ApiSocket;
use crate::Result;
use anyhow::anyhow;
use log::info;
use onion::{Peer, RsaPrivateKey, RsaPublicKey};
use ring::signature;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub enum RpsModule {
    Socket(SocketRpsModule),
    Mock(Vec<Peer>, usize),
}

impl RpsModule {
    pub async fn new(config: &RpsConfig) -> Result<Self> {
        if let Some(api_address) = &config.api_address {
            Ok(Self::Socket(SocketRpsModule::connect(api_address).await?))
        } else if let Some(peers) = &config.peers {
            let peers = peers.iter().filter_map(peer_from_config).collect();
            Ok(Self::Mock(peers, 0))
        } else {
            Err(anyhow!(
                "The RPS config must either specify api_address or peers"
            ))
        }
    }

    pub async fn query(&mut self) -> Result<Peer> {
        match self {
            RpsModule::Socket(s) => s.query().await,
            RpsModule::Mock(peers, i) => {
                let peer = peers[*i].clone();
                *i = (*i + 1) % peers.len();
                Ok(peer)
            }
        }
    }
}

fn peer_from_config(config: &PeerConfig) -> Option<Peer> {
    let hostkey = RsaPrivateKey::from_pem_file("testkey.pem").ok()?;
    Some(Peer::new(config.p2p_address, hostkey.public_key()))
}

pub struct SocketRpsModule {
    socket: ApiSocket<TcpStream>,
}

impl SocketRpsModule {
    async fn connect(api_address: &SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(api_address).await?;
        info!("Connected to RPS module at {:?}", stream.peer_addr());
        let socket = ApiSocket::new(stream);
        Ok(SocketRpsModule { socket })
    }

    async fn query(&mut self) -> Result<Peer> {
        self.socket.write(RpsRequest::Query).await?;
        if let Some(msg) = self.socket.read_next().await? {
            match msg {
                RpsResponse::Peer(_port, portmap, peer_addr, peer_hostkey) => {
                    let (_, peer_port) = portmap
                        .iter()
                        .find(|(m, _)| *m == Module::Onion)
                        .ok_or(anyhow!("Peer does not expose onion port"))?;
                    let peer_addr = SocketAddr::new(peer_addr, *peer_port);
                    let peer_hostkey = RsaPublicKey::new(peer_hostkey.to_vec());
                    Ok(Peer::new(peer_addr, peer_hostkey))
                }
            }
        } else {
            Err(anyhow!("rps query failed"))
        }
    }
}
