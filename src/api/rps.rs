use crate::api::config::{PeerConfig, RpsConfig};
use crate::api::protocol::{Module, RpsRequest, RpsResponse};
use crate::api::socket::ApiSocket;
use crate::Result;
use allium::{Peer, RsaPrivateKey, RsaPublicKey};
use anyhow::anyhow;
use futures::Stream;
use log::info;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time;
use tokio::time::Duration;

const PEER_BUFFER_SIZE: usize = 20;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

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

    pub fn into_stream(mut self) -> impl Stream<Item = Peer> {
        let (peer_tx, peer_rx) = mpsc::channel(PEER_BUFFER_SIZE);
        tokio::spawn(async move {
            loop {
                let peer = self.query().await.unwrap();
                peer_tx.send(peer).await.unwrap();
            }
        });
        peer_rx
    }
}

fn peer_from_config(config: &PeerConfig) -> Option<Peer> {
    let hostkey = RsaPrivateKey::from_pem_file(&config.hostkey).ok()?;
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
        let msg = time::timeout(QUERY_TIMEOUT, self.socket.read_next())
            .await
            .map_err(|_| anyhow!("RPS query timed out"))?
            .map_err(|e| anyhow!("RPS query failed: {}", e))?;

        match msg {
            RpsResponse::Peer(_port, portmap, peer_addr, peer_hostkey) => {
                let (_, peer_port) = portmap
                    .iter()
                    .find(|(m, _)| *m == Module::Onion)
                    .ok_or_else(|| anyhow!("Peer does not expose onion port"))?;
                let peer_addr = SocketAddr::new(peer_addr, *peer_port);
                let peer_hostkey = RsaPublicKey::new(peer_hostkey.as_ref());
                Ok(Peer::new(peer_addr, peer_hostkey))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::config::RpsConfig;
    use crate::api::rps::RpsModule;

    #[tokio::test]
    #[ignore = "requires a running RPS instance listening on 127.0.0.1:7101"]
    async fn test_rps_query() {
        let config = RpsConfig {
            api_address: Some("127.0.0.1:7101".parse().unwrap()),
            peers: None,
        };

        let mut rps = RpsModule::new(&config).await.unwrap();
        println!("Connected to RPS");
        println!("{:?}", rps.query().await);
    }
}
