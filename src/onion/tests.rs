use crate::onion::circuit::CircuitHandler;
use crate::onion::crypto::{self, RsaPrivateKey};
use crate::onion::tunnel::{Tunnel, TunnelError};
use crate::*;
use std::net::{IpAddr, Ipv4Addr};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TEST_PORT: u16 = 4200;

async fn listen(mut listener: TcpListener, host_key: &RsaPrivateKey) -> Result<()> {
    println!(
        "Listening for P2P connections on {}",
        listener.local_addr()?
    );
    let stream = listener.incoming().next().await.unwrap()?;
    let socket = OnionSocket::new(stream);
    let (events, _) = mpsc::channel(1);
    let (tunnel_tx, _) = oneshot::channel();
    let mut handler = CircuitHandler::init(socket, host_key, events, tunnel_tx).await?;
    handler.handle().await?;
    Ok(())
}

async fn spawn_n_peers(n: usize) -> Vec<Peer> {
    let (host_key, peer_key) = crypto::read_rsa_keypair("testkey.pem").unwrap();
    let mut peers = Vec::new();
    let host_key = Arc::new(host_key);
    for i in 0..n {
        let peer_addr = (TEST_IP, TEST_PORT + i as u16).into();
        let listener = TcpListener::bind(&peer_addr).await.unwrap();
        let host_key = host_key.clone();
        tokio::spawn(async move {
            listen(listener, &host_key).await.unwrap();
        });
        peers.push(Peer::new(peer_addr, peer_key.clone()));
    }
    peers
}

async fn build_tunnel_n_peers(n: usize) -> Result<Tunnel> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(n).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..n {
        tunnel.extend(&peers[i], &rng).await?;
    }
    Ok(tunnel)
}

#[tokio::test]
async fn test_handshake_single_peer() -> Result<()> {
    let tunnel = build_tunnel_n_peers(1).await?;
    assert_eq!(tunnel.len(), 1);
    Ok(())
}

#[tokio::test]
async fn test_handshake_two_peers() -> Result<()> {
    let tunnel = build_tunnel_n_peers(2).await?;
    assert_eq!(tunnel.len(), 2);
    Ok(())
}

#[tokio::test]
async fn test_handshake_three_peers() -> Result<()> {
    let tunnel = build_tunnel_n_peers(3).await?;
    assert_eq!(tunnel.len(), 3);
    Ok(())
}

#[tokio::test]
async fn test_truncate_zero_peers() -> Result<()> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(2).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..2 {
        tunnel.extend(&peers[i], &rng).await?;
    }
    match tunnel.truncate(0, &rng).await {
        Err(TunnelError::Incomplete) => {
            assert_eq!(tunnel.len(), 2);
            Ok(())
        }
        _ => Err(anyhow!(
            "Expected truncate to fail since it tries to truncate a non-existing tail"
        )),
    }
}

#[tokio::test]
async fn test_truncate_one_peer() -> Result<()> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(2).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..2 {
        tunnel.extend(&peers[i], &rng).await?;
    }
    tunnel.truncate(1, &rng).await?;
    assert_eq!(tunnel.len(), 1);
    Ok(())
}

#[tokio::test]
async fn test_truncate_two_peers() -> Result<()> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(3).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..3 {
        tunnel.extend(&peers[i], &rng).await?;
    }
    assert_eq!(tunnel.len(), 3);
    tunnel.truncate(2, &rng).await?;
    assert_eq!(tunnel.len(), 1);
    Ok(())
}
