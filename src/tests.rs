use super::*;
use crate::circuit::CircuitHandler;
use crate::tunnel::Tunnel;
use crate::utils::read_hostkey;
use ring::signature::KeyPair;
use std::net::{IpAddr, Ipv4Addr};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TEST_PORT: u16 = 4200;

async fn listen(mut listener: TcpListener, host_key: &signature::RsaKeyPair) -> Result<()> {
    println!(
        "Listening for p2p connections on {}",
        listener.local_addr()?
    );
    let stream = listener.incoming().next().await.unwrap()?;
    let socket = OnionSocket::new(stream);
    let mut handler = CircuitHandler::init(socket, host_key).await?;
    handler.handle().await?;
    Ok(())
}

fn read_rsa_testkey() -> Result<(signature::RsaKeyPair, Vec<u8>)> {
    let key_pair = signature::RsaKeyPair::from_pkcs8(&read_hostkey("testkey.pem")?)?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    Ok((key_pair, public_key))
}

async fn spawn_n_peers(n: usize) -> Vec<Peer> {
    let (host_key, peer_key) = read_rsa_testkey().unwrap();
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

async fn build_tunnel_n_peers(n: usize) -> Result<()> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(n).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..n {
        tunnel.extend(&peers[i], &rng).await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_handshake_single_peer() -> Result<()> {
    build_tunnel_n_peers(1).await?;
    Ok(())
}

#[tokio::test]
async fn test_handshake_two_peers() -> Result<()> {
    build_tunnel_n_peers(2).await?;
    Ok(())
}

#[tokio::test]
async fn test_handshake_three_peers() -> Result<()> {
    build_tunnel_n_peers(3).await?;
    Ok(())
}