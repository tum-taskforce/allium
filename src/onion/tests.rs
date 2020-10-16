use crate::onion::circuit::CircuitHandler;
use crate::onion::crypto::RsaPrivateKey;
use crate::onion::tunnel::{Event, Tunnel, TunnelError};
use crate::*;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::stream;

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
static PORT_COUNTER: AtomicU16 = AtomicU16::new(42000);
const ERROR_TIMEOUT: Duration = Duration::from_secs(4);
const ROUND_DURATION: Duration = Duration::from_secs(5);

pub(crate) fn read_rsa_keypair<P: AsRef<Path>>(path: P) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let private_key = RsaPrivateKey::from_pem_file(path)?;
    let public_key = private_key.public_key();
    Ok((private_key, public_key))
}

async fn listen(listener: TcpListener, host_key: &RsaPrivateKey) -> Result<()> {
    println!(
        "Listening for P2P connections on {}",
        listener.local_addr()?
    );
    let (stream, _) = listener.accept().await?;
    let socket = OnionSocket::new(stream);
    let (incoming, _) = mpsc::channel(1);
    let mut handler = CircuitHandler::init(socket, host_key, incoming).await?;
    handler.handle().await?;
    Ok(())
}

async fn spawn_n_peers(n: usize) -> Vec<Peer> {
    let (host_key, peer_key) = read_rsa_keypair("testkey.pem").unwrap();
    let mut peers = Vec::new();
    let host_key = Arc::new(host_key);
    for _ in 0..n {
        let peer_port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let peer_addr = (TEST_IP, peer_port).into();
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

#[tokio::test]
#[ignore = "broken"]
async fn test_data_unidirectional() -> Result<()> {
    let (host_key, peer_key) = read_rsa_keypair("testkey.pem").unwrap();
    let peer_port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let peer_addr = (TEST_IP, peer_port).into();
    let peer = Peer::new(peer_addr, peer_key);

    let (incoming_tx, mut incoming_rx) = mpsc::channel(100);
    tokio::spawn({
        let mut listener = OnionListener::new(host_key, incoming_tx);
        let tcp_listener = TcpListener::bind(peer_addr).await?;
        async move { listener.listen(tcp_listener).await }
    });

    let (evt_tx, _) = broadcast::channel(1);
    let peer_provider = PeerProvider::from_stream(stream::empty());
    let ctx = OnionContext::new(evt_tx.clone(), peer_provider, 0, false);

    let send_tunnel = ctx.build_tunnel(peer).await.unwrap(); // FIXME task
    evt_tx.send(Event::Switchover).unwrap();
    let mut recv_tunnel = incoming_rx.recv().await.unwrap();

    let data = Bytes::from_static(b"test");
    send_tunnel.write(data.clone()).unwrap();
    assert_eq!(recv_tunnel.read().await.unwrap(), data);
    Ok(())
}

#[tokio::test]
#[ignore = "broken"]
async fn test_data_bidirectional() -> Result<()> {
    let (host_key, peer_key) = read_rsa_keypair("testkey.pem").unwrap();
    let peer_port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let peer_addr = (TEST_IP, peer_port).into();
    let peer = Peer::new(peer_addr, peer_key);

    let data_ping = Bytes::from_static(b"ping");
    let data_pong = Bytes::from_static(b"pong");

    let (incoming_tx, mut incoming_rx) = mpsc::channel(100);
    tokio::spawn({
        let mut listener = OnionListener::new(host_key, incoming_tx);
        let tcp_listener = TcpListener::bind(peer_addr).await?;
        async move { listener.listen(tcp_listener).await }
    });

    tokio::spawn({
        let data_ping = data_ping.clone();
        let data_pong = data_pong.clone();

        async move {
            let mut tunnel = incoming_rx.recv().await.unwrap();
            while let Ok(data) = tunnel.read().await {
                println!("{:?}", &data);
                assert_eq!(data, data_ping);
                tunnel.write(data_pong.clone()).unwrap();
            }
        }
    });

    let (evt_tx, _) = broadcast::channel(1);
    let peer_provider = PeerProvider::from_stream(stream::empty());
    let ctx = OnionContext::new(evt_tx.clone(), peer_provider, 0, false);

    let mut tunnel = ctx.build_tunnel(peer).await.unwrap(); // FIXME task
    evt_tx.send(Event::Switchover).unwrap();

    tunnel.write(data_ping).unwrap();
    assert_eq!(tunnel.read().await.unwrap(), data_pong);
    Ok(())
}

#[tokio::test]
async fn test_keep_alive() -> Result<()> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(3).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..3 {
        tunnel.extend(&peers[i], &rng).await?;
    }
    assert_eq!(tunnel.len(), 3);
    tunnel.keep_alive(&rng).await?;
    assert_eq!(tunnel.len(), 3);
    Ok(())
}

#[tokio::test]
#[ignore = "takes very long to complete"]
async fn test_timeout() -> Result<()> {
    let rng = rand::SystemRandom::new();
    let peers = spawn_n_peers(3).await;
    let mut tunnel = Tunnel::init(0, &peers[0], &rng).await?;
    for i in 1..2 {
        tunnel.extend(&peers[i], &rng).await?;
    }
    assert_eq!(tunnel.len(), 2);

    let tunnel_id = tunnel.id;
    let peer_provider = PeerProvider::from_stream(stream::iter(vec![peers[2].clone()]));
    let builder = TunnelBuilder::new(
        tunnel.id,
        Target::Peer(peers[1].clone()),
        1,
        peer_provider,
        rng,
    );

    let (events_tx, events_rx) = broadcast::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut handler = TunnelHandler::new(tunnel, builder, events_rx, ready_tx);

    let handler_task = tokio::spawn({
        async move {
            handler.handle().await;
        }
    });

    events_tx.send(Event::Switchover).unwrap();
    let ready = time::timeout(ERROR_TIMEOUT, ready_rx)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(ready.id(), tunnel_id);

    let mut delay = time::sleep(circuit::IDLE_TIMEOUT + ERROR_TIMEOUT);
    tokio::select! {
        _ = handler_task => Ok(()),
        _ = &mut delay => {
            panic!("No circuit destroyed the tunnel before timeout")
        },
    }
}
