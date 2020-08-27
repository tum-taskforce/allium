use crate::onion::circuit::CircuitHandler;
use crate::onion::crypto::{self, RsaPrivateKey};
use crate::onion::tunnel::{Tunnel, TunnelError};
use crate::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::stream;

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
static PORT_COUNTER: AtomicU16 = AtomicU16::new(42000);

async fn listen(mut listener: TcpListener, host_key: &RsaPrivateKey) -> Result<()> {
    println!(
        "Listening for P2P connections on {}",
        listener.local_addr()?
    );
    let stream = listener.incoming().next().await.unwrap()?;
    let socket = OnionSocket::new(stream);
    let (events, _) = mpsc::channel(1);
    let mut handler = CircuitHandler::init(socket, host_key, events).await?;
    handler.handle().await?;
    Ok(())
}

async fn spawn_n_peers(n: usize) -> Vec<Peer> {
    let (host_key, peer_key) = crypto::read_rsa_keypair("testkey.pem").unwrap();
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
async fn test_data_unidirectional() -> Result<()> {
    let (host_key, peer_key) = crypto::read_rsa_keypair("testkey.pem").unwrap();
    let peer_port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let peer_addr = (TEST_IP, peer_port).into();
    let peer = Peer::new(peer_addr, peer_key);

    let (evt_tx, mut evt_rx) = mpsc::channel(100);
    tokio::spawn({
        let mut listener = OnionListener::new(host_key, evt_tx, Default::default());
        let tcp_listener = TcpListener::bind(peer_addr).await?;
        async move { listener.listen(tcp_listener).await }
    });

    let (_, req_rx) = mpsc::unbounded_channel();
    let (evt_tx, _) = mpsc::channel(100);
    let peer_provider = PeerProvider::from_stream(stream::empty());
    let mut round_handler =
        RoundHandler::new(req_rx, evt_tx, peer_provider, Default::default(), false, 0);

    let tunnel_id = 3;
    round_handler.handle_build(tunnel_id, peer).await;
    round_handler.next_round().await;
    assert_eq!(evt_rx.recv().await, Some(Event::Incoming { tunnel_id }));

    let data = Bytes::from_static(b"test");
    round_handler.handle_data(tunnel_id, data.clone()).await;
    assert_eq!(evt_rx.recv().await, Some(Event::Data { tunnel_id, data }));
    Ok(())
}

#[tokio::test]
async fn test_data_bidirectional() -> Result<()> {
    let (host_key, peer_key) = crypto::read_rsa_keypair("testkey.pem").unwrap();
    let peer_port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let peer_addr = (TEST_IP, peer_port).into();
    let peer = Peer::new(peer_addr, peer_key);

    let data_ping = Bytes::from_static(b"ping");
    let data_pong = Bytes::from_static(b"pong");

    let (evt_tx, mut evt_rx) = mpsc::channel(100);
    let tunnels = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn({
        let mut listener = OnionListener::new(host_key, evt_tx, tunnels.clone());
        let tcp_listener = TcpListener::bind(peer_addr).await?;
        async move { listener.listen(tcp_listener).await }
    });

    tokio::spawn({
        let data_ping = data_ping.clone();
        let data_pong = data_pong.clone();

        async move {
            while let Some(evt) = evt_rx.recv().await {
                println!("{:?}", &evt);
                match evt {
                    Event::Data { tunnel_id, data } => {
                        assert_eq!(&data[..], &data_ping[..]);
                        let _ = tunnels.lock().await.get(&tunnel_id).unwrap().send(
                            tunnel::Request::Data {
                                data: data_pong.clone(),
                            },
                        );
                    }
                    _ => {}
                }
            }
        }
    });

    let (_, req_rx) = mpsc::unbounded_channel();
    let (evt_tx, mut evt_rx) = mpsc::channel(100);
    let peer_provider = PeerProvider::from_stream(stream::empty());
    let mut round_handler =
        RoundHandler::new(req_rx, evt_tx, peer_provider, Default::default(), false, 0);

    let tunnel_id = 3;
    round_handler.handle_build(tunnel_id, peer).await;
    round_handler.next_round().await;
    assert_eq!(evt_rx.recv().await, Some(Event::Ready { tunnel_id }));

    round_handler.handle_data(tunnel_id, data_ping).await;
    assert_eq!(
        evt_rx.recv().await,
        Some(Event::Data {
            tunnel_id,
            data: data_pong
        })
    );
    Ok(())
}
