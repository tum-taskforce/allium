use bytes::Bytes;
use onion::{ErrorReason, Event, Onion, Peer, PeerProvider, RsaPrivateKey, TunnelId};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use time::Duration;
use tokio::stream;
use tokio::stream::Stream;
use tokio::stream::StreamExt;
use tokio::time;

static PORT_COUNTER: AtomicU16 = AtomicU16::new(42000);
const ERROR_TIMEOUT: Duration = Duration::from_secs(2);
const ROUND_TIMEOUT: Duration = Duration::from_secs(45);
const TUNNEL_ID: TunnelId = 3; // chosen by fair dice roll
const TEST_DATA: &[u8] = b"test";
const LONG_DATA: [u8; 4098] = [13; 4098];

struct TestPeer<S> {
    peer: Peer,
    onion: Onion,
    events: S,
}

fn new_unique_peer() -> (Peer, RsaPrivateKey) {
    let port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let hostkey = RsaPrivateKey::from_pem_file("testkey.pem").unwrap();
    (Peer::new(addr, hostkey.public_key()), hostkey)
}

async fn spawn_peer(peers: Vec<Peer>) -> TestPeer<impl Stream<Item = Event>> {
    let (peer, hostkey) = new_unique_peer();
    let peer_provider = PeerProvider::from_stream(stream::iter(peers));
    let (onion, events) = Onion::new(peer.address(), hostkey, peer_provider)
        .start()
        .unwrap();
    TestPeer {
        peer,
        onion,
        events,
    }
}

#[tokio::test]
async fn test_idle() {
    let _ = spawn_peer(vec![]).await;
}

#[tokio::test]
async fn test_cover() {
    let peer1 = spawn_peer(vec![]).await;
    let mut peer2 = spawn_peer(vec![peer1.peer.clone(), peer1.peer]).await;
    time::delay_for(ERROR_TIMEOUT).await;
    peer2.onion.send_cover(1);
    match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
        Ok(e) => panic!("Got error event: {:?}", e),
        Err(_) => {}
    }
}

#[tokio::test]
async fn test_cover_error() {
    let mut peer1 = spawn_peer(vec![]).await;
    peer1.onion.send_cover(1);
    match time::timeout(ERROR_TIMEOUT, peer1.events.next()).await {
        Ok(Some(Event::Error {
            reason: ErrorReason::Cover,
            ..
        })) => {}
        Ok(e) => panic!("Expected error event, got {:?}", e),
        Err(_) => panic!("Expected error event, got timeout"),
    }
}

#[tokio::test]
async fn test_build() {
    let mut peer1 = spawn_peer(vec![]).await;
    let mut peer2 = spawn_peer(vec![]).await;
    peer1.onion.build_tunnel(TUNNEL_ID, peer2.peer, 0);
    match time::timeout(ROUND_TIMEOUT, peer1.events.next()).await {
        Ok(Some(Event::Ready { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected ready event, got {:?}", e),
        Err(_) => panic!("Expected ready event, got timeout"),
    }

    match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
        Ok(Some(Event::Incoming { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected incoming event, got {:?}", e),
        Err(_) => panic!("Expected incoming event, got timeout"),
    }
}

#[tokio::test]
async fn test_build_error() {
    let mut peer1 = spawn_peer(vec![]).await;
    let (peer2, _) = new_unique_peer();
    peer1.onion.build_tunnel(TUNNEL_ID, peer2, 0);
    match time::timeout(ERROR_TIMEOUT, peer1.events.next()).await {
        Ok(Some(Event::Error {
            reason: ErrorReason::Build,
            tunnel_id,
        })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected error event, got {:?}", e),
        Err(_) => panic!("Expected error event, got timeout"),
    }
}

#[tokio::test]
async fn test_data() {
    let mut peer1 = spawn_peer(vec![]).await;
    let mut peer2 = spawn_peer(vec![]).await;

    peer1.onion.build_tunnel(TUNNEL_ID, peer2.peer, 0);
    match time::timeout(ROUND_TIMEOUT, peer1.events.next()).await {
        Ok(Some(Event::Ready { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected ready event, got {:?}", e),
        Err(_) => panic!("Expected ready event, got timeout"),
    }

    match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
        Ok(Some(Event::Incoming { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected incoming event, got {:?}", e),
        Err(_) => panic!("Expected incoming event, got timeout"),
    }

    peer1.onion.send_data(TUNNEL_ID, TEST_DATA);
    match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
        Ok(Some(Event::Data { tunnel_id, data })) => {
            assert_eq!(tunnel_id, TUNNEL_ID);
            assert_eq!(data, Bytes::from_static(&TEST_DATA));
        }
        Ok(e) => panic!("Expected ready event, got {:?}", e),
        Err(_) => panic!("Expected ready event, got timeout"),
    }
}

#[tokio::test]
async fn test_long_data() {
    let mut peer1 = spawn_peer(vec![]).await;
    let mut peer2 = spawn_peer(vec![]).await;

    peer1.onion.build_tunnel(TUNNEL_ID, peer2.peer, 0);
    match time::timeout(ROUND_TIMEOUT, peer1.events.next()).await {
        Ok(Some(Event::Ready { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected ready event, got {:?}", e),
        Err(_) => panic!("Expected ready event, got timeout"),
    }

    match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
        Ok(Some(Event::Incoming { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected incoming event, got {:?}", e),
        Err(_) => panic!("Expected incoming event, got timeout"),
    }

    peer1.onion.send_data(TUNNEL_ID, &LONG_DATA);
    let mut bytes_received = 0;

    while bytes_received < LONG_DATA.len() {
        match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
            Ok(Some(Event::Data { tunnel_id, data })) => {
                bytes_received += data.len();
                assert_eq!(tunnel_id, TUNNEL_ID);
            }
            Ok(e) => panic!("Expected ready event, got {:?}", e),
            Err(_) => panic!("Expected ready event, got timeout"),
        }
    }
}

async fn spawn_many_peers(n: usize) -> Vec<Peer> {
    let mut peers = vec![];
    for _ in 0..n {
        let peer = spawn_peer(vec![]).await;
        peers.push(peer.peer);
    }
    peers
}

#[tokio::test]
async fn test_long_data_two_hops() {
    let hops = spawn_many_peers(3).await;
    let mut peer1 = spawn_peer(hops).await;
    let mut peer2 = spawn_peer(vec![]).await;

    peer1.onion.build_tunnel(TUNNEL_ID, peer2.peer, 0);
    match time::timeout(ROUND_TIMEOUT, peer1.events.next()).await {
        Ok(Some(Event::Ready { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected ready event, got {:?}", e),
        Err(_) => panic!("Expected ready event, got timeout"),
    }

    match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
        Ok(Some(Event::Incoming { tunnel_id })) => assert_eq!(tunnel_id, TUNNEL_ID),
        Ok(e) => panic!("Expected incoming event, got {:?}", e),
        Err(_) => panic!("Expected incoming event, got timeout"),
    }

    peer1.onion.send_data(TUNNEL_ID, &LONG_DATA);
    let mut bytes_received = 0;

    while bytes_received < LONG_DATA.len() {
        match time::timeout(ERROR_TIMEOUT, peer2.events.next()).await {
            Ok(Some(Event::Data { tunnel_id, data })) => {
                bytes_received += data.len();
                assert_eq!(tunnel_id, TUNNEL_ID);
            }
            Ok(e) => panic!("Expected ready event, got {:?}", e),
            Err(_) => panic!("Expected ready event, got timeout"),
        }
    }
}
