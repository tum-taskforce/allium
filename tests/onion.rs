use allium::{Incoming, OnionBuilder, OnionContext, Peer, PeerProvider, RsaPrivateKey};
use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use time::Duration;
use tokio::stream;
use tokio::time;

static PORT_COUNTER: AtomicU16 = AtomicU16::new(42000);
const ROUND_DURATION: Duration = Duration::from_secs(5);
const ERROR_TIMEOUT: Duration = Duration::from_secs(4);
const ROUND_TIMEOUT: Duration = Duration::from_secs(7);
const DELAY_TIMEOUT: Duration = Duration::from_secs(2);
const TEST_DATA: Bytes = Bytes::from_static(b"test");
const LONG_DATA: Bytes = Bytes::from_static(&[13; 4098]);

struct TestPeer {
    peer: Peer,
    ctx: OnionContext,
    incoming: Incoming,
}

fn new_unique_peer() -> (Peer, RsaPrivateKey) {
    let port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let hostkey = RsaPrivateKey::from_pem_file("testkey.pem").unwrap();
    (Peer::new(addr, hostkey.public_key()), hostkey)
}

fn new_unique_peers(n: usize) -> Vec<Peer> {
    let mut peers = vec![];
    for _ in 0..n {
        let (peer, _) = new_unique_peer();
        peers.push(peer);
    }
    peers
}

async fn spawn_peer(peers: Vec<Peer>, cover: bool, hops: usize) -> TestPeer {
    let (peer, hostkey) = new_unique_peer();
    let peer_provider = PeerProvider::from_stream(stream::iter(peers));
    let (ctx, incoming) = OnionBuilder::new(peer.address(), hostkey, peer_provider)
        .enable_cover_traffic(cover)
        .set_hops_per_tunnel(hops)
        .set_round_duration(ROUND_DURATION.as_secs())
        .start();
    TestPeer {
        peer,
        ctx,
        incoming,
    }
}

async fn spawn_simple_peer() -> TestPeer {
    spawn_peer(vec![], false, 0).await
}

#[tokio::test]
async fn test_idle() {
    let _ = spawn_simple_peer().await;
}

#[tokio::test]
async fn test_cover_success() {
    pretty_env_logger::init();
    let peer1 = spawn_simple_peer().await;
    let peer2 = spawn_peer(vec![peer1.peer], true, 0).await;
    time::sleep(DELAY_TIMEOUT).await;
    peer2.ctx.send_cover(1).unwrap();
}

#[tokio::test]
async fn test_cover_error() {
    let peer1 = spawn_simple_peer().await;
    peer1.ctx.send_cover(1).unwrap_err();
}

#[tokio::test]
async fn test_build_success() {
    let peer1 = spawn_simple_peer().await;
    let mut peer2 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer2.peer);
    let ready_id = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap()
        .id();
    let incoming_id = time::timeout(ERROR_TIMEOUT, peer2.incoming.next())
        .await
        .unwrap()
        .unwrap()
        .id();
    assert_eq!(incoming_id, ready_id);
}

#[tokio::test]
async fn test_build_error() {
    let peer1 = spawn_simple_peer().await;
    let (peer2, _) = new_unique_peer();

    let ready_fut = peer1.ctx.build_tunnel(peer2);
    time::timeout(ERROR_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap_err();
}

#[tokio::test]
async fn test_build_unstable_success() {
    // For some reason 8 (MAX_PEER_FAILURES - 2) or higher fails
    let mut hop_candidates = new_unique_peers(7);
    let peer2 = spawn_simple_peer().await;
    hop_candidates.push(peer2.peer);
    let peer1 = spawn_peer(hop_candidates, false, 1).await;
    let mut peer3 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer3.peer);
    let ready_id = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap()
        .id();
    let incoming_id = time::timeout(ERROR_TIMEOUT, peer3.incoming.next())
        .await
        .unwrap()
        .unwrap()
        .id();
    assert_eq!(incoming_id, ready_id);
}

#[tokio::test]
async fn test_build_unstable_error() {
    let mut hop_candidates = new_unique_peers(12);
    let peer2 = spawn_simple_peer().await;
    hop_candidates.push(peer2.peer);
    let peer1 = spawn_peer(hop_candidates, false, 1).await;
    let peer3 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer3.peer);
    time::timeout(ERROR_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap_err();
}

#[tokio::test]
async fn test_data() {
    let peer1 = spawn_simple_peer().await;
    let mut peer2 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer2.peer);
    let ready = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap();

    let mut incoming = time::timeout(ERROR_TIMEOUT, peer2.incoming.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.id(), ready.id());

    ready.write(TEST_DATA).unwrap();
    let read_data = time::timeout(ERROR_TIMEOUT, incoming.read())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read_data, TEST_DATA);
}

#[tokio::test]
async fn test_long_data() {
    let peer1 = spawn_simple_peer().await;
    let mut peer2 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer2.peer);
    let ready = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap();

    let mut incoming = time::timeout(ERROR_TIMEOUT, peer2.incoming.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.id(), ready.id());

    ready.write(LONG_DATA).unwrap();
    let mut bytes_received = 0;

    while bytes_received < LONG_DATA.len() {
        let read_data = time::timeout(ERROR_TIMEOUT, incoming.read())
            .await
            .unwrap()
            .unwrap();
        bytes_received += read_data.len();
    }
}

async fn spawn_many_peers(n: usize) -> Vec<Peer> {
    let mut peers = vec![];
    for _ in 0..n {
        let peer = spawn_simple_peer().await;
        peers.push(peer.peer);
    }
    peers
}

#[tokio::test]
async fn test_long_data_two_hops() {
    let hops = spawn_many_peers(2).await;
    let peer1 = spawn_peer(hops, false, 2).await;
    let mut peer2 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer2.peer);
    let ready = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap();

    let mut incoming = time::timeout(ERROR_TIMEOUT, peer2.incoming.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.id(), ready.id());

    ready.write(LONG_DATA).unwrap();
    let mut bytes_received = 0;

    while bytes_received < LONG_DATA.len() {
        let read_data = time::timeout(ERROR_TIMEOUT, incoming.read())
            .await
            .unwrap()
            .unwrap();
        bytes_received += read_data.len();
    }
}

#[tokio::test]
async fn test_data_error_disconnected_destination() {
    let peer1 = spawn_simple_peer().await;
    let mut peer2 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer2.peer);
    let ready = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap();

    let incoming = time::timeout(ERROR_TIMEOUT, peer2.incoming.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.id(), ready.id());

    drop(incoming);
    time::sleep(DELAY_TIMEOUT).await;
    ready.write(TEST_DATA).unwrap_err();
}

#[tokio::test]
async fn test_data_error_disconnected_source() {
    let peer1 = spawn_simple_peer().await;
    let mut peer2 = spawn_simple_peer().await;

    let ready_fut = peer1.ctx.build_tunnel(peer2.peer);
    let ready = time::timeout(ROUND_TIMEOUT, ready_fut)
        .await
        .unwrap()
        .unwrap();

    let mut incoming = time::timeout(ERROR_TIMEOUT, peer2.incoming.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.id(), ready.id());

    drop(ready);
    time::timeout(ROUND_TIMEOUT, incoming.read())
        .await
        .unwrap()
        .unwrap_err();
}
