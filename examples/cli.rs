use allium::{
    OnionBuilder, OnionContext, Peer, PeerProvider, RsaPrivateKey, RsaPublicKey, Tunnel, TunnelId,
    TunnelWriter,
};
use std::collections::HashMap;
use std::env;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

const DEFAULT_ADDR: &str = "127.0.0.1:4200";

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    let onion_addr = env::args()
        .nth(1)
        .unwrap_or(DEFAULT_ADDR.to_string())
        .parse()
        .unwrap();
    let cover_enabled = env::args().any(|arg| arg == "--cover");
    let hostkey = RsaPrivateKey::from_pem_file("testkey.pem").unwrap();
    let public_key = hostkey.public_key();
    let (mut peer_tx, peer_rx) = mpsc::unbounded_channel();
    let peer_rx = UnboundedReceiverStream::new(peer_rx);
    let (onion, mut incoming) =
        OnionBuilder::new(onion_addr, hostkey, PeerProvider::from_stream(peer_rx))
            .enable_cover_traffic(cover_enabled)
            .set_hops_per_tunnel(0)
            .start();

    let mut tunnels: HashMap<TunnelId, TunnelWriter> = HashMap::new();

    let mut stdin = BufReader::new(io::stdin()).lines();
    loop {
        tokio::select! {
            Some(tunnel) = incoming.next() => {
                println!("Incoming tunnel with ID {}", tunnel.id());
                tunnels.insert(tunnel.id(), tunnel.writer());
                handle_tunnel_data(tunnel);
            }
            Ok(line) = stdin.next_line() => {
                parse_command(line.unwrap(), &onion, &mut tunnels, &public_key, &mut peer_tx).await;
            }
            else => break,
        }
    }
}

async fn parse_command(
    cmd: String,
    onion: &OnionContext,
    tunnels: &mut HashMap<TunnelId, TunnelWriter>,
    hostkey: &RsaPublicKey,
    peers: &mut mpsc::UnboundedSender<Peer>,
) {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("build") => {
            let dest_addr = parts.next().unwrap_or(DEFAULT_ADDR).parse().unwrap();
            let dest = Peer::new(dest_addr, hostkey.clone());
            let tunnel = onion.build_tunnel(dest).await.unwrap();
            println!("Built tunnel with ID {}", tunnel.id());
            tunnels.insert(tunnel.id(), tunnel.writer());
            handle_tunnel_data(tunnel);
        }
        Some("destroy") => {
            let tunnel_id = parts.next().unwrap().parse().unwrap();
            tunnels.remove(&tunnel_id);
        }
        Some("data") => {
            let tunnel_id = parts.next().unwrap().parse().unwrap();
            let data = parts.next().unwrap().as_bytes();
            tunnels
                .get(&tunnel_id)
                .unwrap()
                .write(data.to_vec().into())
                .unwrap();
        }
        Some("peer") => {
            let peer_addr = parts.next().unwrap().parse().unwrap();
            let peer = Peer::new(peer_addr, hostkey.clone());
            let _ = peers.send(peer);
        }
        Some("cover") => {
            let size = parts.next().unwrap().parse().unwrap();
            onion.send_cover(size).unwrap();
        }
        Some("help") => {
            println!("Available Commands:");
            println!("  build <dest_addr> <n_hops>");
            println!("  destroy <tunnel_id>");
            println!("  data <tunnel_id> data");
            println!("  cover <size>");
            println!("  help");
        }
        _ => println!("Unknown command!"),
    }
}

fn handle_tunnel_data(mut tunnel: Tunnel) {
    tokio::spawn(async move {
        while let Ok(data) = tunnel.read().await {
            println!("Received data from tunnel {}: {:?}", tunnel.id(), data);
        }
    });
}
