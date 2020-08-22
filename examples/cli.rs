use onion::{Onion, Peer, RsaPrivateKey, RsaPublicKey};
use std::env;
use tokio::io::{self, BufReader};
use tokio::prelude::*;
use tokio::stream::{self, StreamExt};

const DEFAULT_ADDR: &str = "127.0.0.1:4200";

#[tokio::main]
async fn main() {
    let onion_addr = env::args()
        .nth(1)
        .unwrap_or(DEFAULT_ADDR.to_string())
        .parse()
        .unwrap();
    let hostkey = RsaPrivateKey::from_pem_file("testkey.pem").unwrap();
    let public_key = hostkey.public_key();
    let peer_provider = stream::empty();
    let (onion, mut events) = Onion::new(onion_addr, hostkey, peer_provider).unwrap();

    let mut stdin = BufReader::new(io::stdin()).lines();
    loop {
        tokio::select! {
            Some(evt) = events.next() => {
                println!("Event: {:?}", evt);
            }
            Some(line) = stdin.next() => {
                parse_command(line.unwrap(), &onion, &public_key).await;
            }
            else => break,
        }
    }
}

async fn parse_command(cmd: String, onion: &Onion, hostkey: &RsaPublicKey) {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("build") => {
            let tunnel_id = parts.next().unwrap().parse().unwrap();
            let dest_addr = parts.next().unwrap_or(DEFAULT_ADDR).parse().unwrap();
            let dest = Peer::new(dest_addr, hostkey.clone());
            let n_hops = parts.next().unwrap_or("0").parse().unwrap();
            onion.build_tunnel(tunnel_id, dest, n_hops);
        }
        Some("destroy") => {
            let tunnel_id = parts.next().unwrap().parse().unwrap();
            onion.destroy_tunnel(tunnel_id);
        }
        Some("data") => {
            let tunnel_id = parts.next().unwrap().parse().unwrap();
            let data = parts.next().unwrap().as_bytes();
            onion.send_data(tunnel_id, data);
        }
        Some("help") => {
            println!("Available commands:");
            println!("  build <tunnel_id> <dest_addr> <n_hops>");
            println!("  destroy <tunnel_id>");
            println!("  data <tunnel_id> data");
            println!("  help");
        }
        _ => println!("Unknown command!"),
    }
}
