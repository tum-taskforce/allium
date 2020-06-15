#![allow(dead_code)]
#![allow(unused_variables)]
use async_std::net::TcpStream;
use async_std::stream::Stream;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use ring::agreement::PublicKey;
use ring::rand::SecureRandom;
use ring::{agreement, pbkdf2, rand};
use std::char::decode_utf16;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::IpAddr;

pub mod messages;
mod onion_protocol;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Peer {
    addr: IpAddr,
    port: u16,
    hostkey: Vec<u8>,
}

impl Peer {
    pub fn new(addr: IpAddr, port: u16, hostkey: Vec<u8>) -> Self {
        Peer {
            addr,
            port,
            hostkey,
        }
    }
}

type TunnelId = u32;
pub struct Tunnel {
    id: TunnelId,

    notify_channels: Receiver<u8>,
}

type CircuitId = u16;
struct OutCircuit {
    id: CircuitId,
    key: Vec<u8>,
    partner: Option<CircuitId>,
}
struct InCircuit {
    id: CircuitId,
    partner: Option<CircuitId>
}

pub struct Onion<P: Stream<Item = Peer>> {
    p2p_hostname: String,
    p2p_port: u16,
    in_circuits: HashMap<CircuitId, InCircuit>,
    out_circuits: HashMap<CircuitId, OutCircuit>,
    rng: rand::SystemRandom,
    old_tunnels: HashMap<TunnelId, Tunnel>,
    new_tunnels: HashMap<TunnelId, Tunnel>,
    peer_provider: P,
}

impl<P> Onion<P>
where
    P: Stream<Item = Peer>,
{
    pub fn new(p2p_hostname: String, p2p_port: u16, peer_provider: P) -> Self {
        Onion {
            p2p_hostname,
            p2p_port,
            in_circuits: HashMap::new(),
            out_circuits: HashMap::new(),
            rng: rand::SystemRandom::new(),
            old_tunnels: HashMap::new(),
            new_tunnels: HashMap::new(),
            peer_provider,
        }
    }

    /// Tunnels created in one period should be torn down and rebuilt for the next period.
    /// However, Onion should ensure that this is done transparently to the modules, using these
    /// tunnels. This could be achieved by creating a new tunnel before the end of a period and
    /// seamlessly switching over the data stream to the new tunnel once at the end of the current
    /// period. Since the destination peer of both old and new tunnel remains the same, the seamless
    /// switch over is possible.
    pub async fn next_round(&mut self) {
        for (_, tunnel) in self.old_tunnels.iter() {
            // create new tunnel
        }

        // old_tunnels is now rebuilt new tunnels
        self.new_tunnels.clear();
        // add all old_tunnels to new_tunnels
    }

    pub async fn build_tunnel(&self, n_hops: usize) -> Result<TunnelId> {
        // TODO schedule and await future for tunnel creation in the next round
        let tunnel_id = self.generate_tunnel_id()?;
        Ok(tunnel_id)
    }

    pub async fn destroy_tunnel(&self, tunnel_id: TunnelId) -> Result<()> {
        Ok(())
    }

    pub async fn send_data(&self, tunnel_id: TunnelId, data: &[u8]) -> Result<()> {
        Ok(())
    }

    pub async fn listen_p2p(&self) -> Result<()> {
        Ok(())
    }

    /// Build a new circuit to `peer`. Sends a CREATE message to `peer` containing a DH secret.
    /// The returned CircuitId shall be a key of out_circuits.
    async fn create_circuit(
        &mut self,
        peer: &Peer,
        src_circuit: Option<CircuitId>,
    ) -> Result<CircuitId> {
        let circuit_id = self.generate_circuit_id()?;
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)?;
        let public_key = private_key.compute_public_key()?;

        // send public_key to peer
        let peer_public_key = self.exchange_keys(peer, circuit_id, public_key).await?;

        let key = agreement::agree_ephemeral(
            private_key,
            &peer_public_key,
            ring::error::Unspecified,
            |key_material| {
                let mut key = Vec::new();
                key.extend_from_slice(key_material);
                Ok(key)
            },
        )?;

        let circuit = OutCircuit {
            id: circuit_id,
            key,
            partner: src_circuit,
        };

        self.out_circuits.insert(circuit_id, circuit);
        Ok(circuit_id)
    }

    fn generate_circuit_id(&self) -> Result<CircuitId> {
        // FIXME an attacker may fill up all ids
        loop {
            let mut buf = [0u8; 2];
            self.rng.fill(&mut buf);
            let id: CircuitId = u16::from_le_bytes(buf);
            if !self.out_circuits.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    fn generate_tunnel_id(&self) -> Result<TunnelId> {
        // FIXME an attacker may fill up all ids
        loop {
            let mut buf = [0u8; 4];
            self.rng.fill(&mut buf);
            let id: TunnelId = u32::from_le_bytes(buf);
            if !self.new_tunnels.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    async fn exchange_keys(
        &self,
        peer: &Peer,
        circuit_id: CircuitId,
        public_key: PublicKey,
    ) -> Result<agreement::UnparsedPublicKey<Vec<u8>>> {
        let stream = TcpStream::connect((peer.addr, peer.port)).await?;
        let req = onion_protocol::CreateMessage {
            secret: public_key.as_ref().to_vec(),
        };
        // magic happens (encode req to bytes, write req to stream, recv response, decode), error handling
        let res: onion_protocol::CreatedMessage = todo!();
        Ok(agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            res.peer_secret,
        ))
    }
}
