#![allow(dead_code)]
#![allow(unused_variables)]
use crate::onion_protocol::*;
use anyhow::anyhow;
use async_std::net::{SocketAddr, TcpStream};
use async_std::stream::Stream;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use ring::rand::SecureRandom;
use ring::{agreement, pbkdf2, rand, signature};
use std::char::decode_utf16;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::IpAddr;

pub mod messages;
mod onion_protocol;
mod utils;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Peer {
    addr: IpAddr,
    port: u16,
    hostkey: signature::UnparsedPublicKey<Vec<u8>>,
}

impl Peer {
    pub fn new(addr: IpAddr, port: u16, hostkey: Vec<u8>) -> Self {
        let hostkey =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, hostkey);
        Peer {
            addr,
            port,
            hostkey,
        }
    }
}

struct Hop {
    // maybe additional information like peer
    key: Vec<u8>,
}

type TunnelId = u32;
struct OutTunnel {
    id: TunnelId,
    out_circuit: Option<CircuitId>,
    hops: Vec<Hop>,
    // TODO notify_channels: Receiver<u8>,
}

struct InTunnel {
    id: TunnelId,
    // TODO notify_channels: Receiver<u8>,
}

type CircuitId = u16;
struct OutCircuit {
    id: CircuitId,
    partner: Option<CircuitId>,
}
struct InCircuit {
    id: CircuitId,
    key: Vec<u8>,
    partner: Option<CircuitId>
}

pub struct Onion<P: Stream<Item = Peer>> {
    hostkey: signature::RsaKeyPair,
    in_circuits: HashMap<CircuitId, InCircuit>,
    out_circuits: HashMap<CircuitId, OutCircuit>,
    rng: rand::SystemRandom,
    old_tunnels: HashMap<TunnelId, OutTunnel>, // FIXME Rework types
    new_tunnels: HashMap<TunnelId, OutTunnel>,
    peer_provider: P,
}

impl<P> Onion<P>
where
    P: Stream<Item = Peer>,
{
    /// Construct a new onion instance.
    /// Returns Err if the supplied hostkey is invalid.
    pub fn new(hostkey: &[u8], peer_provider: P) -> Result<Self> {
        let hostkey = signature::RsaKeyPair::from_pkcs8(hostkey)?;

        Ok(Onion {
            hostkey,
            in_circuits: HashMap::new(),
            out_circuits: HashMap::new(),
            rng: rand::SystemRandom::new(),
            old_tunnels: HashMap::new(),
            new_tunnels: HashMap::new(),
            peer_provider,
        })
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

    pub async fn listen(&self, addr: SocketAddr) -> Result<()> {
        Ok(())
    }

    /*
    async fn handle_message(&self, msg: OnionMessage) {
        match msg {
            OnionMessage::CreateRequest(circuit_id, peer_key) => {
                // - generate ephemeral key pair
                let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)?;
                // - reply to sender with ephemeral public key
                let public_key = self.sign_key(private_key.compute_public_key()?)?;
                let res = OnionMessage::CreateResponse(circuit_id, public_key);
                // TODO send response
                // - obtain shared secret (aaed::LessSafeKey) from ephemeral private key and peer
                //   key using agree_ephemeral and hkdf
                let secret =
            }
            OnionMessage::CreateResponse(circuit_id, peer_key) => {
                // _ if extension: send extended to in circuit peer
                // - else: verify peer_key with peer hostkey
                //   - obtain shared secret (aaed::LessSafeKey) from ephemeral private key and peer
                //     key using agree_ephemeral and hkdf
            }
            OnionMessage::Relay(circuit_id, relay_msg) => {
                // - decrypt with secret associated to circuit and try to parse
                //    - if parsing works: handle relay message
                //    - else: get relay circuit
                //      - out circuit: forward decrypted message to peer
                //      - in circuit: encrypt message and forward
            }
        }
    }

    fn sign_key(&self, public_key: agreement::PublicKey) -> Result<SignedKey> {
        SignedKey::sign(
            Key::new(&agreement::X25519, public_key.as_ref().to_vec()),
            &self.hostkey,
            &self.rng,
        )
    }

    async fn handle_relay_message(&self, circuit_id: CircuitId, msg: RelayMessage) {
        match msg {
            RelayMessage::Extend(tunnel_id, dest, key) => {
                // - send create message to dest containing key
                // - associate circuit_id (in) with new circuit (out)
            }
            RelayMessage::Extended(tunnel_id, peer_key) => {
                // - verify peer_key signature
                // - save shared secret
            }
            RelayMessage::Data(tunnel_id, data) => {}
        }
    }
    */

    /// Build a new circuit to `peer`. Sends a CREATE message to `peer` containing a the given DH secret.
    /// The returned CircuitId shall be a key of out_circuits.
    // TODO maybe replace key types with more useful types
    async fn create_circuit(
        &mut self,
        peer: &Peer,
        secret: PublicKey,
        src_circuit: Option<CircuitId>,
    ) -> Result<(CircuitId, UnparsedPublicKey<Vec<u8>>)> {
        let circuit_id = self.generate_circuit_id()?;

        // send secret to peer
        let stream = async_std::net::TcpStream::connect((peer.addr, peer.port)).await?;
        let req = onion_protocol::CreateMessage {
            secret: secret.as_ref().to_vec(),
        };
        // TODO magic happens (encode req to bytes, write req to stream, recv response, decode), error handling
        let res: onion_protocol::CreatedMessage = todo!();
        let peer_public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            res.peer_secret,
        );

        let circuit = OutCircuit {
            id: circuit_id,
            partner: src_circuit,
        };

        self.out_circuits.insert(circuit_id, circuit);
        Ok((circuit_id, peer_public_key))
    }

    /// Generates a fresh circuit id to be used for adding a new circuit either to out_circuits or
    /// in_circuits. The id is unique among both to ensure that incoming packages with that specific
    /// circuit id can be identified as an incoming circuit or outgoing circuit. For example any
    /// RELAY EXTEND packets coming from incoming circuits may be valid and processed, but any RELAY
    /// EXTEND packets from outgoing circuits should not be accepted as valid.
    ///
    /// The call to this function and the use of the circuit id to add a new circuit to either
    /// in_circuits and out_circuits should be atomic to prevent any race conditions where any used
    /// circuit id is returned by this function.
    fn generate_circuit_id(&self) -> Result<CircuitId> {
        // FIXME an attacker may fill up all ids
        loop {
            let mut buf = [0u8; 2];
            self.rng.fill(&mut buf);
            let id: CircuitId = u16::from_le_bytes(buf);
            if !self.out_circuits.contains_key(&id) && !self.in_circuits.contains_key(&id) {
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

    /// Performs a key exchange with the given peer and extends the tunnel with a new circuit
    ///
    /// If `tunnel` has no hops, the peer will be contacted directly using CREATE packets.
    /// If `tunnel` has at least one hop, the key exchange will be perfomed remotely via RELAY
    /// EXTEND packets.
    ///
    /// # Arguments
    /// * `peer` - the peer that should be exchanged keys with
    /// * `tunnel` - the tunnel that should be extended
    async fn extend_tunnel(
        &mut self,
        peer: &Peer,
        tunnel: &mut OutTunnel,
    ) -> Result<()> {
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)?;
        let public_key = private_key.compute_public_key()?;

        let (out_circuit, peer_public_key) = if tunnel.hops.is_empty() {
            if tunnel.out_circuit.is_some() {
                // FIXME This case may be ignored or should be avoided
                // There should be either no hops and no circuit, or at least one hop
                return Err(anyhow!("Broken tunnel, no hops defined, but existing out circuit."));
            }
            // create first hop
            self.create_circuit(peer, public_key, None).await?
        } else {
            if tunnel.out_circuit.is_none() {
                // FIXME This case may be ignored or should be avoided
                // There should be either some hops and a circuit, or no hops
                return Err(anyhow!("Broken tunnel, no circuit defined, but existing hops."));
            }
            // extend the tunnel with peer
            let req = onion_protocol::RelayExtend {
                dest_addr: peer.addr,
                dest_port: peer.port,
                secret: public_key.as_ref().to_vec(),
            };
            // any errors that happen in this stage (i.e. timeout or errors from tunnel) cause a fail here and should be managed by the parent function
            // TODO Manage answer selection more elegantly
            if let onion_protocol::RelayResponse::Extended(res) = self.relay_out(tunnel, onion_protocol::RelayRequest::Extend(req)).await? {
                (tunnel.out_circuit, res.key)
            } else {
                return Err(anyhow!("No extended"));
            }
        };

        // Any fail because of any incorrect secret answer should not cause our tunnel to become corrupted
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

        let hop = Hop {
            key: key
        };

        tunnel.out_circuit = out_circuit; // FIXME maybe there is a better way
        tunnel.hops.push(hop);
        Ok(())
    }

    /// Sends the given relay message to the final hop in the tunnel
    async fn relay_out(
        &self,
        tunnel: &OutTunnel,
        req: onion_protocol::RelayRequest,
    ) -> Result<onion_protocol::RelayResponse> {
        self.relay_out_n(tunnel, tunnel.hops.len() - 1, req)
    }

    /// Sends the given relay message to the hop at index `n` in the tunnel
    async fn relay_out_n(
        &self,
        tunnel: &OutTunnel,
        n: usize,
        req: onion_protocol::RelayRequest,
    ) -> Result<onion_protocol::RelayResponse> {
        // TODO magic happens (encode req to bytes, write req to stream, recv response, decode), error handling
        todo!()
    }
}
