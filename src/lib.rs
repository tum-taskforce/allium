#![allow(dead_code)]
#![allow(unused_variables)]
use crate::onion_protocol::*;
use anyhow::{anyhow, Context};
use async_std::net::{SocketAddr, TcpListener, TcpStream};
use async_std::stream::Stream;
use async_std::sync::{Arc, Mutex, RwLock};
use async_std::{stream, task};
use bytes::{Bytes, BytesMut};
use futures::channel::mpsc::Receiver;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use ring::rand::SecureRandom;
use ring::{aead, agreement, pbkdf2, rand, signature};
use std::char::decode_utf16;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::net::IpAddr;

pub mod messages;
mod onion_protocol;
mod utils;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Peer {
    addr: SocketAddr,
    hostkey: signature::UnparsedPublicKey<Bytes>,
}

impl Peer {
    pub fn new(addr: SocketAddr, hostkey: Vec<u8>) -> Self {
        let hostkey = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            hostkey.into(),
        );
        Peer { addr, hostkey }
    }
}

struct Hop {
    // maybe additional information like peer
    secret: aead::LessSafeKey,
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

struct Circuit {
    id: CircuitId,
    stream: Mutex<TcpStream>,
    partner: Option<CircuitId>,
}

struct OutCircuit {
    base: Circuit,
}

struct InCircuit {
    base: Circuit,
    secret: aead::LessSafeKey,
}

impl Circuit {
    async fn write_all(&self, buf: &[u8]) -> Result<()> {
        self.stream.lock().await.write_all(buf).await
    }

    async fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
        self.stream.lock().await.read_exact(buf).await
    }
}

pub struct Onion<P: Stream<Item = Peer>> {
    hostkey: signature::RsaKeyPair,
    in_circuits: RwLock<HashMap<CircuitId, InCircuit>>,
    out_circuits: RwLock<HashMap<CircuitId, OutCircuit>>,
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
            in_circuits: RwLock::new(HashMap::new()),
            out_circuits: RwLock::new(HashMap::new()),
            rng: rand::SystemRandom::new(),
            old_tunnels: HashMap::new(),
            new_tunnels: HashMap::new(),
            peer_provider,
        })
    }

    async fn insert_new_in_circuit(
        &self,
        circuit_id: CircuitId,
        stream: TcpStream,
        secret: aead::LessSafeKey,
    ) -> Result<&InCircuit> {
        let in_circuit = InCircuit {
            base: Circuit {
                id: circuit_id,
                stream: Mutex::new(stream),
                partner: None,
            },
            secret,
        };

        let mut map = self.in_circuits.write().await;
        if !map.contains_key(&circuit_id) {
            map.insert(circuit_id, in_circuit);
            Ok(map.get(&circuit_id).unwrap())
        } else {
            Err(anyhow!(
                "Could not insert new InCircuit: CircuitId already in use"
            ))
        }
    }

    // TODO deduplicate
    async fn insert_new_out_circuit(
        &self,
        circuit_id: CircuitId,
        stream: TcpStream,
    ) -> Result<&OutCircuit> {
        let out_circuit = OutCircuit {
            base: Circuit {
                id: circuit_id,
                stream: Mutex::new(stream),
                partner: None,
            },
        };

        let mut map = self.out_circuits.write().await;
        if !map.contains_key(&circuit_id) {
            map.insert(circuit_id, out_circuit);
            Ok(map.get(&circuit_id).unwrap())
        } else {
            Err(anyhow!(
                "Could not insert new OutCircuit: CircuitId already in use"
            ))
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

    pub async fn listen(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("Listening fo p2p connections on {}", listener.local_addr()?);
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            let handler = self.clone();
            task::spawn(async move {
                handler.handle(stream).await.unwrap();
            });
        }
        Ok(())
    }

    async fn handle(self: Arc<Self>, mut stream: TcpStream) -> Result<()> {
        let mut buf = BytesMut::with_capacity(ONION_MESSAGE_SIZE);
        stream.read_exact(&mut buf).await?; // TODO timeouts
        let msg = CircuitCreate::read_from(&mut buf)
            .context("Handshake with new connection failed: Invalid create message")?;
        let circuit_id = msg.circuit_id;

        // TODO handle errors
        let (private_key, key) = self.generate_ephemeral_key_pair().unwrap();
        let key = SignKey::sign(&key, &self.hostkey, &self.rng);

        let secret = self.derive_secret(private_key, &msg.key).unwrap();

        // TODO errrr
        let circuit = self
            .insert_new_in_circuit(circuit_id, stream, secret)
            .await?;

        let res = CircuitCreated { circuit_id, key };
        res.write_padded_to(&mut buf, &self.rng, ONION_MESSAGE_SIZE);
        // TODO timeouts
        if let Err(_) = circuit.write_all(buf.as_ref()).await {
            self.in_circuits.write().await.remove(&circuit_id).unwrap()
        }

        // TODO recv loop
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
        handshake_key: Key,
        src_circuit: Option<CircuitId>,
    ) -> Result<(CircuitId, VerifyKey)> {
        let circuit_id = self.generate_circuit_id()?;

        // TODO refactor all this to separate function/module
        // send secret to peer
        let mut stream = async_std::net::TcpStream::connect((peer.addr, peer.port)).await?;
        let mut buf = BytesMut::with_capacity(ONION_MESSAGE_SIZE);
        let req = CircuitCreate {
            circuit_id,
            key: handshake_key,
        };
        req.write_padded_to(&mut buf, &self.rng, ONION_MESSAGE_SIZE);
        stream.write_all(buf.as_ref()).await?;

        stream.read_exact(&mut buf).await?; // TODO handle timeout
        let res = CircuitCreated::read_from(&mut buf).context("Could not read circuit created")?;

        if res.circuit_id != circuit_id {
            return Err(anyhow!(
                "CircuitId in handshake response did not match sent CircuitId"
            ));
        }

        self.insert_new_out_circuit(circuit_id, stream);
        Ok((circuit_id, res.key))
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
    async fn extend_tunnel(&mut self, peer: &Peer, tunnel: &mut OutTunnel) -> Result<()> {
        let (private_key, key) = self.generate_ephemeral_key_pair().unwrap();

        let (out_circuit, peer_public_key) = if tunnel.hops.is_empty() {
            if tunnel.out_circuit.is_some() {
                // FIXME This case may be ignored or should be avoided
                // There should be either no hops and no circuit, or at least one hop
                return Err(anyhow!(
                    "Broken tunnel, no hops defined, but existing out circuit."
                ));
            }
            // create first hop
            self.create_circuit(peer, key, None).await?
        } else {
            // FIXME This case may be ignored or should be avoided
            // There should be either some hops and a circuit, or no hops
            let out_circuit = tunnel
                .out_circuit
                .and_then(|id| self.out_circuits.read().await.get(&id))
                .ok_or(anyhow!(
                    "Broken tunnel, no circuit defined, but existing hops."
                ))?;

            // extend the tunnel with peer
            let tunnel_msg = TunnelRequest::Extend(tunnel.id, peer.addr, key);
            let mut buf = BytesMut::with_capacity(tunnel_msg.size());
            tunnel_msg.write_with_digest_to(&mut buf, &self.rng);

            let mut msg = CircuitOpaque {
                circuit_id: out_circuit.id,
                payload: buf,
            };
            msg.encrypt(&self.rng, tunnel.hops.iter().rev().map(|hop| hop.secret))?;
            let mut buf = BytesMut::with_capacity(ONION_MESSAGE_SIZE);
            msg.write_padded_to(&mut buf, &self.rng, ONION_MESSAGE_SIZE);
            out_circuit.base.write_all(buf.as_ref());

            out_circuit.base.read_exact(buf.as_mut());
            let mut msg = CircuitOpaque::read_from(&mut buf)?;
            msg.decrypt(&self.rng, tunnel.hops.iter().map(|hop| hop.secret))?;
            let tunnel_msg = TunnelResponse::read_with_digest_from(&mut msg.payload)
                .context("Could not read TunnelResponse")?;

            match tunnel_msg {
                TunnelResponse::Extended(tunnel_id, read_key) => {
                    if tunnel_id != tunnel.id {
                        return Err(anyhow!(
                            "TunnelId in Extended does not match the expected value"
                        ));
                    }

                    (out_circuit.base.id, read_key)
                }
            }
        };

        let read_key = peer_public_key.verify(&peer.hostkey)?;

        // Any fail because of any incorrect secret answer should not cause our tunnel to become corrupted
        // TODO notify peer(s) upon failure
        let secret = self.derive_secret(private_key, &read_key)?;

        let hop = Hop { secret };

        tunnel.out_circuit = Some(out_circuit); // FIXME maybe there is a better way
        tunnel.hops.push(hop);
        Ok(())
    }

    /// Sends the given relay message to the final hop in the tunnel
    async fn relay_out(
        &self,
        tunnel: &OutTunnel,
        req: TunnelRequest,
    ) -> Result<TunnelResponse<VerifyKey>> {
        self.relay_out_n(tunnel, tunnel.hops.len() - 1, req)
    }

    /// Sends the given relay message to the hop at index `n` in the tunnel
    async fn relay_out_n(
        &self,
        tunnel: &OutTunnel,
        n: usize,
        req: TunnelRequest,
    ) -> Result<TunnelResponse<VerifyKey>> {
        // TODO magic happens (encode req to bytes, write req to stream, recv response, decode), error handling
        todo!()
    }

    fn generate_ephemeral_key_pair(&self) -> Result<(agreement::EphemeralPrivateKey, Key)> {
        let private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng).unwrap();
        let public_key = private_key.compute_public_key().unwrap();
        // TODO maybe avoid allocating here
        let key = Key::new(&agreement::X25519, public_key.as_ref().to_vec().into());
        Ok((private_key, key))
    }

    fn derive_secret(
        &self,
        private_key: agreement::EphemeralPrivateKey,
        peer_key: &Key,
    ) -> Result<aead::LessSafeKey> {
        // TODO use proper key derivation function
        agreement::agree_ephemeral(
            private_key,
            peer_key,
            ring::error::Unspecified,
            |key_material| {
                let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key_material[..16])
                    .context("Could not construct unbound key from keying material")?;
                Ok(aead::LessSafeKey::new(unbound))
            },
        )
    }
}
