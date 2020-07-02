#![allow(dead_code)]
#![allow(unused_variables)]
use crate::onion_protocol::*;
use crate::socket::OnionSocket;
use anyhow::{anyhow, Context};
use bytes::Bytes;
use futures::stream::StreamExt;
use ring::rand::SecureRandom;
use ring::{aead, agreement, rand, signature};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::Stream;
use tokio::sync::{Mutex, RwLock};

mod onion_protocol;
mod socket;
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
    hops: Vec<aead::LessSafeKey>,
    // TODO notify_channels: Receiver<u8>,
}

struct InTunnel {
    id: TunnelId,
    // TODO notify_channels: Receiver<u8>,
}

type CircuitId = u16;

struct Circuit {
    id: CircuitId,
    socket: Mutex<OnionSocket<TcpStream>>,
    partner: Option<CircuitId>,
}

struct OutCircuit {
    base: Circuit,
}

struct InCircuit {
    base: Circuit,
    secret: aead::LessSafeKey,
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
    P: Stream<Item = Peer> + Send + Sync + 'static,
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
        socket: OnionSocket<TcpStream>,
        secret: aead::LessSafeKey,
    ) -> Result<&InCircuit> {
        let in_circuit = InCircuit {
            base: Circuit {
                id: circuit_id,
                socket: Mutex::new(socket),
                partner: None,
            },
            secret,
        };

        let mut map = self.in_circuits.write().await;
        if !map.contains_key(&circuit_id) {
            map.insert(circuit_id, in_circuit);
            //Ok(map.get(&circuit_id).unwrap())
            todo!()
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
        socket: OnionSocket<TcpStream>,
    ) -> Result<&OutCircuit> {
        let out_circuit = OutCircuit {
            base: Circuit {
                id: circuit_id,
                socket: Mutex::new(socket),
                partner: None,
            },
        };

        let mut map = self.out_circuits.write().await;
        if !map.contains_key(&circuit_id) {
            map.insert(circuit_id, out_circuit);
            //Ok(map.get(&circuit_id).unwrap())
            todo!()
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
        let mut listener = TcpListener::bind(addr).await?;
        println!("Listening fo p2p connections on {}", listener.local_addr()?);
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let socket = OnionSocket::new(stream?);
            let handler = self.clone();
            tokio::spawn(async move {
                if let Err(e) = handler.handle(socket).await {
                    eprintln!("{}", e);
                }
            });
        }
        Ok(())
    }

    async fn handle(self: Arc<Self>, mut socket: OnionSocket<TcpStream>) -> Result<()> {
        let (circuit_id, peer_key) = socket
            .accept_handshake()
            .await
            .context("Handshake with new connection failed")?;

        // TODO handle errors
        let (private_key, key) = self.generate_ephemeral_key_pair().unwrap();
        let key = SignKey::sign(&key, &self.hostkey, &self.rng);

        let secret = self.derive_secret(private_key, &peer_key).unwrap();
        let aes_keys = [secret];
        socket
            .finalize_handshake(circuit_id, key, &self.rng)
            .await?;

        // TODO errrr
        // let circuit = self
        //     .insert_new_in_circuit(circuit_id, socket, secret)
        //     .await?;

        // let res = circuit
        //     .base
        //     .socket
        //     .lock()
        //     .await
        //     .finalize_handshake(circuit_id, key, &self.rng)
        //     .await;
        // if let Err(_) = res {
        //     self.in_circuits.write().await.remove(&circuit_id).unwrap();
        // }

        // should be Option<Circuit>
        let mut relay_circuit_id: Option<CircuitId> = None;
        let mut relay_socket: Option<OnionSocket<TcpStream>> = None;
        // TODO timeouts, also handle incoming messages from realy_socket
        loop {
            let msg = socket.accept_opaque().await;
            match msg {
                Ok(mut msg) => {
                    // match msg source, don't decrypt msgs from relay_socket
                    msg.decrypt(&self.rng, aes_keys.iter())?;
                    match TunnelRequest::read_with_digest_from(&mut msg.payload) {
                        Ok(tunnel_msg) => {
                            // addressed to us
                            match tunnel_msg {
                                TunnelRequest::Extend(tunnel_id, dest, key) => {
                                    if relay_socket.is_some() {
                                        // error
                                        continue;
                                    }

                                    // TODO handle connect failure
                                    let stream = TcpStream::connect(dest).await?;
                                    relay_circuit_id = Some(0); // TODO generate
                                    relay_socket = Some(OnionSocket::new(stream));
                                    let peer_key = relay_socket
                                        .as_mut()
                                        .unwrap() // TODO avoid unwrap here
                                        .initiate_handshake(circuit_id, key, &self.rng)
                                        .await?;

                                    socket
                                        .finalize_tunnel_handshake(
                                            circuit_id, tunnel_id, peer_key, &aes_keys, &self.rng,
                                        )
                                        .await?;
                                }
                                TunnelRequest::Data(tunnel_id, data) => unimplemented!(),
                            }
                        }
                        Err(e) => {
                            // forward to relay_socket (only if digest wrong)
                            if let Some(relay_socket) = &mut relay_socket {
                                // TODO avoid unwrap here
                                relay_socket
                                    .send_opaque(relay_circuit_id.unwrap(), msg.payload, &self.rng)
                                    .await?;
                            } else {
                                // no realy_socket => proto breach teardown
                            }
                        }
                    }
                }
                Err(_e) => {
                    // socket closed or failed to read opaque message teardown
                }
            }
        }
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

        // send secret to peer
        let stream = TcpStream::connect(peer.addr).await?;
        let mut socket = OnionSocket::new(stream);
        let peer_key = socket
            .initiate_handshake(circuit_id, handshake_key, &self.rng)
            .await?;

        self.insert_new_out_circuit(circuit_id, socket).await;
        Ok((circuit_id, peer_key))
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
            self.rng.fill(&mut buf).unwrap();
            let id: CircuitId = u16::from_le_bytes(buf);
            return todo!();
            // if !self.out_circuits.contains_key(&id) && !self.in_circuits.contains_key(&id) {
            //     return Ok(id);
            // }
        }
    }

    fn generate_tunnel_id(&self) -> Result<TunnelId> {
        // FIXME an attacker may fill up all ids
        loop {
            let mut buf = [0u8; 4];
            self.rng.fill(&mut buf).unwrap();
            let id: TunnelId = u32::from_le_bytes(buf);
            return todo!();
            // if !self.new_tunnels.contains_key(&id) {
            //     return Ok(id);
            // }
        }
    }

    async fn connect_peer(&self, peer: &Peer) -> Result<()> {
        let (private_key, key) = self.generate_ephemeral_key_pair().unwrap();

        let circuit_id = 0; // TODO random
        let stream = TcpStream::connect(peer.addr).await?;
        let mut socket = OnionSocket::new(stream);
        let peer_key = socket
            .initiate_handshake(circuit_id, key, &self.rng)
            .await?;

        let peer_key = peer_key.verify(&peer.hostkey)?;
        let _secret = self.derive_secret(private_key, &peer_key)?;
        Ok(())
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
            let out_circuit_id = tunnel.out_circuit.ok_or(anyhow!(
                "Broken tunnel, no circuit defined, but existing hops."
            ))?;
            let out_circuit: &OutCircuit = todo!();
            // let out_circuit = self
            //     .out_circuits
            //     .read()
            //     .await
            //     .get(&out_circuit_id)
            //     .ok_or(anyhow!("Invalid out circuit id: {}", out_circuit_id))?;

            // extend the tunnel with peer
            let mut socket = out_circuit.base.socket.lock().await;
            let peer_key = socket
                .initiate_tunnel_handshake(
                    out_circuit.base.id,
                    tunnel.id,
                    peer.addr,
                    key,
                    &tunnel.hops,
                    &self.rng,
                )
                .await?;
            (out_circuit.base.id, peer_key)
        };

        let read_key = peer_public_key.verify(&peer.hostkey)?;

        // Any fail because of any incorrect secret answer should not cause our tunnel to become corrupted
        // TODO notify peer(s) upon failure
        let secret = self.derive_secret(private_key, &read_key)?;

        tunnel.out_circuit = Some(out_circuit); // FIXME maybe there is a better way
        tunnel.hops.insert(0, secret);
        Ok(())
    }

    /// Sends the given relay message to the final hop in the tunnel
    async fn relay_out(
        &self,
        tunnel: &OutTunnel,
        req: TunnelRequest,
    ) -> Result<TunnelResponse<VerifyKey>> {
        self.relay_out_n(tunnel, tunnel.hops.len() - 1, req).await
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
            anyhow!("Key exchange failed"),
            |key_material| {
                let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key_material[..16])
                    .context("Could not construct unbound key from keying material")?;
                Ok(aead::LessSafeKey::new(unbound))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    use tokio::stream;

    #[tokio::test]
    async fn test_listen() -> Result<()> {
        let host_key = utils::read_hostkey("testkey.pem")?;
        let peer_provider = stream::empty();
        let onion = Arc::new(Onion::new(&host_key, peer_provider)?);
        onion.listen("127.0.0.1:4201".parse().unwrap()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_handshake() -> Result<()> {
        let host_key = utils::read_hostkey("testkey.pem")?;
        let peer_key = signature::RsaKeyPair::from_pkcs8(&host_key)?
            .public_key()
            .as_ref()
            .to_vec();
        let peer_provider = stream::empty();
        let onion = Arc::new(Onion::new(&host_key, peer_provider)?);
        let peer = Peer::new("127.0.0.1:4201".parse().unwrap(), peer_key);
        onion.connect_peer(&peer).await?;
        Ok(())
    }
}
