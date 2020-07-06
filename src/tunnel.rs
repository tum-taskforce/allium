use crate::circuit::Circuit;
use crate::socket::OnionSocket;
use crate::utils::derive_secret;
use crate::utils::generate_ephemeral_key_pair;
use crate::Peer;
use crate::Result;
use anyhow::Context;
use log::trace;
use ring::{aead, rand};
use tokio::net::TcpStream;

pub(crate) type TunnelId = u32;

pub(crate) struct Tunnel {
    pub(crate) id: TunnelId,
    out_circuit: Circuit,
    aes_keys: Vec<aead::LessSafeKey>,
}

impl Tunnel {
    pub(crate) async fn init(id: TunnelId, peer: &Peer, rng: &rand::SystemRandom) -> Result<Self> {
        trace!("Creating tunnel {} to peer {}", id, &peer.addr);
        let (private_key, key) = generate_ephemeral_key_pair(rng).unwrap();

        let circuit_id = 0; // TODO random
        let stream = TcpStream::connect(peer.addr)
            .await
            .context("Could not connect to peer")?;
        let mut socket = OnionSocket::new(stream);
        let peer_key = socket.initiate_handshake(circuit_id, key, rng).await?;

        let peer_key = peer_key
            .verify(&peer.hostkey)
            .context("Could not verify peer public key")?;
        let secret = derive_secret(private_key, &peer_key)?;
        Ok(Self {
            id,
            out_circuit: Circuit::new(circuit_id, socket),
            aes_keys: vec![secret],
        })
    }

    /// Performs a key exchange with the given peer and extends the tunnel with a new circuit
    pub(crate) async fn extend(&mut self, peer: &Peer, rng: &rand::SystemRandom) -> Result<()> {
        trace!("Extending tunnel {} to peer {}", self.id, &peer.addr);
        let (private_key, key) = generate_ephemeral_key_pair(rng).unwrap();

        let peer_key = self
            .out_circuit
            .socket()
            .await
            .initiate_tunnel_handshake(
                self.out_circuit.id,
                self.id,
                peer.addr,
                key,
                &self.aes_keys,
                rng,
            )
            .await?;

        // Any failure because of any incorrect secret answer should not cause our tunnel to become corrupted
        // TODO notify peer(s) upon failure
        let peer_key = peer_key
            .verify(&peer.hostkey)
            .context("Could not verify peer public key")?;
        let secret = derive_secret(private_key, &peer_key)?;
        self.aes_keys.insert(0, secret);
        Ok(())
    }
}
