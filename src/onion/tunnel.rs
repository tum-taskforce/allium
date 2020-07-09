use crate::onion::circuit::Circuit;
use crate::onion::crypto::{self, SessionKey};
use crate::onion::protocol::{TryFromBytesExt, TunnelRequest};
use crate::onion::socket::OnionSocket;
use crate::Result;
use crate::{Event, Peer};
use anyhow::Context;
use futures::Stream;
use log::trace;
use ring::rand;
use ring::rand::SecureRandom;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub(crate) type TunnelId = u32;

#[derive(Error, Debug)]
pub(crate) enum TunnelError {
    /// The requested operation could not be run to completion, but the tunnel has a consistent
    /// state that can be expanded on
    #[error("Incomplete")]
    Incomplete,
    /// The requested operation could not be completed and the tunnel is left in a broken state
    /// that needs to be cleaned up. This may be triggered by an undecryptable `OPAQUE` message,
    /// or a `TEARDOWN` message from the first hop.
    #[error("Broken")]
    Broken,
}

pub(crate) type TunnelResult<T> = std::result::Result<T, TunnelError>;

pub(crate) struct Tunnel {
    pub(crate) id: TunnelId,
    out_circuit: Circuit,
    aes_keys: Vec<SessionKey>,
}

impl Tunnel {
    pub(crate) async fn init(id: TunnelId, peer: &Peer, rng: &rand::SystemRandom) -> Result<Self> {
        trace!("Creating tunnel {} to peer {}", id, &peer.addr);
        let (private_key, key) = crypto::generate_ephemeral_keypair(rng);

        let circuit_id = Circuit::random_id(rng);
        let stream = TcpStream::connect(peer.addr)
            .await
            .context("Could not connect to peer")?;
        let mut socket = OnionSocket::new(stream);
        let peer_key = socket.initiate_handshake(circuit_id, key, rng).await?;

        let peer_key = peer_key
            .verify(&peer.hostkey)
            .context("Could not verify peer public key")?;
        let secret = SessionKey::from_key_exchange(private_key, &peer_key)?;
        Ok(Self {
            id,
            out_circuit: Circuit::new(circuit_id, socket),
            aes_keys: vec![secret],
        })
    }

    /// Performs a key exchange with the given peer and extends the tunnel with a new hop
    pub(crate) async fn extend(
        &mut self,
        peer: &Peer,
        rng: &rand::SystemRandom,
    ) -> TunnelResult<()> {
        trace!("Extending tunnel {} to peer {}", self.id, &peer.addr);
        let (private_key, key) = crypto::generate_ephemeral_keypair(rng);

        // TODO handle RemoteError
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

        let secret = SessionKey::from_key_exchange(private_key, &peer_key)?;
        self.aes_keys.insert(0, secret);
        Ok(())
    }

    pub(crate) async fn handle_tunnel_messages(
        &self,
        mut events: mpsc::Sender<Event>,
    ) -> Result<()> {
        loop {
            let mut msg = self.out_circuit.socket.lock().await.accept_opaque().await?;
            msg.decrypt(self.aes_keys.iter().rev())?;
            let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
            if let Ok(TunnelRequest::Data(tunnel_id, data)) = tunnel_msg {
                let event = Event::Data { tunnel_id, data };
                events.send(event).await?
            }
        }
    }

    /// Truncates the tunnel by one hop
    pub(crate) async fn truncate(&mut self, rng: &rand::SystemRandom) -> TunnelResult<()> {
        todo!()
    }

    /// Begins a data connection with the last hop in the tunnel
    ///
    /// If there is already a tunnel connected to the same peer with the same `TunnelId`, the
    /// targeted peer should no longer use the old tunnel for communication and is expected to send a
    /// `TUNNEL END` message through the old tunnel. This works like an implicit `TUNNEL END` to the
    /// remote tunnel.
    ///
    /// After sending a `TUNNEL BEGIN` message to the other endpoint of a tunnel, the tunnel should
    /// be monitored for `TUNNEL DATA` messages, as long as no explicit `TUNNEL END` message is
    /// received, or any explicit or implicit `TUNNEL END` message is sent. After sending an
    /// implicit `TUNNEL END` message by calling this function (as mentioned above), the old tunnel
    /// should be monitored for any incoming `TUNNEL DATA` packets and a final `TUNNEL END` packet
    /// before tearing down the old tunnel. Be aware that the other endpoint peer should not be
    /// allowed to use the old tunnel indefinitely despite receiving a `TUNNEL END` packet. Any old
    /// tunnel that has been replaced should only have finite lifetime.
    pub(crate) async fn begin(&mut self, rng: &rand::SystemRandom) -> TunnelResult<()> {
        todo!()
    }

    /// Tries to build this tunnel to hop count `n` and final hop `final_peer`.
    ///
    /// The peers provided by `peer_provider` will be used as a source for the intermediate hops,
    /// the final hop at index `n-1` will be `final_peer`. If the tunnel already has a length of at
    /// least `n`, the tunnel will be truncated to length `n-1` and then extended by `final_peer`.
    ///
    /// # TODO
    /// It is important for anonymity preservation that this function checks whether the tunnel does
    /// not contain two equal consecutive hops
    pub(crate) async fn try_build<P: Stream<Item = Peer> + Send + Sync + 'static>(
        &mut self,
        length: usize,
        peer_provider: P,
        final_peer: Peer,
    ) -> TunnelResult<()> {
        todo!()
    }

    pub(crate) fn random_id(rng: &rand::SystemRandom) -> TunnelId {
        // FIXME an attacker may fill up all ids
        let mut id_buf = [0u8; 4];
        rng.fill(&mut id_buf).unwrap();
        u32::from_le_bytes(id_buf)
    }
}
