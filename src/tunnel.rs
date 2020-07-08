use crate::circuit::Circuit;
use crate::socket::OnionSocket;
use crate::utils::derive_secret;
use crate::utils::generate_ephemeral_key_pair;
use crate::Peer;
use crate::Result;
use anyhow::Context;
use thiserror::Error;
use log::trace;
use ring::{aead, rand};
use tokio::net::TcpStream;
use futures::Stream;

pub(crate) type TunnelId = u32;

#[derive(Error, Debug)]
pub(crate) enum TunnelError {
    /// The requested operation could not be run to completion, but the tunnel has a consistent
    /// state that can be expanded on
    Incomplete,
    /// The requested operation could not be completed and the tunnel is left in a broken state
    /// that needs to be cleaned up. This may be triggered by an undecryptable `OPAQUE` message,
    /// or a `TEARDOWN` message from the first hop.
    Broken,
}

pub(crate) type TunnelResult<T> = std::result::Result<T, TunnelError>;

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

    /// Performs a key exchange with the given peer and extends the tunnel with a new hop
    pub(crate) async fn extend(&mut self, peer: &Peer, rng: &rand::SystemRandom) -> Result<()> {
        trace!("Extending tunnel {} to peer {}", self.id, &peer.addr);
        let (private_key, key) = generate_ephemeral_key_pair(rng).unwrap();

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
        let secret = derive_secret(private_key, &peer_key)?;
        self.aes_keys.insert(0, secret);
        Ok(())
    }

    /// Truncates the tunnel by one hop
    pub(crate) async fn truncate(&mut self, rng: &rand::SystemRandom) -> Result<()> {
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
    pub(crate) async fn begin(&mut self, rng: &rand::SystemRandom) -> Result<()> {
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

    ) {
        todo!()
    }
}
