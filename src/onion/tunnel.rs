use crate::onion::circuit::Circuit;
use crate::onion::crypto::{self, SessionKey, EphemeralPrivateKey};
use crate::onion::protocol::{TryFromBytesExt, TunnelRequest, VerifyKey};
use crate::onion::socket::{OnionSocket, OnionSocketError};
use crate::Result;
use crate::{Event, Peer};
use anyhow::Context;
use futures::{Stream, StreamExt, TryFutureExt};
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
    #[error("Tunnel operation could not be completed")]
    Incomplete,
    /// The requested operation could not be completed and the tunnel is left in a broken state
    /// that needs to be cleaned up. This may be triggered by an undecryptable `OPAQUE` message,
    /// or a `TEARDOWN` message from the first hop.
    #[error("Tunnel operation caused the tunnel to break")]
    Broken,
}

impl From<OnionSocketError> for TunnelError {
    fn from(e: OnionSocketError) -> Self {
        match e {
            OnionSocketError::StreamTerminated(_) => { TunnelError::Broken },
            OnionSocketError::StreamTimeout(_) => { TunnelError::Broken },
            OnionSocketError::TeardownMessage => { TunnelError::Broken },
            OnionSocketError::BrokenMessage => { TunnelError::Broken },
        }
    }
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

        let secret = Tunnel::derive_secret(&peer, private_key, peer_key)?;
        Ok(Self {
            id,
            out_circuit: Circuit::new(circuit_id, socket),
            aes_keys: vec![secret],
        })
    }

    fn derive_secret(peer: &&Peer, private_key: EphemeralPrivateKey, peer_key: VerifyKey) -> Result<SessionKey> {
        let peer_key = peer_key
            .verify(&peer.hostkey)
            .context("Could not verify peer public key")?;
        let secret = SessionKey::from_key_exchange(private_key, &peer_key)?;
        Ok(secret)
    }

    /// Performs a key exchange with the given peer and extends the tunnel with a new hop
    pub(crate) async fn extend(
        &mut self,
        peer: &Peer,
        rng: &rand::SystemRandom,
    ) -> TunnelResult<()> {
        trace!("Extending tunnel {} to peer {}", self.id, &peer.addr);
        let (private_key, key) = crypto::generate_ephemeral_keypair(rng);

        let peer_key = self
            .out_circuit
            .socket()
            .await
            .initiate_tunnel_handshake(
                self.out_circuit.id,
                peer.addr,
                key,
                &self.aes_keys,
                rng,
            )
            .await?
            .map_err(|_| TunnelError::Incomplete)?;

        /*
        let peer_key = peer_key
            .verify(&peer.hostkey)
            // TODO introduce error indicating broken final hop
            .map_err(|_| TunnelError::Broken)?;
            //.context("Could not verify peer public key")?;

        let secret = SessionKey::from_key_exchange(private_key, &peer_key)
            // TODO introduce error indicating broken final hop
            .map_err(|_| TunnelError::Broken)?;
         */

        // Any failure because of any incorrect secret answer should not cause our tunnel to become corrupted
        if let Ok(secret) = Tunnel::derive_secret(&peer, private_key, peer_key) {
            self.aes_keys.insert(0, secret);
            Ok(())
        } else {
            // key derivation failed, the final hop needs to be truncated
            // if the truncate fails too, the tunnel is broken
            // TODO do not remove a key
            self.truncate(0, rng).map_err(|_| TunnelError::Broken);
            Err(TunnelError::Incomplete)
        }
    }

    pub(crate) async fn handle_tunnel_messages(
        &self,
        mut events: mpsc::Sender<Event>,
    ) -> Result<()> {
        loop {
            // TODO apply timeout to handle tunnel rotation
            // TODO send event in case of error
            let mut msg = self.out_circuit.socket.lock().await.accept_opaque().await?;
            // TODO send event in case of error
            msg.decrypt(self.aes_keys.iter().rev())?;
            let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
            match tunnel_msg {
                Ok(TunnelRequest::Data(tunnel_id, data)) => {
                    let event = Event::Data { tunnel_id, data };
                    // TODO send event in case of error
                    events.send(event).await?
                }
                Ok(TunnelRequest::End(tunnel_id)) => {
                    // TODO send event and deconstruct tunnel
                    todo!()
                }
                _ => {
                    // invalid request or broken digest
                    // TODO teardown tunnel
                    todo!()
                }
            }
        }
    }

    /// Truncates the tunnel by `n` hops with one `TUNNEL TRUNCATE` message. If message returns with
    /// an error code, `Incomplete` will be returned.
    ///
    /// Returns `Incomplete` if the resulting hop count would be less than one.
    pub(crate) async fn truncate(&mut self, n: usize, rng: &rand::SystemRandom) -> TunnelResult<()> {
        if n >= self.aes_keys.len() {
            return Err(TunnelError::Incomplete);
        }

        let error_code = self.out_circuit
            .socket()
            .await
            .truncate_tunnel(
                self.out_circuit.id,
                &self.aes_keys[n..],
                rng,)
            .await?;

        if let Some(error_code) = error_code {
            Err(TunnelError::Incomplete)
        } else {
            &self.aes_keys.remove(0);
            Ok(())
        }
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
        self.out_circuit
            .socket()
            .await
            .begin(
                self.out_circuit.id,
                self.id,
                &self.aes_keys,
                rng,)
            .await?;
        Ok(())
    }

    /// Tries to build this tunnel to hop count `n` and final hop `final_peer`.
    ///
    /// The peers provided by `peer_provider` will be used as a source for the intermediate hops,
    /// the final hop at index `n-1` will be `final_peer`. If the tunnel already has a length of at
    /// least `n`, the tunnel will be truncated to length `n-1` and then extended by `final_peer`.
    ///
    /// This function does not check whether the peers provided by `peer_provider` are particularity
    /// secure. In order to preserve anonymity, there should never be two consecutive hops to the
    /// same peer. Also, `peer_provider` should produce peers in a way that potentially malicious
    /// peers with shared knowledge of circuits should be returned with a low probability (or with
    /// equal probability to any other peer) to prevent the tunnel from becoming compromised.
    ///
    /// Even if there is a high failure-rate among peers, the `peer_provider` should be able to
    /// generate a secure stream of peers.
    pub(crate) async fn try_build<P: Stream<Item = Peer> + Send + Sync + Unpin + 'static>(
        &mut self,
        length: usize,
        mut peer_provider: P,
        final_peer: &Peer,
        rng: &rand::SystemRandom,
    ) -> TunnelResult<()> {
        while self.aes_keys.len() >= length {
            match self.truncate(1, rng).await {
                Err(TunnelError::Broken) => {
                    return Err(TunnelError::Broken)
                }
                Err(TunnelError::Incomplete) => {
                    // TODO implement a counter for failed Truncate calls
                }
                Ok(_) => {}
            }
        }

        while self.aes_keys.len() < length {
            if let Some(peer) = peer_provider.next().await {
                match self.extend(&peer, &rng).await {
                    Err(TunnelError::Broken) => {
                        // do not try to fix this error to prevent endless looping
                        return Err(TunnelError::Broken)
                    }
                    Err(TunnelError::Incomplete) => {
                        // TODO implement a counter for failed Extend calls
                    }
                    Ok(_) => {}
                }
            } else {
                return Err(TunnelError::Incomplete);
            }
        }

        self.extend(final_peer, rng).await?;
        Ok(())
    }

    pub(crate) fn random_id(rng: &rand::SystemRandom) -> TunnelId {
        // FIXME an attacker may fill up all ids
        let mut id_buf = [0u8; 4];
        rng.fill(&mut id_buf).unwrap();
        u32::from_le_bytes(id_buf)
    }
}
