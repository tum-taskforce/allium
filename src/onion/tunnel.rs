use crate::onion::circuit::Circuit;
use crate::onion::crypto::{self, EphemeralPrivateKey, SessionKey};
use crate::onion::protocol::{
    CircuitOpaque, CircuitOpaqueBytes, TryFromBytesExt, TunnelRequest, VerifyKey,
};
use crate::onion::socket::{OnionSocket, OnionSocketError, SocketResult};
use crate::Result;
use crate::{Event, Peer};
use anyhow::Context;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use log::trace;
use ring::rand;
use ring::rand::SecureRandom;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub type TunnelId = u32;

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
    Broken(Option<OnionSocketError>),
}

impl From<OnionSocketError> for TunnelError {
    fn from(e: OnionSocketError) -> Self {
        match e {
            OnionSocketError::Peer => TunnelError::Incomplete,
            e => TunnelError::Broken(Some(e)),
        }
    }
}

pub(crate) type TunnelResult<T> = std::result::Result<T, TunnelError>;

pub(crate) enum Request {
    Data { data: Bytes },
    Switchover,
    Destroy,
}

/// Represents the tunnel controller view of a tunnel.
/// Manages the first circuit and stores all session keys in encryption order.
pub(crate) struct Tunnel {
    pub(crate) id: TunnelId,
    out_circuit: Circuit,
    session_keys: Vec<SessionKey>,
}

impl Tunnel {
    /// Performs a circuit handshake with the first hop (peer).
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
            session_keys: vec![secret],
        })
    }

    fn derive_secret(
        peer: &&Peer,
        private_key: EphemeralPrivateKey,
        peer_key: VerifyKey,
    ) -> Result<SessionKey> {
        let peer_key = peer_key
            .verify(&peer.hostkey)
            .context("Could not verify peer public key")?;
        let secret = SessionKey::from_key_exchange(private_key, &peer_key)?;
        Ok(secret)
    }

    /// Returns the length of a tunnel. The result of this function may be used with caution if the
    /// tunnel is in a broken state.
    pub(crate) fn len(&self) -> usize {
        self.session_keys.len()
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
            .initiate_tunnel_handshake(self.out_circuit.id, peer.addr, key, &self.session_keys, rng)
            .await?;

        // Any failure because of any incorrect secret answer should not cause our tunnel to become corrupted
        if let Ok(secret) = Tunnel::derive_secret(&peer, private_key, peer_key) {
            self.session_keys.insert(0, secret);
            Ok(())
        } else {
            // key derivation failed, the final hop needs to be truncated
            // if the truncate fails too, the tunnel is broken
            self.truncate(0, rng)
                .await
                .map_err(|_| TunnelError::Broken(None))?;
            Err(TunnelError::Incomplete)
        }
    }

    /// Truncates the tunnel by `n` hops with one `TUNNEL TRUNCATE` message. If message returns with
    /// an error code, `Incomplete` will be returned.
    ///
    /// Returns `Incomplete` if the resulting hop count would be less than one.
    pub(crate) async fn truncate(
        &mut self,
        n: usize,
        rng: &rand::SystemRandom,
    ) -> TunnelResult<()> {
        if n >= self.session_keys.len() {
            return Err(TunnelError::Incomplete);
        }

        self.out_circuit
            .socket()
            .await
            .truncate_tunnel(self.out_circuit.id, &self.session_keys[n..], rng)
            .await?;

        for _ in 0..n {
            &self.session_keys.remove(0);
        }
        Ok(())
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
            .begin(self.out_circuit.id, self.id, &self.session_keys, rng)
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
        while self.session_keys.len() >= length {
            match self.truncate(1, rng).await {
                Err(TunnelError::Broken(e)) => {
                    // do not try to fix this error to prevent endless looping
                    return Err(TunnelError::Broken(e));
                }
                Err(TunnelError::Incomplete) => {
                    // TODO implement a counter for failed Truncate calls
                }
                Ok(_) => {}
            }
        }

        while self.session_keys.len() < length {
            if let Some(peer) = peer_provider.next().await {
                match self.extend(&peer, &rng).await {
                    Err(TunnelError::Broken(e)) => {
                        // do not try to fix this error to prevent endless looping
                        return Err(TunnelError::Broken(e));
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

/// Manages a tunnel after its creation.
/// Associates a requests channel with a concrete tunnel (enabling switch-over??)
pub(crate) struct TunnelHandler {
    tunnel: Option<Tunnel>,
    interim_tunnel: Option<Tunnel>,
    destroyed: bool,
    requests: mpsc::UnboundedReceiver<Request>,
    events: mpsc::Sender<Event>,
    rng: rand::SystemRandom,
}

impl TunnelHandler {
    pub(crate) fn new(
        tunnel: Tunnel,
        requests: mpsc::UnboundedReceiver<Request>,
        events: mpsc::Sender<Event>,
    ) -> Self {
        TunnelHandler {
            tunnel: None,
            interim_tunnel: Some(tunnel),
            destroyed: false,
            requests,
            events,
            rng: rand::SystemRandom::new(),
        }
    }

    pub(crate) async fn handle(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                msg = self.tunnel.out_circuit.accept_opaque() => {
                    self.handle_tunnel_message(msg).await?;
                }
                Some(req) = self.requests.recv() => {
                    self.handle_request(req).await?;
                }
            }
        }

        // TODO cleanup
    }

    async fn handle_tunnel_message(
        &mut self,
        msg: SocketResult<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // TODO apply timeout to handle tunnel rotation
        // TODO send event in case of error
        let mut msg = msg?;
        // TODO send event in case of error
        msg.decrypt(self.tunnel.session_keys.iter().rev())?;
        let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
        match tunnel_msg {
            Ok(TunnelRequest::Data(tunnel_id, data)) => {
                let event = Event::Data { tunnel_id, data };
                // TODO send event in case of error
                self.events.send(event).await?
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
        Ok(())
    }

    async fn handle_request(&mut self, req: Request) -> Result<()> {
        match req {
            Request::Data { data } => match &self.tunnel {
                Some(tunnel) => {
                    let circuit_id = tunnel.out_circuit.id;
                    let tunnel_id = tunnel.id;
                    tunnel
                        .out_circuit
                        .socket()
                        .await
                        .send_data(circuit_id, tunnel_id, data, &tunnel.session_keys, &self.rng)
                        .await?;
                    Ok(())
                }
                None => Err(anyhow!("Tunnel not ready.")),
            },
            (Request::Switchover) => {
                if !self.destroyed {
                    match self.interim_tunnel.take() {
                        Some(mut t) => {
                            t.begin(&self.rng).await?;
                            let old_tunnel = self.tunnel.replace(t);
                            if old_tunnel.is_none() {
                                // self.events.send(Event::Ready)
                            }

                            tokio::spawn(async move {
                                // build new tunnel to dest
                                // replace interims
                                // deconstruct old_tunnel
                            })
                        }
                        None => {
                            // send error
                            return Err(anyhow!("Switchover failed"));
                        }
                    }
                } else {
                    // deconstruct both tunnel and interim tunnel
                    return Err(anyhow!("Tunnel was destroyed"));
                }
            }
            Request::Destroy => {
                self.destroyed = true;
                Ok(())
            }
        }
    }
}
