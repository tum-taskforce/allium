use crate::onion_protocol::{CircuitCreate, CircuitCreated, CircuitOpaque, CircuitOpaqueBytes, CircuitOpaquePayload,
    FromBytesExt, Key, SignKey, ToBytesExt, TunnelRequest, TunnelResponse, VerifyKey, MESSAGE_SIZE, CircuitTeardown};
use crate::utils::{FromBytes, ToBytes};
use crate::{CircuitId, Result, TunnelId};
use anyhow::{anyhow, Context};
use thiserror::Error;
use bytes::BytesMut;
use ring::{aead, rand};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio::time::{timeout, Duration, Elapsed};
use crate::socket::OnionSocketError::{BrokenMessage, TeardownMessage};

#[derive(Error, Debug)]
pub(crate) enum OnionSocketError {
    /// The stream of this `OnionSocket` has been terminated and is unavailable for communication.
    /// The cause is underlying network layer stream of type  `S` threw an I/O error during interaction
    #[error("stream has been terminated")]
    StreamTerminated(#[from] io::Error),
    /// Reading or writing on the stream of this `OnionSocket` timed out
    #[error("stream operation has timed out")]
    StreamTimeout(#[from] Elapsed),
    /// The received message is of type `TEARDOWN` and the function throwing this error cannot deal
    /// with it. The `TEARDOWN` message is always allowed by protocol to indicate a closed circuit
    /// by the connected peer.
    #[error("received teardown message that cannot be handled")]
    TeardownMessage(),
    /// The received message does not comply with the protocol
    /// This may be caused by:
    /// - an undefined message type or tunnel message type
    /// - an irregular message type (like waiting for an Tunnel `TRUNCATED` message, yet receiving a
    /// `TUNNEL EXTENDED` message)
    /// - a wrong circuit id
    // In the case that a command response is awaited, incoming Tunnel Data messages may or may
    // not be ignored. Either way would be conforming to the specification.
    // TODO argument: message
    #[error("received broken message that cannot be parsed and violates protocol")]
    BrokenMessage(),
}

pub(crate) struct OnionSocket<S> {
    stream: S,
    buf: BytesMut,
}

impl<S: AsyncWrite + AsyncRead + Unpin> OnionSocket<S> {
    pub(crate) fn new(stream: S) -> Self {
        OnionSocket {
            stream,
            buf: BytesMut::with_capacity(MESSAGE_SIZE),
        }
    }

    /// Performs a circuit handshake with the peer connected to this socket.
    /// The `CIRCUIT CREATE` message is sent with the given `key` and sent to the peer. Then, this
    /// method tries to receive a `CIRCUIT CREATED` message from the peer. If parsed correctly, the
    /// received peer's key is returned.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    /// - `TeardownMessage` - A `TEARDOWN`message has been received instead of `CIRCUIT CREATE`
    /// - `BrokenMessage` - The received answer message could not be parsed
    pub(crate) async fn initiate_handshake(
        &mut self,
        circuit_id: CircuitId,
        key: Key,
        rng: &rand::SystemRandom,
    ) -> std::result::Result<VerifyKey, OnionSocketError> {
        self.buf.clear();
        let req = CircuitCreate { circuit_id, key };

        req.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        // TODO can I extract this?????????
        timeout(Duration::from_secs(10), // TODO needs proper timeout definition
                self.stream.write_all(self.buf.as_ref())).await??;

        timeout(Duration::from_secs(10), // TODO needs proper timeout definition
                self.stream.read_exact(&mut self.buf)).await??;
        match CircuitCreated::read_from(&mut self.buf) {
            Ok(res) => {
                if res.circuit_id != circuit_id {
                    Err(BrokenMessage())
                } else {
                    Ok(res.key)
                }
            }
            Err(_) => {
                if let Ok(td) = CircuitTeardown::read_from(&mut self.buf) {
                    // TODO invalid circuit ids are being ignored
                    Err(TeardownMessage())
                } else {
                    Err(BrokenMessage())
                }
            }
        }
    }

    pub(crate) async fn accept_handshake(&mut self) -> Result<(CircuitId, Key)> {
        self.buf.resize(MESSAGE_SIZE, 0);
        self.stream
            .read_exact(&mut self.buf)
            .await
            .context("Error while reading CircuitCreate")?; // TODO handle timeout
        let msg =
            CircuitCreate::read_from(&mut self.buf).context("Invalid CircuitCreate message")?;
        Ok((msg.circuit_id, msg.key))
    }

    pub(crate) async fn finalize_handshake<'k>(
        &mut self,
        circuit_id: CircuitId,
        key: SignKey<'k>,
        rng: &rand::SystemRandom,
    ) -> Result<()> {
        self.buf.clear();
        let res = CircuitCreated { circuit_id, key };
        res.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        self.stream
            .write_all(&mut self.buf)
            .await
            .context("Error while writing CircuitCreated")?; // TODO handle timeout
        Ok(())
    }

    /// aes_key are in encrypt order
    pub(crate) async fn initiate_tunnel_handshake(
        &mut self,
        circuit_id: CircuitId,
        tunnel_id: TunnelId,
        peer_addr: SocketAddr,
        key: Key,
        aes_keys: &[aead::LessSafeKey],
        rng: &rand::SystemRandom,
    ) -> Result<VerifyKey> {
        self.buf.clear();
        let tunnel_req = TunnelRequest::Extend(tunnel_id, peer_addr, key);
        let req = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_req,
                rng,
                encrypt_keys: aes_keys,
            },
        };

        req.write_to(&mut self.buf);
        assert_eq!(self.buf.len(), MESSAGE_SIZE);
        self.stream
            .write_all(self.buf.as_ref())
            .await
            .context("Error while writing CircuitOpaque<TunnelRequest::Extend>")?;

        self.stream
            .read_exact(&mut self.buf)
            .await
            .context("Error while reading TunnelResponse::Extended")?; // TODO handle timeout
        let mut res =
            CircuitOpaque::read_from(&mut self.buf).context("Invalid CircuitOpaque message")?;

        if res.circuit_id != circuit_id {
            return Err(anyhow!(
                "Circuit ID in Opaque response does not match ID in request"
            ));
        }

        res.decrypt(aes_keys.iter().rev())?;
        let tunnel_res = TunnelResponse::read_with_digest_from(&mut res.payload.bytes)
            .context("Invalid TunnelResponse message")?;

        match tunnel_res {
            TunnelResponse::Extended(res_tunnel_id, res_key) => {
                if res_tunnel_id != tunnel_id {
                    return Err(anyhow!("Tunnel ID in Extended does not match ID in Extend"));
                }

                Ok(res_key)
            }
        }
    }

    pub(crate) async fn finalize_tunnel_handshake(
        &mut self,
        circuit_id: CircuitId,
        tunnel_id: TunnelId,
        key: VerifyKey,
        aes_keys: &[aead::LessSafeKey],
        rng: &rand::SystemRandom,
    ) -> Result<()> {
        self.buf.clear();
        let tunnel_res = TunnelResponse::Extended(tunnel_id, key);
        let req = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_res,
                rng,
                encrypt_keys: aes_keys,
            },
        };

        req.write_to(&mut self.buf);
        assert_eq!(self.buf.len(), MESSAGE_SIZE);
        self.stream
            .write_all(self.buf.as_ref())
            .await
            .context("Error while writing CircuitOpaque<TunnelResponse::Extended>")?;
        Ok(())
    }

    /// Tries to read an entire onion protocol message before returning.
    ///
    pub(crate) async fn accept_opaque(&mut self) -> Result<CircuitOpaque<CircuitOpaqueBytes>> {
        self.buf.resize(MESSAGE_SIZE, 0);
        self.stream
            .read_exact(&mut self.buf)
            .await
            .context("Error while reading CircuitOpaque")?; // TODO handle timeout
        let msg =
            CircuitOpaque::read_from(&mut self.buf).context("Invalid CircuitOpaque message")?;
        Ok(msg)
    }

    pub(crate) async fn forward_opaque(
        &mut self,
        circuit_id: CircuitId,
        payload: CircuitOpaqueBytes,
        rng: &rand::SystemRandom,
    ) -> Result<()> {
        self.buf.clear();
        let msg = CircuitOpaque {
            circuit_id,
            payload,
        };

        msg.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        self.stream
            .write_all(self.buf.as_ref())
            .await
            .context("Error while writing CircuitOpaque")?;
        Ok(())
    }
}

impl OnionSocket<TcpStream> {
    pub(crate) fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.stream.peer_addr()?)
    }
}
