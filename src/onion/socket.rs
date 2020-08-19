use crate::onion::crypto::SessionKey;
use crate::onion::protocol::*;
use crate::utils::{ToBytes, TryFromBytes};
use crate::{CircuitId, Result, TunnelId};
use bytes::{Bytes, BytesMut};
use ring::rand;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio::time::{timeout, Duration, Elapsed};

#[derive(Error, Debug)]
pub(crate) enum OnionSocketError {
    /// The stream of this `OnionSocket` has been terminated and is unavailable for communication.
    /// The cause is underlying network layer stream of type  `S` threw an I/O error during interaction
    #[error("stream has been terminated")]
    StreamTerminated(#[from] io::Error),
    /// Reading or writing on the stream of this `OnionSocket` timed out. Be aware of any possible
    /// scenarios in which a partial message has been received and the buffer is partially filled.
    /// If another operation on this `OnionSocket` is called, the buffer may not be filled with one
    /// complete message as expected and `BrokenMessage` may be returned. Alternatively, clearing
    /// the buffer may cause broken message fragments to remain in the underlying stream, which will
    /// be ending up in the buffer on the next read call.
    #[error("stream operation has timed out")]
    StreamTimeout(#[from] Elapsed),
    /// The received message is of type `TEARDOWN` and the function throwing this error cannot deal
    /// with it. The `TEARDOWN` message is always allowed by protocol to indicate a closed circuit
    /// by the connected peer.
    #[error("received teardown message that cannot be handled")]
    TeardownMessage,
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
    BrokenMessage,
    /// Indicates that the remote peer returned a tunnel request with an error code
    #[error("tunnel request returned error")]
    Peer,
}

pub(crate) type SocketResult<T> = std::result::Result<T, OnionSocketError>;

impl From<CircuitProtocolError> for OnionSocketError {
    fn from(e: CircuitProtocolError) -> Self {
        match e {
            CircuitProtocolError::Teardown { expected } => OnionSocketError::TeardownMessage,
            CircuitProtocolError::Unknown { expected, actual } => OnionSocketError::BrokenMessage,
        }
    }
}

impl<E: std::fmt::Debug> From<TunnelProtocolError<E>> for OnionSocketError {
    fn from(e: TunnelProtocolError<E>) -> Self {
        match e {
            TunnelProtocolError::Peer(_) => OnionSocketError::Peer,
            _ => OnionSocketError::BrokenMessage,
        }
    }
}

/// Wraps an underlying network primitive (eg. TCP or TLS stream) and provides methods implementing the protocol.
/// Utilizes an internal buffer for (de-)serialization.
///
/// The socket layer serves as glue between the onion protocol and higher layers.
pub(crate) struct OnionSocket<S> {
    stream: S,
    buf: BytesMut,
}

impl<S> OnionSocket<S> {
    pub(crate) fn new(stream: S) -> Self {
        OnionSocket {
            stream,
            buf: BytesMut::with_capacity(MESSAGE_SIZE),
        }
    }
}

impl<S: AsyncRead + Unpin> OnionSocket<S> {
    async fn read_buf_from_stream(&mut self) -> SocketResult<usize> {
        Ok(timeout(
            Duration::from_secs(5), // TODO don't hard code timeouts
            self.stream.read_exact(&mut self.buf),
        )
        .await??)
    }

    /// Listends for incoming `CIRCUIT CREATE` messages and returns the circuit id and key in this
    /// message.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    /// - `TeardownMessage` - A `TEARDOWN` message has been received instead of `CIRCUIT CREATE`
    /// - `BrokenMessage` - The received answer message could not be parsed
    pub(crate) async fn accept_handshake(&mut self) -> SocketResult<(CircuitId, Key)> {
        self.buf.resize(MESSAGE_SIZE, 0);
        self.read_buf_from_stream().await?;
        let msg = CircuitCreate::try_read_from(&mut self.buf)?;
        Ok((msg.circuit_id, msg.key))
    }

    /// Tries to read an entire onion protocol message before returning. This function does not
    /// apply a timeout on stream listening, so expect this function to deadlock if the stream is
    /// idle, but kept alive.
    ///
    /// Returns a `CIRCUIT OPAQUE` message if the received message could successfully be parsed. If
    /// not, an error will be returned.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `TeardownMessage` - A `TEARDOWN` message has been received instead of `CIRCUIT OPAQUE`
    /// - `BrokenMessage` - The received answer message could not be parsed
    pub(crate) async fn accept_opaque(
        &mut self,
    ) -> SocketResult<CircuitOpaque<CircuitOpaqueBytes>> {
        self.buf.resize(MESSAGE_SIZE, 0);
        // NOTE: no timeout applied here, parent is supposed to handle that
        self.stream.read_exact(&mut self.buf).await?;
        //.context("Error while reading CircuitOpaque")?;
        let msg = CircuitOpaque::try_read_from(&mut self.buf)?;
        Ok(msg)
    }
}

impl<S: AsyncWrite + Unpin> OnionSocket<S> {
    async fn write_buf_to_stream(&mut self) -> SocketResult<()> {
        Ok(timeout(
            Duration::from_secs(2), // TODO don't hard code timeouts
            self.stream.write_all(self.buf.as_ref()),
        )
        .await??)
    }

    async fn encrypt_and_send_opaque<K: ToBytes>(
        &mut self,
        circuit_id: u16,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
        tunnel_res: K,
    ) -> SocketResult<()> {
        let req = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_res,
                rng,
                encrypt_keys: session_keys,
            },
        };

        req.write_to(&mut self.buf);
        assert_eq!(self.buf.len(), MESSAGE_SIZE);
        // TODO omit timeout here?
        self.write_buf_to_stream().await
    }

    /// Sends a `CIRCUIT CREATED` reply message to the connected peer with the given `circuit_id`
    /// and `key`. The `rng` will be used for randomly generated message padding.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn finalize_handshake<'k>(
        &mut self,
        circuit_id: CircuitId,
        key: SignKey<'k>,
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let res = CircuitCreated { circuit_id, key };
        res.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        self.write_buf_to_stream().await?;
        Ok(())
    }

    /// Replies on this `OnionSocket` with an `EXTENDED` message to a successful `EXTEND` call.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn finalize_tunnel_handshake(
        &mut self,
        circuit_id: CircuitId,
        key: VerifyKey,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let tunnel_res = TunnelResponseExtended { peer_key: key };
        self.encrypt_and_send_opaque(circuit_id, session_keys, rng, tunnel_res)
            .await
        //.context("Error while writing CircuitOpaque<TunnelResponse::Extended>")?;
    }

    /// Replies on this `OnionSocket` with an `EXTENDED` message to an unsuccessful `EXTEND` call
    /// with error code `error_code`.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn reject_tunnel_handshake(
        &mut self,
        circuit_id: CircuitId,
        session_keys: &[SessionKey],
        error: TunnelExtendedError,
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        self.encrypt_and_send_opaque(circuit_id, session_keys, rng, error)
            .await
        //.context("Error while writing CircuitOpaque<TunnelResponse::Extended>")?;
    }

    /// Replies on this `OnionSocket` with a `TRUNCATED` message to a successful `TRUNCATE` call.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn finalize_tunnel_truncate(
        &mut self,
        circuit_id: CircuitId,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        // FIXME why do I have to define Key here?
        let tunnel_res = TunnelResponseTruncated;
        self.encrypt_and_send_opaque(circuit_id, session_keys, rng, tunnel_res)
            .await
        //.context("Error while writing CircuitOpaque<TunnelResponse::Truncated>")?;
    }

    /// Replies on this `OnionSocket` with an `TRUNCATED` message to a unsuccessful `TRUNCATE` call
    /// with error code `error_code`.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn reject_tunnel_truncate(
        &mut self,
        circuit_id: CircuitId,
        session_keys: &[SessionKey],
        error: TunnelTruncatedError,
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        self.encrypt_and_send_opaque(circuit_id, session_keys, rng, error)
            .await
        //.context("Error while writing CircuitOpaque<TunnelResponse::Extended>")?;
    }

    /// Forwards an already correctly encrypted `payload` to the stream in this `OnionSocket`
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn forward_opaque(
        &mut self,
        circuit_id: CircuitId,
        payload: CircuitOpaqueBytes,
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let msg = CircuitOpaque {
            circuit_id,
            payload,
        };

        msg.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        // FIXME Do we want to apply the timeout here? Generally: no, but what do we do instead?
        self.write_buf_to_stream().await?;
        //.context("Error while writing CircuitOpaque")?;
        Ok(())
    }

    /// Sends a `TEARDOWN` message via the stream.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    pub(crate) async fn teardown(
        &mut self,
        circuit_id: CircuitId,
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let res = CircuitTeardown { circuit_id };
        res.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        // NOTE: A timeout needs to be applied here
        self.write_buf_to_stream().await?;
        Ok(())
    }

    /// Sends a `TUNNEL BEGIN` message via this stream with the given `tunnel_id` to indicate a
    /// conversation begin to the final hop on this socket. This function does not block for
    /// responses.
    ///
    /// If the targeted hop is not the final hop or forbids the connection, it may send a `TEARDOWN`
    /// message that will not be read here, but listening on the connection for `TUNNEL DATA`
    /// packets may reveal this.
    /// If the connection is rejected, an `END` packet may be sent by the connected hop, which may
    /// be evaluated when handling the incoming packets.
    pub(crate) async fn begin(
        &mut self,
        circuit_id: CircuitId,
        tunnel_id: TunnelId,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let tunnel_res = TunnelRequest::Begin(tunnel_id);
        self.encrypt_and_send_opaque(circuit_id, session_keys, rng, tunnel_res)
            .await
    }

    pub(crate) async fn send_data(
        &mut self,
        circuit_id: CircuitId,
        tunnel_id: TunnelId,
        data: Bytes,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let tunnel_req = TunnelRequest::Data(tunnel_id, data);
        self.encrypt_and_send_opaque(circuit_id, session_keys, rng, tunnel_req)
            .await
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin> OnionSocket<S> {
    /// Performs a circuit handshake with the peer connected to this socket.
    /// The `CIRCUIT CREATE` message is sent with the given `key` and sent to the peer. Then, this
    /// method tries to receive a `CIRCUIT CREATED` message from the peer. If parsed correctly, the
    /// received peer's key is returned.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    /// - `TeardownMessage` - A `TEARDOWN`message has been received instead of `CIRCUIT CREATED`
    /// - `BrokenMessage` - The received answer message could not be parsed or has an unexpected
    ///   circuit_id
    pub(crate) async fn initiate_handshake(
        &mut self,
        circuit_id: CircuitId,
        key: Key,
        rng: &rand::SystemRandom,
    ) -> SocketResult<VerifyKey> {
        self.buf.clear();
        let req = CircuitCreate { circuit_id, key };

        req.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        self.write_buf_to_stream().await?;

        self.read_buf_from_stream().await?;
        let res = CircuitCreated::try_read_from(&mut self.buf)?;
        if res.circuit_id == circuit_id {
            Ok(res.key)
        } else {
            Err(OnionSocketError::BrokenMessage)
        }
    }

    /// Initializes a tunnel handshake by forwarding the given `circuit_id` and `key` through a
    /// tunnel with the connected peer as its first hop.
    ///
    /// The last hop in the tunnel will try to extend the tunnel to the peer defined by its address
    /// in `peer_addr`.
    ///
    /// To encrypt the `OPAQUE` message, `aes_keys` will be used. The keys in `aes_keys` are
    /// expected to be in encrypt order.
    ///
    /// The `rng` will be used for randomly generated message padding.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    /// - `TeardownMessage` - A `TEARDOWN`message has been received instead of `CIRCUIT OPAQUE`
    /// - `BrokenMessage` - The received answer message could not be parsed
    pub(crate) async fn initiate_tunnel_handshake(
        &mut self,
        circuit_id: CircuitId,
        peer_addr: SocketAddr,
        key: Key,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
    ) -> SocketResult<VerifyKey> {
        self.buf.clear();
        let tunnel_req = TunnelRequest::Extend(peer_addr, key);
        let req = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_req,
                rng,
                encrypt_keys: session_keys,
            },
        };

        req.write_to(&mut self.buf);
        assert_eq!(self.buf.len(), MESSAGE_SIZE);
        // TODO Fix timeout
        self.write_buf_to_stream().await?;

        self.read_buf_from_stream().await?;
        let mut res = CircuitOpaque::try_read_from(&mut self.buf)?;

        if res.circuit_id != circuit_id {
            return Err(OnionSocketError::BrokenMessage);
            //return Err(anyhow!(
            //    "Circuit ID in Opaque response does not match ID in request"
            //));
        }

        res.decrypt(session_keys.iter().rev())
            .map_err(|_| OnionSocketError::BrokenMessage)?;
        let tunnel_res = TunnelResponseExtended::read_with_digest_from(&mut res.payload.bytes)?;
        //.context("Invalid TunnelResponse message")?;

        Ok(tunnel_res.peer_key)
    }

    /// Sends a `TUNNEL TRUNCATE` message to the socket. The receiving peer is determined by the
    /// length of `aes_keys`. For example, if `aes_keys` consists of two elements, the hop at
    /// index 1 (the second hop) will be able to read the packet and process the truncate.
    ///
    /// To encrypt the `OPAQUE` message, `aes_keys` will be used. The keys in `aes_keys` are
    /// expected to be in encrypt order.
    ///
    /// The `rng` will be used for randomly generated message padding.
    ///
    /// # Errors:
    /// - `StreamTerminated` - The stream is broken
    /// - `StreamTimeout` -  The stream operations timed out
    /// - `TeardownMessage` - A `TEARDOWN`message has been received instead of `CIRCUIT OPAQUE`
    /// - `BrokenMessage` - The received answer message could not be parsed
    pub(crate) async fn truncate_tunnel(
        &mut self,
        circuit_id: CircuitId,
        session_keys: &[SessionKey],
        rng: &rand::SystemRandom,
    ) -> SocketResult<()> {
        self.buf.clear();
        let tunnel_req = TunnelRequest::Truncate;
        let req = CircuitOpaque {
            circuit_id,
            payload: CircuitOpaquePayload {
                msg: &tunnel_req,
                rng,
                encrypt_keys: session_keys,
            },
        };

        req.write_to(&mut self.buf);
        assert_eq!(self.buf.len(), MESSAGE_SIZE);
        // TODO Fix timeout
        self.write_buf_to_stream().await?;

        self.read_buf_from_stream().await?;
        let mut res = CircuitOpaque::try_read_from(&mut self.buf)?;

        if res.circuit_id != circuit_id {
            return Err(OnionSocketError::BrokenMessage);
            //return Err(anyhow!(
            //    "Circuit ID in Opaque response does not match ID in request"
            //));
        }

        res.decrypt(session_keys.iter().rev())
            .map_err(|_| OnionSocketError::BrokenMessage)?;
        let tunnel_res = TunnelResponseTruncated::read_with_digest_from(&mut res.payload.bytes)?;
        //.context("Invalid TunnelResponse message")?;

        Ok(())
    }
}

impl OnionSocket<TcpStream> {
    pub(crate) fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.stream.peer_addr()?)
    }
}
