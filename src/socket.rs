use crate::onion_protocol::{
    CircuitCreate, CircuitCreated, CircuitOpaque, CircuitOpaquePayload, FromBytesExt, Key, SignKey,
    ToBytesExt, TunnelRequest, TunnelResponse, VerifyKey, MESSAGE_SIZE,
};
use crate::utils::{FromBytes, ToBytes};
use crate::{CircuitId, Result, TunnelId};
use anyhow::{anyhow, Context};
use bytes::BytesMut;
use ring::{aead, rand};
use std::net::SocketAddr;
use tokio::prelude::*;

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

    pub(crate) async fn initiate_handshake(
        &mut self,
        circuit_id: CircuitId,
        key: Key,
        rng: &rand::SystemRandom,
    ) -> Result<VerifyKey> {
        self.buf.clear();
        let req = CircuitCreate { circuit_id, key };

        req.write_padded_to(&mut self.buf, rng, MESSAGE_SIZE);
        self.stream
            .write_all(self.buf.as_ref())
            .await
            .context("Error while writing CircuitCreate")?;

        self.stream
            .read_exact(&mut self.buf)
            .await
            .context("Error while reading CircuitCreated")?; // TODO handle timeout
        let res =
            CircuitCreated::read_from(&mut self.buf).context("Invalid CircuitCreated message")?;

        if res.circuit_id != circuit_id {
            return Err(anyhow!(
                "Circuit ID in CircuitCreated does not match ID in CircuitCreate"
            ));
        }

        Ok(res.key)
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

        res.decrypt(&rng, aes_keys.iter().rev())?;
        let tunnel_res = TunnelResponse::read_with_digest_from(&mut res.payload)
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

    pub(crate) async fn next_message(&mut self) -> Result<CircuitOpaque<BytesMut>> {
        todo!()
    }

    pub(crate) async fn send_opaque(
        &mut self,
        circuit_id: CircuitId,
        payload: BytesMut,
        rng: &rand::SystemRandom,
    ) -> Result<()> {
        todo!()
    }
}
