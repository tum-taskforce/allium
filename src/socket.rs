use crate::onion_protocol::{
    CircuitCreate, CircuitCreated, FromBytes, Key, SignKey, ToBytes, VerifyKey, ONION_MESSAGE_SIZE,
};
use crate::{CircuitId, Result};
use anyhow::{anyhow, Context};
use async_std::io::{Read, Write};
use bytes::BytesMut;
use futures::{AsyncReadExt, AsyncWriteExt};
use ring::rand;

pub(crate) struct OnionSocket<S> {
    stream: S,
    buf: BytesMut,
}

impl<S: Write + Read> OnionSocket<S> {
    pub(crate) fn new(stream: S) -> Self {
        OnionSocket {
            stream,
            buf: BytesMut::with_capacity(ONION_MESSAGE_SIZE),
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

        req.write_padded_to(&mut self.buf, rng, ONION_MESSAGE_SIZE);
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
        self.buf.clear();
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
        res.write_padded_to(&mut self.buf, rng, ONION_MESSAGE_SIZE);
        self.stream
            .write_all(&mut self.buf)
            .await
            .context("Error while writing CircuitCreated")?; // TODO handle timeout
        Ok(())
    }
}
