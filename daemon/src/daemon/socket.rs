use crate::utils::{ToBytes, TryFromBytes};
use crate::Result;
use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct DaemonSocket<S> {
    stream: S,
    buf: BytesMut,
}

impl<S> DaemonSocket<S> {
    pub fn new(stream: S) -> Self {
        DaemonSocket {
            stream,
            buf: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> DaemonSocket<S> {
    pub async fn read_next<M: TryFromBytes<anyhow::Error>>(&mut self) -> Result<M> {
        let size = loop {
            if self.buf.len() >= 2 {
                break u16::from_be_bytes(self.buf[..2].try_into().unwrap()) as usize;
            }

            let bytes_read = self.stream.read_buf(&mut self.buf).await?;
            if 0 == bytes_read {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        };

        // This method reclaims no longer referenced space in front of the buffer.
        // To avoid the buffer growing indefinitely, we must ensure that byte slices contained
        // in messages returned from this function are not kept around longer than needed.
        self.buf.reserve(size);

        loop {
            if self.buf.len() >= 2 + size {
                return Ok(M::try_read_from(&mut self.buf)?);
            }

            let bytes_read = self.stream.read_buf(&mut self.buf).await?;
            if 0 == bytes_read {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> DaemonSocket<S> {
    pub async fn write<M: ToBytes>(&mut self, message: M) -> Result<()> {
        self.buf.clear();
        self.buf.reserve(message.size());
        message.write_to(&mut self.buf);
        self.stream.write_all(&self.buf).await?;
        Ok(())
    }
}
