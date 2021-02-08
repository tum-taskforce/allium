use crate::utils::{ToBytes, TryFromBytes};
use crate::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct ApiSocket<S> {
    stream: S,
    buf: BytesMut,
}

impl<S> ApiSocket<S> {
    pub fn new(stream: S) -> Self {
        ApiSocket {
            stream,
            buf: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> ApiSocket<S> {
    pub async fn read_next<M: TryFromBytes<anyhow::Error>>(&mut self) -> Result<M> {
        let mut size_buf = [0u8; 2];
        self.stream.read_exact(&mut size_buf).await?;
        let size = u16::from_be_bytes(size_buf) as usize;

        self.buf.resize(size, 0);
        self.buf[0] = size_buf[0];
        self.buf[1] = size_buf[1];
        self.stream.read_exact(&mut self.buf[2..]).await?;
        Ok(M::try_read_from(&mut self.buf)?)
    }
}

impl<S: AsyncWrite + Unpin> ApiSocket<S> {
    pub async fn write<M: ToBytes>(&mut self, message: M) -> Result<()> {
        self.buf.clear();
        self.buf.reserve(message.size());
        message.write_to(&mut self.buf);
        self.stream.write_all(&self.buf).await?;
        Ok(())
    }
}
