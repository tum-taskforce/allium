use async_std::io;
use futures::{AsyncReadExt, AsyncWriteExt};

use crate::Result;

pub trait ReadMessage {
    fn read_from<R: std::io::Read>(r: &mut R) -> Result<Self>
    where
        Self: Sized;
}

pub trait WriteMessage {
    fn size(&self) -> usize;
    fn write_to<W: std::io::Write>(&self, w: &mut W) -> Result<()>;
}

pub struct MessageReader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R> MessageReader<R> {
    pub fn new(inner: R) -> Self {
        MessageReader {
            inner,
            buf: Vec::new(),
        }
    }
}

impl<R: io::Read + Unpin> MessageReader<R> {
    pub async fn read_next<M: ReadMessage>(&mut self) -> Result<Option<M>> {
        let mut size_buf = [0u8; 2];
        self.inner.read_exact(&mut size_buf).await?;
        let size = u16::from_be_bytes(size_buf) as usize;

        self.buf.clear();
        self.buf.reserve(size);
        self.buf.extend_from_slice(&size_buf);
        self.inner.read_exact(&mut self.buf[..2]).await?;
        Ok(Some(M::read_from(&mut self.buf.as_slice())?))
    }
}

pub struct MessageWriter<W> {
    inner: W,
    buf: Vec<u8>,
}

impl<W> MessageWriter<W> {
    pub fn new(inner: W) -> Self {
        MessageWriter {
            inner,
            buf: Vec::new(),
        }
    }
}

impl<W: io::Write + Unpin> MessageWriter<W> {
    pub async fn write<M: WriteMessage>(&mut self, message: M) -> Result<()> {
        self.buf.clear();
        self.buf.reserve(message.size());
        message.write_to(&mut self.buf)?;
        self.inner.write_all(&self.buf).await?;
        Ok(())
    }
}

/*
pub fn messages(stream: &mut TcpStream) -> (MessageReader<impl io::Read>, MessageWriter<impl io::Write>) {
    let (reader, writer) = stream.split();
    (MessageReader::new(reader), MessageWriter::new(writer))
}

#[derive(Debug)]
pub(crate) struct Messages<R> {
    reader: R,
    size: Option<usize>,
}

impl<R: BufRead> Stream for Messages<R> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let available = futures::ready!(self.reader.poll_fill_buf(cx))?;
            if available.len() == 0 {
                return Poll::Ready(None);
            }
            match self.size {
                Some(n) if available.len() >= n => {
                    self.reader.consume(n);
                    self.size = None;
                    return Poll::Ready(Some(Ok(available[..n].into())));
                },
                None if available.len() >= 2 => {
                    let size = u16::from_be_bytes(available[..2].try_into().unwrap());
                    self.size = Some(size as usize);
                }
            }
        }
    }
}

pub trait MessagesExt: BufRead {
    fn messages(self) -> Messages<Self>
    where
        Self: Sized,
    {
        Messages { reader: self, size: None }
    }
}

impl<T: BufRead> MessagesExt for T {}
*/
