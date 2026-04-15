use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

const CHANNEL_CAPACITY: usize = 32;

pub struct WriteCommand {
    pub stream_id: u32,
    pub data: Bytes,
}

pub struct Stream {
    id: u32,
    data_rx: mpsc::Receiver<Bytes>,
    session_tx: PollSender<WriteCommand>,
    read_buf: Bytes,
}

impl Stream {
    pub fn new(id: u32, session_tx: mpsc::Sender<WriteCommand>) -> (mpsc::Sender<Bytes>, Self) {
        let (data_tx, data_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let stream = Self {
            id,
            data_rx,
            session_tx: PollSender::new(session_tx),
            read_buf: Bytes::new(),
        };
        (data_tx, stream)
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain read_buf first
        if !self.read_buf.is_empty() {
            let amt = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..amt]);
            self.read_buf = self.read_buf.slice(amt..);
            return Poll::Ready(Ok(()));
        }

        // Poll for new data
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let amt = data.len().min(buf.remaining());
                buf.put_slice(&data[..amt]);
                if amt < data.len() {
                    self.read_buf = data.slice(amt..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.session_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let stream_id = self.id;
                let data = Bytes::copy_from_slice(buf);
                let len = data.len();
                self.session_tx
                    .send_item(WriteCommand { stream_id, data })
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "session closed"))?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_stream_read_receives_data() {
        let (writer, mut stream) = Stream::new(1, dummy_writer());
        writer
            .send(bytes::Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn test_stream_read_eof_on_drop() {
        let (writer, mut stream) = Stream::new(1, dummy_writer());
        drop(writer);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_stream_read_partial_buffer() {
        let (writer, mut stream) = Stream::new(1, dummy_writer());
        writer
            .send(bytes::Bytes::from_static(b"hello world"))
            .await
            .unwrap();
        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b" worl");
    }

    #[tokio::test]
    async fn test_stream_write_sends_frame() {
        let (session_writer, mut rx) = tokio::sync::mpsc::channel::<WriteCommand>(8);
        let (_data_tx, mut stream) = Stream::new(1, session_writer);
        stream.write_all(b"hello").await.unwrap();
        let cmd = rx.recv().await.unwrap();
        assert_eq!(cmd.stream_id, 1);
        assert_eq!(&cmd.data[..], b"hello");
    }

    #[tokio::test]
    async fn test_stream_id() {
        let (_writer, stream) = Stream::new(42, dummy_writer());
        assert_eq!(stream.id(), 42);
    }

    fn dummy_writer() -> tokio::sync::mpsc::Sender<WriteCommand> {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        tx
    }
}
