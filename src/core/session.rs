use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};
use crate::core::padding::PaddingFactory;
use crate::core::stream::{Stream, WriteCommand};
use crate::error::Result;

pub struct SessionConfig {
    pub max_streams: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { max_streams: 256 }
    }
}

pub struct Session<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    read_half: Mutex<tokio::io::ReadHalf<T>>,
    write_half: Arc<Mutex<tokio::io::WriteHalf<T>>>,
    padding: PaddingFactory,
    config: SessionConfig,
    peer_version: AtomicU8,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<T> {
    pub fn new_server(conn: T, padding: PaddingFactory, config: SessionConfig) -> Self {
        let (read_half, write_half) = tokio::io::split(conn);
        Self {
            read_half: Mutex::new(read_half),
            write_half: Arc::new(Mutex::new(write_half)),
            padding,
            config,
            peer_version: AtomicU8::new(0),
        }
    }

    pub fn padding_md5(&self) -> &str {
        self.padding.md5_hex()
    }

    pub async fn recv_loop(self: Arc<Self>, new_stream_tx: mpsc::Sender<Stream>) -> Result<()> {
        let mut streams: HashMap<u32, mpsc::Sender<Bytes>> = HashMap::new();
        let mut settings_received = false;

        // Create the write command channel and spawn writer task
        let (write_cmd_tx, mut write_cmd_rx) = mpsc::channel::<WriteCommand>(256);
        let writer = self.write_half.clone();
        tokio::spawn(async move {
            while let Some(cmd) = write_cmd_rx.recv().await {
                // Split data into u16::MAX-sized PSH frames to avoid truncation,
                // matching the Go implementation's writeDataFrame chunking logic.
                let mut offset = 0;
                let data = &cmd.data;
                let total = data.len();
                // Always send at least one frame (even for empty payloads).
                loop {
                    let chunk_end = (offset + u16::MAX as usize).min(total);
                    let chunk = &data[offset..chunk_end];
                    let header = FrameHeader {
                        command: Command::Psh,
                        stream_id: cmd.stream_id,
                        length: chunk.len() as u16,
                    };
                    let mut hdr_buf = [0u8; HEADER_SIZE];
                    header.encode(&mut hdr_buf);
                    let mut w = writer.lock().await;
                    if w.write_all(&hdr_buf).await.is_err() {
                        return;
                    }
                    if !chunk.is_empty() && w.write_all(chunk).await.is_err() {
                        return;
                    }
                    drop(w);
                    offset = chunk_end;
                    if offset >= total {
                        break;
                    }
                }
            }
        });

        let mut reader = self.read_half.lock().await;
        loop {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            match reader.read_exact(&mut hdr_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("connection closed");
                    break;
                }
                Err(e) => return Err(e.into()),
            }

            let header = FrameHeader::decode(&hdr_buf);
            match header.command {
                Command::Settings => {
                    let mut data = vec![0u8; header.length as usize];
                    if header.length > 0 {
                        reader.read_exact(&mut data).await?;
                    }
                    let text = String::from_utf8_lossy(&data);
                    let mut peer_version: u8 = 0;
                    let mut peer_padding_md5 = String::new();
                    for line in text.lines() {
                        if let Some(v) = line.strip_prefix("v=") {
                            peer_version = v.parse().unwrap_or(0);
                        } else if let Some(md5) = line.strip_prefix("padding-md5=") {
                            peer_padding_md5 = md5.to_string();
                        }
                    }
                    self.peer_version.store(peer_version, Ordering::Relaxed);
                    settings_received = true;

                    if peer_padding_md5 != self.padding.md5_hex() {
                        self.write_frame(
                            Command::UpdatePaddingScheme,
                            0,
                            self.padding.raw_scheme().as_bytes(),
                        )
                        .await?;
                    }

                    if peer_version >= 2 {
                        self.write_frame(Command::ServerSettings, 0, b"v=2").await?;
                    }
                }
                Command::Syn => {
                    if !settings_received {
                        self.write_frame(
                            Command::Alert,
                            header.stream_id,
                            b"settings not received",
                        )
                        .await?;
                        if header.length > 0 {
                            let mut skip = vec![0u8; header.length as usize];
                            reader.read_exact(&mut skip).await?;
                        }
                        continue;
                    }
                    if streams.len() >= self.config.max_streams {
                        self.write_frame(Command::Alert, header.stream_id, b"max streams exceeded")
                            .await?;
                        if header.length > 0 {
                            let mut skip = vec![0u8; header.length as usize];
                            reader.read_exact(&mut skip).await?;
                        }
                        continue;
                    }
                    if header.length > 0 {
                        let mut skip = vec![0u8; header.length as usize];
                        reader.read_exact(&mut skip).await?;
                    }
                    let (data_tx, stream) = Stream::new(header.stream_id, write_cmd_tx.clone());
                    streams.insert(header.stream_id, data_tx);
                    if new_stream_tx.send(stream).await.is_err() {
                        warn!("new_stream_tx receiver dropped");
                        break;
                    }
                }
                Command::Psh => {
                    let mut data = vec![0u8; header.length as usize];
                    if header.length > 0 {
                        reader.read_exact(&mut data).await?;
                    }
                    if let Some(tx) = streams.get(&header.stream_id) {
                        let _ = tx.send(Bytes::from(data)).await;
                    }
                }
                Command::Fin => {
                    if header.length > 0 {
                        let mut skip = vec![0u8; header.length as usize];
                        reader.read_exact(&mut skip).await?;
                    }
                    streams.remove(&header.stream_id);
                }
                Command::Waste => {
                    if header.length > 0 {
                        let mut skip = vec![0u8; header.length as usize];
                        reader.read_exact(&mut skip).await?;
                    }
                }
                Command::HeartRequest => {
                    if header.length > 0 {
                        let mut skip = vec![0u8; header.length as usize];
                        reader.read_exact(&mut skip).await?;
                    }
                    self.write_frame(Command::HeartResponse, 0, &[]).await?;
                }
                Command::Alert => {
                    let mut data = vec![0u8; header.length as usize];
                    if header.length > 0 {
                        reader.read_exact(&mut data).await?;
                    }
                    let msg = String::from_utf8_lossy(&data);
                    warn!("received alert: {}", msg);
                    break;
                }
                _ => {
                    if header.length > 0 {
                        let mut skip = vec![0u8; header.length as usize];
                        reader.read_exact(&mut skip).await?;
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn write_frame(&self, command: Command, stream_id: u32, data: &[u8]) -> Result<()> {
        debug_assert!(
            data.len() <= u16::MAX as usize,
            "write_frame: control frame payload exceeds u16::MAX ({} bytes)",
            data.len()
        );
        let header = FrameHeader {
            command,
            stream_id,
            length: data.len() as u16,
        };
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);
        let mut w = self.write_half.lock().await;
        w.write_all(&hdr_buf).await?;
        if !data.is_empty() {
            w.write_all(data).await?;
        }
        Ok(())
    }

    pub async fn handshake_success(&self, stream_id: u32) -> Result<()> {
        if self.peer_version.load(Ordering::Relaxed) >= 2 {
            self.write_frame(Command::SynAck, stream_id, &[]).await?;
        }
        Ok(())
    }

    pub async fn handshake_failure(&self, stream_id: u32, err: &str) -> Result<()> {
        if self.peer_version.load(Ordering::Relaxed) >= 2 {
            self.write_frame(Command::SynAck, stream_id, err.as_bytes())
                .await?;
        }
        Ok(())
    }

    pub async fn send_fin(&self, stream_id: u32) -> Result<()> {
        self.write_frame(Command::Fin, stream_id, &[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};
    use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn test_padding() -> PaddingFactory {
        PaddingFactory::new(DEFAULT_SCHEME).unwrap()
    }

    // Helper: write a frame to an AsyncWrite
    async fn write_frame<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        cmd: Command,
        stream_id: u32,
        data: &[u8],
    ) {
        let header = FrameHeader {
            command: cmd,
            stream_id,
            length: data.len() as u16,
        };
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);
        w.write_all(&hdr_buf).await.unwrap();
        if !data.is_empty() {
            w.write_all(data).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_session_settings_exchange() {
        let (mut client_io, server_io) = duplex(8192);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move { sess.recv_loop(new_stream_tx).await });
        drop(client_io);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_session_syn_creates_stream() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move { sess.recv_loop(new_stream_tx).await });
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        let stream = tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.id(), 1);
        drop(client_io);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_session_psh_delivers_data() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move { sess.recv_loop(new_stream_tx).await });
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();
        write_frame(&mut client_io, Command::Psh, 1, b"hello from client").await;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello from client");
        drop(client_io);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_session_heart_request_response() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move { sess.recv_loop(new_stream_tx).await });
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;
        // Read frames back — may get ServerSettings first, then HeartResponse
        let mut found_heart = false;
        for _ in 0..5 {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_io.read_exact(&mut hdr_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let hdr = FrameHeader::decode(&hdr_buf);
                    if hdr.length > 0 {
                        let mut skip = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut skip).await.unwrap();
                    }
                    if hdr.command == Command::HeartResponse {
                        found_heart = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(found_heart, "did not receive HeartResponse");
        drop(client_io);
        let _ = handle.await;
    }
}
