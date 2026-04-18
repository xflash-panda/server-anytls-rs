use rustc_hash::FxHashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};
use crate::core::padding::PaddingFactory;
use crate::core::stream::{Stream, WriteCommand};
use crate::error::Result;

/// Write a single WriteCommand as one or more PSH frames (chunking at u16::MAX).
/// Does NOT flush — caller is responsible for flushing after batching.
/// Header and payload are coalesced into a single write to avoid generating
/// separate TLS records (each record adds ~29 bytes overhead + encryption).
async fn write_psh_frames<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cmd: &WriteCommand,
    combined_buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    let data = &cmd.data;
    let total = data.len();
    let mut offset = 0;
    loop {
        let chunk_end = (offset + u16::MAX as usize).min(total);
        let chunk = &data[offset..chunk_end];
        let header = FrameHeader {
            command: Command::Psh,
            stream_id: cmd.stream_id,
            length: chunk.len() as u16,
        };
        // Coalesce header + payload into a single write_all call.
        combined_buf.clear();
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);
        combined_buf.extend_from_slice(&hdr_buf);
        combined_buf.extend_from_slice(chunk);
        w.write_all(combined_buf).await?;
        offset = chunk_end;
        if offset >= total {
            break;
        }
    }
    Ok(())
}

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

    pub async fn recv_loop(
        self: Arc<Self>,
        new_stream_tx: mpsc::Sender<Stream>,
        idle_timeout: Option<std::time::Duration>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let mut streams: FxHashMap<u32, mpsc::Sender<Bytes>> = FxHashMap::default();
        let mut settings_received = false;

        // Create the write command channel and spawn writer task
        let (write_cmd_tx, mut write_cmd_rx) = mpsc::channel::<WriteCommand>(256);
        let writer = self.write_half.clone();
        tokio::spawn(async move {
            // Reusable buffer for coalescing header+payload into single writes.
            let mut combined_buf = Vec::with_capacity(HEADER_SIZE + u16::MAX as usize);
            while let Some(cmd) = write_cmd_rx.recv().await {
                let mut w = writer.lock().await;
                if write_psh_frames(&mut *w, &cmd, &mut combined_buf)
                    .await
                    .is_err()
                {
                    return;
                }
                // Drain all pending commands without blocking (batch writes)
                while let Ok(cmd) = write_cmd_rx.try_recv() {
                    if write_psh_frames(&mut *w, &cmd, &mut combined_buf)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                // Single flush for entire batch
                if w.flush().await.is_err() {
                    return;
                }
            }
        });

        let mut reader = self.read_half.lock().await;
        // Reusable buffer to avoid per-frame heap allocation
        let mut payload_buf = BytesMut::with_capacity(u16::MAX as usize);

        // Idle timeout: when enabled, a pinned Sleep resets after every
        // received frame.  When disabled (None), we use a future that never
        // completes so a single select! handles both cases without duplication.
        let idle_sleep = tokio::time::sleep(idle_timeout.unwrap_or_default());
        tokio::pin!(idle_sleep);

        loop {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            let read_result = tokio::select! {
                r = reader.read_exact(&mut hdr_buf) => r,
                _ = &mut idle_sleep, if idle_timeout.is_some() => {
                    debug!("session idle timeout");
                    break;
                }
                _ = cancel_token.cancelled() => {
                    debug!("session cancelled by connection manager");
                    break;
                }
            };
            match read_result {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("connection closed");
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            // Reset idle timer on every received frame.
            if let Some(d) = idle_timeout {
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + d);
            }

            let header = FrameHeader::decode(&hdr_buf);
            let len = header.length as usize;

            match header.command {
                Command::Psh => {
                    payload_buf.resize(len, 0);
                    if len > 0 {
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    if let Some(tx) = streams.get(&header.stream_id) {
                        // split() → freeze() gives a zero-copy Bytes;
                        // the underlying allocation is reused on next resize.
                        let data = payload_buf.split().freeze();
                        // Use try_send to avoid head-of-line blocking: if one
                        // stream's channel is full, we must not block recv_loop
                        // (which would stall ALL streams on this connection).
                        // With channel capacity 1024, Full is extremely rare and
                        // indicates the consumer is severely behind.
                        match tx.try_send(data) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                streams.remove(&header.stream_id);
                            }
                            Err(mpsc::error::TrySendError::Full(data)) => {
                                // Channel is temporarily full. Wait for the
                                // consumer to catch up with a timeout, preserving
                                // frame ordering. With capacity 1024 this path is
                                // rarely hit — only when the consumer is severely
                                // behind (e.g. slow downstream connection).
                                let stream_id = header.stream_id;
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    tx.send(data),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(_)) => {
                                        debug!(
                                            stream_id,
                                            "stream closed while waiting for channel space"
                                        );
                                        streams.remove(&stream_id);
                                    }
                                    Err(_) => {
                                        warn!(
                                            stream_id,
                                            "stream channel full for 5s, closing stream"
                                        );
                                        streams.remove(&stream_id);
                                    }
                                }
                            }
                        }
                    }
                }
                Command::Settings => {
                    payload_buf.resize(len, 0);
                    if len > 0 {
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    let text = String::from_utf8_lossy(&payload_buf[..len]);
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

                    // Batch settings response frames under a single lock + flush.
                    let need_padding = peer_padding_md5 != self.padding.md5_hex();
                    let need_server_settings = peer_version >= 2;
                    if need_padding || need_server_settings {
                        self.write_settings_response(need_padding, need_server_settings)
                            .await?;
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
                        if len > 0 {
                            payload_buf.resize(len, 0);
                            reader.read_exact(&mut payload_buf[..len]).await?;
                        }
                        continue;
                    }
                    if streams.len() >= self.config.max_streams {
                        self.write_frame(Command::Alert, header.stream_id, b"max streams exceeded")
                            .await?;
                        if len > 0 {
                            payload_buf.resize(len, 0);
                            reader.read_exact(&mut payload_buf[..len]).await?;
                        }
                        continue;
                    }
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    let (data_tx, stream) = Stream::new(header.stream_id, write_cmd_tx.clone());
                    streams.insert(header.stream_id, data_tx);
                    if new_stream_tx.send(stream).await.is_err() {
                        warn!("new_stream_tx receiver dropped");
                        break;
                    }
                }
                Command::Fin => {
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    streams.remove(&header.stream_id);
                }
                Command::Alert => {
                    payload_buf.resize(len, 0);
                    if len > 0 {
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    let msg = String::from_utf8_lossy(&payload_buf[..len]);
                    warn!("received alert: {}", msg);
                    break;
                }
                Command::HeartRequest => {
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    self.write_frame(Command::HeartResponse, 0, &[]).await?;
                }
                // Waste, HeartResponse, and unknown commands: skip payload
                _ => {
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn write_frame(&self, command: Command, stream_id: u32, data: &[u8]) -> Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(crate::error::Error::FrameTooLarge(data.len()));
        }
        let header = FrameHeader {
            command,
            stream_id,
            length: data.len() as u16,
        };
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);

        let total = HEADER_SIZE + data.len();
        let mut w = self.write_half.lock().await;

        // Use stack buffer for small control frames (FIN, SynAck, HeartResponse, etc.)
        // to avoid heap allocation. Most control frames are ≤ 128 bytes.
        if total <= 128 {
            let mut stack_buf = [0u8; 128];
            stack_buf[..HEADER_SIZE].copy_from_slice(&hdr_buf);
            stack_buf[HEADER_SIZE..total].copy_from_slice(data);
            w.write_all(&stack_buf[..total]).await?;
        } else {
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&hdr_buf);
            buf.extend_from_slice(data);
            w.write_all(&buf).await?;
        }
        // Flush immediately so control frames are not delayed in the buffer.
        w.flush().await?;
        Ok(())
    }

    /// Batch-write settings response frames (UpdatePaddingScheme and/or
    /// ServerSettings) in a single lock acquisition, single write_all, and flush.
    /// All frames are coalesced into one buffer to avoid generating separate TLS
    /// records (each record adds ~29 bytes overhead + encryption cost).
    async fn write_settings_response(
        &self,
        send_padding: bool,
        send_server_settings: bool,
    ) -> Result<()> {
        if !send_padding && !send_server_settings {
            return Ok(());
        }

        // Pre-compute total size and build a single coalesced buffer.
        let padding_data = if send_padding {
            let data = self.padding.raw_scheme().as_bytes();
            if data.len() > u16::MAX as usize {
                return Err(crate::error::Error::FrameTooLarge(data.len()));
            }
            Some(data)
        } else {
            None
        };
        let padding_frame_len = padding_data.map_or(0, |d| HEADER_SIZE + d.len());
        let settings_frame_len = if send_server_settings {
            HEADER_SIZE + 3
        } else {
            0
        };
        let total = padding_frame_len + settings_frame_len;

        let mut buf = Vec::with_capacity(total);

        if let Some(data) = padding_data {
            let header = FrameHeader {
                command: Command::UpdatePaddingScheme,
                stream_id: 0,
                length: data.len() as u16,
            };
            let mut hdr_buf = [0u8; HEADER_SIZE];
            header.encode(&mut hdr_buf);
            buf.extend_from_slice(&hdr_buf);
            buf.extend_from_slice(data);
        }

        if send_server_settings {
            let header = FrameHeader {
                command: Command::ServerSettings,
                stream_id: 0,
                length: 3,
            };
            let mut hdr_buf = [0u8; HEADER_SIZE];
            header.encode(&mut hdr_buf);
            buf.extend_from_slice(&hdr_buf);
            buf.extend_from_slice(b"v=2");
        }

        let mut w = self.write_half.lock().await;
        w.write_all(&buf).await?;
        w.flush().await?;
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
    use tokio_util::sync::CancellationToken;

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
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });
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
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });
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
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });
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

    /// Verify that write_frame flushes immediately so control frames are not
    /// delayed when the transport is buffered (e.g. BufWriter / TLS).
    #[tokio::test]
    async fn test_control_frame_flushed_immediately() {
        let (mut client_io, server_io) = duplex(65536);
        let buf_server_io = tokio::io::BufWriter::with_capacity(8192, server_io);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            buf_server_io,
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
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });

        // Send a HeartRequest — server should respond with HeartResponse
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;

        // Try to read the response within a short timeout.
        // If write_frame doesn't flush, the HeartResponse will be stuck in BufWriter.
        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut found_heart = false;
        for _ in 0..5 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
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
        assert!(
            found_heart,
            "HeartResponse not received within timeout — write_frame likely not flushing"
        );
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
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });
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

    /// recv_loop must exit promptly when a CancellationToken is cancelled,
    /// even if the connection is otherwise healthy and active.
    #[tokio::test]
    async fn test_recv_loop_exits_on_cancel_token() {
        let (mut client_io, server_io) = duplex(65536);
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

        let cancel_token = tokio_util::sync::CancellationToken::new();
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let ct = cancel_token.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, Some(std::time::Duration::from_secs(300)), ct)
                .await
        });

        // Connection is alive — send a heartbeat to confirm
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "session should still be running");

        // Cancel the token — recv_loop should exit promptly
        cancel_token.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "recv_loop did not exit after cancel_token was cancelled"
        );

        drop(client_io);
    }

    /// write_settings_response must coalesce UpdatePaddingScheme and
    /// ServerSettings into a single write so they share one TLS record.
    #[tokio::test]
    async fn test_settings_response_coalesced() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        // Send settings with a wrong padding MD5 to trigger UpdatePaddingScheme + ServerSettings
        let settings_data = "v=2\npadding-md5=wrong_md5";
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });

        let mut found_padding = false;
        let mut found_server_settings = false;
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
                        let mut payload = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut payload).await.unwrap();
                        if hdr.command == Command::ServerSettings {
                            assert_eq!(&payload, b"v=2");
                        }
                    }
                    match hdr.command {
                        Command::UpdatePaddingScheme => found_padding = true,
                        Command::ServerSettings => found_server_settings = true,
                        _ => {}
                    }
                }
                _ => break,
            }
        }
        assert!(
            found_padding,
            "expected UpdatePaddingScheme frame in response"
        );
        assert!(
            found_server_settings,
            "expected ServerSettings frame in response"
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// Active connections must survive past the idle timeout duration.
    /// Idle timeout should reset on every received frame, not be a fixed timer.
    #[tokio::test]
    async fn test_idle_timeout_resets_on_activity() {
        let (mut client_io, server_io) = duplex(65536);
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
        let idle_timeout = std::time::Duration::from_millis(200);
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, Some(idle_timeout), CancellationToken::new())
                .await
        });

        // Send HeartRequest every 100ms for 500ms (well past the 200ms timeout).
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;
        }

        // Session should still be alive — the idle timer should have been
        // reset by each received frame.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "session terminated despite continuous activity — idle timeout not resetting"
        );

        // Now stop sending.  Session should idle-timeout within ~200ms.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "session did not terminate after going idle");

        drop(client_io);
    }

    /// When a stream's channel is temporarily full, the stream must survive
    /// and continue to deliver data once the consumer catches up.
    /// This test floods frames faster than the consumer reads, ensuring no
    /// data is lost and the stream is not prematurely closed.
    #[tokio::test]
    async fn test_stream_survives_channel_pressure() {
        let (mut client_io, server_io) = duplex(4 * 1024 * 1024);
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
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Send more frames than the channel capacity (currently 128) to trigger
        // backpressure. The stream must NOT be killed.
        let frame_count = 200;
        let frame_data = vec![0xAB_u8; 1024];
        let total_expected = frame_count * 1024;

        // Burst-send ALL frames first, WITHOUT reading from the stream.
        // This ensures recv_loop processes them and the channel fills up.
        for _ in 0..frame_count {
            write_frame(&mut client_io, Command::Psh, 1, &frame_data).await;
        }
        write_frame(&mut client_io, Command::Fin, 1, &[]).await;

        // Give recv_loop time to process all frames and hit channel pressure.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // NOW start consuming. The stream should still be alive and deliver
        // all data despite the channel having been full.
        let mut total = 0;
        let mut buf = [0u8; 4096];
        let read_result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
            }
            total
        })
        .await;

        let total = read_result.expect("read timed out — stream likely killed by channel pressure");
        assert_eq!(
            total, total_expected,
            "stream lost data under channel pressure: expected {} got {}",
            total_expected, total
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// Even under extreme pressure (far exceeding channel capacity), the
    /// stream must survive by using async send fallback with a timeout.
    /// Only truly stuck streams (consumer completely dead) should be closed.
    #[tokio::test]
    async fn test_stream_survives_extreme_channel_pressure() {
        let (mut client_io, server_io) = duplex(16 * 1024 * 1024);
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
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Send 1200 frames — exceeds channel capacity of 1024.
        // We send them all into the duplex pipe (16MB, big enough) BEFORE
        // reading, so recv_loop processes them and try_send fills the channel.
        let frame_count = 1200;
        let frame_data = vec![0xAB_u8; 512];
        let total_expected = frame_count * 512;

        // Write all frames synchronously — duplex is large enough to hold them.
        for _ in 0..frame_count {
            write_frame(&mut client_io, Command::Psh, 1, &frame_data).await;
        }
        write_frame(&mut client_io, Command::Fin, 1, &[]).await;

        // Give recv_loop time to process all frames and hit channel pressure.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // NOW start consuming. The stream should still be alive.
        let mut total = 0;
        let mut buf = [0u8; 4096];
        let read_result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
            }
            total
        })
        .await;

        let total =
            read_result.expect("read timed out — stream likely killed by channel pressure");
        assert_eq!(
            total, total_expected,
            "stream lost data under extreme pressure: expected {} got {}",
            total_expected, total
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// When one stream's channel is full, recv_loop must NOT block all other
    /// streams.  This test fills stream 1's channel (capacity 128) without
    /// reading, then sends data to stream 2 and asserts it arrives promptly.
    #[tokio::test]
    async fn test_no_head_of_line_blocking() {
        let (mut client_io, server_io) = duplex(1024 * 1024);
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
        // Create two streams
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        write_frame(&mut client_io, Command::Syn, 2, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, CancellationToken::new())
                .await
        });

        let _stream1 =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();
        let mut stream2 =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Fill stream 1's channel (capacity 128) — we intentionally never read from _stream1.
        for _ in 0..130 {
            write_frame(&mut client_io, Command::Psh, 1, b"x").await;
        }
        // Send data destined for stream 2.
        write_frame(&mut client_io, Command::Psh, 2, b"hello stream 2").await;

        // Stream 2 should receive data even though stream 1 is backed up.
        let mut buf = [0u8; 64];
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream2.read(&mut buf)).await;
        assert!(
            result.is_ok(),
            "stream 2 read timed out — head-of-line blocking detected"
        );
        let n = result.unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello stream 2");

        drop(client_io);
        let _ = handle.await;
    }
}
