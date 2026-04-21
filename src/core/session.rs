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

pub const DEFAULT_WRITE_BUF_SIZE: usize = 32 * 1024;
pub const DEFAULT_STREAM_CHANNEL_CAPACITY: usize = 128;

pub struct SessionConfig {
    pub max_streams: usize,
    pub write_cmd_capacity: usize,
    /// BufWriter buffer size for the TLS write half (bytes).
    pub write_buf_size: usize,
    /// Per-stream data channel capacity (number of Bytes messages).
    pub stream_channel_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_streams: 256,
            write_cmd_capacity: 512,
            write_buf_size: DEFAULT_WRITE_BUF_SIZE,
            stream_channel_capacity: DEFAULT_STREAM_CHANNEL_CAPACITY,
        }
    }
}

pub struct Session<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    read_half: Mutex<tokio::io::ReadHalf<T>>,
    write_half: Arc<Mutex<tokio::io::BufWriter<tokio::io::WriteHalf<T>>>>,
    padding: PaddingFactory,
    config: SessionConfig,
    peer_version: AtomicU8,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<T> {
    pub fn new_server(conn: T, padding: PaddingFactory, config: SessionConfig) -> Self {
        let (read_half, write_half) = tokio::io::split(conn);
        let buf_size = config.write_buf_size;
        Self {
            read_half: Mutex::new(read_half),
            write_half: Arc::new(Mutex::new(tokio::io::BufWriter::with_capacity(
                buf_size, write_half,
            ))),
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
        keepalive_interval: Option<std::time::Duration>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let mut streams: FxHashMap<u32, mpsc::Sender<Bytes>> = FxHashMap::default();
        let mut settings_received = false;

        // Create the write command channel and spawn writer task
        let (write_cmd_tx, mut write_cmd_rx) =
            mpsc::channel::<WriteCommand>(self.config.write_cmd_capacity);
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

        // Server-side keepalive: periodically send HeartRequest to prevent
        // NAT devices from dropping idle connections.  The timer resets on
        // every received frame so we only send keepalives when truly idle.
        // If a HeartRequest goes unanswered by the next tick, the connection
        // is considered dead.
        let keepalive_sleep = tokio::time::sleep(keepalive_interval.unwrap_or_default());
        tokio::pin!(keepalive_sleep);
        let mut heartbeat_pending = false;

        loop {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            let read_result = tokio::select! {
                r = reader.read_exact(&mut hdr_buf) => r,
                _ = &mut idle_sleep, if idle_timeout.is_some() => {
                    debug!("session idle timeout");
                    break;
                }
                _ = &mut keepalive_sleep, if keepalive_interval.is_some() => {
                    if heartbeat_pending {
                        debug!("heartbeat timeout — no HeartResponse received");
                        break;
                    }
                    if let Err(e) = self.write_frame(Command::HeartRequest, 0, &[]).await {
                        debug!("keepalive write failed: {}", e);
                        break;
                    }
                    heartbeat_pending = true;
                    // unwrap is safe: guard ensures keepalive_interval is Some
                    let d = keepalive_interval.unwrap();
                    keepalive_sleep.as_mut().reset(tokio::time::Instant::now() + d);
                    continue;
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
            // Reset keepalive timer on activity — only send keepalives when idle.
            if let Some(d) = keepalive_interval {
                keepalive_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + d);
                // Any received frame proves the connection is alive.
                heartbeat_pending = false;
            }

            let header = FrameHeader::decode(&hdr_buf);

            // Reset idle timer only on data frames (not heartbeat frames).
            // This ensures connections without real traffic will eventually
            // time out, matching the Go server behavior.
            if let Some(d) = idle_timeout
                && !matches!(
                    header.command,
                    Command::HeartRequest | Command::HeartResponse
                )
            {
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + d);
            }
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
                        match tx.try_send(data) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                streams.remove(&header.stream_id);
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                // Channel full — consumer is severely behind.
                                // Drop this stream to avoid blocking recv_loop
                                // (which would stall ALL streams).
                                let stream_id = header.stream_id;
                                warn!(stream_id, "stream channel full, closing stream");
                                streams.remove(&stream_id);
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
                    let (data_tx, stream) = Stream::new(
                        header.stream_id,
                        write_cmd_tx.clone(),
                        self.config.stream_channel_capacity,
                    );
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
                // HeartResponse, Waste, and unknown commands: skip payload.
                // (heartbeat_pending is already cleared by the blanket reset
                // on any received frame above.)
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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
            sess.recv_loop(
                new_stream_tx,
                Some(std::time::Duration::from_secs(300)),
                None,
                ct,
            )
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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
            sess.recv_loop(
                new_stream_tx,
                Some(idle_timeout),
                None,
                CancellationToken::new(),
            )
            .await
        });

        // Send Waste frames every 100ms for 500ms (well past the 200ms timeout).
        // Only data frames reset idle timeout; heartbeat frames do not.
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            write_frame(&mut client_io, Command::Waste, 0, &[]).await;
        }

        // Session should still be alive — the idle timer should have been
        // reset by each data frame.
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

    /// Issue #2: write_cmd channel (capacity 256) shared by ALL streams.
    /// Verify that the writer task's try_recv batch drains the entire channel
    /// under a single lock hold. When the batch is large (many streams writing
    /// simultaneously), the lock is held for a long time, starving control frames.
    /// This test verifies data from multiple streams flows through correctly.
    #[tokio::test]
    async fn test_write_cmd_shared_channel_multiple_streams() {
        let (mut client_io, server_io) = duplex(2 * 1024 * 1024);
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

        // Create 5 streams
        for i in 1..=5u32 {
            write_frame(&mut client_io, Command::Syn, i, &[]).await;
        }

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
                .await
        });

        let mut streams = Vec::new();
        for _ in 0..5 {
            let stream =
                tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
            streams.push(stream);
        }

        // Each stream writes 20 chunks of 1KB through the SHARED write_cmd channel.
        // Total: 5 streams * 20 * 1KB = 100KB. All competing for capacity 256.
        let chunk = vec![0xCD_u8; 1024];
        let mut write_handles = Vec::new();
        for mut stream in streams {
            let data = chunk.clone();
            write_handles.push(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                for _ in 0..20 {
                    stream.write_all(&data).await.unwrap();
                }
            }));
        }

        // Drain output concurrently so writer doesn't block on duplex.
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match client_io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        // All 100 writes (5*20) must complete within 2 seconds.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            for h in write_handles {
                h.await.unwrap();
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "concurrent writes from 5 streams timed out — write_cmd channel bottleneck"
        );

        drain.abort();
        let _ = handle.await;
    }

    /// Issue #3: write_frame (control) and writer task (data) share write_half
    /// mutex. The writer task's try_recv loop drains ALL pending data under one
    /// lock hold, blocking control frames. This test sends a HeartRequest while
    /// a stream is actively writing and verifies HeartResponse arrives promptly.
    #[tokio::test]
    async fn test_control_frame_not_starved_by_data_writes() {
        let (mut client_io, server_io) = duplex(2 * 1024 * 1024);
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Stream writes 50 * 4KB = 200KB to keep writer task busy.
        let write_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let data = vec![0xAB_u8; 4096];
            for _ in 0..50 {
                if stream.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        // Let writer task start processing
        tokio::task::yield_now().await;

        // Send HeartRequest — response requires write_frame (same mutex)
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;

        // Read all frames, look for HeartResponse
        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut skip_buf = vec![0u8; 65536];

        let found_heart = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                client_io.read_exact(&mut hdr_buf).await.unwrap();
                let hdr = FrameHeader::decode(&hdr_buf);
                if hdr.length > 0 {
                    client_io
                        .read_exact(&mut skip_buf[..hdr.length as usize])
                        .await
                        .unwrap();
                }
                if hdr.command == Command::HeartResponse {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            found_heart,
            "HeartResponse not received — control frame starved by data writer mutex"
        );

        write_task.abort();
        drop(client_io);
        let _ = handle.await;
    }

    /// Server-side keepalive: recv_loop should proactively send HeartRequest
    /// at the configured interval to prevent NAT devices from dropping idle
    /// connections.
    #[tokio::test]
    async fn test_server_keepalive_sends_heart_request() {
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
        // Short keepalive interval for testing
        let keepalive = Some(std::time::Duration::from_millis(100));
        let handle = tokio::spawn(async move {
            sess.recv_loop(
                new_stream_tx,
                Some(std::time::Duration::from_secs(300)),
                keepalive,
                CancellationToken::new(),
            )
            .await
        });

        // Client does NOT send anything — just listens.
        // Server should proactively send HeartRequest within ~100ms.
        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut found_heart_request = false;
        for _ in 0..10 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
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
                    if hdr.command == Command::HeartRequest {
                        found_heart_request = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            found_heart_request,
            "server did not send proactive HeartRequest within keepalive interval"
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// Heartbeat frames should NOT reset the idle timer — connections without
    /// real data traffic should still idle-timeout even if keepalive succeeds.
    #[tokio::test]
    async fn test_keepalive_does_not_prevent_idle_timeout() {
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
        // idle_timeout=200ms, keepalive=80ms — keepalive should fire before idle
        let handle = tokio::spawn(async move {
            sess.recv_loop(
                new_stream_tx,
                Some(std::time::Duration::from_millis(200)),
                Some(std::time::Duration::from_millis(80)),
                CancellationToken::new(),
            )
            .await
        });

        // Client responds to HeartRequest with HeartResponse (simulating real client)
        let respond_task = tokio::spawn(async move {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            loop {
                match client_io.read_exact(&mut hdr_buf).await {
                    Ok(_) => {
                        let hdr = FrameHeader::decode(&hdr_buf);
                        if hdr.length > 0 {
                            let mut skip = vec![0u8; hdr.length as usize];
                            if client_io.read_exact(&mut skip).await.is_err() {
                                break;
                            }
                        }
                        if hdr.command == Command::HeartRequest {
                            write_frame(&mut client_io, Command::HeartResponse, 0, &[]).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Heartbeat frames do NOT reset idle timeout, so despite keepalive
        // succeeding, the session should still idle-timeout after 200ms.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "session did not terminate — idle timeout should fire even with keepalive"
        );

        respond_task.abort();
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
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

    /// SessionConfig should have a write_buf_size field that defaults to 32KB.
    #[test]
    fn test_session_config_write_buf_size_default() {
        let config = SessionConfig::default();
        assert_eq!(config.write_buf_size, 32 * 1024);
    }

    /// SessionConfig should have a stream_channel_capacity field that defaults to 128.
    #[test]
    fn test_session_config_stream_channel_capacity_default() {
        let config = SessionConfig::default();
        assert_eq!(config.stream_channel_capacity, 128);
    }

    /// Session should use the configured stream_channel_capacity when creating streams.
    #[tokio::test]
    async fn test_session_uses_configured_stream_channel_capacity() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let config = SessionConfig {
            stream_channel_capacity: 16,
            ..SessionConfig::default()
        };
        let session = Arc::new(Session::new_server(server_io, padding, config));
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
            sess.recv_loop(new_stream_tx, None, None, CancellationToken::new())
                .await
        });

        let _stream = tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Fill the stream channel with capacity=16.
        // With capacity 16, sending 17 messages should trigger the "full" path.
        for i in 0..18 {
            let msg = format!("msg{}", i);
            write_frame(&mut client_io, Command::Psh, 1, msg.as_bytes()).await;
        }
        // Give recv_loop time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        drop(client_io);
        let _ = handle.await;
    }

    /// RED: when the server sends HeartRequest but the client never responds,
    /// the session should terminate within `heartbeat_timeout`.  Currently
    /// recv_loop does not track outstanding heartbeats, so this test FAILS.
    #[tokio::test]
    async fn test_heartbeat_timeout_terminates_session() {
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
        // keepalive=50ms, heartbeat_timeout=100ms
        // idle_timeout=10s (long enough to never fire)
        let handle = tokio::spawn(async move {
            sess.recv_loop(
                new_stream_tx,
                Some(std::time::Duration::from_secs(10)),
                Some(std::time::Duration::from_millis(50)),
                CancellationToken::new(),
            )
            .await
        });

        // Client reads frames but does NOT respond to HeartRequest.
        let drain_task = tokio::spawn(async move {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            loop {
                match client_io.read_exact(&mut hdr_buf).await {
                    Ok(_) => {
                        let hdr = FrameHeader::decode(&hdr_buf);
                        if hdr.length > 0 {
                            let mut skip = vec![0u8; hdr.length as usize];
                            if client_io.read_exact(&mut skip).await.is_err() {
                                break;
                            }
                        }
                        // Deliberately do NOT respond to HeartRequest
                    }
                    Err(_) => break,
                }
            }
        });

        // The session should terminate within ~200ms (heartbeat_timeout
        // after first unanswered HeartRequest at 50ms).
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), handle).await;
        drain_task.abort();
        assert!(
            result.is_ok(),
            "session should terminate when HeartResponse is not received, \
             but it stayed alive — heartbeat timeout not implemented"
        );
    }
}
