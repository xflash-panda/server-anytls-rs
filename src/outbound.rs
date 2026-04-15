#[allow(dead_code)]
pub(crate) async fn handle_stream<
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    _server: std::sync::Arc<crate::core::server::Server>,
    _session: std::sync::Arc<crate::core::session::Session<T>>,
    _stream: crate::core::stream::Stream,
) -> crate::error::Result<()> {
    Ok(())
}
