use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("authentication failed")]
    AuthFailed,

    #[error("session closed")]
    SessionClosed,

    #[error("stream closed")]
    StreamClosed,

    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    #[error("max streams exceeded")]
    MaxStreamsExceeded,

    #[error("max connections exceeded")]
    MaxConnectionsExceeded,

    #[error("padding scheme parse error: {0}")]
    PaddingParse(String),
}

pub type Result<T> = std::result::Result<T, Error>;
