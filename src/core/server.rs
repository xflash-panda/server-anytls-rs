use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::core::hooks::{Authenticator, NoopStatsCollector, OutboundRouter, StatsCollector};
use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use crate::core::session::SessionConfig;

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

pub struct ServerConfig {
    pub max_connections: usize,
    pub max_streams_per_session: usize,
    pub tcp_connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            max_streams_per_session: 256,
            tcp_connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct Server {
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) stats: Arc<dyn StatsCollector>,
    pub(crate) router: Arc<dyn OutboundRouter>,
    pub(crate) tls_config: Option<Arc<rustls::ServerConfig>>,
    pub(crate) padding: PaddingFactory,
    pub(crate) config: ServerConfig,
    pub(crate) semaphore: Arc<Semaphore>,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    pub fn session_config(&self) -> SessionConfig {
        SessionConfig {
            max_streams: self.config.max_streams_per_session,
        }
    }
}

// ---------------------------------------------------------------------------
// ServerBuilder
// ---------------------------------------------------------------------------

pub struct ServerBuilder {
    authenticator: Option<Arc<dyn Authenticator>>,
    stats: Option<Arc<dyn StatsCollector>>,
    router: Option<Arc<dyn OutboundRouter>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    padding_scheme: Option<String>,
    max_connections: usize,
    max_streams_per_session: usize,
    tcp_connect_timeout: Duration,
    idle_timeout: Duration,
}

impl ServerBuilder {
    fn new() -> Self {
        let defaults = ServerConfig::default();
        Self {
            authenticator: None,
            stats: None,
            router: None,
            tls_config: None,
            padding_scheme: None,
            max_connections: defaults.max_connections,
            max_streams_per_session: defaults.max_streams_per_session,
            tcp_connect_timeout: defaults.tcp_connect_timeout,
            idle_timeout: defaults.idle_timeout,
        }
    }

    pub fn authenticator(mut self, auth: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(auth);
        self
    }

    pub fn stats(mut self, stats: Arc<dyn StatsCollector>) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn router(mut self, router: Arc<dyn OutboundRouter>) -> Self {
        self.router = Some(router);
        self
    }

    pub fn tls_config(mut self, tls: Arc<rustls::ServerConfig>) -> Self {
        self.tls_config = Some(tls);
        self
    }

    pub fn padding_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.padding_scheme = Some(scheme.into());
        self
    }

    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    pub fn max_streams_per_session(mut self, n: usize) -> Self {
        self.max_streams_per_session = n;
        self
    }

    pub fn tcp_connect_timeout(mut self, d: Duration) -> Self {
        self.tcp_connect_timeout = d;
        self
    }

    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    pub fn build(self) -> Server {
        let authenticator = self.authenticator.expect("authenticator is required");

        let stats: Arc<dyn StatsCollector> =
            self.stats.unwrap_or_else(|| Arc::new(NoopStatsCollector));

        let router: Arc<dyn OutboundRouter> = self
            .router
            .unwrap_or_else(|| Arc::new(crate::core::hooks::DirectRouter));

        let scheme = self.padding_scheme.as_deref().unwrap_or(DEFAULT_SCHEME);
        let padding = PaddingFactory::new(scheme).expect("invalid padding scheme");

        let config = ServerConfig {
            max_connections: self.max_connections,
            max_streams_per_session: self.max_streams_per_session,
            tcp_connect_timeout: self.tcp_connect_timeout,
            idle_timeout: self.idle_timeout,
        };

        let semaphore = Arc::new(Semaphore::new(config.max_connections));

        Server {
            authenticator,
            stats,
            router,
            tls_config: self.tls_config,
            padding,
            config,
            semaphore,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hooks::*;

    #[test]
    fn test_server_builder_defaults() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("test")))
            .build();
        assert_eq!(server.config.max_connections, 10000);
        assert_eq!(server.config.max_streams_per_session, 256);
    }

    #[test]
    fn test_server_builder_custom_config() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("test")))
            .max_connections(500)
            .max_streams_per_session(64)
            .tcp_connect_timeout(std::time::Duration::from_secs(10))
            .build();
        assert_eq!(server.config.max_connections, 500);
        assert_eq!(server.config.max_streams_per_session, 64);
        assert_eq!(
            server.config.tcp_connect_timeout,
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    #[should_panic(expected = "authenticator is required")]
    fn test_server_builder_missing_auth() {
        Server::builder().build();
    }

    #[test]
    fn test_server_builder_with_custom_hooks() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("pw")))
            .stats(Arc::new(NoopStatsCollector))
            .router(Arc::new(DirectRouter))
            .build();
        let _ = server;
    }

    #[test]
    fn test_session_config() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("test")))
            .max_streams_per_session(128)
            .build();
        let sc = server.session_config();
        assert_eq!(sc.max_streams, 128);
    }
}
