use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

pub type UserId = i64;

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Address {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) | Address::IPv6(_, port) | Address::Domain(_, port) => *port,
        }
    }

    pub fn to_socket_string(&self) -> String {
        match self {
            Address::IPv4(ip, port) => {
                format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
            }
            Address::IPv6(ip, port) => {
                let segments: Vec<String> = ip
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                format!("[{}]:{}", segments.join(":"), port)
            }
            Address::Domain(host, port) => format!("{}:{}", host, port),
        }
    }
}

impl Address {
    pub fn host_string(&self) -> String {
        match self {
            Address::IPv4(ip, _) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            Address::IPv6(ip, _) => std::net::Ipv6Addr::from(*ip).to_string(),
            Address::Domain(host, _) => host.clone(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_socket_string())
    }
}

// ---------------------------------------------------------------------------
// OutboundType
// ---------------------------------------------------------------------------

pub enum OutboundType {
    Direct,
    Reject,
    /// Proxy connection via ACL engine outbound handler (Socks5, Http, etc.)
    Proxy(Arc<dyn acl_engine_rs::outbound::AsyncOutbound>),
}

impl fmt::Debug for OutboundType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutboundType::Direct => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),
            OutboundType::Proxy(_) => write!(f, "Proxy"),
        }
    }
}

// ---------------------------------------------------------------------------
// Authenticator trait
// ---------------------------------------------------------------------------

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, password_hash: &[u8; 32]) -> Option<UserId>;
}

// ---------------------------------------------------------------------------
// StatsCollector trait
// ---------------------------------------------------------------------------

pub trait StatsCollector: Send + Sync {
    fn record_upload(&self, user_id: UserId, bytes: u64);
    fn record_download(&self, user_id: UserId, bytes: u64);
}

// ---------------------------------------------------------------------------
// OutboundRouter trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait OutboundRouter: Send + Sync {
    async fn route(&self, target: &Address) -> OutboundType;
}

// ---------------------------------------------------------------------------
// SinglePasswordAuth
// ---------------------------------------------------------------------------

pub struct SinglePasswordAuth {
    hash: [u8; 32],
}

impl SinglePasswordAuth {
    pub fn new(password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Self { hash }
    }
}

impl Authenticator for SinglePasswordAuth {
    fn authenticate(&self, password_hash: &[u8; 32]) -> Option<UserId> {
        // Constant-time comparison to avoid timing attacks.
        use subtle::ConstantTimeEq;
        if self.hash.ct_eq(password_hash).into() {
            Some(0)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// NoopStatsCollector
// ---------------------------------------------------------------------------

pub struct NoopStatsCollector;

impl StatsCollector for NoopStatsCollector {
    fn record_upload(&self, _user_id: UserId, _bytes: u64) {}
    fn record_download(&self, _user_id: UserId, _bytes: u64) {}
}

// ---------------------------------------------------------------------------
// DirectRouter
// ---------------------------------------------------------------------------

pub struct DirectRouter;

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, _target: &Address) -> OutboundType {
        OutboundType::Direct
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_password_auth_correct() {
        let auth = SinglePasswordAuth::new("mypassword");
        let hash = sha2_hash(b"mypassword");
        assert_eq!(auth.authenticate(&hash), Some(0));
    }

    #[test]
    fn test_single_password_auth_wrong() {
        let auth = SinglePasswordAuth::new("mypassword");
        let hash = sha2_hash(b"wrongpassword");
        assert_eq!(auth.authenticate(&hash), None);
    }

    #[test]
    fn test_noop_stats_collector() {
        let stats = NoopStatsCollector;
        stats.record_upload(0, 1024);
        stats.record_download(0, 2048);
    }

    #[tokio::test]
    async fn test_direct_router() {
        let router = DirectRouter;
        let addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct));
    }

    fn sha2_hash(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}
