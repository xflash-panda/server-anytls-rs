use std::sync::Arc;

use server_anytls_rs::{Authenticator, StatsCollector, UserId};
use sha2::{Digest, Sha256};

// Re-export panel types used by main.rs
pub use panel_core::{
    BackgroundTasks, StatsCollector as PanelStatsCollector, TaskConfig, UserManager,
};
pub use panel_http::{HttpApiManager as ApiManager, HttpPanelConfig as PanelConfig, IpVersion};

/// SHA-256 key derivation for AnyTLS protocol
pub fn sha256_key(uuid: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// AnyTLS-specific UserManager using SHA-256 raw keys ([u8; 32])
pub type AnyTlsUserManager = UserManager<[u8; 32]>;

/// Newtype bridging panel::StatsCollector to core::hooks::StatsCollector trait
pub struct AnyTlsStatsCollector(pub Arc<PanelStatsCollector>);

impl StatsCollector for AnyTlsStatsCollector {
    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.0.record_upload(user_id, bytes);
    }

    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.0.record_download(user_id, bytes);
    }

    fn record_request(&self, user_id: UserId) {
        self.0.record_request(user_id);
    }
}

/// Newtype bridging UserManager::authenticate() to core::hooks::Authenticator trait
pub struct AnyTlsAuthenticator(pub Arc<AnyTlsUserManager>);

impl Authenticator for AnyTlsAuthenticator {
    fn authenticate(&self, password_hash: &[u8; 32]) -> Option<UserId> {
        self.0.authenticate(password_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::User;

    fn create_user(id: i64, uuid: &str) -> User {
        User {
            id,
            uuid: uuid.to_string(),
        }
    }

    fn make_authenticator(entries: &[(&str, i64)]) -> AnyTlsAuthenticator {
        let um = AnyTlsUserManager::new(sha256_key);
        let users: Vec<User> = entries
            .iter()
            .map(|(uuid, id)| create_user(*id, uuid))
            .collect();
        um.init(&users);
        AnyTlsAuthenticator(Arc::new(um))
    }

    #[test]
    fn test_sha256_key_deterministic() {
        let k1 = sha256_key("test-uuid");
        let k2 = sha256_key("test-uuid");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_sha256_key_different_inputs() {
        let k1 = sha256_key("uuid-1");
        let k2 = sha256_key("uuid-2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_sha256_key_length() {
        let key = sha256_key("any-uuid");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_authenticate_valid() {
        let auth = make_authenticator(&[("uuid-1", 1), ("uuid-2", 2)]);
        let key = sha256_key("uuid-1");
        assert_eq!(auth.authenticate(&key), Some(1));
    }

    #[test]
    fn test_authenticate_invalid() {
        let auth = make_authenticator(&[("uuid-1", 1)]);
        let key = sha256_key("wrong-uuid");
        assert_eq!(auth.authenticate(&key), None);
    }

    #[test]
    fn test_authenticate_empty_map() {
        let auth = make_authenticator(&[]);
        let key = sha256_key("any-uuid");
        assert_eq!(auth.authenticate(&key), None);
    }

    #[test]
    fn test_authenticate_hot_reload() {
        let um = Arc::new(AnyTlsUserManager::new(sha256_key));
        um.init(&[create_user(1, "uuid-1")]);
        let auth = AnyTlsAuthenticator(Arc::clone(&um));

        assert_eq!(auth.authenticate(&sha256_key("uuid-1")), Some(1));
        assert_eq!(auth.authenticate(&sha256_key("uuid-2")), None);

        um.update(&[create_user(2, "uuid-2")]);

        assert_eq!(auth.authenticate(&sha256_key("uuid-1")), None);
        assert_eq!(auth.authenticate(&sha256_key("uuid-2")), Some(2));
    }

    #[test]
    fn test_stats_record_upload_download() {
        let panel = Arc::new(PanelStatsCollector::new());
        let stats = AnyTlsStatsCollector(Arc::clone(&panel));

        stats.record_upload(1, 100);
        stats.record_upload(1, 50);
        stats.record_download(1, 200);

        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.upload_bytes, 150);
        assert_eq!(snap.download_bytes, 200);
    }

    #[test]
    fn test_stats_bridge_shares_underlying_collector() {
        let panel = Arc::new(PanelStatsCollector::new());
        let stats = AnyTlsStatsCollector(Arc::clone(&panel));

        stats.record_upload(1, 100);
        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.upload_bytes, 100);

        let snapshots = panel.reset_all();
        assert_eq!(snapshots.len(), 1);

        stats.record_download(1, 50);
        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.download_bytes, 50);
        assert_eq!(snap.upload_bytes, 0);
    }
}
