//! Connection management module
//!
//! Tracks active connections and provides kick-off capability.

use dashmap::DashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use super::hooks::UserId;

/// Unique connection identifier
pub type ConnectionId = u64;

/// Information about an active connection
#[derive(Debug, Clone)]
struct ConnectionInfo {
    user_id: UserId,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    connected_at: Instant,
}

/// Active connection handle with cancellation support
#[derive(Debug)]
struct ActiveConnection {
    info: ConnectionInfo,
    cancel_token: CancellationToken,
}

/// Manager for active connections with kick-off capability
#[derive(Debug, Clone)]
pub struct ConnectionManager {
    next_conn_id: Arc<AtomicU64>,
    connections: Arc<DashMap<ConnectionId, ActiveConnection>>,
    user_connections: Arc<DashMap<UserId, HashSet<ConnectionId>>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            next_conn_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(DashMap::new()),
            user_connections: Arc::new(DashMap::new()),
        }
    }

    pub fn register(
        &self,
        user_id: UserId,
        peer_addr: SocketAddr,
    ) -> (ConnectionId, CancellationToken) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let cancel_token = CancellationToken::new();

        let conn = ActiveConnection {
            info: ConnectionInfo {
                user_id,
                peer_addr,
                connected_at: Instant::now(),
            },
            cancel_token: cancel_token.clone(),
        };

        self.connections.insert(conn_id, conn);
        self.user_connections
            .entry(user_id)
            .or_default()
            .insert(conn_id);

        (conn_id, cancel_token)
    }

    pub fn unregister(&self, conn_id: ConnectionId) {
        if let Some((_, conn)) = self.connections.remove(&conn_id) {
            let user_id = conn.info.user_id;
            self.user_connections
                .remove_if_mut(&user_id, |_, conn_ids| {
                    conn_ids.remove(&conn_id);
                    conn_ids.is_empty()
                });
        }
    }

    pub fn kick_user(&self, user_id: UserId) -> usize {
        let mut kicked = 0;
        if let Some(conn_ids) = self.user_connections.get(&user_id) {
            for &conn_id in conn_ids.iter() {
                if let Some(conn) = self.connections.get(&conn_id) {
                    conn.cancel_token.cancel();
                    kicked += 1;
                }
            }
        }
        kicked
    }

    pub fn cancel_all(&self) -> usize {
        let mut cancelled = 0;
        for entry in self.connections.iter() {
            entry.value().cancel_token.cancel();
            cancelled += 1;
        }
        cancelled
    }

    /// Cancel all connections and wait for them to drain, with a timeout.
    ///
    /// Re-cancels on each poll to catch connections that registered after
    /// the initial `cancel_all()`.
    pub async fn shutdown_drain(&self, timeout: std::time::Duration) {
        self.cancel_all();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = self.connection_count();
            if remaining == 0 || tokio::time::Instant::now() >= deadline {
                break;
            }
            self.cancel_all();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    #[allow(dead_code)]
    pub fn user_count(&self) -> usize {
        self.user_connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_new() {
        let manager = ConnectionManager::new();
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_register_increments_ids() {
        let manager = ConnectionManager::new();
        let (id1, _) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        let (id2, _) = manager.register(1, "127.0.0.1:1235".parse().unwrap());
        let (id3, _) = manager.register(2, "127.0.0.1:1236".parse().unwrap());

        assert_eq!(manager.connection_count(), 3);
        assert_eq!(manager.user_count(), 2);
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn test_unregister_cleans_up() {
        let manager = ConnectionManager::new();
        let (conn_id, _) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(manager.connection_count(), 1);
        assert_eq!(manager.user_count(), 1);

        manager.unregister(conn_id);
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_unregister_partial() {
        let manager = ConnectionManager::new();
        let (id1, _) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        let (id2, _) = manager.register(1, "127.0.0.1:1235".parse().unwrap());

        manager.unregister(id1);
        assert_eq!(manager.connection_count(), 1);
        assert_eq!(manager.user_count(), 1); // still has one connection

        manager.unregister(id2);
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_kick_user_cancels_tokens() {
        let manager = ConnectionManager::new();
        let (_, token1) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        let (_, token2) = manager.register(1, "127.0.0.1:1235".parse().unwrap());
        let (_, token3) = manager.register(2, "127.0.0.1:1236".parse().unwrap());

        assert!(!token1.is_cancelled());
        assert!(!token2.is_cancelled());
        assert!(!token3.is_cancelled());

        let kicked = manager.kick_user(1);
        assert_eq!(kicked, 2);
        assert!(token1.is_cancelled());
        assert!(token2.is_cancelled());
        assert!(!token3.is_cancelled()); // user 2 unaffected
    }

    #[test]
    fn test_cancel_all() {
        let manager = ConnectionManager::new();
        let (_, t1) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        let (_, t2) = manager.register(1, "127.0.0.1:1235".parse().unwrap());
        let (_, t3) = manager.register(2, "127.0.0.1:1236".parse().unwrap());

        let cancelled = manager.cancel_all();
        assert_eq!(cancelled, 3);
        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
        assert!(t3.is_cancelled());
    }

    #[test]
    fn test_concurrent_register_unregister() {
        use std::thread;

        let manager = ConnectionManager::new();
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let m = manager.clone();
                thread::spawn(move || {
                    for j in 0..100 {
                        let (conn_id, _) = m.register(
                            i % 3,
                            SocketAddr::from(([127, 0, 0, 1], (i * 1000 + j) as u16)),
                        );
                        std::thread::yield_now();
                        m.unregister(conn_id);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }

    /// Race: unregister last conn for user vs register new conn for same user.
    /// remove_if_mut ensures atomicity.
    #[test]
    fn test_unregister_register_race_same_user() {
        use std::sync::Barrier;
        use std::thread;

        for _ in 0..200 {
            let manager = ConnectionManager::new();
            let user_id: UserId = 42;
            let (conn_id1, _) = manager.register(user_id, "127.0.0.1:1000".parse().unwrap());

            let barrier = Arc::new(Barrier::new(2));

            let m_a = manager.clone();
            let b_a = Arc::clone(&barrier);
            let handle_a = thread::spawn(move || {
                b_a.wait();
                m_a.unregister(conn_id1);
            });

            let m_b = manager.clone();
            let b_b = Arc::clone(&barrier);
            let handle_b = thread::spawn(move || {
                b_b.wait();
                m_b.register(user_id, "127.0.0.1:2000".parse().unwrap())
            });

            handle_a.join().unwrap();
            let (conn_id2, _) = handle_b.join().unwrap();

            assert!(manager.connections.get(&conn_id1).is_none());
            assert!(manager.connections.get(&conn_id2).is_some());
            assert!(
                manager
                    .user_connections
                    .get(&user_id)
                    .map(|ids| ids.contains(&conn_id2))
                    .unwrap_or(false),
                "user_connections must contain conn_id2"
            );

            manager.unregister(conn_id2);
            assert_eq!(manager.connection_count(), 0);
            assert_eq!(manager.user_count(), 0);
        }
    }

    #[test]
    fn test_concurrent_same_user_consistency() {
        use std::thread;

        for _ in 0..50 {
            let manager = ConnectionManager::new();
            let user_id: UserId = 1;

            let handles: Vec<_> = (0..20)
                .map(|j| {
                    let m = manager.clone();
                    thread::spawn(move || {
                        for k in 0..100 {
                            let (conn_id, _) = m.register(
                                user_id,
                                SocketAddr::from(([127, 0, 0, 1], (j * 1000 + k) as u16)),
                            );
                            std::thread::yield_now();
                            m.unregister(conn_id);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            assert_eq!(manager.connection_count(), 0);
            assert_eq!(manager.user_count(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_shutdown_cancel_all_drains_connections() {
        use std::time::Duration;

        let manager = ConnectionManager::new();

        for i in 0..100i64 {
            let m = manager.clone();
            let (conn_id, cancel_token) = manager.register(
                i % 10,
                SocketAddr::from(([127, 0, 0, 1], (1000 + i) as u16)),
            );
            tokio::spawn(async move {
                cancel_token.cancelled().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                m.unregister(conn_id);
            });
        }

        assert_eq!(manager.connection_count(), 100);

        // Without cancel_all, connections stay alive
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(manager.connection_count(), 100);

        // With cancel_all, connections drain
        let cancelled = manager.cancel_all();
        assert_eq!(cancelled, 100);

        let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = manager.connection_count();
            if remaining == 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < drain_deadline,
                "Drain timeout: {remaining} connections remaining"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }
}
