#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub mod core;
pub mod error;
pub mod handler;
pub mod outbound;

// Convenience re-exports
pub use core::hooks::{
    Address, Authenticator, DirectRouter, NoopStatsCollector, OutboundRouter, OutboundType,
    SinglePasswordAuth, StatsCollector, UserId,
};
pub use core::server::Server;
pub use error::{Error, Result};
