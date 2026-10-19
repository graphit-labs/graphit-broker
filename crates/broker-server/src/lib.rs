//! Native SQL Broker server. Configuration owns secrets and runtime owns resources.
mod config;
mod discovery;
mod runtime;
pub use config::{PreparedConfig, ServerError, default_config_path, load_config};
pub use runtime::{bootstrap_local_administrator, serve};
