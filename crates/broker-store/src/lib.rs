//! Broker durability contracts, independently consumable by future SQL adapters.
//!
//! Schema and seed definitions are data. This crate does not open a database,
//! authenticate a caller, or make an authorization decision.
pub mod schema;
pub mod seeds;
pub mod time;
