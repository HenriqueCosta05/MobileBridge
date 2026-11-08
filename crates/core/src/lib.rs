//! Platform-neutral core of mobile-bridge: event model, provider contract, recording pipeline,
//! session persistence, filtering, redaction, analysis and export.

pub mod analysis;
pub mod device;
pub mod event;
pub mod export;
pub mod filter;
pub mod pipeline;
pub mod private_fs;
pub mod provider;
pub mod redact;
pub mod session;
