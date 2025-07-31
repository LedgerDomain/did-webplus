#[cfg(target_arch = "wasm32")]
mod software_wallet_indexeddb;

#[cfg(target_arch = "wasm32")]
pub use crate::software_wallet_indexeddb::SoftwareWalletIndexedDB;

#[cfg(target_arch = "wasm32")]
pub use anyhow::{Error, Result};
