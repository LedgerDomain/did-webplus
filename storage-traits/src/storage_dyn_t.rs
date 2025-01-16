use crate::{Result, TransactionDynT};

/// Object-safe Storage trait, able to begin a transaction of the appropriate type.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait StorageDynT {
    async fn begin_transaction(&self) -> Result<Box<dyn TransactionDynT>>;
}
