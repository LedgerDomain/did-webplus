use crate::{Result, TransactionT};

/// Storage trait meant for maximal monomorphization.  This trait is not object-safe.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait StorageT: Clone + Send + Sync {
    /// Defines the transaction type for this storage implementation.  The transaction must rollback upon Drop.
    type Transaction<'t>: TransactionT<'t>
    where
        Self: 't;
    /// Begin a transaction.
    async fn begin_transaction(&self) -> Result<Self::Transaction<'_>>;
}
