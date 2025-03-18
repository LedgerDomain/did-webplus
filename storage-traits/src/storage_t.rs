use crate::{Result, TransactionT};

/// Storage trait meant for maximal monomorphization.  This trait is not object-safe.
/// TL;DR: Consider using StorageDynT instead of this trait, since the advantages of this trait are subtle and niche.
/// Advantages:
/// - Code is fully monomorphized, giving best chance for maximal inlining and optimization.
/// - You have direct access to the transaction type, instead of to a `dyn TransactionDynT`.
/// Disadvantages:
/// - The code that uses this trait must either pick a specific type implementing it, or propagate the type parameter.
/// - Compilation will likely be slower and produce larger code because it monomorphizes the storage calls.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait StorageT: Clone + Send + Sync {
    /// Defines the transaction type for this storage implementation.  The transaction must rollback upon Drop.
    type Transaction<'t>: TransactionT<'t>
    where
        Self: 't;
    /// Begin a transaction.
    #[allow(elided_named_lifetimes)]
    async fn begin_transaction(&self) -> Result<Self::Transaction<'_>>;
}
