use crate::{Result, TransactionDynT};

/// Object-safe Storage trait, able to begin a transaction of the appropriate type.
/// TL;DR: Consider using this trait instead of StorageT, since the advantages of StorageT are subtle and niche.
/// Advantages of StorageDynT:
/// - Storage impls can be plugged in without changing a generic.
/// - Compilation will likely be much faster and produce smaller code because it avoids monomorphizing.
/// Disadvantages of StorageDynT:
/// - Slight overhead on each call due to dynamic dispatch.  However, this is almost certainly dominated
///   by the overhead of the storage call (e.g. SQL query) itself.
/// - You don't have direct access to the transaction type, since you only have access to a `dyn TransactionDynT`.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait StorageDynT {
    async fn begin_transaction(&self) -> Result<Box<dyn TransactionDynT>>;
}
