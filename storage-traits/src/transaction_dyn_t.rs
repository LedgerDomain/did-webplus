use crate::Result;

/// Object-safe transaction trait meant to be used by impls of StorageDynT.  The Drop impl must call rollback.
#[allow(drop_bounds)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait TransactionDynT: std::ops::Drop + Send + Sync {
    /// This is so the StorageDynT impl can downcast this TransactionDynT to its expected transaction type.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
    /// Commit the transaction, consuming it in the process.
    async fn commit(self: Box<Self>) -> Result<()>;
    /// Rollback the transaction, consuming it in the process.
    async fn rollback(self: Box<Self>) -> Result<()>;
}

#[cfg(feature = "sqlx-postgres")]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TransactionDynT for sqlx::Transaction<'static, sqlx::Postgres> {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn commit(self: Box<Self>) -> Result<()> {
        Ok((*self).commit().await?)
    }
    async fn rollback(self: Box<Self>) -> Result<()> {
        Ok((*self).rollback().await?)
    }
}

#[cfg(feature = "sqlx-sqlite")]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TransactionDynT for sqlx::Transaction<'static, sqlx::Sqlite> {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn commit(self: Box<Self>) -> Result<()> {
        Ok((*self).commit().await?)
    }
    async fn rollback(self: Box<Self>) -> Result<()> {
        Ok((*self).rollback().await?)
    }
}
