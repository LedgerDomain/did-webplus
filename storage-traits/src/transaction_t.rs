use crate::Result;

/// This transaction trait is meant for maximal monomorphization.  It is not object-safe.  The Drop impl must call rollback.
#[allow(drop_bounds)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait TransactionT<'t>: std::ops::Drop + Send + Sync + 't {
    /// Commit the transaction, consuming it in the process.
    async fn commit(self) -> Result<()>;
    /// Rollback the transaction, consuming it in the process.
    async fn rollback(self) -> Result<()>;
}

#[cfg(feature = "sqlx-postgres")]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'t> TransactionT<'t> for sqlx::Transaction<'t, sqlx::Postgres> {
    async fn commit(self) -> Result<()> {
        Ok(self.commit().await?)
    }
    async fn rollback(self) -> Result<()> {
        Ok(self.rollback().await?)
    }
}

#[cfg(feature = "sqlx-sqlite")]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'t> TransactionT<'t> for sqlx::Transaction<'t, sqlx::Sqlite> {
    async fn commit(self) -> Result<()> {
        Ok(self.commit().await?)
    }
    async fn rollback(self) -> Result<()> {
        Ok(self.rollback().await?)
    }
}
