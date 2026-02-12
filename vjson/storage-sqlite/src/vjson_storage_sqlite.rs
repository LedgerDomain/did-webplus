use sqlx::SqlitePool;
use vjson_store::{AlreadyExistsPolicy, Error, Result, VJSONRecord, error_invalid_vjson};

#[derive(Clone)]
pub struct VJSONStorageSQLite {
    sqlite_pool: SqlitePool,
}

impl VJSONStorageSQLite {
    pub async fn open_and_run_migrations(sqlite_pool: SqlitePool) -> Result<Self> {
        sqlx::migrate!().run(&sqlite_pool).await.map_err(|err| {
            Error::StorageError(
                format!(
                    "Failed to run SQLite database migrations; error was: {}",
                    err
                )
                .into(),
            )
        })?;
        Ok(Self { sqlite_pool })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for VJSONStorageSQLite {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(self.sqlite_pool.begin().await?))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl vjson_store::VJSONStorage for VJSONStorageSQLite {
    async fn add_vjson_str(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        vjson_record: VJSONRecord,
        already_exists_policy: AlreadyExistsPolicy,
    ) -> Result<()> {
        let self_hash_str = vjson_record.self_hash.as_str();
        tracing::trace!(
            "VJSONStorageSQLite attempting to add VJSONRecord with self-hash {}; already_exists_policy: {:?}",
            self_hash_str,
            already_exists_policy
        );
        match already_exists_policy {
            AlreadyExistsPolicy::DoNothing => {
                let query = sqlx::query!(
                    r#"
                        INSERT INTO vjson_records(self_hash, added_at, vjson_jcs)
                        VALUES ($1, $2, $3)
                        ON CONFLICT DO NOTHING
                    "#,
                    self_hash_str,
                    vjson_record.added_at,
                    vjson_record.vjson_jcs,
                );
                if let Some(transaction) = transaction_o {
                    query
                        .execute(
                            transaction
                                .as_any_mut()
                                .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                                .unwrap()
                                .as_mut(),
                        )
                        .await?;
                } else {
                    query.execute(&self.sqlite_pool).await?;
                }
            }
            AlreadyExistsPolicy::Fail => {
                let query = sqlx::query!(
                    r#"
                        INSERT INTO vjson_records(self_hash, added_at, vjson_jcs)
                        VALUES ($1, $2, $3)
                    "#,
                    self_hash_str,
                    vjson_record.added_at,
                    vjson_record.vjson_jcs,
                );
                if let Some(transaction) = transaction_o {
                    query
                        .execute(
                            transaction
                                .as_any_mut()
                                .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                                .unwrap()
                                .as_mut(),
                        )
                        .await?;
                } else {
                    query.execute(&self.sqlite_pool).await?;
                }
            }
        }
        tracing::trace!(
            "VJSONStorageSQLite successfully added VJSONRecord with self-hash {}",
            self_hash_str
        );
        Ok(())
    }
    async fn get_vjson_str(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        self_hash: &mbx::MBHashStr,
    ) -> Result<VJSONRecord> {
        let self_hash_str = self_hash.as_str();
        let query = sqlx::query_as!(
            VJSONRecordRowSQLite,
            r#"
                SELECT self_hash, added_at, vjson_jcs
                FROM vjson_records
                WHERE self_hash = $1
            "#,
            self_hash_str
        );
        let query_result = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.sqlite_pool).await?
        };
        let vjson_record = query_result
            .ok_or_else(|| {
                Error::NotFound(format!("VJSONRecord with self-hash {}", self_hash_str).into())
            })?
            .try_into()?;
        Ok(vjson_record)
    }
}

/// Because of a bug in an early version of SQLite, PRIMARY KEY doesn't imply NOT NULL.
/// https://www.sqlite.org/lang_createtable.html
/// Thus we have to have a hacky, separate version of vjson_store::VJSONRecord
/// in which the self_hash field is Option<_>
#[derive(Debug)]
pub struct VJSONRecordRowSQLite {
    pub self_hash: Option<String>,
    pub added_at: time::OffsetDateTime,
    pub vjson_jcs: String,
}

impl TryFrom<VJSONRecordRowSQLite> for vjson_store::VJSONRecord {
    type Error = Error;
    fn try_from(vjson_record_sqlite: VJSONRecordRowSQLite) -> Result<Self> {
        Ok(vjson_store::VJSONRecord {
            self_hash: vjson_record_sqlite
                .self_hash
                .ok_or_else(|| {
                    Error::StorageError("self_hash column was expected to be non-NULL".into())
                })?
                .try_into()
                .map_err(error_invalid_vjson)?,
            added_at: vjson_record_sqlite.added_at,
            vjson_jcs: vjson_record_sqlite.vjson_jcs,
        })
    }
}
