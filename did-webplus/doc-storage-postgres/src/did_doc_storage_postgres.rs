use did_webplus_core::{DIDDocument, DIDStr};
use did_webplus_doc_store::{DIDDocRecord, DIDDocRecordFilter, Error, Result};
use sqlx::PgPool;

#[derive(Clone)]
pub struct DIDDocStoragePostgres {
    pg_pool: PgPool,
}

impl DIDDocStoragePostgres {
    pub async fn open_and_run_migrations(pg_pool: PgPool) -> Result<Self> {
        sqlx::migrate!().run(&pg_pool).await.map_err(|err| {
            Error::StorageError(
                format!(
                    "Failed to run PostgreSQL database migrations; error was: {}",
                    err
                )
                .into(),
            )
        })?;
        Ok(Self { pg_pool })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_doc_store::DIDDocStorage for DIDDocStoragePostgres {
    async fn add_did_document(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> Result<()> {
        assert!(
            did_document.self_hash_o.is_some(),
            "programmer error: self_hash is expected to be present on a valid DID document"
        );
        // TODO: Figure out how, on conflict, to check that the did_document_jcs matches what's in the DB.
        // Though this is an extremely pedantic check which may not be worth doing.
        let query = sqlx::query!(
            r#"
                INSERT INTO did_document_records(did, version_id, valid_from, self_hash, did_document)
                VALUES ($1, $2, $3, $4, to_jsonb($5::text))
                ON CONFLICT DO NOTHING
            "#,
            did_document.did.as_str(),
            did_document.version_id() as i64,
            did_document.valid_from(),
            did_document.self_hash().as_str(),
            did_document_jcs,
        );
        if let Some(transaction) = transaction_o {
            query
                .execute(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Postgres>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?;
        } else {
            query.execute(&self.pg_pool).await?;
        }
        Ok(())
    }
    async fn add_did_documents(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did_document_jcs_v: &[&str],
        _did_document_v: &[DIDDocument],
    ) -> Result<()> {
        todo!();
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        let query = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where did = $1 and self_hash = $2
            "#,
            did.as_str(),
            self_hash.as_str()
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Postgres>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.pg_pool).await?
        };
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        let query = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where did = $1 and version_id = $2
            "#,
            did.as_str(),
            version_id as i64
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Postgres>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.pg_pool).await?
        };
        Ok(did_doc_record_o)
    }
    async fn get_latest_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        let query = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did.as_str(),
        );
        let did_doc_record = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Postgres>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.pg_pool).await?
        };
        Ok(did_doc_record)
    }
    async fn get_did_doc_records(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> Result<Vec<DIDDocRecord>> {
        let filter_on_did = did_doc_record_filter.did_o.is_some();
        let filter_on_self_hash = did_doc_record_filter.self_hash_o.is_some();
        let filter_on_version_id = did_doc_record_filter.version_id_o.is_some();
        // TODO: SQL-based filtering on valid_at
        // let filter_on_valid_at = did_doc_record_filter.valid_at_o.is_some();
        let query = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where (NOT $1 OR did = $2) AND
                      (NOT $3 OR self_hash = $4) AND
                      (NOT $5 OR version_id = $6)
            "#,
            filter_on_did,
            did_doc_record_filter.did_o,
            filter_on_self_hash,
            did_doc_record_filter.self_hash_o,
            filter_on_version_id,
            did_doc_record_filter
                .version_id_o
                .map(|version_id| version_id as i64),
        );
        let did_doc_record_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Postgres>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.pg_pool).await?
        };
        Ok(did_doc_record_v)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for DIDDocStoragePostgres {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(self.pg_pool.begin().await?))
    }
}
