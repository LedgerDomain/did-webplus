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
        // Regarding "ON CONFLICT DO NOTHING", a conflict will only happen when the self_hash already exists,
        // and that means that the DID document is verifiably already present in the database.
        let query = sqlx::query!(
            r#"
                INSERT INTO did_document_records(did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs)
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    COALESCE(
                        (
                            SELECT did_documents_jsonl_octet_length
                            FROM did_document_records
                            WHERE did = $1
                            ORDER BY version_id DESC
                            LIMIT 1
                        ),
                        0
                    ) + OCTET_LENGTH($5) + 1,
                    $5
                )
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
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1 AND self_hash = $2
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
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1 AND version_id = $2
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
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1
                ORDER BY version_id DESC
                LIMIT 1
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
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE (NOT $1 OR did = $2) AND
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
    async fn get_known_did_documents_jsonl_octet_length(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<u64> {
        let query = sqlx::query!(
            r#"
                SELECT did_documents_jsonl_octet_length
                FROM did_document_records
                WHERE did = $1
                ORDER BY version_id DESC
                LIMIT 1
            "#,
            did.as_str()
        );
        let did_documents_jsonl_octet_length = if let Some(transaction) = transaction_o {
            query
                .fetch_one(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Postgres>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
                .did_documents_jsonl_octet_length
        } else {
            query
                .fetch_one(&self.pg_pool)
                .await?
                .did_documents_jsonl_octet_length
        };
        let did_documents_jsonl_octet_length = did_documents_jsonl_octet_length as u64;
        Ok(did_documents_jsonl_octet_length)
    }
    async fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> Result<Vec<DIDDocRecord>> {
        let range_begin_inclusive = range_begin_inclusive_o.map(|x| x as i64).unwrap_or(0);
        let range_end_exclusive = range_end_exclusive_o.map(|x| x as i64).unwrap_or(i64::MAX);

        if range_begin_inclusive >= range_end_exclusive {
            // If the range is empty (or invalid), return an empty vector.
            return Ok(Vec::new());
        }

        let query = sqlx::query_as!(
            DIDDocRecord,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1 AND
                      $2 < did_documents_jsonl_octet_length AND
                      did_documents_jsonl_octet_length - (OCTET_LENGTH(did_document_jcs) + 1) < $3
                ORDER BY version_id ASC
            "#,
            did.as_str(),
            range_begin_inclusive,
            range_end_exclusive,
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
