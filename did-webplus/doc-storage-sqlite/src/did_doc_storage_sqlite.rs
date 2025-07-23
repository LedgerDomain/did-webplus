use did_webplus_core::{DIDDocument, DIDStr};
use did_webplus_doc_store::{DIDDocRecord, DIDDocRecordFilter, Error, Result};
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct DIDDocStorageSQLite {
    sqlite_pool: SqlitePool,
}

impl DIDDocStorageSQLite {
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
impl did_webplus_doc_store::DIDDocStorage for DIDDocStorageSQLite {
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
        let did_str = did_document.did.as_str();
        let version_id = did_document.version_id() as i64;
        let valid_from = did_document.valid_from();
        let self_hash_str = did_document.self_hash().as_str();
        let query = sqlx::query!(
            r#"
                insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                values ($1, $2, $3, $4, $5)
            "#,
            did_str,
            version_id,
            valid_from,
            self_hash_str,
            did_document_jcs,
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
        Ok(())
    }
    async fn add_did_documents(
        &self,
        mut transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document_jcs_v: &[&str],
        did_document_v: &[DIDDocument],
    ) -> Result<()> {
        assert_eq!(did_document_jcs_v.len(), did_document_v.len());

        // SQLite doesn't support batch inserts, so we have to do one at a time.
        for (&did_document_jcs, did_document) in
            did_document_jcs_v.iter().zip(did_document_v.iter())
        {
            // self.add_did_document(transaction_o.as_deref_mut(), did_document, did_document_jcs)
            //     .await?;

            // TEMP HACK -- should just call add_did_document, but there's some compiler error regarding lifetimes of transaction_o

            assert!(
                did_document.self_hash_o.is_some(),
                "programmer error: self_hash is expected to be present on a valid DID document"
            );
            let did_str = did_document.did.as_str();
            let version_id = did_document.version_id() as i64;
            let valid_from = did_document.valid_from();
            let self_hash_str = did_document.self_hash().as_str();
            let query = sqlx::query!(
                r#"
                insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                values ($1, $2, $3, $4, $5)
            "#,
                did_str,
                version_id,
                valid_from,
                self_hash_str,
                did_document_jcs,
            );
            if let Some(transaction) = &mut transaction_o {
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
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let self_hash_str = self_hash.as_str();
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1 and self_hash = $2
            "#,
            did_str,
            self_hash_str
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
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
        }
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let version_id = version_id as i64;
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1 and version_id = $2
            "#,
            did_str,
            version_id,
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
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
        }
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_latest_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did_str,
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
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
        }
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
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
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
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
            did_doc_record_filter.version_id_o,
        );
        let did_doc_record_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        }
        .into_iter()
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .collect::<Result<Vec<_>>>()?;
        Ok(did_doc_record_v)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for DIDDocStorageSQLite {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(self.sqlite_pool.begin().await?))
    }
}

/// Because of a bug in an early version of SQLite, PRIMARY KEY doesn't imply NOT NULL.
/// https://www.sqlite.org/lang_createtable.html
/// Thus we have to have a hacky, separate version of did_webplus_doc_store::DIDDocRecord
/// in which the self_hash field is Option<_>
#[derive(Debug)]
pub struct DIDDocumentRowSQLite {
    pub self_hash: Option<String>,
    pub did: String,
    pub version_id: i64,
    pub valid_from: time::OffsetDateTime,
    pub did_document: String,
}

impl TryFrom<DIDDocumentRowSQLite> for did_webplus_doc_store::DIDDocRecord {
    type Error = Error;
    fn try_from(did_doc_record_sqlite: DIDDocumentRowSQLite) -> Result<Self> {
        Ok(did_webplus_doc_store::DIDDocRecord {
            self_hash: did_doc_record_sqlite.self_hash.ok_or(Error::StorageError(
                "self_hash column was expected to be non-NULL".into(),
            ))?,
            did: did_doc_record_sqlite.did,
            version_id: did_doc_record_sqlite.version_id,
            valid_from: did_doc_record_sqlite.valid_from,
            did_document_jcs: did_doc_record_sqlite.did_document,
        })
    }
}
