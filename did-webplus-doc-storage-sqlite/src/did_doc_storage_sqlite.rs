use did_webplus::{DIDDocument, DIDStr};
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
                    "Failed to run SQLite database migrations; error was {}",
                    err
                )
                .into(),
            )
        })?;
        Ok(Self { sqlite_pool })
    }
}

#[async_trait::async_trait]
impl did_webplus_doc_store::DIDDocStorage for DIDDocStorageSQLite {
    type Transaction<'t> = sqlx::Transaction<'t, sqlx::Sqlite>;
    async fn begin_transaction<'s, 't: 's, 'u: 't>(
        &self,
        existing_transaction_o: Option<&'u mut Self::Transaction<'t>>,
    ) -> Result<Self::Transaction<'s>> {
        if let Some(existing_transaction) = existing_transaction_o {
            use sqlx::Acquire;
            Ok(existing_transaction.begin().await?)
        } else {
            Ok(self.sqlite_pool.begin().await?)
        }
    }
    async fn commit_transaction(&self, transaction: Self::Transaction<'_>) -> Result<()> {
        Ok(transaction.commit().await?)
    }
    async fn rollback_transaction(&self, transaction: Self::Transaction<'_>) -> Result<()> {
        Ok(transaction.rollback().await?)
    }
    async fn add_did_document(
        &self,
        transaction: &mut Self::Transaction<'_>,
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
        sqlx::query!(
            r#"
                insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                values ($1, $2, $3, $4, $5)
            "#,
            did_str,
            version_id,
            valid_from,
            self_hash_str,
            did_document_jcs,
        )
        .execute(transaction.as_mut())
        .await?;
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let self_hash_str = self_hash.as_str();
        let did_doc_record_o = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1 and self_hash = $2
            "#,
            did_str,
            self_hash_str
        )
        .fetch_optional(transaction.as_mut())
        .await?
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let version_id = version_id as i64;
        let did_doc_record_o = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1 and version_id = $2
            "#,
            did_str,
            version_id,
        )
        .fetch_optional(transaction.as_mut())
        .await?
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_latest_did_doc_record(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let did_doc_record_o = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did_str,
        )
        .fetch_optional(transaction.as_mut())
        .await?
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_records(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> Result<Vec<DIDDocRecord>> {
        let filter_on_did = did_doc_record_filter.did_o.is_some();
        let filter_on_self_hash = did_doc_record_filter.self_hash_o.is_some();
        let filter_on_version_id = did_doc_record_filter.version_id_o.is_some();
        // TODO: SQL-based filtering on valid_at
        // let filter_on_valid_at = did_doc_record_filter.valid_at_o.is_some();
        let did_doc_record_v = sqlx::query_as!(
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
        )
        .fetch_all(transaction.as_mut())
        .await?
        .into_iter()
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .collect::<Result<Vec<_>>>()?;
        Ok(did_doc_record_v)
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
