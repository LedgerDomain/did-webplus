use did_webplus::{DIDDocument, DID};
use did_webplus_doc_store::{DIDDocRecord, Error, Result};
use sqlx::SqlitePool;

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
            Ok(existing_transaction
                .begin()
                .await
                .map_err(sqlx_error_into_storage_error)?)
        } else {
            Ok(self
                .sqlite_pool
                .begin()
                .await
                .map_err(sqlx_error_into_storage_error)?)
        }
    }
    async fn commit_transaction(&self, transaction: Self::Transaction<'_>) -> Result<()> {
        transaction
            .commit()
            .await
            .map_err(sqlx_error_into_storage_error)
    }
    async fn rollback_transaction(&self, transaction: Self::Transaction<'_>) -> Result<()> {
        transaction
            .rollback()
            .await
            .map_err(sqlx_error_into_storage_error)
    }
    async fn add_did_document(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did_document: &DIDDocument,
        did_document_body: &str,
    ) -> Result<()> {
        assert!(
            did_document.self_hash_o.is_some(),
            "programmer error: self_hash is expected to be present on a valid DID document"
        );
        let did_doc_record_sqlite = DIDDocRecordSQLite {
            self_hash: Some(did_document.self_hash().to_string()),
            did: did_document.did.to_string(),
            version_id: did_document.version_id() as i64,
            valid_from: did_document.valid_from(),
            did_document: did_document_body.to_string(),
        };
        sqlx::query!(
            r#"
                insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                values ($1, $2, $3, $4, $5)
            "#,
            did_doc_record_sqlite.did,
            did_doc_record_sqlite.version_id,
            did_doc_record_sqlite.valid_from,
            did_doc_record_sqlite.self_hash,
            did_doc_record_sqlite.did_document,
        )
        .execute(transaction.as_mut())
        .await
        .map_err(sqlx_error_into_storage_error)?;
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DID,
        self_hash: &str,
    ) -> Result<Option<DIDDocRecord>> {
        let did_string = did.to_string();
        let did_doc_record_o = sqlx::query_as!(
            DIDDocRecordSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1 and self_hash = $2
            "#,
            did_string,
            self_hash
        )
        .fetch_optional(transaction.as_mut())
        .await
        .map_err(sqlx_error_into_storage_error)?
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DID,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        let did_string = did.to_string();
        let version_id = version_id as i64;
        let did_doc_record_o = sqlx::query_as!(
            DIDDocRecordSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1 and version_id = $2
            "#,
            did_string,
            version_id,
        )
        .fetch_optional(transaction.as_mut())
        .await
        .map_err(sqlx_error_into_storage_error)?
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_latest_did_doc_record(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DID,
    ) -> Result<Option<DIDDocRecord>> {
        let did_string = did.to_string();
        let did_doc_record_o = sqlx::query_as!(
            DIDDocRecordSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did_string,
        )
        .fetch_optional(transaction.as_mut())
        .await
        .map_err(sqlx_error_into_storage_error)?
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
}

/// Helper function to convert a sqlx::Error into a did_webplus_doc_store::Error::StorageError.
fn sqlx_error_into_storage_error(err: sqlx::Error) -> Error {
    Error::StorageError(err.to_string().into())
}

/// Because of a bug in an early version of SQLite, PRIMARY KEY doesn't imply NOT NULL.
/// https://www.sqlite.org/lang_createtable.html
/// Thus we have to have a hacky, separate version of did_webplus_doc_store::DIDDocRecord
/// in which the self_hash field is Option<_>
#[derive(Debug)]
pub struct DIDDocRecordSQLite {
    pub self_hash: Option<String>,
    pub did: String,
    pub version_id: i64,
    pub valid_from: time::OffsetDateTime,
    pub did_document: String,
}

impl TryFrom<DIDDocRecordSQLite> for did_webplus_doc_store::DIDDocRecord {
    type Error = Error;
    fn try_from(did_doc_record_sqlite: DIDDocRecordSQLite) -> Result<Self> {
        Ok(did_webplus_doc_store::DIDDocRecord {
            self_hash: did_doc_record_sqlite.self_hash.ok_or(Error::StorageError(
                "self_hash column was expected to be non-NULL".into(),
            ))?,
            did: did_doc_record_sqlite.did,
            version_id: did_doc_record_sqlite.version_id,
            valid_from: did_doc_record_sqlite.valid_from,
            did_document: did_doc_record_sqlite.did_document,
        })
    }
}
