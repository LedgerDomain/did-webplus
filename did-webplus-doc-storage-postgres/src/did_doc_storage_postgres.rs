use did_webplus::{DIDDocument, DIDStr};
use did_webplus_doc_store::{DIDDocRecord, Error, Result};
use sqlx::PgPool;

pub struct DIDDocStoragePostgres {
    pg_pool: PgPool,
}

impl DIDDocStoragePostgres {
    pub async fn open_and_run_migrations(pg_pool: PgPool) -> Result<Self> {
        sqlx::migrate!().run(&pg_pool).await.map_err(|err| {
            Error::StorageError(
                format!(
                    "Failed to run PostgreSQL database migrations; error was {}",
                    err
                )
                .into(),
            )
        })?;
        Ok(Self { pg_pool })
    }
}

#[async_trait::async_trait]
impl did_webplus_doc_store::DIDDocStorage for DIDDocStoragePostgres {
    type Transaction<'t> = sqlx::Transaction<'t, sqlx::Postgres>;
    async fn begin_transaction<'s, 't: 's, 'u: 't>(
        &self,
        existing_transaction_o: Option<&'u mut Self::Transaction<'t>>,
    ) -> Result<Self::Transaction<'s>> {
        if let Some(existing_transaction) = existing_transaction_o {
            use sqlx::Acquire;
            Ok(existing_transaction.begin().await?)
        } else {
            Ok(self.pg_pool.begin().await?)
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
        let did_string = did_document.parsed_did.to_string();
        sqlx::query_as!(
            did_webplus_doc_store::DIDDocRecord,
            r#"
                with inserted_record as (
                    insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                    values ($1, $2, $3, $4, to_jsonb($5::text))
                    returning *
                )
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from inserted_record
            "#,
            did_string,
            did_document.version_id() as i64,
            did_document.valid_from(),
            did_document.self_hash().to_string(),
            did_document_jcs,
        )
        .fetch_one(transaction.as_mut())
        .await?;
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        let did_doc_record_o = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where did = $1 and self_hash = $2
            "#,
            did.as_str(),
            self_hash.as_str()
        )
        .fetch_optional(transaction.as_mut())
        .await?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        let did_doc_record_o = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where did = $1 and version_id = $2
            "#,
            did.as_str(),
            version_id as i64
        )
        .fetch_optional(transaction.as_mut())
        .await?;
        Ok(did_doc_record_o)
    }
    async fn get_latest_did_doc_record(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        let did_doc_record = sqlx::query_as!(
            DIDDocRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document_jcs!: String"
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did.as_str(),
        )
        .fetch_optional(transaction.as_mut())
        .await?;
        Ok(did_doc_record)
    }
}
