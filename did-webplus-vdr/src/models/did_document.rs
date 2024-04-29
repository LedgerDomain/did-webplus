use anyhow::Context;
use did_webplus::{DIDDocument, DID};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocumentRecord {
    pub self_hash: String,
    pub did: String,
    pub version_id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    pub did_document: String,
}

impl DIDDocumentRecord {
    pub async fn append_did_document(
        db: &PgPool,
        did_document: DIDDocument,
        prev_did_document: Option<&DIDDocument>,
        body: String,
    ) -> Result<Self, anyhow::Error> {
        let did_string = did_document.did.to_string();
        let self_hash = did_document
            .verify_nonrecursive(prev_did_document)
            .context("invalid did document")?;
        Ok(sqlx::query_as!(
            DIDDocumentRecord,
            r#"
                with inserted_record as (
                    insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                    values ($1, $2, $3, $4, to_jsonb($5::text))
                    returning *
                )
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                from inserted_record
            "#,
            did_string,
            did_document.version_id() as i64,
            did_document.valid_from(),
            self_hash.to_string(),
            body,
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn fetch_did_documents(
        db: &PgPool,
        since: OffsetDateTime,
        start_version_id: u32,
        end_version_id: u32,
        did: &DID,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let did_string = did.to_string();
        let did_documents_records = sqlx::query_as!(
            DIDDocumentRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                from did_document_records
                where did = $1
                and version_id >= $2
                and version_id <= $3
                and valid_from >= $4
                order by version_id asc
            "#,
            did_string,
            start_version_id as i64,
            end_version_id as i64,
            since,
        )
        .fetch_all(db)
        .await?;
        Ok(did_documents_records)
    }

    pub async fn did_exists(db: &PgPool, did: &DID) -> Result<bool, anyhow::Error> {
        let did_string = did.to_string();
        Ok(sqlx::query!(
            r#"
                select exists(select 1 from did_document_records where did = $1)
            "#,
            did_string
        )
        .fetch_one(db)
        .await
        .context("failed to check if microledger exists")?
        .exists
        .unwrap())
    }

    pub async fn fetch_latest(db: &PgPool, did: &DID) -> Result<Option<Self>, anyhow::Error> {
        let did_string = did.to_string();
        let did_documents_record = sqlx::query_as!(
            DIDDocumentRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did_string,
        )
        .fetch_optional(db)
        .await?;
        Ok(did_documents_record)
    }
}
