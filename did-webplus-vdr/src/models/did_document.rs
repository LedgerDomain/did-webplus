use anyhow::Context;
use did_webplus::DIDDocument;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentRecord {
    pub self_hash: String,
    pub did: String,
    pub version_id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    pub did_document: String,
}

impl DidDocumentRecord {
    pub async fn insert(
        db: &PgPool,
        did_document: DIDDocument,
        prev_did_document: Option<&DIDDocument>,
        did: String,
        body: String,
    ) -> Result<Self, anyhow::Error> {
        let self_hash = did_document
            .verify_nonrecursive(prev_did_document)
            .context("invalid did document")?;
        Ok(sqlx::query_as!(
                    DidDocumentRecord,
                    r#"
                        with inserted_record as (
                            insert into did_document_records(did, version_id, valid_from, self_hash, did_document)
                            values ($1, $2, $3, $4, to_jsonb($5::text))
                            returning *
                        )
                        select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                        from inserted_record
                    "#,
                    did,
                    did_document.version_id() as i64,
                    did_document.valid_from(),
                    self_hash.to_string(),
                    body,
                )
                .fetch_one(db)
                .await?)
    }

    pub async fn fetch_microledger(
        db: &PgPool,
        since: OffsetDateTime,
        start_version_id: u32,
        end_version_id: u32,
        did: String,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let did_documents_records = sqlx::query_as!(
            DidDocumentRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                from did_document_records
                where did = $1
                and version_id >= $2
                and version_id <= $3
                and valid_from >= $4
                order by version_id asc
            "#,
            did,
            start_version_id as i64,
            end_version_id as i64,
            since,
        )
        .fetch_all(db)
        .await?;
        Ok(did_documents_records)
    }

    pub async fn check_microledger_exists(
        db: &PgPool,
        did: &String,
    ) -> Result<bool, anyhow::Error> {
        Ok(sqlx::query!(
            r#"
                select exists(select 1 from did_document_records where did = $1)
            "#,
            did
        )
        .fetch_one(db)
        .await
        .context("failed to check if microledger exists")?
        .exists
        .unwrap())
    }

    pub async fn fetch_last_record(
        db: &PgPool,
        did: String,
    ) -> Result<Option<Self>, anyhow::Error> {
        let did_documents_record = sqlx::query_as!(
            DidDocumentRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                from did_document_records
                where did = $1
                order by version_id desc
                limit 1
            "#,
            did,
        )
        .fetch_optional(db)
        .await?;
        Ok(did_documents_record)
    }
}
