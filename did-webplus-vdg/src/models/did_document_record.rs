use axum::http::StatusCode;
use did_webplus::{DIDDocument, DID};
// use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::parse_did_document;

// #[derive(Serialize, Deserialize)]
#[derive(Debug)]
// #[serde(rename_all = "camelCase")]
pub struct DIDDocumentRecord {
    pub self_hash: String,
    pub did: String,
    pub version_id: i64,
    // #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    pub did_document: String,
}

impl DIDDocumentRecord {
    // NOTE: did_document and body are redundant, and this assumes that they're consistent.
    pub async fn append_did_document(
        db: &PgPool,
        did_document: &DIDDocument,
        prev_did_document: Option<&DIDDocument>,
        body: &str,
    ) -> Result<Self, (StatusCode, String)> {
        assert_eq!(
            parse_did_document(body)?,
            *did_document,
            "programmer error: body and did_document are inconsistent"
        );
        let did_string = did_document.did.to_string();
        // This assumes that all stored DID documents have been validated inductively from the root!
        let self_hash = did_document
            .verify_nonrecursive(prev_did_document)
            .map_err(|err| (StatusCode::UNPROCESSABLE_ENTITY, err.to_string()))?;
        sqlx::query_as!(
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
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "error in database operation".to_string()))
    }

    pub async fn select_did_document(
        db: &PgPool,
        did: &DID,
        self_hash_o: Option<&str>,
        version_id_o: Option<u32>,
    ) -> Result<Option<Self>, (StatusCode, String)> {
        assert!(
            self_hash_o.is_some() != version_id_o.is_some(),
            "exactly one of self_hash_o or version_id_o must be set"
        );
        let did_string = did.to_string();
        let filter_on_self_hash = self_hash_o.is_some();
        let filter_on_version_id = version_id_o.is_some();
        let did_document_record_o = sqlx::query_as!(
            DIDDocumentRecord,
            r#"
                select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
                from did_document_records
                where did = $1
                and (not $2 or self_hash = $3)
                and (not $4 or version_id = $5)
            "#,
            did_string,
            filter_on_self_hash,
            if let Some(self_hash) = self_hash_o.as_ref() {
                self_hash.to_string()
            } else {
                "".to_string()
            },
            filter_on_version_id,
            if let Some(version_id) = version_id_o {
                version_id as i64
            } else {
                0
            },
        )
        .fetch_optional(db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "error in database operation".to_string()))?;
        Ok(did_document_record_o)
    }

    // pub async fn select_did_documents(
    //     db: &PgPool,
    //     since: OffsetDateTime,
    //     start_version_id: u32,
    //     end_version_id: u32,
    //     did: &DID,
    // ) -> Result<Vec<Self>, anyhow::Error> {
    //     let did_string = did.to_string();
    //     let did_documents_records = sqlx::query_as!(
    //         DIDDocumentRecord,
    //         r#"
    //             select did, version_id, valid_from, self_hash, did_document#>>'{}' as "did_document!: String"
    //             from did_document_records
    //             where did = $1
    //             and version_id >= $2
    //             and version_id <= $3
    //             and valid_from >= $4
    //             order by version_id asc
    //         "#,
    //         did_string,
    //         start_version_id as i64,
    //         end_version_id as i64,
    //         since,
    //     )
    //     .fetch_all(db)
    //     .await?;
    //     Ok(did_documents_records)
    // }

    // pub async fn did_exists(db: &PgPool, did: &DID) -> Result<bool, anyhow::Error> {
    //     let did_string = did.to_string();
    //     Ok(sqlx::query!(
    //         r#"
    //             select exists(select 1 from did_document_records where did = $1)
    //         "#,
    //         did_string
    //     )
    //     .fetch_one(db)
    //     .await
    //     .context("failed to check if microledger exists")?
    //     .exists
    //     .unwrap())
    // }

    pub async fn select_latest(
        db: &PgPool,
        did: &DID,
    ) -> Result<Option<Self>, (StatusCode, String)> {
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
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "error in database operation".to_string()))?;
        Ok(did_documents_record)
    }
}
