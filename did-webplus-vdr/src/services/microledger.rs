use anyhow::Context;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use did_webplus::DIDDocument;
use serde::Deserialize;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::models::did_document::DidDocumentRecord;

use super::internal_error;

pub fn get_routes(pool: &PgPool) -> Router {
    Router::new()
        .route(
            "/:path/:did_id",
            post(create_microledger_with_path)
                .get(get_microledger_with_path)
                .put(update_microledger_with_path),
        )
        .route(
            "/:did_id",
            get(get_microledger_without_path)
                .post(create_microledger_without_path)
                .put(update_microledger_without_path),
        )
        // .route("/:path/:did_id/did.json", get_latest_microledger)
        // .route("/:did_id/did.json", get_latest_microledger)
        .with_state(pool.clone())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentRecordListRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub since: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_version_id: Option<u32>,
    pub end_version_id: Option<u32>,
}

async fn get_microledger_without_path(
    State(db): State<PgPool>,
    query: Query<DidDocumentRecordListRequest>,
    Path(did_id): Path<String>,
) -> Result<Json<Vec<DidDocumentRecord>>, (StatusCode, String)> {
    let did = did_from_components(None, did_id);
    get_microledger(db, query, did).await
}

async fn get_microledger_with_path(
    State(db): State<PgPool>,
    query: Query<DidDocumentRecordListRequest>,
    Path((path, did_id)): Path<(String, String)>,
) -> Result<Json<Vec<DidDocumentRecord>>, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id);
    get_microledger(db, query, did).await
}

async fn get_microledger(
    db: PgPool,
    query: Query<DidDocumentRecordListRequest>,
    did: String,
) -> Result<Json<Vec<DidDocumentRecord>>, (StatusCode, String)> {
    let since = query
        .since
        .unwrap_or(OffsetDateTime::from_unix_timestamp(0).unwrap());
    let start_version_id = query.start_version_id.unwrap_or(0);
    let end_version_id = query.end_version_id.unwrap_or(u32::MAX);

    let did_documents_records = DidDocumentRecord::fetch_microledger(
        &db,
        since,
        start_version_id,
        end_version_id,
        did.clone(),
    )
    .await
    .map_err(internal_error)?;

    if did_documents_records.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("microledger not found: {}", did),
        ));
    }
    Ok(Json(did_documents_records))
}

async fn create_microledger_with_path(
    State(db): State<PgPool>,
    Path((path, did_id)): Path<(String, String)>,
    body: String,
) -> Result<Json<DidDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id);
    create_microledger(db, did, body).await
}

async fn create_microledger_without_path(
    State(db): State<PgPool>,
    Path(did_id): Path<String>,
    body: String,
) -> Result<Json<DidDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(None, did_id);
    create_microledger(db, did, body).await
}

async fn create_microledger(
    db: PgPool,
    did: String,
    body: String,
) -> Result<Json<DidDocumentRecord>, (StatusCode, String)> {
    if DidDocumentRecord::check_microledger_exists(&db, &did)
        .await
        .context("checking microledger exists")
        .map_err(internal_error)?
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("microledger already exists: {}", did),
        ));
    }

    let root_did_document = serde_json::from_str::<DIDDocument>(&body).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid did document: {}", err),
        )
    })?;

    let did_document_record = DidDocumentRecord::insert(&db, root_did_document, None, did, body)
        .await
        .map_err(internal_error)?;

    Ok(Json(did_document_record))
}

async fn update_microledger_with_path(
    State(db): State<PgPool>,
    Path((path, did_id)): Path<(String, String)>,
    body: String,
) -> Result<Json<DidDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id);
    update_microledger(db, did, body).await
}

async fn update_microledger_without_path(
    State(db): State<PgPool>,
    Path(did_id): Path<String>,
    body: String,
) -> Result<Json<DidDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(None, did_id);
    update_microledger(db, did, body).await
}

async fn update_microledger(
    db: PgPool,
    did: String,
    body: String,
) -> Result<Json<DidDocumentRecord>, (StatusCode, String)> {
    let last_record = DidDocumentRecord::fetch_last_record(&db, did.clone())
        .await
        .context("fetching last record")
        .map_err(internal_error)?;
    if last_record.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("microledger does not exist: {}", did),
        ));
    }

    let new_did_document = serde_json::from_str::<DIDDocument>(&body).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid did document: {}", err),
        )
    })?;

    // TODO: Check if the previous did document is the root record if this will work. Otherwise add more logic.
    let prev_document = serde_json::from_str::<DIDDocument>(&last_record.unwrap().did_document)
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid did document: {}", err),
            )
        })?;

    let did_document_record =
        DidDocumentRecord::insert(&db, new_did_document, Some(&prev_document), did, body)
            .await
            .map_err(internal_error)?;

    Ok(Json(did_document_record))
}

fn did_from_components(path: Option<String>, did_id: String) -> String {
    let domain = dotenvy::var("SERVICE_DOMAIN").expect("SERVICE_DOMAIN must be set");
    if let Some(path) = path {
        return format!("{}:{}:{}", domain, path, did_id);
    }
    format!("{}:{}", domain, did_id)
}
