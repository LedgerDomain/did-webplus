use anyhow::Context;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use did_webplus::{DIDDocument, DID};
use serde::Deserialize;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::models::did_document::DIDDocumentRecord;

use super::internal_error;

pub fn get_routes(pool: &PgPool) -> Router {
    Router::new()
        .route(
            "/:path/:did_id",
            // Note: This "get all DID docs in version range" endpoint is not compatible with
            // static-host VDRs, which can only serve a single DID doc at a time.
            get(get_did_documents_with_path),
        )
        .route(
            "/:did_id",
            // Note: This "get all DID docs in version range" endpoint is not compatible with
            // static-host VDRs, which can only serve a single DID doc at a time.
            get(get_did_documents_without_path),
        )
        .route(
            "/:path/:did_id/did.json",
            // Note: These are the three endpoint methods that are compatible with static-host VDRs.
            get(get_latest_did_document_with_path)
                .post(create_did_with_path)
                .put(update_did_with_path),
        )
        .route(
            "/:did_id/did.json",
            // Note: These are the three endpoint methods that are compatible with static-host VDRs.
            get(get_latest_did_document_without_path)
                .post(create_did_without_path)
                .put(update_did_without_path),
        )
        .with_state(pool.clone())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocumentRecordListRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub since: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_version_id: Option<u32>,
    pub end_version_id: Option<u32>,
}

async fn get_did_documents_with_path(
    State(db): State<PgPool>,
    query: Query<DIDDocumentRecordListRequest>,
    Path((path, did_id)): Path<(String, String)>,
) -> Result<Json<Vec<DIDDocumentRecord>>, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id)?;
    get_did_documents(db, query, &did).await
}

async fn get_did_documents_without_path(
    State(db): State<PgPool>,
    query: Query<DIDDocumentRecordListRequest>,
    Path(did_id): Path<String>,
) -> Result<Json<Vec<DIDDocumentRecord>>, (StatusCode, String)> {
    let did = did_from_components(None, did_id)?;
    get_did_documents(db, query, &did).await
}

async fn get_did_documents(
    db: PgPool,
    query: Query<DIDDocumentRecordListRequest>,
    did: &DID,
) -> Result<Json<Vec<DIDDocumentRecord>>, (StatusCode, String)> {
    let since = query
        .since
        .unwrap_or(OffsetDateTime::from_unix_timestamp(0).unwrap());
    let start_version_id = query.start_version_id.unwrap_or(0);
    let end_version_id = query.end_version_id.unwrap_or(u32::MAX);

    let did_documents_records =
        DIDDocumentRecord::fetch_did_documents(&db, since, start_version_id, end_version_id, did)
            .await
            .map_err(internal_error)?;

    if did_documents_records.is_empty() {
        return Err((StatusCode::NOT_FOUND, format!("DID not found: {}", did)));
    }
    Ok(Json(did_documents_records))
}

#[tracing::instrument(err(Debug), ret)]
async fn create_did_with_path(
    State(db): State<PgPool>,
    Path((path, did_id)): Path<(String, String)>,
    body: String,
) -> Result<Json<DIDDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id)?;
    create_did(db, &did, body).await
}

#[tracing::instrument(err(Debug), ret)]
async fn create_did_without_path(
    State(db): State<PgPool>,
    Path(did_id): Path<String>,
    body: String,
) -> Result<Json<DIDDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(None, did_id)?;
    create_did(db, &did, body).await
}

async fn create_did(
    db: PgPool,
    did: &DID,
    body: String,
) -> Result<Json<DIDDocumentRecord>, (StatusCode, String)> {
    if DIDDocumentRecord::did_exists(&db, did)
        .await
        .context("checking if DID exists")
        .map_err(internal_error)?
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("DID already exists: {}", did),
        ));
    }

    let root_did_document = serde_json::from_str::<DIDDocument>(&body).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid DID document: {}", err),
        )
    })?;
    if &root_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the path: {} != {}",
                root_did_document.did, did
            ),
        ));
    }

    let did_document_record =
        DIDDocumentRecord::append_did_document(&db, root_did_document, None, body)
            .await
            .map_err(internal_error)?;

    Ok(Json(did_document_record))
}

#[tracing::instrument(err(Debug), ret)]
async fn update_did_with_path(
    State(db): State<PgPool>,
    Path((path, did_id)): Path<(String, String)>,
    body: String,
) -> Result<Json<DIDDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id)?;
    update_did(db, &did, body).await
}

#[tracing::instrument(err(Debug), ret)]
async fn update_did_without_path(
    State(db): State<PgPool>,
    Path(did_id): Path<String>,
    body: String,
) -> Result<Json<DIDDocumentRecord>, (StatusCode, String)> {
    let did = did_from_components(None, did_id)?;
    update_did(db, &did, body).await
}

async fn update_did(
    db: PgPool,
    did: &DID,
    body: String,
) -> Result<Json<DIDDocumentRecord>, (StatusCode, String)> {
    let last_record = DIDDocumentRecord::fetch_latest(&db, did)
        .await
        .context("fetching last record")
        .map_err(internal_error)?;
    if last_record.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("DID does not exist: {}", did),
        ));
    }

    let new_did_document = serde_json::from_str::<DIDDocument>(&body).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid DID document: {}", err),
        )
    })?;
    if &new_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the path: {} != {}",
                new_did_document.did, did
            ),
        ));
    }

    // TODO: Check if the previous did document is the root record if this will work. Otherwise add more logic.
    let prev_document = serde_json::from_str::<DIDDocument>(&last_record.unwrap().did_document)
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid did document: {}", err),
            )
        })?;

    let did_document_record =
        DIDDocumentRecord::append_did_document(&db, new_did_document, Some(&prev_document), body)
            .await
            .map_err(internal_error)?;

    Ok(Json(did_document_record))
}

#[tracing::instrument(err(Debug), ret)]
async fn get_latest_did_document_with_path(
    State(db): State<PgPool>,
    Path((path, did_id)): Path<(String, String)>,
) -> Result<String, (StatusCode, String)> {
    let did = did_from_components(Some(path), did_id)?;
    get_latest_did_document(db, &did).await
}

#[tracing::instrument(err(Debug), ret)]
async fn get_latest_did_document_without_path(
    State(db): State<PgPool>,
    Path(did_id): Path<String>,
) -> Result<String, (StatusCode, String)> {
    let did = did_from_components(None, did_id)?;
    get_latest_did_document(db, &did).await
}

async fn get_latest_did_document(db: PgPool, did: &DID) -> Result<String, (StatusCode, String)> {
    let latest_record_o = match DIDDocumentRecord::fetch_latest(&db, did).await {
        Ok(last_record) => last_record,
        Err(err) => {
            tracing::error!(
                "Error while attempting to get latest DID document for {}: {}",
                did,
                err
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "".to_string()));
        }
    };
    match latest_record_o {
        Some(latest_did_document_record) => Ok(latest_did_document_record.did_document),
        None => Err((StatusCode::NOT_FOUND, format!("DID not found: {}", did))),
    }
}

fn did_from_components(
    path_o: Option<String>,
    did_id: String,
) -> Result<DID, (StatusCode, String)> {
    let domain = dotenvy::var("DID_WEBPLUS_VDR_SERVICE_DOMAIN")
        .expect("DID_WEBPLUS_VDR_SERVICE_DOMAIN must be set");
    Ok(DID::new_with_self_hash_string(domain, path_o, did_id)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("malformed DID: {}", err)))?)
}
