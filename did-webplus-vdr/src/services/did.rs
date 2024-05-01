use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use did_webplus::{DIDWithQuery, DID};
use sqlx::PgPool;

use crate::{models::did_document::DIDDocumentRecord, parse_did_document};

pub fn get_routes(pool: &PgPool) -> Router {
    Router::new()
        .route(
            // We have to do our own URL processing in each handler because of the non-standard
            // form of the "query" (e.g. did.selfHash=<hash>.json) and the fact that we're using
            // the same handler for multiple routes.
            "/*path",
            get(get_did_document).post(create_did).put(update_did),
        )
        .with_state(pool.clone())
}

#[tracing::instrument(err(Debug), ret)]
async fn get_did_document(
    State(db): State<PgPool>,
    Path(path): Path<String>,
) -> Result<String, (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let host = dotenvy::var("DID_WEBPLUS_VDR_SERVICE_DOMAIN")
        .expect("DID_WEBPLUS_VDR_SERVICE_DOMAIN must be set");

    // Case for retrieving the latest DID doc.
    if path.ends_with("did.json") {
        let did = DID::from_resolution_url(host.as_str(), path.as_str()).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("malformed DID resolution URL: {}", err),
            )
        })?;
        return get_latest_did_document(db, &did).await;
    }

    // Case for retrieving a specific DID doc.
    if path.ends_with(".json") {
        let did_with_query = DIDWithQuery::from_resolution_url(host.as_str(), path.as_str())
            .map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("malformed DID resolution URL: {}", err),
                )
            })?;
        let specific_did_document_record_o = DIDDocumentRecord::select_did_document(
            &db,
            &did_with_query.without_query(),
            did_with_query
                .query_self_hash()
                .map_err(|err| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("malformed selfHash: {}", err),
                    )
                })?
                .as_deref(),
            did_with_query.query_version_id().map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("malformed versionId: {}", err),
                )
            })?,
        )
        .await?;
        if specific_did_document_record_o.is_none() {
            return Err((StatusCode::NOT_FOUND, "".to_string()));
        }
        return Ok(specific_did_document_record_o.unwrap().did_document);
    }

    Err((StatusCode::BAD_REQUEST, "".to_string()))
}

#[tracing::instrument(err(Debug), ret)]
async fn create_did(
    State(db): State<PgPool>,
    Path(path): Path<String>,
    body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let host = dotenvy::var("DID_WEBPLUS_VDR_SERVICE_DOMAIN")
        .expect("DID_WEBPLUS_VDR_SERVICE_DOMAIN must be set");

    let did = DID::from_resolution_url(host.as_str(), path.as_str()).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;

    if DIDDocumentRecord::did_exists(&db, &did)
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error checking if DID exists: {}", err),
            )
        })?
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("DID already exists: {}", did),
        ));
    }

    let root_did_document = parse_did_document(&body)?;
    if root_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the resolution URL: {} != {}",
                root_did_document.did, did
            ),
        ));
    }

    DIDDocumentRecord::append_did_document(&db, &root_did_document, None, &body).await?;

    Ok(())
}

#[tracing::instrument(err(Debug), ret)]
async fn update_did(
    State(db): State<PgPool>,
    Path(path): Path<String>,
    body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let host = dotenvy::var("DID_WEBPLUS_VDR_SERVICE_DOMAIN")
        .expect("DID_WEBPLUS_VDR_SERVICE_DOMAIN must be set");

    let did = DID::from_resolution_url(host.as_str(), path.as_str()).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;

    let latest_did_document_record_o =
        DIDDocumentRecord::select_latest(&db, &did)
            .await
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("error fetching latest DID doc: {}", err),
                )
            })?;
    if latest_did_document_record_o.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("DID does not exist: {}", did),
        ));
    }
    let latest_did_document_record = latest_did_document_record_o.unwrap();

    let new_did_document = parse_did_document(&body)?;
    if new_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the resolution URL: {} != {}",
                new_did_document.did, did
            ),
        ));
    }

    // TODO: Check if the previous did document is the root record if this will work. Otherwise add more logic.
    let prev_document =
        parse_did_document(&latest_did_document_record.did_document).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid DID document in storage".to_string(),
            )
        })?;

    DIDDocumentRecord::append_did_document(&db, &new_did_document, Some(&prev_document), &body)
        .await?;

    Ok(())
}

async fn get_latest_did_document(db: PgPool, did: &DID) -> Result<String, (StatusCode, String)> {
    let latest_record_o = match DIDDocumentRecord::select_latest(&db, did).await {
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
