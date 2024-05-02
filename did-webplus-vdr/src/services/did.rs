use std::ops::Deref;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use did_webplus::{
    DIDDocumentMetadata, DIDDocumentMetadataConstant, DIDDocumentMetadataCurrency,
    DIDDocumentMetadataIdempotent, DIDWithQuery, DID,
};
use sqlx::PgPool;

use crate::{models::did_document_record::DIDDocumentRecord, parse_did_document};

pub fn get_routes(pool: &PgPool) -> Router {
    Router::new()
        .route(
            // We have to do our own URL processing in each handler because of the non-standard
            // form of the "query" (e.g. did.selfHash=<hash>.json) and the fact that we're using
            // the same handler for multiple routes.
            "/*path",
            get(get_did_document_or_metadata)
                .post(create_did)
                .put(update_did),
        )
        .with_state(pool.clone())
}

#[tracing::instrument(err(Debug), skip(db))]
async fn get_did_document_or_metadata(
    State(db): State<PgPool>,
    Path(path): Path<String>,
) -> Result<String, (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let host = dotenvy::var("DID_WEBPLUS_VDR_SERVICE_DOMAIN")
        .expect("DID_WEBPLUS_VDR_SERVICE_DOMAIN must be set");

    // Case for retrieving the latest DID doc.
    if let Ok(did) = DID::from_resolution_url(host.as_str(), path.as_str()) {
        return get_latest_did_document(db, &did).await;
    }

    // Cases for retrieving a specific DID doc based on selfHash or versionId
    if let Ok(did_with_query) = DIDWithQuery::from_resolution_url(host.as_str(), path.as_str()) {
        let did = did_with_query.without_query();
        if let Some(query_self_hash) = did_with_query.query_self_hash_o() {
            return get_did_document_with_self_hash(db, &did, query_self_hash.deref()).await;
        } else if let Some(query_version_id) = did_with_query.query_version_id_o() {
            return get_did_document_with_version_id(db, &did, query_version_id).await;
        } else {
            return Err((StatusCode::BAD_REQUEST, "".to_string()));
        }
    }

    // Cases for metadata
    if path.ends_with("/did/metadata.json") {
        let path = path.strip_suffix("/did/metadata.json").unwrap();
        let did = DID::from_resolution_url(host.as_str(), path)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let latest_did_document_record = DIDDocumentRecord::select_latest(&db, &did)
            .await?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        let first_did_document_record =
            DIDDocumentRecord::select_did_document(&db, &did, None, Some(0))
                .await?
                .ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "if any DID doc is present in database for a DID, then its root DID doc (version 0) is expected to be present in database"
                            .to_string(),
                    )
                })?;
        let current_did_document_metadata = DIDDocumentMetadata {
            constant_o: Some(DIDDocumentMetadataConstant {
                created: first_did_document_record.valid_from,
            }),
            idempotent_o: Some(DIDDocumentMetadataIdempotent {
                next_update_o: None,
                next_version_id_o: None,
            }),
            currency_o: Some(DIDDocumentMetadataCurrency {
                most_recent_update: latest_did_document_record.valid_from,
                most_recent_version_id: latest_did_document_record.version_id as u32,
            }),
        };
        return Ok(
            serde_json::to_string(&current_did_document_metadata).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to serialize current DID document metadata into JSON".to_string(),
                )
            })?,
        );
    } else if path.ends_with("/did/metadata/constant.json") {
        let path = path.strip_suffix("/did/metadata/constant.json").unwrap();
        let did = DID::from_resolution_url(host.as_str(), path)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let first_did_document_record =
            DIDDocumentRecord::select_did_document(&db, &did, None, Some(0))
                .await?
                .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        let current_did_document_metadata = DIDDocumentMetadata {
            constant_o: Some(DIDDocumentMetadataConstant {
                created: first_did_document_record.valid_from,
            }),
            idempotent_o: None,
            currency_o: None,
        };
        return Ok(
            serde_json::to_string(&current_did_document_metadata).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to serialize current DID document metadata into JSON".to_string(),
                )
            })?,
        );
    } else if let Some((path, filename)) = path.rsplit_once('/') {
        if !filename.ends_with(".json") {
            return Err((StatusCode::NOT_FOUND, "".to_string()));
        }
        let (did, did_document_record) = if path.ends_with("/did/metadata/selfHash") {
            let path = path.strip_suffix("/did/metadata/selfHash").unwrap();
            let did = DID::from_resolution_url(host.as_str(), path)
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let filename_self_hash_str = filename.strip_suffix(".json").unwrap();
            let did_document_record = DIDDocumentRecord::select_did_document(
                &db,
                &did,
                Some(filename_self_hash_str),
                None,
            )
            .await?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
            (did, did_document_record)
        } else if path.ends_with("/did/metadata/versionId") {
            let path = path.strip_suffix("/did/metadata/versionId").unwrap();
            let did = DID::from_resolution_url(host.as_str(), path)
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let filename_version_id_str = filename.strip_suffix(".json").unwrap();
            let filename_version_id: u32 = filename_version_id_str
                .parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let did_document_record =
                DIDDocumentRecord::select_did_document(&db, &did, None, Some(filename_version_id))
                    .await?
                    .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
            (did, did_document_record)
        } else {
            return Err((StatusCode::NOT_FOUND, "".to_string()));
        };
        let next_did_document_record_o = DIDDocumentRecord::select_did_document(
            &db,
            &did,
            None,
            Some(did_document_record.version_id as u32 + 1),
        )
        .await?;
        let first_did_document_record =
        DIDDocumentRecord::select_did_document(&db, &did, None, Some(0))
            .await?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "if any DID doc is present in database for a DID, then its root DID doc (version 0) is expected to be present in database"
                        .to_string(),
                )
            })?;
        let current_did_document_metadata = DIDDocumentMetadata {
            constant_o: Some(DIDDocumentMetadataConstant {
                created: first_did_document_record.valid_from,
            }),
            idempotent_o: Some(DIDDocumentMetadataIdempotent {
                next_update_o: next_did_document_record_o
                    .as_ref()
                    .map(|next_did_document_record| next_did_document_record.valid_from),
                next_version_id_o: next_did_document_record_o
                    .as_ref()
                    .map(|next_did_document_record| next_did_document_record.version_id as u32),
            }),
            currency_o: None,
        };
        return Ok(
            serde_json::to_string(&current_did_document_metadata).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to serialize current DID document metadata into JSON".to_string(),
                )
            })?,
        );
    }

    // If none of the cases above matched, then the path is malformed.
    Err((StatusCode::BAD_REQUEST, "".to_string()))
}

async fn get_latest_did_document(db: PgPool, did: &DID) -> Result<String, (StatusCode, String)> {
    let latest_record_o = DIDDocumentRecord::select_latest(&db, did).await?;
    match latest_record_o {
        Some(latest_did_document_record) => Ok(latest_did_document_record.did_document),
        None => Err((StatusCode::NOT_FOUND, format!("DID not found: {}", did))),
    }
}

async fn get_did_document_with_self_hash(
    db: PgPool,
    did: &DID,
    self_hash_str: &str,
) -> Result<String, (StatusCode, String)> {
    let did_document_record_o =
        DIDDocumentRecord::select_did_document(&db, did, Some(self_hash_str), None).await?;
    match did_document_record_o {
        Some(did_document_record) => Ok(did_document_record.did_document),
        None => Err((StatusCode::NOT_FOUND, "".to_string())),
    }
}

async fn get_did_document_with_version_id(
    db: PgPool,
    did: &DID,
    version_id: u32,
) -> Result<String, (StatusCode, String)> {
    let did_document_record_o =
        DIDDocumentRecord::select_did_document(&db, did, None, Some(version_id)).await?;
    match did_document_record_o {
        Some(did_document_record) => Ok(did_document_record.did_document),
        None => Err((StatusCode::NOT_FOUND, "".to_string())),
    }
}

#[tracing::instrument(err(Debug), skip(db))]
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

#[tracing::instrument(err(Debug), skip(db))]
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

    let latest_did_document_record_o = DIDDocumentRecord::select_latest(&db, &did).await?;
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
