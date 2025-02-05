use super::VDRState;
use crate::VDRConfig;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use did_webplus_core::{
    DIDDocumentMetadata, DIDDocumentMetadataConstant, DIDDocumentMetadataCurrency,
    DIDDocumentMetadataIdempotent, DIDWithQuery, DID,
};
use did_webplus_doc_store::DIDDocStore;
use tokio::task;

pub fn get_routes(did_doc_store: DIDDocStore, vdr_config: &VDRConfig) -> Router {
    let state = VDRState {
        did_doc_store,
        vdr_config: vdr_config.clone(),
    };

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
        .with_state(state)
}

#[tracing::instrument(err(Debug), skip(vdr_state))]
async fn get_did_document_or_metadata(
    State(vdr_state): State<VDRState>,
    Path(path): Path<String>,
) -> Result<String, (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did_host = vdr_state.vdr_config.did_host.as_str();

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Case for retrieving the latest DID doc.
    if let Ok(did) =
        DID::from_resolution_url(did_host, vdr_state.vdr_config.did_port_o, path.as_str())
    {
        let latest_did_doc_record = vdr_state
            .did_doc_store
            .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(latest_did_doc_record.did_document_jcs);
    }

    // Cases for retrieving a specific DID doc based on selfHash or versionId
    if let Ok(did_with_query) =
        DIDWithQuery::from_resolution_url(did_host, vdr_state.vdr_config.did_port_o, path.as_str())
    {
        let did = did_with_query.did();
        if let Some(query_self_hash) = did_with_query.query_self_hash_o() {
            let did_doc_record = vdr_state
                .did_doc_store
                .get_did_doc_record_with_self_hash(
                    Some(transaction_b.as_mut()),
                    &did,
                    query_self_hash,
                )
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
            transaction_b
                .commit()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            return Ok(did_doc_record.did_document_jcs);
        } else if let Some(query_version_id) = did_with_query.query_version_id_o() {
            let did_doc_record = vdr_state
                .did_doc_store
                .get_did_doc_record_with_version_id(
                    Some(transaction_b.as_mut()),
                    &did,
                    query_version_id,
                )
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
            transaction_b
                .commit()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            return Ok(did_doc_record.did_document_jcs);
        } else {
            return Err((StatusCode::BAD_REQUEST, "".to_string()));
        }
    }

    // Cases for metadata
    if path.ends_with("/did/metadata.json") {
        let path = path.strip_suffix("/did/metadata.json").unwrap();
        let did = DID::from_resolution_url(did_host, vdr_state.vdr_config.did_port_o, path)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let latest_did_document_record = vdr_state
            .did_doc_store
            .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        let first_did_document_record = vdr_state
            .did_doc_store
            .get_did_doc_record_with_version_id(Some(transaction_b.as_mut()), &did, 0)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "if any DID doc is present in database for a DID, then its root DID doc (version 0) is expected to be present in database"
                        .to_string(),
                )
            })?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
        return serde_json::to_string(&current_did_document_metadata).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize current DID document metadata into JSON".to_string(),
            )
        });
    } else if path.ends_with("/did/metadata/constant.json") {
        let path = path.strip_suffix("/did/metadata/constant.json").unwrap();
        let did = DID::from_resolution_url(did_host, vdr_state.vdr_config.did_port_o, path)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let first_did_document_record = vdr_state
            .did_doc_store
            .get_did_doc_record_with_version_id(Some(transaction_b.as_mut()), &did, 0)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let current_did_document_metadata = DIDDocumentMetadata {
            constant_o: Some(DIDDocumentMetadataConstant {
                created: first_did_document_record.valid_from,
            }),
            idempotent_o: None,
            currency_o: None,
        };
        return serde_json::to_string(&current_did_document_metadata).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize current DID document metadata into JSON".to_string(),
            )
        });
    } else if let Some((path, filename)) = path.rsplit_once('/') {
        if !filename.ends_with(".json") {
            return Err((StatusCode::NOT_FOUND, "".to_string()));
        }
        let (did, did_document_record) = if path.ends_with("/did/metadata/selfHash") {
            let path = path.strip_suffix("/did/metadata/selfHash").unwrap();
            let did = DID::from_resolution_url(did_host, vdr_state.vdr_config.did_port_o, path)
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let filename_self_hash_str = filename.strip_suffix(".json").unwrap();
            let filename_self_hash = selfhash::KERIHashStr::new_ref(filename_self_hash_str)
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let did_document_record = vdr_state
                .did_doc_store
                .get_did_doc_record_with_self_hash(
                    Some(transaction_b.as_mut()),
                    &did,
                    filename_self_hash,
                )
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
            (did, did_document_record)
        } else if path.ends_with("/did/metadata/versionId") {
            let path = path.strip_suffix("/did/metadata/versionId").unwrap();
            let did = DID::from_resolution_url(did_host, vdr_state.vdr_config.did_port_o, path)
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let filename_version_id_str = filename.strip_suffix(".json").unwrap();
            let filename_version_id: u32 = filename_version_id_str
                .parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let did_document_record = vdr_state
                .did_doc_store
                .get_did_doc_record_with_version_id(
                    Some(transaction_b.as_mut()),
                    &did,
                    filename_version_id,
                )
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
            (did, did_document_record)
        } else {
            return Err((StatusCode::NOT_FOUND, "".to_string()));
        };
        let next_did_document_record_o = vdr_state
            .did_doc_store
            .get_did_doc_record_with_version_id(
                Some(transaction_b.as_mut()),
                &did,
                did_document_record.version_id as u32 + 1,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let first_did_document_record = vdr_state
            .did_doc_store
            .get_did_doc_record_with_version_id(Some(transaction_b.as_mut()), &did, 0)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return serde_json::to_string(&current_did_document_metadata).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize current DID document metadata into JSON".to_string(),
            )
        });
    }

    // If none of the cases above matched, then the path is malformed.
    Err((StatusCode::BAD_REQUEST, "".to_string()))
}

#[tracing::instrument(err(Debug), skip(vdr_state))]
async fn create_did(
    State(vdr_state): State<VDRState>,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did = DID::from_resolution_url(
        vdr_state.vdr_config.did_host.as_str(),
        vdr_state.vdr_config.did_port_o,
        path.as_str(),
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;

    let root_did_document = parse_did_document(&did_document_body)?;
    if root_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the resolution URL: {} != {}",
                root_did_document.did, did
            ),
        ));
    }

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    vdr_state
        .did_doc_store
        .validate_and_add_did_doc(
            Some(transaction_b.as_mut()),
            &root_did_document,
            None,
            &did_document_body,
        )
        .await
        .map_err(|e| match e {
            did_webplus_doc_store::Error::AlreadyExists(_)
            | did_webplus_doc_store::Error::InvalidDIDDocument(_) => {
                (StatusCode::BAD_REQUEST, e.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}

#[tracing::instrument(err(Debug), skip(vdr_state))]
async fn update_did(
    State(vdr_state): State<VDRState>,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did = DID::from_resolution_url(
        vdr_state.vdr_config.did_host.as_str(),
        vdr_state.vdr_config.did_port_o,
        path.as_str(),
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;
    tracing::trace!("update_did; path: {:?}, did: {}", path, did);

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let latest_did_document_record_o = vdr_state
        .did_doc_store
        .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if latest_did_document_record_o.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("DID does not exist: {}", did),
        ));
    }
    let latest_did_document_record = latest_did_document_record_o.unwrap();

    let new_did_document = parse_did_document(&did_document_body)?;
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
        parse_did_document(&latest_did_document_record.did_document_jcs).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid DID document in storage".to_string(),
            )
        })?;

    vdr_state
        .did_doc_store
        .validate_and_add_did_doc(
            Some(transaction_b.as_mut()),
            &new_did_document,
            Some(&prev_document),
            &did_document_body,
        )
        .await
        .map_err(|e| match e {
            did_webplus_doc_store::Error::InvalidDIDDocument(_) => {
                (StatusCode::BAD_REQUEST, e.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    task::spawn(send_vdg_updates(vdr_state.vdr_config.gateways.clone(), did));

    Ok(())
}

lazy_static::lazy_static! {
    static ref VDG_CLIENT: reqwest::Client = reqwest::Client::new();
}

/// The reason this function takes its parameters by value instead of reference is because
/// it's called via task::spawn.
async fn send_vdg_updates(gateways: Vec<String>, did: DID) {
    tracing::trace!(
        "VDR; send_vdg_updates; gateways: {:?}, did: {}",
        gateways,
        did
    );
    // NOTE: We have to percent-encode the DID in the request, because there can be a percent
    // character in it, which will be automatically percent-decoded by the HTTP server.
    let percent_encoded_did = temp_hack_incomplete_percent_encoded(did.as_str());
    tracing::trace!(
        "VDR; send_vdg_updates; percent_encoded_did: {}",
        percent_encoded_did
    );
    for vdg in gateways.iter() {
        // if vdg starts with http:// or https://, then use it as is, otherwise assume https://
        let url = if vdg.starts_with("http://") || vdg.starts_with("https://") {
            format!("{}/update/{}", vdg, percent_encoded_did)
        } else {
            format!("https://{}/update/{}", vdg, percent_encoded_did)
        };
        tracing::info!("sending update to VDG {}: {}", vdg, url);
        // There is no reason to do these sequentially, so spawn a task for each one.
        let vdg = vdg.clone();
        task::spawn(async move {
            let response = VDG_CLIENT.post(&url).send().await;
            if let Err(err) = response {
                tracing::error!("error in sending update to VDG {}: {}", vdg, err);
            }
        });
    }
}

/// INCOMPLETE, TEMP HACK
fn temp_hack_incomplete_percent_encoded(s: &str) -> String {
    // Note that the '%' -> "%25" replacement must happen first.
    s.replace('%', "%25")
        .replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
}

fn parse_did_document(
    did_document_body: &str,
) -> Result<did_webplus_core::DIDDocument, (axum::http::StatusCode, String)> {
    serde_json::from_str(did_document_body).map_err(|_| {
        (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "malformed DID document".to_string(),
        )
    })
}
