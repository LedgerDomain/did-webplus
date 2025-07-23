use crate::{VDRAppState, VDRConfig};
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
    let state = VDRAppState {
        did_doc_store,
        vdr_config: vdr_config.clone(),
    };

    Router::new()
        .route(
            // We have to do our own URL processing in each handler because of the non-standard
            // form of the "query" (e.g. did.selfHash=<hash>.json) and the fact that we're using
            // the same handler for multiple routes.
            "/{*path}",
            get(get_did_document_or_metadata)
                .post(create_did)
                .put(update_did),
        )
        .with_state(state)
}

#[tracing::instrument(level = tracing::Level::INFO, ret(level = tracing::Level::DEBUG, Display), err(Debug), skip(vdr_app_state))]
async fn get_did_document_or_metadata(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
) -> Result<String, (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did_hostname = vdr_app_state.vdr_config.did_hostname.as_str();

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Case for retrieving did-documents.jsonl (i.e. all DID docs concatenated into a single JSONL file)
    if let Ok(did) = DID::from_did_documents_jsonl_resolution_url(
        did_hostname,
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        tracing::debug!(
            ?did,
            "retrieving all DID docs concatenated into a single JSONL file"
        );
        let did_doc_records = vdr_app_state
            .did_doc_store
            .get_all_did_doc_records(Some(transaction_b.as_mut()), &did)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Now print all the DID documents into the response, separated by newlines.
        let did_document_jcs_v = did_doc_records
            .into_iter()
            .map(|did_doc_record| did_doc_record.did_document_jcs)
            .collect::<Vec<_>>();
        let did_document_jsonl = did_document_jcs_v.join("\n");
        return Ok(did_document_jsonl);
    }

    // Case for retrieving the latest DID doc.
    if let Ok(did) = DID::from_resolution_url(
        did_hostname,
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        tracing::debug!(?did, "retrieving latest DID doc");
        let latest_did_doc_record = vdr_app_state
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
    if let Ok(did_with_query) = DIDWithQuery::from_resolution_url(
        did_hostname,
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        tracing::debug!(
            ?did_with_query,
            "retrieving specific DID doc based on selfHash or versionId"
        );
        let did = did_with_query.did();
        if let Some(query_self_hash) = did_with_query.query_self_hash_o() {
            let did_doc_record = vdr_app_state
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
            let did_doc_record = vdr_app_state
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
        tracing::debug!("retrieving latest DID doc metadata");
        let path = path.strip_suffix("/did/metadata.json").unwrap();
        let did = DID::from_resolution_url(did_hostname, vdr_app_state.vdr_config.did_port_o, path)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let latest_did_document_record = vdr_app_state
            .did_doc_store
            .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        let first_did_document_record = vdr_app_state
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
        tracing::debug!("retrieving 'constant' DID doc metadata");
        let path = path.strip_suffix("/did/metadata/constant.json").unwrap();
        let did = DID::from_resolution_url(did_hostname, vdr_app_state.vdr_config.did_port_o, path)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let first_did_document_record = vdr_app_state
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
        tracing::debug!(
            ?path,
            ?filename,
            "retrieving 'selfHash' or 'versionId' DID doc metadata"
        );
        if !filename.ends_with(".json") {
            return Err((StatusCode::NOT_FOUND, "".to_string()));
        }
        let (did, did_document_record) = if path.ends_with("/did/metadata/selfHash") {
            let path = path.strip_suffix("/did/metadata/selfHash").unwrap();
            let did =
                DID::from_resolution_url(did_hostname, vdr_app_state.vdr_config.did_port_o, path)
                    .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let filename_self_hash_str = filename.strip_suffix(".json").unwrap();
            let filename_self_hash = selfhash::KERIHashStr::new_ref(filename_self_hash_str)
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let did_document_record = vdr_app_state
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
            let did =
                DID::from_resolution_url(did_hostname, vdr_app_state.vdr_config.did_port_o, path)
                    .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let filename_version_id_str = filename.strip_suffix(".json").unwrap();
            let filename_version_id: u32 = filename_version_id_str
                .parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
            let did_document_record = vdr_app_state
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
        let next_did_document_record_o = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_version_id(
                Some(transaction_b.as_mut()),
                &did,
                did_document_record.version_id as u32 + 1,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let first_did_document_record = vdr_app_state
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

#[tracing::instrument(ret(Debug), err(Debug), skip(vdr_app_state, did_document_body))]
async fn create_did(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;

    tracing::debug!(?did);

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
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    vdr_app_state
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

#[tracing::instrument(ret(Debug), err(Debug), skip(vdr_app_state, did_document_body))]
async fn update_did(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;
    tracing::debug!(?path, ?did);

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let latest_did_document_record_o = vdr_app_state
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

    vdr_app_state
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

    // TODO: Is there any reason to wait for this to complete, e.g. to ensure that all VDG updates succeeded?
    task::spawn(send_vdg_updates(
        vdr_app_state.vdr_config.gateway_url_v.clone(),
        did,
    ));

    Ok(())
}

lazy_static::lazy_static! {
    static ref VDG_CLIENT: reqwest::Client = reqwest::Client::new();
}

/// The reason this function takes its parameters by value instead of reference is because
/// it's called via task::spawn.  Note that errors here do not propagate back to the spawner,
/// and the client won't be aware that there was an error.  It's probably worth queue'ing these
/// updates and retrying them if they fail, with some retry schedule and eventually give up
/// after a certain number of retries, logging that fact.
#[tracing::instrument(level = tracing::Level::DEBUG, ret(Debug), err(Debug), skip(gateway_url_v))]
async fn send_vdg_updates(
    gateway_url_v: Vec<url::Url>,
    did: DID,
) -> anyhow::Result<Vec<(url::Url, reqwest::Result<reqwest::Response>)>> {
    tracing::trace!(
        gateway_url_v = ?gateway_url_v,
        did = ?did,
        "VDR; send_vdg_updates"
    );
    // NOTE: We have to percent-encode the DID in the request, because there can be a percent
    // character in it, which will be automatically percent-decoded by the HTTP server.
    let percent_encoded_did = temp_hack_incomplete_percent_encoded(did.as_str());
    tracing::trace!(
        "VDR; send_vdg_updates; percent_encoded_did: {}",
        percent_encoded_did
    );
    let mut join_set = tokio::task::JoinSet::new();
    for gateway_url in gateway_url_v.iter() {
        // Form the specific URL to POST to.
        let update_url = gateway_url
            .join(&format!("/update/{}", percent_encoded_did))
            .unwrap();
        tracing::info!("POST-ing update to VDG: {}", update_url);
        // There is no reason to do these sequentially, so spawn a task for each one.
        join_set.spawn(async move {
            let result = VDG_CLIENT
                .post(update_url.as_str())
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        "error in POST-ing update to VDG: {}; error was: {}",
                        update_url,
                        err
                    );
                    err
                });
            (update_url, result)
        });
    }
    // Wait for all the tasks to complete, then return their results.
    Ok(join_set.join_all().await)
}

/// INCOMPLETE, TEMP HACK -- TODO: use percent-encoding crate
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
