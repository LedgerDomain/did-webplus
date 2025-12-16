use crate::{VDRAppState, VDRConfig};
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use did_webplus_core::DID;
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
            // form of the "query" (a catch-all path ending with "/did-documents.jsonl").
            "/{*path}",
            get(get_did_documents_jsonl)
                .post(create_did)
                .put(update_did),
        )
        .with_state(state)
}

#[tracing::instrument(level = tracing::Level::INFO, err(Debug), skip(vdr_app_state))]
async fn get_did_documents_jsonl(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
    header_map: HeaderMap,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    // Try to retrieve did-documents.jsonl (i.e. all DID docs concatenated into a single JSONL file)
    if let Ok(did) = DID::from_did_documents_jsonl_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        get_did_document_jsonl_impl(State(vdr_app_state), header_map, did).await
    } else {
        Err((StatusCode::BAD_REQUEST, "".to_string()))
    }
}

// NOTE: This is duplicated in did-webplus-vdg-lib crate.  In order to de-duplicate, there would need to be
// an axum-aware crate common to this and that crate.
async fn get_did_document_jsonl_impl(
    State(vdr_app_state): State<VDRAppState>,
    header_map: HeaderMap,
    did: DID,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(
        ?did,
        "retrieving all DID docs concatenated into a single JSONL file; header_map: {:?}",
        header_map
    );

    let mut response_header_map = HeaderMap::new();
    response_header_map.insert("Content-Type", "application/jsonl".parse().unwrap());

    if let Some(range_header) = header_map.get(header::RANGE) {
        // Parse the "Range" header, if present, and then handle.

        let time_start = std::time::SystemTime::now();

        tracing::debug!("Range header: {:?}", range_header);
        let range_header_str = range_header.to_str().unwrap();
        if !range_header_str.starts_with("bytes=") {
            return Err((
                StatusCode::BAD_REQUEST,
                "Malformed Range header -- expected it to begin with 'bytes='".to_string(),
            ));
        }
        let range_header_str = range_header_str.strip_prefix("bytes=").unwrap();
        let (range_start_str, range_end_str) = range_header_str.split_once('-').unwrap();
        let range_begin_inclusive_o = if range_start_str.is_empty() {
            None
        } else {
            Some(range_start_str.parse::<u64>().unwrap())
        };
        let range_end_inclusive_o = if range_end_str.is_empty() {
            None
        } else {
            Some(range_end_str.parse::<u64>().unwrap())
        };
        let range_end_exclusive_o = range_end_inclusive_o.map(|x| x + 1);

        use storage_traits::StorageDynT;
        let mut transaction_b = vdr_app_state
            .did_doc_store
            .begin_transaction()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let did_documents_jsonl_range = vdr_app_state
            .did_doc_store
            .get_did_documents_jsonl_range(
                Some(transaction_b.as_mut()),
                &did,
                range_begin_inclusive_o,
                range_end_exclusive_o,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        response_header_map.insert(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                range_start_str,
                range_end_str,
                did_documents_jsonl_range.len()
            )
            .parse()
            .unwrap(),
        );

        let duration = time_start.elapsed().unwrap();
        tracing::debug!(
            "retrieved range `{}` of did-documents.jsonl in {:?}",
            range_header_str,
            duration
        );

        return Ok((response_header_map, did_documents_jsonl_range));
    } else {
        // No Range header present, so serve the whole did-documents.jsonl file.

        let time_start = std::time::SystemTime::now();

        use storage_traits::StorageDynT;
        let mut transaction_b = vdr_app_state
            .did_doc_store
            .begin_transaction()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let did_documents_jsonl = vdr_app_state
            .did_doc_store
            .get_did_documents_jsonl_range(Some(transaction_b.as_mut()), &did, None, None)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let duration = time_start.elapsed().unwrap();
        tracing::debug!(
            "retrieved entire did-documents.jsonl file in {:?}",
            duration
        );

        return Ok((response_header_map, did_documents_jsonl));
    }
}

#[tracing::instrument(ret(Debug), err(Debug), skip(vdr_app_state, did_document_body))]
async fn create_did(
    State(vdr_app_state): State<VDRAppState>,
    header_map: HeaderMap,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    vdr_app_state.verify_authorization(&header_map)?;

    let did = DID::from_did_documents_jsonl_resolution_url(
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
    tracing::trace!(
        "received request to create DID using DID document: {}",
        did_document_body
    );

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

    // TODO: Is there any reason to wait for this to complete, e.g. to ensure that all VDG updates succeeded?
    task::spawn(send_vdg_updates(
        vdr_app_state.vdr_config.vdg_base_url_v.clone(),
        did,
        root_did_document.version_id,
    ));

    Ok(())
}

#[tracing::instrument(ret(Debug), err(Debug), skip(vdr_app_state, did_document_body))]
async fn update_did(
    State(vdr_app_state): State<VDRAppState>,
    header_map: HeaderMap,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    vdr_app_state.verify_authorization(&header_map)?;

    let did = DID::from_did_documents_jsonl_resolution_url(
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
    tracing::trace!("did_document_body: {}", did_document_body);
    tracing::trace!(
        "did_document_body JCS: {}",
        serde_json_canonicalizer::pipe(&did_document_body).unwrap()
    );

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let latest_did_document_record_o = vdr_app_state
        .did_doc_store
        .get_latest_known_did_doc_record(Some(transaction_b.as_mut()), &did)
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
        vdr_app_state.vdr_config.vdg_base_url_v.clone(),
        did,
        new_did_document.version_id,
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
#[tracing::instrument(level = tracing::Level::DEBUG, ret(Debug), err(Debug), skip(vdg_base_url_v))]
async fn send_vdg_updates(
    vdg_base_url_v: Vec<url::Url>,
    did: DID,
    new_version_id: u32,
) -> anyhow::Result<Vec<(url::Url, reqwest::Result<reqwest::Response>)>> {
    tracing::trace!(?vdg_base_url_v, ?did, "VDR; send_vdg_updates");
    let mut join_set = tokio::task::JoinSet::new();
    for vdg_base_url in vdg_base_url_v.iter() {
        // Form the specific URL to POST to.
        let mut update_url = vdg_base_url.clone();
        update_url.path_segments_mut().unwrap().push("webplus");
        update_url.path_segments_mut().unwrap().push("v1");
        update_url.path_segments_mut().unwrap().push("update");
        // Note that `push` will percent-encode did_query!
        update_url.path_segments_mut().unwrap().push(did.as_str());
        tracing::debug!(
            "VDR notifying VDG of DID update (new versionId: {}): {}",
            new_version_id,
            update_url
        );
        // There is no reason to do these sequentially, so spawn a task for each one.
        join_set.spawn(async move {
            let result = VDG_CLIENT
                .post(update_url.as_str())
                .send()
                .await;
            match &result {
                Ok(_) => {
                    tracing::debug!("success in VDR notifying VDG of DID update (new versionId: {}): {}", new_version_id, update_url);
                }
                Err(err) => {
                    tracing::error!(
                        "error in VDR notifying VDG of DID update (new versionId: {}): {}; error was: {}",
                        new_version_id,
                        update_url,
                        err
                    );
                }
            }
            (update_url, result)
        });
    }
    // Wait for all the tasks to complete, then return their results.
    Ok(join_set.join_all().await)
}

fn parse_did_document(
    did_document_body: &str,
) -> Result<did_webplus_core::DIDDocument, (axum::http::StatusCode, String)> {
    let did_document = serde_json::from_str::<did_webplus_core::DIDDocument>(did_document_body)
        .map_err(|e| {
            tracing::error!(?e, "error parsing DID document");
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                format!("malformed DID document: {}", e),
            )
        })?;
    did_document
        .verify_is_canonically_serialized(did_document_body)
        .map_err(|e| (axum::http::StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(did_document)
}
