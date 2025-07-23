use crate::{
    vdr_fetch_did_document_body, vdr_fetch_did_documents_jsonl, vdr_fetch_latest_did_document_body,
    verifier_resolver_impl, DIDResolver, Error, Result,
};
use did_webplus_core::{DIDStr, DIDWebplusURIComponents, DIDWithQueryStr};
use did_webplus_doc_store::{parse_did_document, DIDDocRecord, DIDDocStore};
use std::sync::Arc;

/// This is the "full" implementation of a DID resolver, which which keeps a local copy of all DID
/// documents it has fetched and verified.  This is in contrast to the "thin" implementation, which
/// outsources the retrieval and verification of DID documents to a trusted Verifiable Data Gateway (VDG).
/// A VDG can optionally be specified to forward resolution requests through, though DID documents will
/// still be locally verified and stored.  The reason for this is to ensure a broader scope-of-truth
/// for which DID updates are considered valid (all resolvers which trust the specified VDG will agree).
#[derive(Clone)]
pub struct DIDResolverFull {
    // TODO: Ideally this wouldn't be generic.
    pub did_doc_store: did_webplus_doc_store::DIDDocStore,
    // /// Optionally specifies the URL of the "resolve" endpoint of a VDG to use for DID resolution.  The URL
    // /// can omit the scheme (i.e. the "https://" portion), in which case, "https://" will be used.  The URL
    // /// must not contain a query string or fragment.
    // TODO: Implement this.
    // pub vdg_resolve_endpoint_o: Option<url::Url>,
    pub http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
    pub fetch_pattern: FetchPattern,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DIDResolver for DIDResolverFull {
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        requested_did_document_metadata: did_webplus_core::RequestedDIDDocumentMetadata,
    ) -> Result<(String, did_webplus_core::DIDDocumentMetadata)> {
        tracing::debug!(
            "DIDResolverFull::resolve_did_document_string; did_query: {}; requested_did_document_metadata: {:?}",
            did_query,
            requested_did_document_metadata
        );

        if requested_did_document_metadata.constant
            || requested_did_document_metadata.idempotent
            || requested_did_document_metadata.currency
        {
            panic!("Temporary limitation: RequestedDIDDocumentMetadata must be empty for DIDResolverFull");
        }

        use storage_traits::StorageDynT;
        let mut transaction_b = self.did_doc_store.begin_transaction().await?;
        let did_doc_record = resolve_did(
            &self.did_doc_store,
            transaction_b.as_mut(),
            did_query,
            self.http_scheme_override_o.as_ref(),
            self.fetch_pattern,
        )
        .await?;
        transaction_b.commit().await?;

        // TODO: Implement metadata
        let did_document_metadata = did_webplus_core::DIDDocumentMetadata {
            constant_o: None,
            idempotent_o: None,
            currency_o: None,
        };

        tracing::trace!(
            "DIDResolverFull::resolve_did_document_string; successfully resolved DID document: {}",
            did_doc_record.did_document_jcs
        );
        Ok((did_doc_record.did_document_jcs, did_document_metadata))
    }
    fn as_verifier_resolver(&self) -> &dyn verifier_resolver::VerifierResolver {
        self
    }
    fn as_verifier_resolver_a(self: Arc<Self>) -> Arc<dyn verifier_resolver::VerifierResolver> {
        self
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl verifier_resolver::VerifierResolver for DIDResolverFull {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn selfsign::Verifier>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}

/// TEMP HACK
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FetchPattern {
    Batch,
    Parallel,
    Serial,
}

// TODO: Probably add params for what metadata is desired
async fn resolve_did(
    did_doc_store: &DIDDocStore,
    // TODO: Use Option
    // transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
    transaction: &mut dyn storage_traits::TransactionDynT,
    did_query: &str,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    fetch_pattern: FetchPattern,
) -> Result<DIDDocRecord> {
    tracing::trace!("starting DID resolution");

    let mut query_self_hash_o = None;
    let mut query_version_id_o = None;

    // Determine which case we're handling; a DID with or without query params.
    let did_webplus_uri_components = DIDWebplusURIComponents::try_from(did_query)
        .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?;
    tracing::trace!(
        "did_webplus_uri_components: {:?}",
        did_webplus_uri_components
    );
    if did_webplus_uri_components.has_fragment() {
        return Err(Error::MalformedDIDQuery(
            "DID query contains a fragment (this is not (yet?) supported)".into(),
        ));
    }
    let did = if !did_webplus_uri_components.has_query() {
        tracing::trace!("got a plain DID to resolve, no query params: {}", did_query);
        DIDStr::new_ref(did_query)
            .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?
    } else {
        tracing::trace!("got a DID with query params: {}", did_query);
        let did_with_query = DIDWithQueryStr::new_ref(did_query)
            .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?;
        query_self_hash_o = did_with_query.query_self_hash_o();
        query_version_id_o = did_with_query.query_version_id_o();
        did_with_query.did()
    };
    tracing::trace!("DID: {:?}", did);

    // If either (or both) query param(s) are present, then it's possible it's already present in the
    // database and we can attempt to retrieve it.  Contrast with the no-query-params case, which requires
    // fetching the latest DID document from the VDR.
    if query_self_hash_o.is_some() || query_version_id_o.is_some() {
        tracing::trace!(
            "query param(s) present, attempting to retrieve DID document from database"
        );

        // There is a bit of a subtlety here, in that the query params, which act as filters on the
        // GET request, might conflict with the actual DID document.  I.e. one might ask for versionId=3
        // and selfHash=<hash> but the selfHash of version 3 might actually be different.  Thus we perform
        // the select only on one of the query params, and then check the other one after the fact.
        // versionId will be the primary filter (if present), and selfHash will be the secondary filter,
        // because versionId is more comprehensible for humans as having a particular location in the
        // DID microledger.
        let did_doc_record_o = match (query_self_hash_o.as_deref(), query_version_id_o) {
            (Some(self_hash_str), None) => {
                // If only a selfHash is present, then we simply use it to select the DID document.
                did_doc_store
                    .get_did_doc_record_with_self_hash(Some(&mut *transaction), &did, self_hash_str)
                    .await?
            }
            (self_hash_str_o, Some(version_id)) => {
                // If a versionId is present, then we can use it to select the DID document.
                let did_doc_record_o = did_doc_store
                    .get_did_doc_record_with_version_id(Some(&mut *transaction), &did, version_id)
                    .await?;
                if let Some(self_hash_str) = self_hash_str_o {
                    if let Some(did_doc_record) = did_doc_record_o.as_ref() {
                        tracing::trace!("both selfHash and versionId query params present, so now a consistency check will be performed");
                        if did_doc_record.self_hash.as_str() != self_hash_str.as_str() {
                            // Note: If there is a real signature by the DID which contains the
                            // conflicting selfHash and versionId values, then that represents a fork
                            // in the DID document, which is considered illegal and fraudulent.
                            // However, simply receiving a request with conflicting selfHash and
                            // versionId values is not necessarily fraudulent, as it doesn't
                            // constitute proof that a signature was generated against a forked DID.
                            // Perhaps there could be a way to report a forked DID.
                            return Err(Error::FailedConstraint(format!(
                                "DID document with versionId {} has selfHash {} which does not match requested selfHash {}",
                                version_id,
                                did_doc_record.self_hash,
                                self_hash_str,
                            ).into()));
                        }
                    }
                }
                did_doc_record_o
            }
            (None, None) => {
                unreachable!("programmer error");
            }
        };
        if let Some(did_doc_record) = did_doc_record_o {
            // If we do have the requested DID document record,  return it.
            tracing::trace!("requested DID document already in database");
            // Do some validation on the record to make sure it's consistent with the DID doc itself.
            // This check is a bit expensive, but it's necessary to ensure the integrity of the DID doc
            // store for now -- in particular to detect attacks on the DIDDocStore.
            did_doc_record.validate_consistency()?;
            return Ok(did_doc_record);
        } else {
            tracing::trace!("requested DID document not in database");
        }
    }

    // Check what the latest version we do have is.
    tracing::trace!("checking latest DID document version in database");
    let latest_did_doc_record_o = did_doc_store
        .get_latest_did_doc_record(Some(&mut *transaction), &did)
        .await?;
    if let Some(latest_did_doc_record) = latest_did_doc_record_o.as_ref() {
        tracing::trace!(
            "latest DID document version in database: {}",
            latest_did_doc_record.version_id
        );
    } else {
        tracing::trace!("no DID documents in database for DID {}", did);
    }
    let latest_did_doc_version_id_o = latest_did_doc_record_o
        .as_ref()
        .map(|record| record.version_id as u32);
    // Compute 1 plus the latest version_id we have, or 0 if we have none.
    let version_id_start = if let Some(latest_did_doc_record) = latest_did_doc_record_o.as_ref() {
        (latest_did_doc_record.version_id as u32)
            .checked_add(1).expect("programmer error: version_id overflow while incrementing latest version_id (this should be practically impossible)")
    } else {
        0
    };

    // Because we don't have the requested DID doc, we should fetch it and its predecessors from the VDR.
    let target_did_doc_body = match (query_self_hash_o, query_version_id_o) {
        (Some(query_self_hash), _) => {
            // A DID doc with a specific selfHash value is being requested.  selfHash always overrides
            // versionId in terms of resolution.  Thus we have to fetch the selfHash-identified DID doc,
            // then all its predecessors.
            let did_with_query = did.with_query_self_hash(query_self_hash);
            tracing::trace!(
                "fetching DID document from VDR with selfHash value {}",
                query_self_hash
            );
            vdr_fetch_did_document_body(&did_with_query, http_scheme_override_o).await?
        }
        (None, Some(version_id)) => {
            // A DID doc with the specified versionId is being requested, but no selfHash is specified.
            // We can simply retrieve the precedessors sequentially up to the specified version.
            let did_with_query = did.with_query_version_id(version_id);
            tracing::trace!(
                "fetching DID document from VDR with versionId {}",
                version_id
            );
            vdr_fetch_did_document_body(&did_with_query, http_scheme_override_o).await?
        }
        (None, None) => {
            // The VDR's latest DID doc is being requested.  We must retrieve the latest version, then
            // all its predecessors.
            tracing::trace!("fetching latest DID document from VDR");
            vdr_fetch_latest_did_document_body(&did, http_scheme_override_o).await?
        }
    };
    let target_did_document = parse_did_document(&target_did_doc_body)?;
    // Fetch predecessor DID docs from VDR.  TODO: Probably parallelize these requests with some max
    // on the number of simultaneous requests.
    let prev_did_document_body_o = latest_did_doc_record_o.map(|record| record.did_document_jcs);
    let mut prev_did_document_o = prev_did_document_body_o.map(|prev_did_document_body| {
        parse_did_document(&prev_did_document_body)
            .expect("programmer error: stored DID document should be valid JSON")
    });

    match fetch_pattern {
        FetchPattern::Batch => {
            // TODO: It would be better to be able to fetch a specific range of DID docs by versionId instead of all of them.
            let did_documents_jsonl =
                vdr_fetch_did_documents_jsonl(&did, http_scheme_override_o).await?;

            let time_start = std::time::SystemTime::now();
            // TEMP HACK -- TODO: This needs to be bounded in memory, since the version_id comes from external source and could be arbitrarily large.
            tracing::trace!(?target_did_document.version_id, ?version_id_start, "HIPPO");
            // saturating_sub is necessary because version_id_start could be bigger than target_did_document.version_id.
            let mut did_document_jcs_v = Vec::with_capacity(
                (target_did_document
                    .version_id
                    .saturating_sub(version_id_start)) as usize,
            );
            let mut did_document_v = Vec::with_capacity(
                (target_did_document
                    .version_id
                    .saturating_sub(version_id_start)) as usize,
            );
            let original_prev_did_document_o = prev_did_document_o.clone();
            // TEMP HACK: Skip all DID docs before version_id_start.
            for did_document_jcs in did_documents_jsonl
                .split('\n')
                .skip(version_id_start as usize)
            {
                let did_document = parse_did_document(did_document_jcs)?;
                // HACK: Don't handle the latest DID doc here, because it's being handled below.
                if did_document.version_id == target_did_document.version_id {
                    break;
                }
                if did_document.version_id + 1 == target_did_document.version_id {
                    prev_did_document_o = Some(did_document.clone());
                }
                did_document_jcs_v.push(did_document_jcs);
                did_document_v.push(did_document);
            }
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::info!(
                "Time taken to assemble predecessor DID documents (fetch_pattern: {:?}): {:?}",
                fetch_pattern,
                duration
            );

            // let time_start = std::time::SystemTime::now();
            did_doc_store
                .validate_and_add_did_docs(
                    Some(&mut *transaction),
                    &did_document_jcs_v,
                    &did_document_v,
                    original_prev_did_document_o.as_ref(),
                )
                .await?;
            // let duration = std::time::SystemTime::now()
            //     .duration_since(time_start)
            //     .expect("pass");
            // tracing::info!(
            //     "Time taken to store predecessor DID documents (fetch_pattern: {:?}): {:?}",
            //     fetch_pattern,
            //     duration
            // );
        }
        FetchPattern::Parallel => {
            const PARALLEL_FETCH_LIMIT: usize = 0x100;

            let time_start = std::time::SystemTime::now();
            use futures::StreamExt;
            let predecessor_did_document_body_rv =
                futures::stream::iter(version_id_start..target_did_document.version_id)
                    .map(|version_id| {
                        tracing::trace!(
                            "fetching predecessor DID document with versionId {}",
                            version_id
                        );
                        async move {
                            let did_with_query = did.with_query_version_id(version_id);
                            // Yes, this returns a future!
                            vdr_fetch_did_document_body(&did_with_query, http_scheme_override_o)
                                .await
                        }
                    })
                    .buffered(PARALLEL_FETCH_LIMIT)
                    .collect::<Vec<_>>()
                    .await;
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::info!(
                "Time taken to fetch predecessor DID documents (fetch_pattern: {:?}): {:?}",
                fetch_pattern,
                duration
            );

            // Process the validation and storage of the predecessor DID documents serially -- this likely can't be fully parallelized.
            let time_start = std::time::SystemTime::now();
            for predecessor_did_document_body_r in predecessor_did_document_body_rv.into_iter() {
                let predecessor_did_document_body = predecessor_did_document_body_r?;
                let predecessor_did_document = parse_did_document(&predecessor_did_document_body)?;
                tracing::trace!(
                    "validating and storing predecessor DID document with versionId {}",
                    predecessor_did_document.version_id
                );
                did_doc_store
                    .validate_and_add_did_doc(
                        Some(&mut *transaction),
                        &predecessor_did_document,
                        prev_did_document_o.as_ref(),
                        &predecessor_did_document_body.as_str(),
                    )
                    .await?;
                prev_did_document_o = Some(predecessor_did_document);
            }
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::info!(
                "Time taken to validate and store predecessor DID documents (fetch_pattern: {:?}): {:?}",
                fetch_pattern,
                duration
            );
        }
        FetchPattern::Serial => {
            let time_start = std::time::SystemTime::now();
            for version_id in version_id_start..target_did_document.version_id {
                tracing::trace!(
                    "fetching, validating, and storing predecessor DID document with versionId {}",
                    version_id
                );
                let did_with_query = did.with_query_version_id(version_id);
                let predecessor_did_document_body =
                    vdr_fetch_did_document_body(&did_with_query, http_scheme_override_o).await?;
                let predecessor_did_document = parse_did_document(&predecessor_did_document_body)?;
                did_doc_store
                    .validate_and_add_did_doc(
                        Some(&mut *transaction),
                        &predecessor_did_document,
                        prev_did_document_o.as_ref(),
                        predecessor_did_document_body.as_str(),
                    )
                    .await?;
                prev_did_document_o = Some(predecessor_did_document);
            }
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::info!(
                "Time taken to fetch, validate, and store predecessor DID documents (fetch_pattern: {:?}): {:?}",
                fetch_pattern,
                duration
            );
        }
    }

    // Finally, validate and store the target DID doc if necessary.
    // TODO: Need to handle forked DIDs eventually, but for now, this logic will use the first DID doc it
    // sees, which is precisely what should happen for a solo VDG (i.e. not part of a consensus cluster
    // of VDGs)
    if latest_did_doc_version_id_o.is_none()
        || *latest_did_doc_version_id_o.as_ref().unwrap() < target_did_document.version_id
    {
        tracing::trace!("validating and storing target DID document");
        did_doc_store
            .validate_and_add_did_doc(
                Some(&mut *transaction),
                &target_did_document,
                prev_did_document_o.as_ref(),
                &target_did_doc_body.as_str(),
            )
            .await?;
    }

    // Now that we have fetched, validated, and stored the target DID doc and its predecessors,
    // we can check that the target DID doc matches the query param constraints and return it.
    if let Some(self_hash_str) = query_self_hash_o.as_deref() {
        use std::ops::Deref;
        if target_did_document.self_hash().deref() != self_hash_str {
            // Note: If there is a real signature by the DID which contains the conflicting selfHash and
            // versionId values, then that represents a fork in the DID document, which is considered
            // illegal and fraudulent.  However, simply receiving a request with conflicting selfHash and
            // versionId values is not necessarily fraudulent, as it doesn't constitute proof that a
            // signature was generated against a forked DID.  Perhaps there could be a way to report a
            // forked DID.
            return Err(Error::FailedConstraint(format!(
                "DID document with versionId {} has selfHash {} which does not match requested selfHash {}",
                target_did_document.version_id,
                target_did_document.self_hash().deref(),
                self_hash_str,
            ).into()));
        }
    }
    if let Some(version_id) = query_version_id_o {
        if target_did_document.version_id != version_id {
            unreachable!("programmer error: this should not be possible");
        }
    }

    let target_did_doc_record = DIDDocRecord {
        self_hash: target_did_document.self_hash().to_string(),
        did: did.to_string(),
        version_id: target_did_document.version_id as i64,
        valid_from: target_did_document.valid_from(),
        did_document_jcs: target_did_doc_body,
    };
    Ok(target_did_doc_record)
}
