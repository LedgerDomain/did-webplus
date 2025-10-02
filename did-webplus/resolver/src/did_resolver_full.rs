use crate::{
    fetch_did_documents_jsonl_update, verifier_resolver_impl, DIDResolver, Error, HTTPError, Result,
};
use did_webplus_core::{DIDStr, DIDURIComponents, DIDWithQueryStr};
use did_webplus_doc_store::{parse_did_document, DIDDocRecord};
use std::sync::Arc;

/// This is the "full" implementation of a DID resolver, which which keeps a local copy of all DID
/// documents it has fetched and verified.  This is in contrast to the "thin" implementation, which
/// outsources the retrieval and verification of DID documents to a trusted Verifiable Data Gateway (VDG).
/// A VDG can optionally be specified to forward resolution requests through, though DID documents will
/// still be locally verified and stored.  The reason for this is to ensure a broader scope-of-truth
/// for which DID updates are considered valid (all resolvers which use the specified VDG will agree).
#[derive(Clone)]
pub struct DIDResolverFull {
    did_doc_store: did_webplus_doc_store::DIDDocStore,
    /// Optionally specifies the "base" URL of a VDG to use for fetching DID documents.  This is used
    /// so that this resolver can take part in the scope of agreement defined by the VDG.  Without
    /// using a VDG, a DIDResolverFull has a scope of agreement that only contains itself.
    vdg_base_url_o: Option<url::Url>,
    http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
}

impl DIDResolverFull {
    pub fn new(
        did_doc_store: did_webplus_doc_store::DIDDocStore,
        vdg_host_o: Option<&str>,
        http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<Self> {
        let vdg_base_url_o = if let Some(vdg_host) = vdg_host_o {
            let http_scheme =
                did_webplus_core::HTTPSchemeOverride::default_http_scheme_for_host(vdg_host)
                    .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
            let vdg_base_url = url::Url::parse(&format!("{}://{}", http_scheme, vdg_host))
                .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
            Some(vdg_base_url)
        } else {
            None
        };
        Ok(Self {
            did_doc_store,
            vdg_base_url_o,
            http_scheme_override_o,
        })
    }
    /// NOTE: Currently, if vdg_base_url_o is Some, then the VDG is used for fetching DID documents, which is not
    /// necessarily the fastest way to fetch+verify+store DID documents.  A better solution would be to have the
    /// VDG stream DID documents, so that the DIDResolverFull can fetch+verify+store them in parallel.
    /// The second bool-typed return value indicates whether the DID document was resolved locally or not.
    // TODO: Probably add params for what metadata is desired
    // TODO: If certain metadata is requested, then we would have to guarantee fetching the latest DID document.
    pub async fn resolve_did_doc_record(
        &self,
        // TODO: Use Option
        // transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        transaction: &mut dyn storage_traits::TransactionDynT,
        did_query: &str,
    ) -> Result<(DIDDocRecord, bool)> {
        tracing::trace!("starting DID resolution");

        let mut query_self_hash_o = None;
        let mut query_version_id_o = None;

        // Determine which case we're handling; a DID with or without query params.
        let did_uri_components = DIDURIComponents::try_from(did_query)
            .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?;
        tracing::trace!("did_uri_components: {:?}", did_uri_components);
        if did_uri_components.has_fragment() {
            return Err(Error::MalformedDIDQuery(
                "DID query contains a fragment (this is not (yet?) supported)".into(),
            ));
        }
        let did = if !did_uri_components.has_query() {
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
        // fetching all DID updates from the VDR.
        if query_self_hash_o.is_some() || query_version_id_o.is_some() {
            tracing::trace!("at least one query param present (query_self_hash_o: {:?}, query_version_id_o: {:?}), attempting to retrieve DID document from database", query_self_hash_o, query_version_id_o);
            let did_doc_record_o = self
                .get_did_doc_record_with_self_hash_or_version_id(
                    Some(&mut *transaction),
                    &did,
                    query_self_hash_o.as_deref(),
                    query_version_id_o,
                )
                .await?;
            if let Some(did_doc_record) = did_doc_record_o {
                tracing::trace!("requested DID document already in database");
                return Ok((did_doc_record, true));
            } else {
                tracing::trace!("requested DID document not in database");
            }
        }

        // Check what the latest version we do have is.
        tracing::trace!("checking latest DID document version in database");
        let latest_did_doc_record_o = self
            .did_doc_store
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

        let latest_did_document_o = latest_did_doc_record_o
            .as_ref()
            .map(|record| parse_did_document(&record.did_document_jcs))
            .transpose()?;

        // We need to track the octet_length of did-documents.jsonl, based on what we already have.
        let mut known_did_documents_jsonl_octet_length = latest_did_doc_record_o
            .as_ref()
            .map(|record| record.did_documents_jsonl_octet_length)
            .unwrap_or(0) as u64;

        // Because we don't have the requested DID doc, we should fetch all updates from the VDR/VDG.
        {
            let did_documents_jsonl_update = fetch_did_documents_jsonl_update(
                &did,
                self.vdg_base_url_o.as_ref(),
                self.http_scheme_override_o.as_ref(),
                known_did_documents_jsonl_octet_length,
            )
            .await?;
            // Trim whitespace off the end (typically a newline)
            let did_documents_jsonl_update_str = did_documents_jsonl_update.trim_end();
            tracing::trace!(
                ?did_documents_jsonl_update_str,
                "got did-documents.jsonl update"
            );

            let time_start = std::time::SystemTime::now();
            // TEMP HACK: Collate it all into memory
            // TODO: This needs to be bounded in memory, since the version_id comes from external
            // source and could be arbitrarily large.
            let mut did_document_jcs_v = Vec::new();
            let mut did_document_v = Vec::new();
            let original_prev_did_document_o = latest_did_document_o.clone();
            if !did_documents_jsonl_update_str.is_empty() {
                for did_document_jcs in did_documents_jsonl_update_str.split('\n') {
                    tracing::trace!(?did_document_jcs, "parsing did_document_jcs");
                    let did_document = parse_did_document(did_document_jcs)?;
                    tracing::trace!(?did_document, "parsed did_document");
                    did_document_jcs_v.push(did_document_jcs);
                    did_document_v.push(did_document);
                    known_did_documents_jsonl_octet_length += did_document_jcs.len() as u64 + 1;
                }
            }
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::debug!(
                "Time taken to assemble predecessor DID documents (vdg_base_url_o: {:?}): {:?}",
                self.vdg_base_url_o.as_ref().map(|url| url.as_str()),
                duration
            );

            tracing::trace!(
                ?did_document_jcs_v,
                ?did_document_v,
                ?original_prev_did_document_o,
                "validating and storing predecessor DID documents"
            );

            self.did_doc_store
                .validate_and_add_did_docs(
                    Some(&mut *transaction),
                    &did_document_jcs_v,
                    &did_document_v,
                    original_prev_did_document_o.as_ref(),
                )
                .await?;
        }

        // Now that we have fetched, validated, and stored the target DID doc and its predecessors,
        // we can check that the target DID doc matches the query param constraints and return it.
        if query_self_hash_o.is_some() || query_version_id_o.is_some() {
            let did_doc_record_o = self
                .get_did_doc_record_with_self_hash_or_version_id(
                    Some(&mut *transaction),
                    &did,
                    query_self_hash_o.as_deref(),
                    query_version_id_o,
                )
                .await?;
            if let Some(did_doc_record) = did_doc_record_o {
                tracing::trace!("requested DID document was found in database after fetching all DID updates from VDR; returning it now");
                Ok((did_doc_record, false))
            } else {
                tracing::trace!("requested DID document was NOT found in database even after fetching all DID updates from VDR");
                Err(Error::DIDResolutionFailure(HTTPError {
                    status_code: reqwest::StatusCode::NOT_FOUND,
                    description: std::borrow::Cow::Owned(format!("DID resolution for {} failed even after fetching all DID updates from the VDR", did)),
                }))
            }
        } else {
            // Return the latest DID document.
            let latest_did_doc_record_o = self
                .did_doc_store
                .get_latest_did_doc_record(Some(&mut *transaction), &did)
                .await?
                .ok_or_else(|| Error::DIDResolutionFailure(HTTPError {
                    status_code: reqwest::StatusCode::NOT_FOUND,
                    description: std::borrow::Cow::Owned(format!("DID resolution for {} failed even after fetching all DID updates from the VDR", did)),
                }))?;
            Ok((latest_did_doc_record_o, false))
        }
    }
    async fn get_did_doc_record_with_self_hash_or_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        query_self_hash_o: Option<&mbx::MBHashStr>,
        query_version_id_o: Option<u32>,
    ) -> Result<Option<DIDDocRecord>> {
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
                self.did_doc_store
                    .get_did_doc_record_with_self_hash(transaction_o, &did, self_hash_str)
                    .await?
            }
            (self_hash_str_o, Some(version_id)) => {
                // If a versionId is present, then we can use it to select the DID document.
                let did_doc_record_o = self
                    .did_doc_store
                    .get_did_doc_record_with_version_id(transaction_o, &did, version_id)
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
            Ok(Some(did_doc_record))
        } else {
            tracing::trace!("requested DID document not in database");
            Ok(None)
        }
    }
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
        let (did_doc_record, _was_resolved_locally) = self
            .resolve_did_doc_record(transaction_b.as_mut(), did_query)
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
    ) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}
