use crate::{parse_did_document, DIDDocRecord, DIDDocRecordFilter, DIDDocStorage, Result};
use did_webplus_core::{DIDDocument, DIDStr};
use std::sync::Arc;

#[derive(Clone)]
pub struct DIDDocStore {
    did_doc_storage_a: Arc<dyn DIDDocStorage>,
}

impl DIDDocStore {
    /// Create a new DIDDocStore using the given DIDDocStorage implementation.
    pub fn new(did_doc_storage_a: Arc<dyn DIDDocStorage>) -> Self {
        Self { did_doc_storage_a }
    }
    // NOTE: did_document and did_document_jcs are redundant, and this assumes that they're consistent.
    pub async fn validate_and_add_did_doc(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        prev_did_document_o: Option<&DIDDocument>,
        did_document_jcs: &str,
    ) -> Result<()> {
        debug_assert_eq!(
            parse_did_document(did_document_jcs)?,
            *did_document,
            "programmer error: body and did_document are inconsistent"
        );
        // This assumes that all stored DID documents have been validated inductively from the root!
        did_document.verify_nonrecursive(prev_did_document_o)?;
        self.did_doc_storage_a
            .add_did_document(transaction_o, did_document, did_document_jcs)
            .await?;
        Ok(())
    }
    // TEMP HACK
    pub async fn validate_and_add_did_docs(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document_jcs_v: &[&str],
        did_document_v: &[DIDDocument],
        prev_did_document_o: Option<&DIDDocument>,
    ) -> Result<()> {
        assert_eq!(did_document_jcs_v.len(), did_document_v.len());
        if did_document_jcs_v.is_empty() {
            // Nothing to do!
            return Ok(());
        }

        // This assumes that all stored DID documents have been validated inductively from the root!
        let time_start = std::time::SystemTime::now();
        let prev_did_document_oi = std::iter::once(prev_did_document_o).chain(
            did_document_v[..did_document_v.len().checked_sub(1).unwrap()]
                .iter()
                .map(|did_document| Some(did_document)),
        );

        // Parallelize the validation of the sequence of DID documents.
        let handle_v = did_document_jcs_v
            .iter()
            .zip(did_document_v.iter())
            .zip(prev_did_document_oi)
            .map(|((&_did_document_jcs, did_document), prev_did_document_o)| {
                // TEMP HACK -- copying is not ideal.  Figure out how to do this without copying.
                // Maybe re-borrowing.
                let prev_did_document_o = prev_did_document_o.cloned();
                let did_document = did_document.clone();
                tokio::spawn(async move {
                    // debug_assert_eq!(
                    //     parse_did_document(did_document_jcs),
                    //     *did_document,
                    //     "programmer error: body and did_document are inconsistent"
                    // );
                    tracing::trace!(
                        "validating and storing predecessor DID document with versionId {}; prev_did_document_o versionId: {:?}",
                        did_document.version_id(),
                        prev_did_document_o.as_ref().map(|did_document| did_document.version_id())
                    );
                    did_document.verify_nonrecursive(prev_did_document_o.as_ref()).map(|_keri_hash| ())
                })
            }).collect::<Vec<_>>();
        let result_v = futures::future::join_all(handle_v).await;
        for result in result_v {
            // TEMP HACK -- handle errors properly
            result.unwrap().unwrap();
        }

        // for ((&did_document_jcs, did_document), prev_did_document_o) in did_document_jcs_v
        //     .iter()
        //     .zip(did_document_v.iter())
        //     .zip(prev_did_document_oi)
        // {
        //     debug_assert_eq!(
        //         parse_did_document(did_document_jcs)?,
        //         *did_document,
        //         "programmer error: body and did_document are inconsistent"
        //     );
        //     tracing::trace!(
        //         "validating and storing predecessor DID document with versionId {}; prev_did_document_o versionId: {:?}",
        //         did_document.version_id(),
        //         prev_did_document_o.map(|did_document| did_document.version_id())
        //     );
        //     let time_start = std::time::SystemTime::now();
        //     did_document.verify_nonrecursive(prev_did_document_o)?;
        //     let duration = std::time::SystemTime::now()
        //         .duration_since(time_start)
        //         .expect("pass");
        //     tracing::info!(
        //         "Time taken to validate predecessor DID document with versionId {}: {:?}",
        //         did_document.version_id(),
        //         duration
        //     );
        //     // prev_did_document_o = Some(did_document);
        // }

        let duration = std::time::SystemTime::now()
            .duration_since(time_start)
            .expect("pass");
        tracing::info!(
            "Time taken to validate predecessor DID documents: {:?}",
            duration
        );

        let time_start = std::time::SystemTime::now();
        self.did_doc_storage_a
            .add_did_documents(transaction_o, did_document_jcs_v, did_document_v)
            .await?;
        let duration = std::time::SystemTime::now()
            .duration_since(time_start)
            .expect("pass");
        tracing::info!("Time taken to store DID documents: {:?}", duration);
        Ok(())
    }
    pub async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_did_doc_record_with_self_hash(transaction_o, did, self_hash)
            .await
    }
    pub async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_did_doc_record_with_version_id(transaction_o, did, version_id)
            .await
    }
    pub async fn get_latest_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_latest_did_doc_record(transaction_o, did)
            .await
    }
    // TEMP HACK
    pub async fn get_all_did_doc_records(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Vec<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_did_doc_records(
                transaction_o,
                &DIDDocRecordFilter {
                    did_o: Some(did.to_string()),
                    self_hash_o: None,
                    version_id_o: None,
                },
            )
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for DIDDocStore {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        self.did_doc_storage_a.begin_transaction().await
    }
}
