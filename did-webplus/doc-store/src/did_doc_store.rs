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

        const USE_PARALLEL_VALIDATION: bool = true;

        if USE_PARALLEL_VALIDATION {
            // Parallelize the validation of the sequence of DID documents.
            let handle_v = did_document_jcs_v
                .iter()
                .zip(did_document_v.iter())
                .zip(prev_did_document_oi)
                .map(|((&_did_document_jcs, did_document), prev_did_document_o)| {
                    // TEMP HACK -- copying is not ideal.  Figure out how to do this without copying.
                    // Maybe re-borrowing?  It would need to be aware of a lifetime that ends at the call to join_all.
                    let prev_did_document_o = prev_did_document_o.cloned();
                    let did_document = did_document.clone();
                    tokio::task::spawn(async move {
                        let validate_r = did_document.verify_nonrecursive(prev_did_document_o.as_ref()).map(|_keri_hash| ());
                        tracing::trace!("validating predecessor DID document with versionId {}; prev_did_document_o versionId: {:?}; result: {:?}", did_document.version_id, prev_did_document_o.as_ref().map(|did_document| did_document.version_id), validate_r);
                        validate_r
                    })
                }).collect::<Vec<_>>();
            let result_v = futures::future::join_all(handle_v).await;
            for result in result_v {
                // TEMP HACK -- handle errors properly
                result.unwrap().unwrap();
            }
        } else {
            // Serial validation.
            for ((&did_document_jcs, did_document), prev_did_document_o) in did_document_jcs_v
                .iter()
                .zip(did_document_v.iter())
                .zip(prev_did_document_oi)
            {
                debug_assert_eq!(
                    parse_did_document(did_document_jcs)?,
                    *did_document,
                    "programmer error: body and did_document are inconsistent"
                );
                tracing::trace!(
                "validating and storing predecessor DID document with versionId {}; prev_did_document_o versionId: {:?}",
                did_document.version_id,
                prev_did_document_o.map(|did_document| did_document.version_id)
            );
                let time_start = std::time::SystemTime::now();
                did_document.verify_nonrecursive(prev_did_document_o)?;
                let duration = std::time::SystemTime::now()
                    .duration_since(time_start)
                    .expect("pass");
                tracing::info!(
                    "Time taken to validate predecessor DID document with versionId {}: {:?}",
                    did_document.version_id,
                    duration
                );
                // prev_did_document_o = Some(did_document);
            }
        }

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
        self_hash: &mbc::MBHashStr,
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
    pub async fn get_known_did_documents_jsonl_octet_length(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<u64> {
        self.did_doc_storage_a
            .get_known_did_documents_jsonl_octet_length(transaction_o, did)
            .await
    }
    pub async fn get_did_documents_jsonl_range(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> Result<String> {
        let did_doc_record_v = self
            .did_doc_storage_a
            .get_did_doc_records_for_did_documents_jsonl_range(
                transaction_o,
                did,
                range_begin_inclusive_o,
                range_end_exclusive_o,
            )
            .await?;

        if did_doc_record_v.is_empty() {
            // Requested range is empty.
            return Ok(String::new());
        }

        let range_begin_inclusive = range_begin_inclusive_o.map(|x| x as i64).unwrap_or(0);
        let range_end_exclusive = range_end_exclusive_o.map(|x| x as i64).unwrap_or(i64::MAX);

        let last_did_doc_record_did_documents_jsonl_octet_length = did_doc_record_v
            .last()
            .unwrap()
            .did_documents_jsonl_octet_length;

        // Compute (an upper bound for) the capacity of the string to be returned.
        let capacity = {
            let first_did_doc_record = did_doc_record_v.first().unwrap();
            let last_did_doc_record = did_doc_record_v.last().unwrap();
            last_did_doc_record.did_documents_jsonl_octet_length
                - (first_did_doc_record.did_documents_jsonl_octet_length
                    - first_did_doc_record.did_document_jcs.len() as i64
                    + 1)
        };
        assert!(capacity >= 0);

        let mut did_documents_jsonl_range = String::with_capacity(capacity as usize);
        for did_doc_record in did_doc_record_v.into_iter() {
            let mut segment = did_doc_record.did_document_jcs;

            // Append the newline.
            segment.push('\n');

            // The previous did-documents.jsonl file ended at this octet length.
            let previous_did_document_jcs_octet_length =
                did_doc_record.did_documents_jsonl_octet_length - (segment.len() as i64);
            assert!(previous_did_document_jcs_octet_length >= 0);

            if range_end_exclusive < did_doc_record.did_documents_jsonl_octet_length {
                assert!(range_end_exclusive > previous_did_document_jcs_octet_length, "if this assertion fails, then get_did_doc_records_for_did_documents_jsonl_range returned more DIDDocRecord-s (at the end) than necessary");
                // If appropriate, truncate the end of did_document_jcs because the range doesn't include it.
                segment.truncate(
                    (range_end_exclusive - previous_did_document_jcs_octet_length) as usize,
                );
            }
            if range_begin_inclusive > previous_did_document_jcs_octet_length {
                assert!(range_begin_inclusive < did_doc_record.did_documents_jsonl_octet_length, "if this assertion fails, then get_did_doc_records_for_did_documents_jsonl_range returned more DIDDocRecord-s (at the beginning) than necessary");
                // If appropriate, truncate the beginning of did_document_jcs because the range doesn't include it.
                segment.drain(
                    0..(range_begin_inclusive - previous_did_document_jcs_octet_length) as usize,
                );
            }
            did_documents_jsonl_range.push_str(&segment);
        }

        // Sanity checks
        assert!(
            did_documents_jsonl_range.len()
                <= (range_end_exclusive - range_begin_inclusive) as usize
        );
        match (range_begin_inclusive_o, range_end_exclusive_o) {
            (Some(range_begin_inclusive), Some(range_end_exclusive)) => {
                assert!(range_begin_inclusive <= range_end_exclusive);
                let range_length = range_end_exclusive - range_begin_inclusive;
                assert!(did_documents_jsonl_range.len() == range_length as usize);
            }
            (Some(range_begin_inclusive), None) => {
                assert!(
                    did_documents_jsonl_range.len()
                        == (last_did_doc_record_did_documents_jsonl_octet_length as u64
                            - range_begin_inclusive) as usize
                );
            }
            (None, Some(range_end_exclusive)) => {
                assert!(did_documents_jsonl_range.len() == range_end_exclusive as usize);
            }
            (None, None) => {
                assert!(
                    did_documents_jsonl_range.len()
                        == last_did_doc_record_did_documents_jsonl_octet_length as usize
                );
            }
        }

        Ok(did_documents_jsonl_range)
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
