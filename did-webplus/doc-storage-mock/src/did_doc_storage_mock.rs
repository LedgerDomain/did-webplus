use did_webplus_core::{DIDDocument, DIDStr, DID};
use did_webplus_doc_store::{DIDDocRecord, DIDDocRecordFilter, Result};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone, Default)]
struct DIDDocStorageMockState {
    next_did_doc_record_primary_key: usize,
    /// This is what actually stores the DIDDocRecords.
    did_doc_record_m: HashMap<usize, DIDDocRecord>,
    index_by_self_hash_m: HashMap<selfhash::KERIHash, usize>,
    index_by_did_and_version_id_m: HashMap<(DID, u32), usize>,
    index_by_latest_m: HashMap<DID, usize>,
}

impl DIDDocStorageMockState {
    fn new() -> Self {
        Self {
            next_did_doc_record_primary_key: 0,
            ..Default::default()
        }
    }
    fn add(&mut self, did_document: &DIDDocument, did_document_jcs: String) {
        let previous_did_documents_jsonl_octet_length = self
            .get_latest(&did_document.did)
            .map(|did_doc_record| did_doc_record.did_documents_jsonl_octet_length)
            .unwrap_or(0);
        let did_doc_record_primary_key = self.next_did_doc_record_primary_key;
        self.next_did_doc_record_primary_key += 1;
        let did_doc_record = DIDDocRecord {
            self_hash: did_document.self_hash.to_string(),
            did: did_document.did.to_string(),
            version_id: did_document.version_id as i64,
            valid_from: did_document.valid_from,
            did_documents_jsonl_octet_length: previous_did_documents_jsonl_octet_length
                + did_document_jcs.len() as i64
                + 1,
            did_document_jcs,
        };
        self.did_doc_record_m
            .insert(did_doc_record_primary_key, did_doc_record);
        self.index_by_self_hash_m
            .insert(did_document.self_hash.clone(), did_doc_record_primary_key);
        self.index_by_did_and_version_id_m.insert(
            (did_document.did.clone(), did_document.version_id),
            did_doc_record_primary_key,
        );
        self.index_by_latest_m
            .insert(did_document.did.clone(), did_doc_record_primary_key);
    }
    fn get_by_self_hash(&self, self_hash: &selfhash::KERIHashStr) -> Option<&DIDDocRecord> {
        self.index_by_self_hash_m
            .get(self_hash)
            .map(|primary_key| self.did_doc_record_m.get(&primary_key))
            .flatten()
    }
    fn get_by_did_and_version_id(&self, did: DID, version_id: u32) -> Option<&DIDDocRecord> {
        self.index_by_did_and_version_id_m
            .get(&(did, version_id))
            .map(|primary_key| self.did_doc_record_m.get(&primary_key))
            .flatten()
    }
    fn get_latest(&self, did: &DIDStr) -> Option<&DIDDocRecord> {
        self.index_by_latest_m
            .get(did)
            .map(|primary_key| self.did_doc_record_m.get(&primary_key))
            .flatten()
    }
    fn get(&self, did_doc_record_filter: &DIDDocRecordFilter) -> Vec<DIDDocRecord> {
        let mut did_doc_record_v = Vec::new();
        for did_doc_record in self.did_doc_record_m.values() {
            if did_doc_record_filter.matches(did_doc_record) {
                did_doc_record_v.push(did_doc_record.clone())
            }
        }
        did_doc_record_v
    }
}

#[derive(Clone)]
pub struct DIDDocStorageMock {
    state_la: Arc<RwLock<DIDDocStorageMockState>>,
}

impl DIDDocStorageMock {
    pub fn new() -> Self {
        Self {
            state_la: Arc::new(RwLock::new(DIDDocStorageMockState::new())),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for DIDDocStorageMock {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(DIDDocStorageMockTransaction))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_doc_store::DIDDocStorage for DIDDocStorageMock {
    async fn add_did_document(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> Result<()> {
        // tracing::trace!(
        //     "DIDDocStorageMock attempting to add DIDDocRecord with self-hash {}",
        //     did_doc_record.self_hash,
        // );
        assert!(
            did_document.self_hash_o().is_some(),
            "programmer error: self_hash is expected to be present on a valid DID document"
        );
        let mut state_g = self.state_la.write().unwrap();
        state_g.add(did_document, did_document_jcs.to_string());
        // tracing::trace!(
        //     "DIDDocStorageMock successfully added DIDDocRecord with self-hash {}",
        //     self_hash_str
        // );
        Ok(())
    }
    async fn add_did_documents(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document_jcs_v: &[&str],
        did_document_v: &[DIDDocument],
    ) -> Result<()> {
        let mut state_g = self.state_la.write().unwrap();
        for (&did_document_jcs, did_document) in
            did_document_jcs_v.iter().zip(did_document_v.iter())
        {
            assert!(
                did_document.self_hash_o().is_some(),
                "programmer error: self_hash is expected to be present on a valid DID document"
            );
            state_g.add(did_document, did_document_jcs.to_string());
        }
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        let did_doc_record_o = state_g.get_by_self_hash(self_hash);
        if let Some(did_doc_record) = did_doc_record_o.as_ref() {
            if did_doc_record.did.as_str() != did.as_str() {
                // did doesn't match.
                return Ok(None);
            }
        }
        Ok(did_doc_record_o.cloned())
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        let did_doc_record_o = state_g.get_by_did_and_version_id(did.to_owned(), version_id);
        Ok(did_doc_record_o.cloned())
    }
    async fn get_latest_did_doc_record(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        let did_doc_record_o = state_g.get_latest(did);
        Ok(did_doc_record_o.cloned())
    }
    async fn get_did_doc_records(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> Result<Vec<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        let did_doc_record_v = state_g.get(did_doc_record_filter);
        Ok(did_doc_record_v)
    }
    async fn get_known_did_documents_jsonl_octet_length(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<u64> {
        let state_g = self.state_la.read().unwrap();
        let did_doc_record_v = state_g.get(&DIDDocRecordFilter {
            did_o: Some(did.to_string()),
            ..Default::default()
        });
        let mut size = 0;
        for did_doc_record in did_doc_record_v {
            size += did_doc_record.did_document_jcs.len() as u64;
            // One more byte for the trailing newline.
            size += 1;
        }
        Ok(size)
    }
    async fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> Result<Vec<DIDDocRecord>> {
        let range_begin_inclusive = range_begin_inclusive_o.map(|x| x as i64).unwrap_or(0);
        let range_end_exclusive = range_end_exclusive_o.map(|x| x as i64).unwrap_or(i64::MAX);

        if range_begin_inclusive >= range_end_exclusive {
            // If the range is empty (or invalid), return an empty vector.
            return Ok(Vec::new());
        }

        let state_g = self.state_la.read().unwrap();
        let did_doc_record_v = state_g
            .get(&DIDDocRecordFilter {
                did_o: Some(did.to_string()),
                ..Default::default()
            })
            .into_iter()
            .filter(|did_doc_record| {
                range_begin_inclusive < did_doc_record.did_documents_jsonl_octet_length
                    && did_doc_record.did_documents_jsonl_octet_length
                        - (did_doc_record.did_document_jcs.len() as i64 + 1)
                        < range_end_exclusive
            })
            .collect();
        Ok(did_doc_record_v)
    }
}

// TODO: Maybe track if this has been committed or not, so that Drop can determine if
// it would be a rollback (which would mean that it would have to panic because rollback
// is not currently supported).
#[derive(Clone, Debug)]
struct DIDDocStorageMockTransaction;

impl std::ops::Drop for DIDDocStorageMockTransaction {
    fn drop(&mut self) {
        // Nothing to do
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::TransactionDynT for DIDDocStorageMockTransaction {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn commit(self: Box<Self>) -> storage_traits::Result<()> {
        Ok(())
    }
    async fn rollback(self: Box<Self>) -> storage_traits::Result<()> {
        panic!("Transaction rollback is not supported by DIDDocStorageMock");
    }
}
