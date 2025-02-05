use crate::WalletStorage;
use std::sync::Arc;

/// This is a bit of a hack to get around Rust's (current as of 2025.02.04) lack of support for
/// upcasting traits.  In particular, trait WalletStorage requires DIDDocStorage, but because
/// upcasting `dyn WalletStorage` to `dyn DIDDocStorage` isn't yet supported, a newtype must be
/// used to provide the DIDDocStorage impl.
#[derive(Clone)]
pub struct WalletStorageAsDIDDocStorage {
    pub wallet_storage_a: Arc<dyn WalletStorage>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_doc_store::DIDDocStorage for WalletStorageAsDIDDocStorage {
    /// Attempt to add a DID document to the store.  Will return an error if the DID document already exists.
    /// Note that did_document and did_document_jcs are redundant, and are expected to be consistent, but
    /// did_document_jcs is required because the specific string representation of the DID document is needed
    /// in order for the self-signature and self-hash to be verified.
    async fn add_did_document(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &did_webplus_core::DIDDocument,
        did_document_jcs: &str,
    ) -> did_webplus_doc_store::Result<()> {
        self.wallet_storage_a
            .add_did_document(transaction_o, did_document, did_document_jcs)
            .await
    }
    /// Attempt to get a DIDDocRecord with a specific self-hash value from the store.  Will return None if
    /// the requested DIDDocRecord does not exist.
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &did_webplus_core::DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> did_webplus_doc_store::Result<Option<did_webplus_doc_store::DIDDocRecord>> {
        self.wallet_storage_a
            .get_did_doc_record_with_self_hash(transaction_o, did, self_hash)
            .await
    }
    /// Attempt to get a DIDDocRecord with a specific version-id value from the store.  Will return None if
    /// the requested DIDDocRecord does not exist.
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &did_webplus_core::DIDStr,
        version_id: u32,
    ) -> did_webplus_doc_store::Result<Option<did_webplus_doc_store::DIDDocRecord>> {
        self.wallet_storage_a
            .get_did_doc_record_with_version_id(transaction_o, did, version_id)
            .await
    }
    /// Get the latest DIDDocRecord for the specified DID from the store.  Will return None if the DID has
    /// no DIDDocRecord-s in this store.
    async fn get_latest_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &did_webplus_core::DIDStr,
    ) -> did_webplus_doc_store::Result<Option<did_webplus_doc_store::DIDDocRecord>> {
        self.wallet_storage_a
            .get_latest_did_doc_record(transaction_o, did)
            .await
    }
    /// Get all DIDDocRecord-s in the store, subject to the given filter.
    async fn get_did_doc_records(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_doc_record_filter: &did_webplus_doc_store::DIDDocRecordFilter,
    ) -> did_webplus_doc_store::Result<Vec<did_webplus_doc_store::DIDDocRecord>> {
        self.wallet_storage_a
            .get_did_doc_records(transaction_o, did_doc_record_filter)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for WalletStorageAsDIDDocStorage {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        self.wallet_storage_a.begin_transaction().await
    }
}
