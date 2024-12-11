use crate::{
    verification_method_record::VerificationMethodRecord,
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter,
    PrivKeyUsageRecord, PrivKeyUsageRecordFilter, Result, WalletRecord, WalletRecordFilter,
    WalletStorageCtx,
};
use did_webplus_core::DIDKeyResourceFullyQualifiedStr;

/// Trait which defines the storage interface for a WalletStore.
#[async_trait::async_trait]
pub trait WalletStorage: Clone + did_webplus_doc_store::DIDDocStorage {
    async fn create_wallet(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_name_o: Option<String>,
    ) -> Result<WalletStorageCtx> {
        // Create a random UUID for the wallet.  The chance of collision is so low that
        // it's more likely a programmer error if it happens.
        let now_utc = time::OffsetDateTime::now_utc();
        for _ in 0..5 {
            let wallet_uuid = uuid::Uuid::new_v4();
            if self.get_wallet(transaction, &wallet_uuid).await?.is_none() {
                let wallet_record = WalletRecord {
                    wallet_uuid,
                    created_at: now_utc,
                    updated_at: now_utc,
                    deleted_at_o: None,
                    wallet_name_o,
                };
                return self.add_wallet(transaction, wallet_record).await;
            }
        }
        panic!("Failed to create a unique wallet UUID after 5 attempts; this is so unlikely that it's almost certainly a programmer error");
    }
    async fn add_wallet(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_record: WalletRecord,
    ) -> Result<WalletStorageCtx>;
    async fn get_wallet(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_uuid: &uuid::Uuid,
    ) -> Result<Option<(WalletStorageCtx, WalletRecord)>>;
    async fn get_wallets(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_record_filter: &WalletRecordFilter,
    ) -> Result<Vec<(WalletStorageCtx, WalletRecord)>>;

    async fn add_priv_key(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> Result<()>;
    async fn delete_priv_key(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        pub_key: &selfsign::KERIVerifierStr,
    ) -> Result<()>;
    async fn get_priv_key(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        pub_key: &selfsign::KERIVerifierStr,
    ) -> Result<Option<PrivKeyRecord>>;
    async fn get_priv_keys(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_record_filter: &PrivKeyRecordFilter,
    ) -> Result<Vec<PrivKeyRecord>>;

    async fn add_priv_key_usage(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record: &PrivKeyUsageRecord,
    ) -> Result<()>;
    async fn get_priv_key_usages(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record_filter: &PrivKeyUsageRecordFilter,
    ) -> Result<Vec<PrivKeyUsageRecord>>;

    async fn get_verification_method(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        did_key_resource_fully_qualified: &DIDKeyResourceFullyQualifiedStr,
    ) -> Result<VerificationMethodRecord>;

    /// A "locally controlled" verification method is one whose associated priv key is present in the wallet.
    /// In particular, the deleted_at_o fields are each None and priv_key_bytes_o fields are each Some(_).
    async fn get_locally_controlled_verification_methods(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, PrivKeyRecord)>>;
}
