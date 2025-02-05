use crate::{
    verification_method_record::VerificationMethodRecord,
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter,
    PrivKeyUsageRecord, PrivKeyUsageRecordFilter, Result, WalletRecord, WalletRecordFilter,
    WalletStorageCtx,
};
use did_webplus_core::DIDKeyResourceFullyQualifiedStr;

/// Trait which defines the storage interface for a WalletStore.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait WalletStorage:
    did_webplus_doc_store::DIDDocStorage + Send + storage_traits::StorageDynT + Sync
{
    async fn create_wallet(
        &self,
        mut transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_name_o: Option<String>,
    ) -> Result<WalletStorageCtx> {
        // Create a random UUID for the wallet.  The chance of collision is so low that
        // it's more likely a programmer error if it happens.
        let now_utc = time::OffsetDateTime::now_utc();
        for _ in 0..5 {
            let wallet_uuid = uuid::Uuid::new_v4();
            // This awkward if-let (and the one below) is because we have to control the lifetime of the
            // mutable borrow of transaction_o's inner ref very precisely in order to play nicely with the
            // lifetime for the Future that is implicitly returned by the async fn.  Not pretty, but it works.
            // TODO: Figure out how to make this more ergonomic.
            let wallet_already_exists = if let Some(transaction) = transaction_o.as_mut() {
                self.get_wallet(Some(*transaction), &wallet_uuid)
                    .await?
                    .is_some()
            } else {
                self.get_wallet(None, &wallet_uuid).await?.is_some()
            };
            if !wallet_already_exists {
                let wallet_record = WalletRecord {
                    wallet_uuid,
                    created_at: now_utc,
                    updated_at: now_utc,
                    deleted_at_o: None,
                    wallet_name_o,
                };
                // TODO: Figure out how to make this more ergonomic.
                if let Some(transaction) = transaction_o.as_mut() {
                    return self.add_wallet(Some(*transaction), wallet_record).await;
                } else {
                    return self.add_wallet(None, wallet_record).await;
                }
            }
        }
        panic!("Failed to create a unique wallet UUID after 5 attempts; this is so unlikely that it's almost certainly a programmer error");
    }
    async fn add_wallet(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_record: WalletRecord,
    ) -> Result<WalletStorageCtx>;
    async fn get_wallet(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_uuid: &uuid::Uuid,
    ) -> Result<Option<(WalletStorageCtx, WalletRecord)>>;
    async fn get_wallets(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_record_filter: &WalletRecordFilter,
    ) -> Result<Vec<(WalletStorageCtx, WalletRecord)>>;

    async fn add_priv_key(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> Result<()>;
    async fn delete_priv_key(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        pub_key: &selfsign::KERIVerifierStr,
    ) -> Result<()>;
    async fn get_priv_key(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        pub_key: &selfsign::KERIVerifierStr,
    ) -> Result<Option<PrivKeyRecord>>;
    async fn get_priv_keys(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_record_filter: &PrivKeyRecordFilter,
    ) -> Result<Vec<PrivKeyRecord>>;

    async fn add_priv_key_usage(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record: &PrivKeyUsageRecord,
    ) -> Result<()>;
    async fn get_priv_key_usages(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record_filter: &PrivKeyUsageRecordFilter,
    ) -> Result<Vec<PrivKeyUsageRecord>>;

    async fn get_verification_method(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        did_key_resource_fully_qualified: &DIDKeyResourceFullyQualifiedStr,
    ) -> Result<VerificationMethodRecord>;

    /// A "locally controlled" verification method is one whose associated priv key is present in the wallet.
    /// In particular, the deleted_at_o fields are each None and priv_key_bytes_o fields are each Some(_).
    async fn get_locally_controlled_verification_methods(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, PrivKeyRecord)>>;
}
