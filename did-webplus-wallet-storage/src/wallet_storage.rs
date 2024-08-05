use crate::{
    verification_method_record::VerificationMethodRecord,
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter,
    PrivKeyUsageRecord, PrivKeyUsageRecordFilter, Result, WalletRecord, WalletRecordFilter,
    WalletStorageCtx,
};
use did_webplus::DIDKeyResourceFullyQualifiedStr;

/// Trait which defines the storage interface for a SoftwareWallet.
// TODO: Should this be SoftwareWalletStorage?
#[async_trait::async_trait]
pub trait WalletStorage: Clone + did_webplus_doc_store::DIDDocStorage {
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
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
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
    /// Return up to one locally controlled verification method for the given DID.  If there are multiple matches,
    /// return error.
    async fn get_locally_controlled_verification_method(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Option<(VerificationMethodRecord, PrivKeyRecord)>>;
}
