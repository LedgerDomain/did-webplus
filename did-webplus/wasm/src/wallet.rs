use crate::{
    DID, HTTPOptions, LocallyControlledVerificationMethodFilter, MBHashFunction, Result,
    VerificationMethodRecord, WalletBasedSigner, into_js_value,
};
use std::{ops::Deref, str::FromStr, sync::Arc};
use wasm_bindgen::prelude::wasm_bindgen;

/// Parameters for creating a new DID in a given wallet.
/// -   `vdr_did_create_endpoint`: The endpoint to create the DID at.
/// -   `mb_hash_function_for_did`: The MBHashFunction to use for the self-hash of the root DID document,
///     which is the self-hash that forms part of the DID itself.  Base64Url is recommended for the base
///     for compactness and encode/decode speed.
/// -   `mb_hash_function_for_update_key_o`: The MBHashFunction to use for the update key.  If None, then
///     the update key will be UpdateKey ("key" in the JSON form of the update rules).  It is recommended
///     to always use a HashedUpdateKey for pre-rotation keys.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct CreateDIDParameters {
    vdr_did_create_endpoint: String,
    mb_hash_function_for_did: MBHashFunction,
    mb_hash_function_for_update_key_o: Option<MBHashFunction>,
}

impl CreateDIDParameters {
    pub fn as_create_did_parameters(&self) -> did_webplus_wallet::CreateDIDParameters<'_> {
        did_webplus_wallet::CreateDIDParameters {
            vdr_did_create_endpoint: self.vdr_did_create_endpoint.as_str(),
            mb_hash_function_for_did: self.mb_hash_function_for_did.deref(),
            mb_hash_function_for_update_key_o: self.mb_hash_function_for_update_key_o.as_deref(),
        }
    }
}

#[wasm_bindgen]
impl CreateDIDParameters {
    pub fn new(
        vdr_did_create_endpoint: String,
        mb_hash_function_for_did: MBHashFunction,
        mb_hash_function_for_update_key_o: Option<MBHashFunction>,
    ) -> Self {
        Self {
            vdr_did_create_endpoint,
            mb_hash_function_for_did,
            mb_hash_function_for_update_key_o,
        }
    }
}

/// Parameters for updating a DID in a given wallet.
/// -   `did`: The DID to update.
/// -   `change_mb_hash_function_for_self_hash_o`: The MBHashFunction to use for the self-hash of the updated DID document.
///     If None, then the same base and hash function as the one for the existing DID document will be used.
///     Typically, one would only change the hash function if the hash function for the existing DID document was
///     considered to be too weak.
/// -   `mb_hash_function_for_update_key_o`: The MBHashFunction to use for the update key.  If None, then
///     the update key will be UpdateKey ("key" in the JSON form of the update rules).  It is recommended
///     to always use a HashedUpdateKey for pre-rotation keys.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct UpdateDIDParameters {
    did: DID,
    change_mb_hash_function_for_self_hash_o: Option<MBHashFunction>,
    mb_hash_function_for_update_key_o: Option<MBHashFunction>,
}

impl UpdateDIDParameters {
    pub fn as_update_did_parameters(&self) -> did_webplus_wallet::UpdateDIDParameters<'_> {
        did_webplus_wallet::UpdateDIDParameters {
            did: self.did.deref(),
            change_mb_hash_function_for_self_hash_o: self
                .change_mb_hash_function_for_self_hash_o
                .as_deref(),
            mb_hash_function_for_update_key_o: self.mb_hash_function_for_update_key_o.as_deref(),
        }
    }
}

#[wasm_bindgen]
impl UpdateDIDParameters {
    pub fn new(
        did: DID,
        change_mb_hash_function_for_self_hash_o: Option<MBHashFunction>,
        mb_hash_function_for_update_key_o: Option<MBHashFunction>,
    ) -> Self {
        Self {
            did,
            change_mb_hash_function_for_self_hash_o,
            mb_hash_function_for_update_key_o,
        }
    }
}

/// Parameters for deactivating a DID in a given wallet.
/// -   `did`: The DID to deactivate.
/// -   `change_mb_hash_function_for_self_hash_o`: The MBHashFunction to use for the self-hash of the deactivated DID document.
///     If None, then the same base and hash function as the one for the existing DID document will be used.
///     Typically, one would only change the hash function if the hash function for the existing DID document was considered
///     to be too weak.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DeactivateDIDParameters {
    did: DID,
    change_mb_hash_function_for_self_hash_o: Option<MBHashFunction>,
}

impl DeactivateDIDParameters {
    pub fn as_deactivate_did_parameters(&self) -> did_webplus_wallet::DeactivateDIDParameters<'_> {
        did_webplus_wallet::DeactivateDIDParameters {
            did: self.did.deref(),
            change_mb_hash_function_for_self_hash_o: self
                .change_mb_hash_function_for_self_hash_o
                .as_deref(),
        }
    }
}

#[wasm_bindgen]
impl DeactivateDIDParameters {
    pub fn new(did: DID, change_mb_hash_function_for_self_hash_o: Option<MBHashFunction>) -> Self {
        Self {
            did,
            change_mb_hash_function_for_self_hash_o,
        }
    }
}

/// Wallet contains private keys, controls a set of DIDs, and is capable of creating WalletBasedSigners,
/// which are used to sign artifacts such as JWTs, VCs, and VPs.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Wallet(Arc<dyn did_webplus_wallet::Wallet>);

#[wasm_bindgen]
impl Wallet {
    /// Create an ephemeral, in-memory wallet.  To be clear, this has no persistent storage and will be
    /// lost when the program exits.
    pub fn new_mock(vdg_host_o: Option<String>) -> js_sys::Promise {
        wasm_bindgen_futures::future_to_promise(async move {
            let wallet_storage = did_webplus_wallet_storage_mock::WalletStorageMock::new();
            let wallet_storage_a = Arc::new(wallet_storage);
            use storage_traits::StorageDynT;
            let mut transaction = wallet_storage_a
                .begin_transaction()
                .await
                .map_err(into_js_value)?;
            let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
                transaction.as_mut(),
                wallet_storage_a,
                Some("fancy mock wallet".to_string()),
                vdg_host_o,
            )
            .await
            .map_err(into_js_value)?;
            transaction.commit().await.map_err(into_js_value)?;
            Ok(Self(Arc::new(software_wallet)).into())
        })
    }
    /// Get the WalletRecord for the given wallet UUID.
    #[cfg(target_arch = "wasm32")]
    pub async fn get_wallet_record(
        db_name: String,
        wallet_uuid: String,
    ) -> Result<crate::WalletRecord> {
        let wallet_uuid = uuid::Uuid::parse_str(&wallet_uuid).map_err(into_js_value)?;
        let wallet_record =
            did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::get_wallet_record(
                db_name,
                wallet_uuid,
            )
            .await
            .map_err(into_js_value)?;
        Ok(wallet_record.into())
    }
    /// Get all WalletRecord-s in the given database.
    #[cfg(target_arch = "wasm32")]
    pub async fn get_wallet_records(db_name: String) -> Result<Vec<crate::WalletRecord>> {
        let wallet_record_filter = did_webplus_wallet_store::WalletRecordFilter::default();
        let wallet_records =
            did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::get_wallet_records(
                db_name,
                wallet_record_filter,
            )
            .await
            .map_err(into_js_value)?;
        Ok(wallet_records
            .into_iter()
            .map(|wallet_record| wallet_record.into())
            .collect())
    }
    /// Create a new (IndexedDB-backed) wallet in the given database, with optional wallet name.
    #[cfg(target_arch = "wasm32")]
    pub async fn create(
        db_name: String,
        wallet_name_o: Option<String>,
        vdg_host_o: Option<String>,
    ) -> Result<Self> {
        let software_wallet_indexeddb =
            did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::create(
                db_name,
                wallet_name_o,
                vdg_host_o,
            )
            .await
            .map_err(into_js_value)?;
        Ok(Self(Arc::new(software_wallet_indexeddb)))
    }
    /// Open an existing (IndexedDB-backed) wallet in the given database.
    #[cfg(target_arch = "wasm32")]
    pub async fn open(
        db_name: String,
        wallet_uuid: String,
        vdg_host_o: Option<String>,
    ) -> Result<Self> {
        let wallet_uuid = uuid::Uuid::parse_str(&wallet_uuid).map_err(into_js_value)?;
        let software_wallet_indexeddb =
            did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::open(
                db_name,
                wallet_uuid,
                vdg_host_o,
            )
            .await
            .map_err(into_js_value)?;
        Ok(Self(Arc::new(software_wallet_indexeddb)))
    }
    /// Create a new (set of) private key(s), create a root DID document containing the corresponding public key(s),
    /// and send the DID document to the specified VDR.  This DID is now a locally-controlled DID.  Returns the
    /// fully qualified DID corresponding to the updated DID doc (i.e. the DID with selfHash and versionId query
    /// params; in this case, the query selfHash matches the DID doc selfHash, and the query versionId is 0).
    pub async fn create_did(
        &self,
        create_did_parameters: CreateDIDParameters,
        http_options_o: Option<HTTPOptions>,
    ) -> Result<String> {
        let http_options_o = http_options_o.map(|o| o.into());
        let controlled_did = self
            .deref()
            .create_did(
                create_did_parameters.as_create_did_parameters(),
                http_options_o.as_ref(),
            )
            .await
            .map_err(into_js_value)?;
        let did = controlled_did.did();
        tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);
        Ok(controlled_did.to_string())
    }
    /// Retrieve all DID document updates for the given DID from the VDR, verify them, and store the latest DID document.
    // TODO: Figure out how to update any other local doc stores.
    pub async fn fetch_did(&self, did: String, http_options_o: Option<HTTPOptions>) -> Result<()> {
        let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
        let http_options_o = http_options_o.map(|o| o.into());
        self.deref()
            .fetch_did(did, http_options_o.as_ref())
            .await
            .map_err(into_js_value)?;
        Ok(())
    }
    /// Retrieve the latest DID document from the VDR, rotate the key(s) of a locally-controlled DID, update
    /// the DID document, and send the updated DID document to the VDR.  The initial retrieval step is necessary
    /// only if there are other wallets that control this DID and that have updated the DID document since the last
    /// time this wallet updated the DID document.  Returns the fully qualified DID corresponding to the updated
    /// DID doc (i.e. the DID with selfHash and versionId query params).
    pub async fn update_did(
        &self,
        update_did_parameters: UpdateDIDParameters,
        http_options_o: Option<HTTPOptions>,
    ) -> Result<String> {
        let http_options_o = http_options_o.map(|o| o.into());
        let controlled_did = self
            .deref()
            .update_did(
                update_did_parameters.as_update_did_parameters(),
                http_options_o.as_ref(),
            )
            .await
            .map_err(into_js_value)?;
        tracing::debug!("updated DID: {}", controlled_did);
        Ok(controlled_did.to_string())
    }
    /// Deactivate a locally-controlled DID by removing all verification methods from the DID document
    /// and setting its update rules to UpdatesDisallowed.  Returns the fully qualified DID corresponding
    /// to the updated DID document.  Note that this is an extremely irreversible action; the DID can't
    /// ever be updated again.
    pub async fn deactivate_did(
        &self,
        deactivate_did_parameters: DeactivateDIDParameters,
        http_options_o: Option<HTTPOptions>,
    ) -> Result<String> {
        let http_options_o = http_options_o.map(|o| o.into());
        let controlled_did = self
            .deref()
            .deactivate_did(
                deactivate_did_parameters.as_deactivate_did_parameters(),
                http_options_o.as_ref(),
            )
            .await
            .map_err(into_js_value)?;
        tracing::debug!("deactivated DID: {}", controlled_did);
        Ok(controlled_did.to_string())
    }
    /// Returns the list of DIDs that this wallet controls, subject to the given filter.
    pub async fn get_controlled_dids(&self, did_o: Option<String>) -> Result<Vec<String>> {
        let did_o = did_o
            .as_deref()
            .map(did_webplus_core::DIDStr::new_ref)
            .transpose()
            .map_err(into_js_value)?;
        let controlled_dids = self
            .deref()
            .get_controlled_dids(did_o)
            .await
            .map_err(into_js_value)?;
        Ok(controlled_dids
            .into_iter()
            .map(did_webplus_core::DIDFullyQualified::into_string)
            .collect::<Vec<String>>())
    }
    /// If did_o is Some(_), then this returns the fully qualified form of the that DID if it is
    /// controlled by this wallet.  Otherwise, if this wallet controls exactly one DID, i.e. it is
    /// uniquely determinable, then this returns the fully qualified form of that DID.  Otherwise,
    /// an error is returned.
    pub async fn get_controlled_did(&self, did_o: Option<String>) -> Result<String> {
        let did_o = did_o
            .as_deref()
            .map(did_webplus_core::DIDStr::new_ref)
            .transpose()
            .map_err(into_js_value)?;
        let controlled_did = self
            .deref()
            .get_controlled_did(did_o)
            .await
            .map_err(into_js_value)?;
        Ok(controlled_did.to_string())
    }
    /// Returns the list of locally-controlled verification methods for the given filter.
    pub async fn get_locally_controlled_verification_methods(
        &self,
        locally_controlled_verification_method_filter: LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<VerificationMethodRecord>> {
        let locally_controlled_verification_method_filter =
            locally_controlled_verification_method_filter.into();
        Ok(self
            .deref()
            .get_locally_controlled_verification_methods(
                &locally_controlled_verification_method_filter,
            )
            .await
            .map_err(into_js_value)?
            .into_iter()
            .map(|(verification_method_record, _signer_bytes)| verification_method_record.into())
            .collect())
    }
    /// Create a WalletBasedSigner for the given DID and key purpose.
    ///
    /// When `fetch_did_first` is true, refreshes the DID from the network before selecting the key.
    /// Set to false for offline signing using only the wallet's cached DID documents.
    pub async fn new_wallet_based_signer(
        &self,
        did: String,
        key_purpose: String,
        key_id_o: Option<String>,
        http_options_o: Option<HTTPOptions>,
        fetch_did_first: bool,
    ) -> Result<WalletBasedSigner> {
        let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
        let key_purpose =
            did_webplus_core::KeyPurpose::from_str(&key_purpose).map_err(into_js_value)?;
        let key_id_o = key_id_o.as_deref().map(|s| s.to_string());
        let http_options_o = http_options_o.map(|o| o.into());
        let wallet_based_signer = did_webplus_wallet::WalletBasedSigner::new(
            self.clone(),
            did,
            key_purpose,
            key_id_o.as_deref(),
            http_options_o.as_ref(),
            fetch_did_first,
        )
        .await
        .map_err(into_js_value)?;
        Ok(wallet_based_signer.into())
    }
}

impl std::ops::Deref for Wallet {
    type Target = dyn did_webplus_wallet::Wallet;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_wallet::Wallet for Wallet {
    async fn create_did(
        &self,
        create_did_parameters: did_webplus_wallet::CreateDIDParameters<'_>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<did_webplus_core::DIDFullyQualified> {
        self.0
            .create_did(create_did_parameters, http_options_o)
            .await
    }
    async fn fetch_did(
        &self,
        did: &did_webplus_core::DIDStr,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<()> {
        self.0.fetch_did(did, http_options_o).await
    }
    async fn update_did(
        &self,
        update_did_parameters: did_webplus_wallet::UpdateDIDParameters<'_>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<did_webplus_core::DIDFullyQualified> {
        self.0
            .update_did(update_did_parameters, http_options_o)
            .await
    }
    async fn deactivate_did(
        &self,
        deactivate_did_parameters: did_webplus_wallet::DeactivateDIDParameters<'_>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<did_webplus_core::DIDFullyQualified> {
        self.0
            .deactivate_did(deactivate_did_parameters, http_options_o)
            .await
    }
    async fn get_locally_controlled_verification_methods(
        &self,
        locally_controlled_verification_method_filter: &did_webplus_wallet_store::LocallyControlledVerificationMethodFilter,
    ) -> did_webplus_wallet::Result<
        Vec<(
            did_webplus_wallet_store::VerificationMethodRecord,
            signature_dyn::SignerBytes<'static>,
        )>,
    > {
        self.0
            .get_locally_controlled_verification_methods(
                locally_controlled_verification_method_filter,
            )
            .await
    }
}
