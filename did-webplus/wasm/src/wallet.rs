use crate::into_js_value;
use std::{ops::Deref, sync::Arc};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
#[derive(Clone)]
pub struct Wallet(Arc<dyn did_webplus_wallet::Wallet>);

#[wasm_bindgen]
impl Wallet {
    /// Create an ephemeral, in-memory wallet.  To be clear, this has no persistent storage and will be
    /// lost when the program exits.
    pub fn new_mock() -> js_sys::Promise {
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
            )
            .await
            .map_err(into_js_value)?;
            transaction.commit().await.map_err(into_js_value)?;
            Ok(Self(Arc::new(software_wallet)).into())
        })
    }
    // TODO: Method for listing wallets in a given database.
    /// Create a new (IndexedDB-backed) wallet in the given database, with optional wallet name.
    pub fn create(db_name: String, wallet_name_o: Option<String>) -> js_sys::Promise {
        wasm_bindgen_futures::future_to_promise(async move {
            let software_wallet_indexeddb = did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::create(db_name, did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::CURRENT_DB_VERSION, wallet_name_o).await.map_err(into_js_value)?;
            Ok(Self(Arc::new(software_wallet_indexeddb)).into())
        })
    }
    /// Open an existing (IndexedDB-backed) wallet in the given database.
    pub fn open(db_name: String, wallet_uuid: String) -> js_sys::Promise {
        wasm_bindgen_futures::future_to_promise(async move {
            let wallet_uuid = uuid::Uuid::parse_str(&wallet_uuid).map_err(into_js_value)?;
            let software_wallet_indexeddb =
                did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::open(
                    db_name,
                    did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::CURRENT_DB_VERSION,
                    wallet_uuid,
                )
                .await
                .map_err(into_js_value)?;
            Ok(Self(Arc::new(software_wallet_indexeddb)).into())
        })
    }
    /// Create a new (set of) private key(s), create a root DID document containing the corresponding public key(s),
    /// and send the DID document to the specified VDR.  This DID is now a locally-controlled DID.  Returns the
    /// fully qualified DID corresponding to the updated DID doc (i.e. the DID with selfHash and versionId query
    /// params; in this case, the query selfHash matches the DID doc selfHash, and the query versionId is 0).
    pub fn create_did(&self, vdr_did_create_endpoint: String) -> js_sys::Promise {
        let wallet = self.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let controlled_did = wallet
                .deref()
                .create_did(vdr_did_create_endpoint.as_str())
                .await
                .map_err(into_js_value)?;
            let did = controlled_did.did();
            tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);
            Ok(controlled_did.to_string().into())
        })
    }
    /// Retrieve all DID document updates for the given DID from the VDR, verify them, and store the latest DID document.
    // TODO: Figure out how to update any other local doc stores.
    pub fn fetch_did(&self, did: String, vdr_scheme: String) -> js_sys::Promise {
        let wallet = self.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
            let vdr_scheme = Self::parse_http_scheme(vdr_scheme.as_str())?;
            wallet
                .deref()
                .fetch_did(did, vdr_scheme)
                .await
                .map_err(into_js_value)?;
            Ok(JsValue::NULL)
        })
    }
    /// Retrieve the latest DID document from the VDR, rotate the key(s) of a locally-controlled DID, update
    /// the DID document, and send the updated DID document to the VDR.  The initial retrieval step is necessary
    /// only if there are other wallets that control this DID and that have updated the DID document since the last
    /// time this wallet updated the DID document.  Returns the fully qualified DID corresponding to the updated
    /// DID doc (i.e. the DID with selfHash and versionId query params).
    pub fn update_did(&self, did: String, vdr_scheme: String) -> js_sys::Promise {
        let wallet = self.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
            let vdr_scheme = Self::parse_http_scheme(vdr_scheme.as_str())?;
            let controlled_did = wallet
                .deref()
                .update_did(did, vdr_scheme)
                .await
                .map_err(into_js_value)?;
            tracing::debug!("updated DID: {}", controlled_did);
            Ok(controlled_did.to_string().into())
        })
    }
    /// Returns the list of DIDs that this wallet controls, subject to the given filter.
    pub fn get_controlled_dids(&self, did_o: Option<String>) -> js_sys::Promise {
        let wallet = self.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let did_o = did_o
                .as_deref()
                .map(did_webplus_core::DIDStr::new_ref)
                .transpose()
                .map_err(into_js_value)?;
            let controlled_dids = wallet
                .deref()
                .get_controlled_dids(did_o)
                .await
                .map_err(into_js_value)?;
            Ok(controlled_dids
                .into_iter()
                .map(did_webplus_core::DIDFullyQualified::into_string)
                .collect::<Vec<String>>()
                .into())
        })
    }
    /// If did_o is Some(_), then this returns the fully qualified form of the that DID if it is
    /// controlled by this wallet.  Otherwise, if this wallet controls exactly one DID, i.e. it is
    /// uniquely determinable, then this returns the fully qualified form of that DID.  Otherwise,
    /// an error is returned.
    pub fn get_controlled_did(&self, did_o: Option<String>) -> js_sys::Promise {
        let wallet = self.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let did_o = did_o
                .as_deref()
                .map(did_webplus_core::DIDStr::new_ref)
                .transpose()
                .map_err(into_js_value)?;
            let controlled_did = wallet
                .deref()
                .get_controlled_did(did_o)
                .await
                .map_err(into_js_value)?;
            Ok(controlled_did.to_string().into())
        })
    }
}

impl Wallet {
    // This ridiculous-looking function is to produce a &'static str from a non-static &str.
    fn parse_http_scheme(http_scheme: &str) -> Result<&'static str, JsValue> {
        match http_scheme {
            "http" => Ok("http"),
            "https" => Ok("https"),
            _ => Err(into_js_value(format!(
                "Invalid http_scheme {:?}",
                http_scheme
            ))),
        }
    }
}

impl std::ops::Deref for Wallet {
    type Target = dyn did_webplus_wallet::Wallet;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
