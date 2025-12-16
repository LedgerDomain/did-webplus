use crate::{HTTPHeadersFor, HTTPSchemeOverride, into_js_value};
use std::{ops::Deref, sync::Arc};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

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
    /// Create a new (set of) private key(s), create a root DID document containing the corresponding public key(s),
    /// and send the DID document to the specified VDR.  This DID is now a locally-controlled DID.  Returns the
    /// fully qualified DID corresponding to the updated DID doc (i.e. the DID with selfHash and versionId query
    /// params; in this case, the query selfHash matches the DID doc selfHash, and the query versionId is 0).
    pub fn create_did(
        &self,
        vdr_did_create_endpoint: String,
        http_headers_for_o: Option<HTTPHeadersFor>,
        http_scheme_override_o: Option<HTTPSchemeOverride>,
    ) -> js_sys::Promise {
        let wallet = self.clone();
        let http_headers_for_o = http_headers_for_o.map(|o| o.into());
        let http_scheme_override_o = http_scheme_override_o.map(Into::into);
        wasm_bindgen_futures::future_to_promise(async move {
            let controlled_did = wallet
                .deref()
                .create_did(
                    vdr_did_create_endpoint.as_str(),
                    http_headers_for_o.as_ref(),
                    http_scheme_override_o.as_ref(),
                )
                .await
                .map_err(into_js_value)?;
            let did = controlled_did.did();
            tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);
            Ok(controlled_did.to_string().into())
        })
    }
    /// Retrieve all DID document updates for the given DID from the VDR, verify them, and store the latest DID document.
    // TODO: Figure out how to update any other local doc stores.
    pub fn fetch_did(
        &self,
        did: String,
        http_headers_for_o: Option<HTTPHeadersFor>,
        http_scheme_override_o: Option<HTTPSchemeOverride>,
    ) -> js_sys::Promise {
        let wallet = self.clone();
        let http_headers_for_o = http_headers_for_o.map(|o| o.into());
        let http_scheme_override_o = http_scheme_override_o.map(Into::into);
        wasm_bindgen_futures::future_to_promise(async move {
            let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
            wallet
                .deref()
                .fetch_did(
                    did,
                    http_headers_for_o.as_ref(),
                    http_scheme_override_o.as_ref(),
                )
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
    pub fn update_did(
        &self,
        did: String,
        http_headers_for_o: Option<HTTPHeadersFor>,
        http_scheme_override_o: Option<HTTPSchemeOverride>,
    ) -> js_sys::Promise {
        let wallet = self.clone();
        let http_headers_for_o = http_headers_for_o.map(|o| o.into());
        let http_scheme_override_o = http_scheme_override_o.map(Into::into);
        wasm_bindgen_futures::future_to_promise(async move {
            let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
            let controlled_did = wallet
                .deref()
                .update_did(
                    did,
                    http_headers_for_o.as_ref(),
                    http_scheme_override_o.as_ref(),
                )
                .await
                .map_err(into_js_value)?;
            tracing::debug!("updated DID: {}", controlled_did);
            Ok(controlled_did.to_string().into())
        })
    }
    /// Deactivate a locally-controlled DID by removing all verification methods from the DID document
    /// and setting its update rules to UpdatesDisallowed.  Returns the fully qualified DID corresponding
    /// to the updated DID document.  Note that this is an extremely irreversible action; the DID can't
    /// ever be updated again.
    pub fn deactivate_did(
        &self,
        did: String,
        http_headers_for_o: Option<HTTPHeadersFor>,
        http_scheme_override_o: Option<HTTPSchemeOverride>,
    ) -> js_sys::Promise {
        let wallet = self.clone();
        let http_headers_for_o = http_headers_for_o.map(|o| o.into());
        let http_scheme_override_o = http_scheme_override_o.map(Into::into);
        wasm_bindgen_futures::future_to_promise(async move {
            let did = did_webplus_core::DIDStr::new_ref(&did).map_err(into_js_value)?;
            let controlled_did = wallet
                .deref()
                .deactivate_did(
                    did,
                    http_headers_for_o.as_ref(),
                    http_scheme_override_o.as_ref(),
                )
                .await
                .map_err(into_js_value)?;
            tracing::debug!("deactivated DID: {}", controlled_did);
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

impl std::ops::Deref for Wallet {
    type Target = dyn did_webplus_wallet::Wallet;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
