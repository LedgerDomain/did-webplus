use wasm_bindgen::prelude::wasm_bindgen;

use crate::{DID, KeyPurpose};

#[wasm_bindgen]
pub struct LocallyControlledVerificationMethodFilter(
    did_webplus_wallet_store::LocallyControlledVerificationMethodFilter,
);

#[wasm_bindgen]
impl LocallyControlledVerificationMethodFilter {
    /// Creates a new LocallyControlledVerificationMethodFilter with the given filters.
    /// did_o: Optionally specify the DID whose verification methods to filter.
    /// version_id_o: Optionally specify the version ID of the DID document whose verification methods to filter.
    /// key_purpose_o: Optionally specify the key purpose of the verification methods to filter.
    /// key_id_o: Optionally specify the key ID (this is the fragment of the fully qualified key) of the verification methods to filter.
    /// result_limit_o: Optionally specify the maximum number of verification methods to return.
    #[wasm_bindgen(constructor)]
    pub fn new(
        did_o: Option<DID>,
        version_id_o: Option<u32>,
        key_purpose_o: Option<KeyPurpose>,
        key_id_o: Option<String>,
        result_limit_o: Option<u32>,
    ) -> Self {
        Self(
            did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                did_o: did_o.map(|did| did.into()),
                version_id_o,
                key_purpose_o: key_purpose_o.map(|key_purpose| key_purpose.into()),
                key_id_o: key_id_o.map(|key_id| key_id.into()),
                result_limit_o,
            },
        )
    }
}

impl From<LocallyControlledVerificationMethodFilter>
    for did_webplus_wallet_store::LocallyControlledVerificationMethodFilter
{
    fn from(
        locally_controlled_verification_method_filter: LocallyControlledVerificationMethodFilter,
    ) -> Self {
        locally_controlled_verification_method_filter.0
    }
}

impl From<did_webplus_wallet_store::LocallyControlledVerificationMethodFilter>
    for LocallyControlledVerificationMethodFilter
{
    fn from(
        locally_controlled_verification_method_filter: did_webplus_wallet_store::LocallyControlledVerificationMethodFilter,
    ) -> Self {
        Self(locally_controlled_verification_method_filter)
    }
}
