/// Enumeration of the purposes of verification methods, as specified by the DID spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[wasm_bindgen::prelude::wasm_bindgen]
pub enum KeyPurpose {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
    UpdateDIDDocument,
}

impl From<did_webplus_core::KeyPurpose> for KeyPurpose {
    fn from(key_purpose: did_webplus_core::KeyPurpose) -> Self {
        match key_purpose {
            did_webplus_core::KeyPurpose::Authentication => KeyPurpose::Authentication,
            did_webplus_core::KeyPurpose::AssertionMethod => KeyPurpose::AssertionMethod,
            did_webplus_core::KeyPurpose::KeyAgreement => KeyPurpose::KeyAgreement,
            did_webplus_core::KeyPurpose::CapabilityInvocation => KeyPurpose::CapabilityInvocation,
            did_webplus_core::KeyPurpose::CapabilityDelegation => KeyPurpose::CapabilityDelegation,
            did_webplus_core::KeyPurpose::UpdateDIDDocument => KeyPurpose::UpdateDIDDocument,
        }
    }
}

impl From<KeyPurpose> for did_webplus_core::KeyPurpose {
    fn from(key_purpose: KeyPurpose) -> Self {
        match key_purpose {
            KeyPurpose::Authentication => did_webplus_core::KeyPurpose::Authentication,
            KeyPurpose::AssertionMethod => did_webplus_core::KeyPurpose::AssertionMethod,
            KeyPurpose::KeyAgreement => did_webplus_core::KeyPurpose::KeyAgreement,
            KeyPurpose::CapabilityInvocation => did_webplus_core::KeyPurpose::CapabilityInvocation,
            KeyPurpose::CapabilityDelegation => did_webplus_core::KeyPurpose::CapabilityDelegation,
            KeyPurpose::UpdateDIDDocument => did_webplus_core::KeyPurpose::UpdateDIDDocument,
        }
    }
}

/// Returns the DID-spec key purpose string (camelCase), e.g. `assertionMethod`.
///
/// Exported as a free function because a separate `#[wasm_bindgen] impl KeyPurpose` would make
/// wasm-bindgen emit a duplicate `KeyPurpose` JS class.
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn key_purpose_as_str(purpose: KeyPurpose) -> String {
    let k: did_webplus_core::KeyPurpose = purpose.into();
    k.as_str().to_string()
}
