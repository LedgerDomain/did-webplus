use crate::{Result, into_js_value};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DID(did_webplus_core::DID);

#[wasm_bindgen]
impl DID {
    pub fn try_from_string(did: String) -> Result<Self> {
        let did = did_webplus_core::DID::try_from(did).map_err(into_js_value)?;
        Ok(Self(did))
    }
}

impl DID {
    pub fn into_inner(self) -> did_webplus_core::DID {
        self.0
    }
}

impl std::ops::Deref for DID {
    type Target = did_webplus_core::DIDStr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<did_webplus_core::DID> for DID {
    fn from(did: did_webplus_core::DID) -> Self {
        Self(did)
    }
}

impl From<DID> for did_webplus_core::DID {
    fn from(did: DID) -> Self {
        did.0
    }
}
