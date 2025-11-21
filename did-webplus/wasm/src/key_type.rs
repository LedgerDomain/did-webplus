use wasm_bindgen::JsValue;

use crate::into_js_value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[wasm_bindgen::prelude::wasm_bindgen]
pub enum KeyType {
    Ed25519,
    Ed448,
    P256,
    P384,
    P521,
    Secp256k1,
}

impl TryFrom<signature_dyn::KeyType> for KeyType {
    type Error = JsValue;
    fn try_from(key_type: signature_dyn::KeyType) -> Result<Self, Self::Error> {
        match key_type {
            signature_dyn::KeyType::Ed25519 => Ok(KeyType::Ed25519),
            signature_dyn::KeyType::Ed448 => Ok(KeyType::Ed448),
            signature_dyn::KeyType::P256 => Ok(KeyType::P256),
            signature_dyn::KeyType::P384 => Ok(KeyType::P384),
            signature_dyn::KeyType::P521 => Ok(KeyType::P521),
            signature_dyn::KeyType::Secp256k1 => Ok(KeyType::Secp256k1),
            _ => Err(into_js_value(format!(
                "unsupported key type: {:?}",
                key_type
            ))),
        }
    }
}

impl From<KeyType> for signature_dyn::KeyType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => signature_dyn::KeyType::Ed25519,
            KeyType::Ed448 => signature_dyn::KeyType::Ed448,
            KeyType::P256 => signature_dyn::KeyType::P256,
            KeyType::P384 => signature_dyn::KeyType::P384,
            KeyType::P521 => signature_dyn::KeyType::P521,
            KeyType::Secp256k1 => signature_dyn::KeyType::Secp256k1,
        }
    }
}
