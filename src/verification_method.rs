use crate::{
    DIDWebplus, DIDWebplusWithFragment, PublicKeyBase58, PublicKeyJWK, VerificationMethodPublicKey,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct VerificationMethod {
    pub id: DIDWebplusWithFragment,
    pub r#type: String,
    pub controller: DIDWebplus,
    #[serde(flatten)]
    pub public_key: VerificationMethodPublicKey,
}

impl VerificationMethod {
    /// Convenience method for making a well-formed EcdsaSecp256k1VerificationKey2019 entry for a
    /// DID document.  Note that the DIDWebplusWithFragment's fragment is the relative DID URI for
    /// this specific key within the DID document.  Note that this will ignore the "kid" field of
    /// public_key_jwk and replace it with the DIDWebplusWithFragment.
    pub fn ecdsa_secp256k1_verification_key_2019(
        did_webplus_with_fragment: DIDWebplusWithFragment,
        mut public_key_jwk: PublicKeyJWK,
    ) -> Self {
        public_key_jwk.kid_o = Some(did_webplus_with_fragment.clone().into());
        let controller = did_webplus_with_fragment.without_fragment();
        Self {
            id: did_webplus_with_fragment,
            r#type: "EcdsaSecp256k1VerificationKey2019".into(),
            controller,
            public_key: public_key_jwk.into(),
        }
    }
    /// Convenience method for making a well-formed Ed25519VerificationKey2018 entry for a
    /// DID document.  Note that the DIDWebplusWithFragment's fragment is the relative DID URI for
    /// this specific key within the DID document.  Note that this will ignore the "kid" field of
    /// public_key_jwk and replace it with the DIDWebplusWithFragment.
    pub fn ed25519_verification_key_2018(
        did_webplus_with_fragment: DIDWebplusWithFragment,
        public_key_base_58: PublicKeyBase58,
    ) -> Self {
        let controller = did_webplus_with_fragment.without_fragment();
        Self {
            id: did_webplus_with_fragment,
            r#type: "Ed25519VerificationKey2018".into(),
            controller,
            public_key: public_key_base_58.into(),
        }
    }
    pub fn said_derivation_value(
        &self,
        hash_function_code: &said::derivation::HashFunctionCode,
        said: Option<&str>,
    ) -> Self {
        let mut c = self.clone();
        c.id = c.id.said_derivation_value(hash_function_code, said);
        c.controller = c.controller.said_derivation_value(hash_function_code, said);
        c.public_key = c.public_key.said_derivation_value(hash_function_code, said);
        c
    }
}
