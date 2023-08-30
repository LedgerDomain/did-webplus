use crate::{DIDWebplus, DIDWebplusWithFragment, Error, PublicKeyJWK, PublicKeyParams};

// TODO: Refactor to use jsonWebKey2020 specifically, absorb "type" field into serde tag.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct VerificationMethod {
    pub id: DIDWebplusWithFragment,
    pub r#type: String,
    pub controller: DIDWebplus,
    /// We only support jsonWebKey2020 here.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicKeyJWK,
}

impl VerificationMethod {
    /// Convenience method for making a well-formed JsonWebKey2020 entry for a DID document.  Note
    /// that the DIDWebplusWithFragment's fragment is the relative DID URI for this specific key
    /// within the DID document.  Note that this will ignore the "kid" field of public_key_jwk and
    /// replace it with the DIDWebplusWithFragment.
    pub fn json_web_key_2020(
        did_webplus_with_fragment: DIDWebplusWithFragment,
        public_key_params: PublicKeyParams,
    ) -> Self {
        let public_key_jwk = PublicKeyJWK {
            kid_o: Some(did_webplus_with_fragment.clone().into()),
            public_key_params,
        };
        // public_key_jwk.kid_o = Some(did_webplus_with_fragment.clone().into());
        let controller = did_webplus_with_fragment.without_fragment();
        Self {
            id: did_webplus_with_fragment,
            r#type: "JsonWebKey2020".into(),
            controller,
            public_key_jwk,
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
        c.public_key_jwk = c
            .public_key_jwk
            .said_derivation_value(hash_function_code, said);
        c
    }
    pub fn verify(&self, expected_controller: &DIDWebplus) -> Result<(), crate::Error> {
        if self.controller != *expected_controller {
            return Err(Error::Malformed(
                "VerificationMethod controller does not match expected DID",
            ));
        }
        if self.public_key_jwk.kid_o.is_none() {
            return Err(Error::Malformed(
                "VerificationMethod publicKeyJwk does not have a 'kid' field",
            ));
        }

        let verification_method_id_did_uri_components = self.id.components();
        let expected_controller_did_uri_components = expected_controller.components();
        assert_eq!(verification_method_id_did_uri_components.method, "webplus");
        assert_eq!(expected_controller_did_uri_components.method, "webplus");
        if verification_method_id_did_uri_components.host
            != expected_controller_did_uri_components.host
        {
            return Err(Error::Malformed(
                "Verification method host does not match expected DID host",
            ));
        }
        if verification_method_id_did_uri_components.path
            != expected_controller_did_uri_components.path
        {
            return Err(Error::Malformed(
                "Verification method SAID (i.e. path) does not match expected DID SAID (i.e. path)",
            ));
        }

        if self.id != *self.public_key_jwk.kid_o.as_ref().unwrap() {
            return Err(Error::Malformed(
                "VerificationMethod id does not match publicKeyJwk 'kid' field",
            ));
        }

        Ok(())
    }
}
