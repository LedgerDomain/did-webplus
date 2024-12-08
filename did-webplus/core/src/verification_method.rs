use crate::{DIDKeyResource, DIDStr, Error, PublicKeyJWK, PublicKeyParams, Result, DID};

// TODO: Refactor to use jsonWebKey2020 specifically, absorb "type" field into serde tag.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct VerificationMethod {
    pub id: DIDKeyResource,
    pub r#type: String,
    pub controller: DID,
    /// We only support jsonWebKey2020 here.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicKeyJWK,
}

impl VerificationMethod {
    /// Convenience method for making a well-formed JsonWebKey2020 entry for a DID document.  Note
    /// that the fragment and the key_id of the PublicKeyJWK will both be set to the KERIVerifier
    /// value of the verifier.
    pub fn json_web_key_2020(controller: DID, verifier: &dyn selfsign::Verifier) -> Self {
        let key_id = verifier.to_keri_verifier();
        let did_key_resource: DIDKeyResource = controller.with_fragment(&key_id);
        let public_key_jwk = PublicKeyJWK {
            kid_o: Some(did_key_resource.clone().into()),
            public_key_params: PublicKeyParams::from(verifier),
        };
        Self {
            id: did_key_resource,
            r#type: "JsonWebKey2020".into(),
            controller,
            public_key_jwk,
        }
    }
    pub fn verify(&self, expected_controller: &DIDStr) -> Result<()> {
        if self.controller.as_did_str() != expected_controller {
            return Err(Error::Malformed(
                "VerificationMethod controller does not match expected DID",
            ));
        }
        if self.public_key_jwk.kid_o.is_none() {
            return Err(Error::Malformed(
                "VerificationMethod publicKeyJwk does not have a 'kid' field",
            ));
        }

        if self.id.host() != self.controller.host() {
            return Err(Error::Malformed(
                "VerificationMethod id host does not match controller host",
            ));
        }
        if self.id.root_self_hash() != self.controller.root_self_hash() {
            return Err(Error::Malformed(
                "VerificationMethod id self-signature component does not match controller self-signature component",
            ));
        }
        if self.id != *self.public_key_jwk.kid_o.as_ref().unwrap() {
            return Err(Error::Malformed(
                "VerificationMethod id does not match publicKeyJwk 'kid' field",
            ));
        }

        // Verify that the id's fragment is actually the KERIVerifier corresponding to the key material.
        // Note that this constraint allows certain parallelization of checks during verification of signatures.
        // In particular, in a JWS/JWT, the kid field is a URI whose fragment specifies the KERIVerifier
        // for the pub key, and that can be used to verify the signature, and then the fact that that pub key
        // is a valid verification method for the DID can be checked in parallel.
        // NOTE: This constraint might be infeasible for some key types that have very large public keys
        // (e.g. some post-quantum crypto schemes).  So this constraint may not stay around.
        let keri_verifier = selfsign::KERIVerifier::try_from(&self.public_key_jwk)?;
        if keri_verifier.as_keri_verifier_str() != self.id.fragment() {
            return Err(Error::Malformed(
                "VerificationMethod id fragment does not match publicKeyJwk key material",
            ));
        }

        Ok(())
    }
    pub fn root_did_document_self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        let mut iter_chain: Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> =
            Box::new(
                std::iter::once(Some(&self.id as &dyn selfhash::Hash)).chain(std::iter::once(
                    Some(&self.controller as &dyn selfhash::Hash),
                )),
            );
        if let Some(kid) = self.public_key_jwk.kid_o.as_ref() {
            iter_chain =
                Box::new(iter_chain.chain(std::iter::once(Some(kid as &dyn selfhash::Hash))));
        }
        iter_chain
    }
    pub fn set_root_did_document_self_hash_slots_to(
        &mut self,
        hash: &dyn selfhash::Hash,
    ) -> Result<()> {
        let keri_hash = hash.to_keri_hash()?;
        self.controller.set_root_self_hash(&keri_hash);
        if let Some(kid) = self.public_key_jwk.kid_o.as_mut() {
            kid.set_root_self_hash(&keri_hash);
        }
        self.id.set_root_self_hash(&keri_hash);
        Ok(())
    }
}
