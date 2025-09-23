use crate::{DIDKeyResource, DIDStr, Error, PublicKeyJWK, PublicKeyParams, Result, DID};

// TODO: Refactor to use jsonWebKey2020 specifically, absorb "type" field into serde tag.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct VerificationMethod {
    pub id: DIDKeyResource,
    pub r#type: String,
    pub controller: DID,
    /// We only support jsonWebKey2020 here.
    // TODO: Support arbitrary types via map.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicKeyJWK,
}

impl VerificationMethod {
    /// Convenience method for making a well-formed JsonWebKey2020 entry for a DID document.
    pub fn json_web_key_2020(
        controller: DID,
        key_id_fragment: &str,
        pub_key: &mbx::MBPubKey,
    ) -> Self {
        let did_key_resource: DIDKeyResource = controller.with_fragment(key_id_fragment);
        let public_key_jwk = PublicKeyJWK {
            kid_o: Some(did_key_resource.clone().into()),
            public_key_params: PublicKeyParams::from(pub_key),
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

        if self.id.hostname() != self.controller.hostname() {
            return Err(Error::Malformed(
                "VerificationMethod id hostname does not match controller hostname",
            ));
        }
        if self.id.port_o() != self.controller.port_o() {
            return Err(Error::Malformed(
                "VerificationMethod id port does not match controller port",
            ));
        }
        if self.id.path_o() != self.controller.path_o() {
            return Err(Error::Malformed(
                "VerificationMethod id path does not match controller path",
            ));
        }
        if self.id.root_self_hash() != self.controller.root_self_hash() {
            return Err(Error::Malformed(
                "VerificationMethod id root-self-hash component does not match controller root-self-hash component",
            ));
        }
        if self.id != *self.public_key_jwk.kid_o.as_ref().unwrap() {
            return Err(Error::Malformed(
                "VerificationMethod id does not match publicKeyJwk 'kid' field",
            ));
        }

        Ok(())
    }
    pub fn root_did_document_self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&'b mbx::MBHashStr>> + 'a> {
        let mut iter_chain: Box<dyn std::iter::Iterator<Item = Option<&'b mbx::MBHashStr>> + 'a> =
            Box::new(
                std::iter::once(Some(self.id.root_self_hash()))
                    .chain(std::iter::once(Some(self.controller.root_self_hash()))),
            );
        if let Some(kid) = self.public_key_jwk.kid_o.as_ref() {
            iter_chain = Box::new(iter_chain.chain(std::iter::once(Some(kid.root_self_hash()))));
        }
        iter_chain
    }
    pub fn set_root_did_document_self_hash_slots_to(
        &mut self,
        hash: &mbx::MBHashStr,
    ) -> Result<()> {
        self.controller.set_root_self_hash(hash);
        if let Some(kid) = self.public_key_jwk.kid_o.as_mut() {
            kid.set_root_self_hash(hash);
        }
        self.id.set_root_self_hash(hash);
        Ok(())
    }
}
