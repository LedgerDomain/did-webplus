use crate::{
    DID, DIDFullyQualifiedStr, DIDKeyResourceFullyQualified, DIDStr, Error, PublicKeyJWK,
    PublicKeyParams, Result,
};

// TODO: Refactor to use jsonWebKey2020 specifically, absorb "type" field into serde tag.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct VerificationMethod {
    pub id: DIDKeyResourceFullyQualified,
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
        did_fully_qualified: &DIDFullyQualifiedStr,
        key_id_fragment: &str,
        pub_key: &mbx::MBPubKey,
    ) -> Self {
        let id = did_fully_qualified.with_fragment(key_id_fragment);
        let public_key_jwk = PublicKeyJWK {
            kid_o: Some(id.clone()),
            public_key_params: PublicKeyParams::from(pub_key),
        };
        Self {
            id,
            r#type: "JsonWebKey2020".into(),
            controller: did_fully_qualified.did().to_owned(),
            public_key_jwk,
        }
    }
    pub fn verify(&self, expected_controller: &DIDStr) -> Result<()> {
        if self.controller.as_did_str() != expected_controller {
            return Err(Error::Malformed(
                format!(
                    "VerificationMethod controller does not match expected DID: {} != {}",
                    self.controller.as_did_str(),
                    expected_controller
                )
                .into(),
            )
            .into());
        }

        if self.id.did() != self.controller.as_did_str() {
            return Err(Error::Malformed(
                format!(
                    "VerificationMethod id ({}) DID segment ({}) does not match controller ({})",
                    self.id,
                    self.id.did(),
                    self.controller
                )
                .into(),
            ));
        }

        if let Some(kid) = self.public_key_jwk.kid_o.as_ref() {
            if kid != &self.id {
                return Err(Error::Malformed(
                    format!(
                        "publicKeyJwk 'kid' field ({}) must match VerificationMethod id ({})",
                        kid, self.id
                    )
                    .into(),
                ));
            }
        } else {
            return Err(Error::Malformed(
                "VerificationMethod publicKeyJwk is missing required 'kid' field".into(),
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
            iter_chain = Box::new(
                iter_chain
                    .chain([Some(kid.root_self_hash()), Some(kid.query_self_hash())].into_iter()),
            );
        }
        iter_chain
    }
    pub fn set_root_did_document_self_hash_slots_to(
        &mut self,
        hash: &mbx::MBHashStr,
    ) -> Result<()> {
        self.id.set_root_self_hash(hash);
        self.id.set_query_self_hash(hash);
        self.controller.set_root_self_hash(hash);
        if let Some(kid) = self.public_key_jwk.kid_o.as_mut() {
            kid.set_root_self_hash(hash);
            kid.set_query_self_hash(hash);
        }
        Ok(())
    }
    pub fn non_root_did_document_self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&'b mbx::MBHashStr>> + 'a> {
        let mut iter_chain: Box<dyn std::iter::Iterator<Item = Option<&'b mbx::MBHashStr>> + 'a> =
            Box::new(std::iter::empty());
        if let Some(kid) = self.public_key_jwk.kid_o.as_ref() {
            iter_chain = Box::new(iter_chain.chain(std::iter::once(Some(kid.query_self_hash()))));
        }
        iter_chain
    }
    pub fn set_non_root_did_document_self_hash_slots_to(
        &mut self,
        hash: &mbx::MBHashStr,
    ) -> Result<()> {
        self.id.set_query_self_hash(hash);
        if let Some(kid) = self.public_key_jwk.kid_o.as_mut() {
            kid.set_query_self_hash(hash);
        }
        Ok(())
    }
}
