use selfsign::SignatureAlgorithm;

use crate::{DIDDocumentTrait, DIDDocumentUpdateParams, DIDWebplus, Error, PublicKeyMaterial};

/// Non-root DID document specific for did:webplus.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct NonRootDIDDocument {
    // Should have the form "did:webplus:host.com:<SAID>", where SAID is derived from the root DID document.
    pub id: DIDWebplus,
    // This is the self-signature of the document.  Because this is a non-root DID document, it will not
    // match the self-signature that forms part of the did:webplus DID (see "id" field).
    #[serde(rename = "selfSignature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
    // This is the self-signature verifier of the document.  For a valid NonRootDIDDocument (which in
    // particular must be self-signed), this value should specify a key in in the capability_invocation_v
    // field of the previous DID document's KeyMaterial.  Note that there is a translation step between
    // KERIVerifier and VerificationMethod.
    #[serde(rename = "selfSignatureVerifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    // This should be the self-signature field of the previous DID document.  This relationship is what forms
    // the microledger.
    #[serde(rename = "prevDIDDocumentSelfSignature")]
    pub prev_did_document_self_signature: selfsign::KERISignature<'static>,
    #[serde(rename = "validFrom")]
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    // This should be exactly 1 greater than the previous DID document's version_id.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    #[serde(flatten)]
    pub public_key_material: PublicKeyMaterial,
}

impl NonRootDIDDocument {
    pub fn update_from_previous(
        prev_did_document_b: Box<&dyn DIDDocumentTrait>,
        did_document_update_params: DIDDocumentUpdateParams,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
        prev_did_document_b.verify_self_signatures().map_err(|_| {
            Error::InvalidDIDWebplusUpdateOperation(
                "Previous DID document self-signature not valid",
            )
        })?;
        // TODO: Put this into a function
        let keri_verifier = signer.verifier().to_keri_verifier().into_owned();
        if !prev_did_document_b
            .public_key_material()
            .capability_invocation_key_id_fragment_v
            .iter()
            .all(|key_id_fragment| **key_id_fragment == keri_verifier)
        {
            return Err(Error::InvalidDIDWebplusUpdateOperation(
                "Unauthorized update operation; Signer's pub key not present in previous DID document's capability_invocation_v",
            ));
        }

        // Form the new DID document
        let did = prev_did_document_b.id().clone();
        let mut new_non_root_did_document = NonRootDIDDocument {
            id: did.clone(),
            self_signature_o: None,
            self_signature_verifier_o: None,
            prev_did_document_self_signature: prev_did_document_b.self_signature().clone(),
            version_id: prev_did_document_b.version_id() + 1,
            valid_from: did_document_update_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                did,
                did_document_update_params.public_key_set,
            )?,
        };
        // Self-sign.
        use selfsign::SelfSignable;
        new_non_root_did_document.self_sign(signer)?;
        // Verify it against the previous DID document.
        new_non_root_did_document
            .verify_non_root_nonrecursive(prev_did_document_b)
            .expect("programmer error: DID document should be valid by construction");
        Ok(new_non_root_did_document)
    }
}

impl DIDDocumentTrait for NonRootDIDDocument {
    fn id(&self) -> &DIDWebplus {
        &self.id
    }
    fn self_signature(&self) -> &selfsign::KERISignature<'static> {
        self.self_signature_o.as_ref().unwrap()
    }
    fn prev_did_document_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>> {
        Some(&self.prev_did_document_self_signature)
    }
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.valid_from
    }
    fn version_id(&self) -> u32 {
        self.version_id
    }
    fn public_key_material(&self) -> &crate::PublicKeyMaterial {
        &self.public_key_material
    }
    fn verify_nonrecursive(
        &self,
        expected_prev_did_document_bo: Option<Box<&dyn DIDDocumentTrait>>,
    ) -> Result<&selfsign::KERISignature<'static>, Error> {
        if expected_prev_did_document_bo.is_none() {
            return Err(Error::Malformed(
                "Non-root DID document must have a previous DID document",
            ));
        }
        let expected_prev_did_document_b = expected_prev_did_document_bo.unwrap();
        let expected_prev_did_document_self_signature =
            expected_prev_did_document_b.verify_self_signatures()?;

        // Check that id (i.e. the DID) matches the previous DID document's id (i.e. DID).
        if self.id != *expected_prev_did_document_b.id() {
            return Err(Error::Malformed(
                "Non-root DID document's id must match the previous DID document's id",
            ));
        }

        // Check that prev_did_document_self_signature matches the expected_prev_did_document_b's self-signature.
        if self.prev_did_document_self_signature
            != expected_prev_did_document_self_signature.to_keri_signature()
        {
            return Err(Error::Malformed(
                "Non-root DID document's prev_did_document_self_signature must match the self-signature of the previous DID document",
            ));
        }

        // TODO Check that self.valid_from is greater than 1970-01-01T00:00:00Z

        // Check monotonicity of version_time.
        if self.valid_from <= *expected_prev_did_document_b.valid_from() {
            return Err(Error::Malformed(
                "Non-initial DID document must have version_time > prev_did_document.version_time",
            ));
        }
        // Check strict succession of version_id.
        if self.version_id != expected_prev_did_document_b.version_id() + 1 {
            return Err(Error::Malformed(
                "Non-root DID document must have version_id exactly equal to 1 plus the previous DID document's version_id",
            ));
        }
        // Check key material
        self.public_key_material.verify(&self.id)?;
        // Now verify the self-signature on this DID document.
        use selfsign::SelfSignable;
        self.verify_self_signatures()?;
        assert!(self.self_signature_o.is_some());
        assert!(self.self_signature_verifier_o.is_some());

        Ok(self.self_signature_o.as_ref().unwrap())
    }
    fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("pass")
    }
}

// NOTE: This could easily be derived because there is a clear and unique self-signature and self-signature verifier.
impl selfsign::SelfSignable for NonRootDIDDocument {
    fn write_digest_data(
        &self,
        signature_algorithm: SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut selfsign::Hasher,
    ) {
        assert!(verifier.key_type() == signature_algorithm.key_type());
        assert!(signature_algorithm.message_digest_hash_function() == hasher.hash_function());
        // NOTE: This is a generic JSON-serialization-based implementation.
        let mut c = self.clone();
        c.set_self_signature_slots_to(&signature_algorithm.placeholder_keri_signature());
        c.set_self_signature_verifier_slots_to(verifier);
        // Not sure if serde_json always produces the same output...
        serde_json::to_writer(hasher, &c).expect("pass");
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Signature>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_o
                .as_ref()
                .map(|s| -> &dyn selfsign::Signature { s }),
        ))
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        let keri_signature = signature.to_keri_signature().into_owned();
        self.self_signature_o = Some(keri_signature);
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Verifier>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_verifier_o
                .as_ref()
                .map(|v| -> &dyn selfsign::Verifier { v }),
        ))
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn selfsign::Verifier) {
        self.self_signature_verifier_o = Some(verifier.to_keri_verifier().into_owned());
    }
}

// TODO: Consider making a formal list of constraints for all the various verification processes.
