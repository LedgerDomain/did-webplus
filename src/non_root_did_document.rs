use crate::{DIDDocument, DIDDocumentUpdateParams, DIDWebplus, Error, PublicKeyMaterial};

/// Non-root DID document specific for did:webplus.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct NonRootDIDDocument {
    /// This is the DID.  This should be identical to the id field of the previous DID document.
    // TODO: Rename this field to 'did', and use serde rename for the JSON serialization.
    pub id: DIDWebplus,
    /// This is the self-hash of the document.  The self-hash functions as the globally unique identifier
    /// for the DID document.
    #[serde(rename = "selfHash")]
    pub self_hash_o: Option<selfhash::KERIHash<'static>>,
    /// This is the self-signature of the document, proving control over the DID.  Because this is a
    /// non-root DID document, it will not match the self-signature that forms part of the did:webplus
    /// DID (see "id" field).
    #[serde(rename = "selfSignature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
    /// This is the self-signature verifier of the document.  For a valid NonRootDIDDocument (which in
    /// particular must be self-signed), this value should specify a key in in the capability_invocation_v
    /// field of the previous DID document's KeyMaterial.  Note that there is a translation step between
    /// KERIVerifier and VerificationMethod.
    #[serde(rename = "selfSignatureVerifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    /// This should be the self-signature field of the previous DID document.  This relationship is what forms
    /// the microledger.
    #[serde(rename = "prevDIDDocumentSelfHash")]
    pub prev_did_document_self_hash: selfhash::KERIHash<'static>,
    /// This defines the timestamp at which this DID document becomes valid.
    #[serde(rename = "validFrom")]
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: time::OffsetDateTime,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    /// This should be exactly 1 greater than the previous DID document's version_id.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    /// Defines all the verification methods for this DID document.
    #[serde(flatten)]
    pub public_key_material: PublicKeyMaterial,
}

impl NonRootDIDDocument {
    pub fn update_from_previous(
        prev_did_document: DIDDocument,
        did_document_update_params: DIDDocumentUpdateParams,
        hasher_b: Box<dyn selfhash::Hasher>,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
        use selfsign::SelfSignAndHashable;
        prev_did_document
            .verify_self_signatures_and_hashes()
            .map_err(|_| {
                Error::InvalidDIDWebplusUpdateOperation(
                    "Previous DID document self-signatures/self-hashes not valid",
                )
            })?;
        // TODO: Put this into a function
        let keri_verifier = signer.verifier().to_keri_verifier().into_owned();
        if !prev_did_document
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
        let did = prev_did_document.id().clone();
        let mut new_non_root_did_document = NonRootDIDDocument {
            id: did.clone(),
            self_hash_o: None,
            self_signature_o: None,
            self_signature_verifier_o: None,
            prev_did_document_self_hash: prev_did_document.self_hash().clone(),
            version_id: prev_did_document.version_id() + 1,
            valid_from: did_document_update_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                did,
                did_document_update_params.public_key_set,
            )?,
        };
        // Self-sign.
        new_non_root_did_document.self_sign_and_hash(signer, hasher_b)?;
        // Verify it against the previous DID document.
        new_non_root_did_document
            .verify_nonrecursive(prev_did_document)
            .expect("programmer error: DID document should be valid by construction");
        Ok(new_non_root_did_document)
    }
    pub fn verify_nonrecursive(
        &self,
        expected_prev_did_document: DIDDocument,
    ) -> Result<&selfhash::KERIHash<'static>, Error> {
        use selfsign::SelfSignAndHashable;
        let (_, expected_prev_did_document_self_hash) =
            expected_prev_did_document.verify_self_signatures_and_hashes()?;

        // Check that id (i.e. the DID) matches the previous DID document's id (i.e. DID).
        // Note that this also implies that the host, embedded in the id, matches the host of the previous
        // DID document's id.
        if self.id != *expected_prev_did_document.id() {
            return Err(Error::Malformed(
                "Non-root DID document's id must match the previous DID document's id",
            ));
        }

        // Check that prev_did_document_self_signature matches the expected_prev_did_document_b's self-signature.
        use selfhash::Hash;
        if !self
            .prev_did_document_self_hash
            .equals(expected_prev_did_document_self_hash)
        {
            return Err(Error::Malformed(
                "Non-root DID document's prev_did_document_self_signature must match the self-signature of the previous DID document",
            ));
        }

        // TODO Check that self.valid_from is greater than 1970-01-01T00:00:00Z

        // Check monotonicity of version_time.
        if self.valid_from <= expected_prev_did_document.valid_from() {
            return Err(Error::Malformed(
                "Non-initial DID document must have version_time > prev_did_document.version_time",
            ));
        }
        // Check strict succession of version_id.
        if self.version_id != expected_prev_did_document.version_id() + 1 {
            return Err(Error::Malformed(
                "Non-root DID document must have version_id exactly equal to 1 plus the previous DID document's version_id",
            ));
        }
        // Check key material
        self.public_key_material.verify(&self.id)?;
        // Now verify the self-signatures and self-hashes on this DID document.
        self.verify_self_signatures_and_hashes()?;
        assert!(self.self_hash_o.is_some());
        assert!(self.self_signature_o.is_some());
        assert!(self.self_signature_verifier_o.is_some());

        Ok(self.self_hash_o.as_ref().unwrap())
    }
}

// NOTE: This could easily be derived because there is a clear and unique self-hash field.
impl selfhash::SelfHashable for NonRootDIDDocument {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        Box::new(std::iter::once(
            self.self_hash_o
                .as_ref()
                .map(|self_hash| self_hash as &dyn selfhash::Hash),
        ))
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        let keri_hash = hash.to_keri_hash().into_owned();
        self.self_hash_o = Some(keri_hash);
    }
}

// NOTE: This could easily be derived because there are clear and unique self-signature and
// self-signature verifier fields.
impl selfsign::SelfSignable for NonRootDIDDocument {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn selfsign::SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        selfsign::write_digest_data_using_jcs(self, signature_algorithm, verifier, hasher);
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
