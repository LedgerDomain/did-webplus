use selfsign::SelfSignAndHashable;

use crate::{
    DIDDocumentCreateParams, DIDDocumentUpdateParams, DIDWebplus, Error, NonRootDIDDocument,
    PublicKeyMaterial, RootDIDDocument,
};

/// The generic data model for did:webplus DID documents.  There are additional constraints on the
/// data (it must be a root DID document or a non-root DID document), and there are conversion
/// functions to convert between this data model and the more constrained data models.
// TODO: Consider getting rid of RootDIDDocument and NonRootDIDDocument given how similar they are.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocument {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_did_document_self_hash_o: Option<selfhash::KERIHash<'static>>,
    /// This defines the timestamp at which this DID document becomes valid.
    #[serde(rename = "validFrom")]
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: time::OffsetDateTime,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    /// This should be exactly 1 greater than the previous DID document's version_id.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    /// Defines all the verification methods (i.e. public key material) for this DID document.
    #[serde(flatten)]
    pub public_key_material: PublicKeyMaterial,
}

impl DIDDocument {
    pub fn create_root<'a>(
        did_document_create_params: DIDDocumentCreateParams<'a>,
        hash_function: &dyn selfhash::HashFunction,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
        // Ensure that the signer's verifier is a member of did_document_create_params.capability_invocation_verifier_v.
        let keri_verifier = signer.verifier().to_keri_verifier().into_owned();
        if !did_document_create_params
            .public_key_set
            .capability_invocation_v
            .iter()
            .map(|v| v.to_keri_verifier())
            .any(|k| k == keri_verifier)
        {
            return Err(Error::Malformed(
                "signer's verifier must be a member of capability_invocation_verifier_v",
            ));
        }
        let did = DIDWebplus {
            host: did_document_create_params.did_webplus_host.to_string(),
            self_hash: hash_function.placeholder_hash().to_keri_hash().to_owned(),
        };
        let root_did_document = Self {
            id: did.clone(),
            self_hash_o: None,
            self_signature_o: None,
            self_signature_verifier_o: None,
            prev_did_document_self_hash_o: None,
            version_id: 0,
            valid_from: did_document_create_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                did,
                did_document_create_params.public_key_set,
            )?,
        };
        let hasher_b = hash_function.new_hasher();
        // TEMP HACK -- get rid of RootDIDDocument
        let mut root_did_document = RootDIDDocument::try_from(root_did_document).unwrap();
        root_did_document.self_sign_and_hash(signer, hasher_b)?;
        let root_did_document = DIDDocument::from(root_did_document);
        // Verify just for good measure.
        root_did_document
            .verify_root_nonrecursive()
            .expect("programmer error: DID document should be valid by construction");
        Ok(root_did_document)
    }
    pub fn update_from_previous(
        prev_did_document: &DIDDocument,
        did_document_update_params: DIDDocumentUpdateParams,
        hasher_b: Box<dyn selfhash::Hasher>,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
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
        let new_non_root_did_document = Self {
            id: did.clone(),
            self_hash_o: None,
            self_signature_o: None,
            self_signature_verifier_o: None,
            prev_did_document_self_hash_o: Some(prev_did_document.self_hash().clone()),
            version_id: prev_did_document.version_id() + 1,
            valid_from: did_document_update_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                did,
                did_document_update_params.public_key_set,
            )?,
        };
        // Self-sign.
        // TEMP HACK - get rid of NonRootDIDDocument
        let mut new_non_root_did_document =
            NonRootDIDDocument::try_from(new_non_root_did_document).unwrap();
        new_non_root_did_document.self_sign_and_hash(signer, hasher_b)?;
        let new_non_root_did_document = DIDDocument::from(new_non_root_did_document);
        // Verify it against the previous DID document.
        new_non_root_did_document
            .verify_non_root_nonrecursive(prev_did_document)
            .expect("programmer error: DID document should be valid by construction");
        Ok(new_non_root_did_document)
    }

    pub fn is_root_did_document(&self) -> bool {
        self.prev_did_document_self_hash_o.is_none()
    }

    // TEMP METHODS
    // TODO: Rename to did
    pub fn id(&self) -> &DIDWebplus {
        &self.id
    }
    // NOTE: This assumes this DIDDocument is self-hashed.
    pub fn self_hash(&self) -> &selfhash::KERIHash<'static> {
        self.self_hash_o.as_ref().expect("programmer error")
    }
    // NOTE: This assumes this DIDDocument is self-signed.
    pub fn self_signature(&self) -> &selfsign::KERISignature<'static> {
        self.self_signature_o.as_ref().expect("programmer error")
    }
    pub fn prev_did_document_self_hash_o(&self) -> Option<&selfhash::KERIHash<'static>> {
        self.prev_did_document_self_hash_o.as_ref()
    }
    pub fn valid_from(&self) -> time::OffsetDateTime {
        self.valid_from
    }
    pub fn version_id(&self) -> u32 {
        self.version_id
    }
    pub fn public_key_material(&self) -> &PublicKeyMaterial {
        &self.public_key_material
    }
    pub fn verify_nonrecursive(
        &self,
        expected_prev_did_document_o: Option<&DIDDocument>,
    ) -> Result<&selfhash::KERIHash<'static>, Error> {
        if self.is_root_did_document() {
            if expected_prev_did_document_o.is_some() {
                return Err(Error::Malformed(
                    "Root DID document cannot have a previous DID document.",
                ));
            }
            self.verify_root_nonrecursive()
        } else {
            if expected_prev_did_document_o.is_none() {
                return Err(Error::Malformed(
                    "Non-root DID document must have a previous DID document.",
                ));
            }
            self.verify_non_root_nonrecursive(expected_prev_did_document_o.unwrap())
        }
    }
    pub fn verify_root_nonrecursive(&self) -> Result<&selfhash::KERIHash<'static>, Error> {
        if !self.is_root_did_document() {
            return Err(Error::Malformed(
                "Expected a root DID document, but this is a non-root DID document.",
            ));
        }
        // Note that if this check succeeds, then in particular, all the expected self-signature slots
        // are equal, all the self-signature verifier slots are equal.
        self.verify_self_signatures_and_hashes()?;
        assert!(self.self_hash_o.is_some());
        assert!(self.self_signature_o.is_some());
        assert!(self.self_signature_verifier_o.is_some());

        // Check that self.valid_from is not before the UNIX epoch.
        if self.valid_from < time::OffsetDateTime::UNIX_EPOCH {
            return Err(Error::Malformed(
                "Non-root DID document's valid_from must be before the UNIX epoch (i.e. 1970-01-01T00:00:00Z)",
            ));
        }

        // Check initial version_id.
        if self.version_id != 0 {
            return Err(Error::Malformed(
                "Root DID document must have version_id == 0",
            ));
        }
        // Check key material
        self.public_key_material.verify(&self.id)?;

        Ok(self.self_hash_o.as_ref().unwrap())
    }
    pub fn verify_non_root_nonrecursive(
        &self,
        expected_prev_did_document: &DIDDocument,
    ) -> Result<&selfhash::KERIHash<'static>, Error> {
        if self.is_root_did_document() {
            return Err(Error::Malformed(
                "Expected a non-root DID document, but this is a root DID document.",
            ));
        }
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
        let prev_did_document_self_hash = self.prev_did_document_self_hash_o.as_ref().unwrap();
        if !prev_did_document_self_hash.equals(expected_prev_did_document_self_hash) {
            return Err(Error::Malformed(
                "Non-root DID document's prev_did_document_self_signature must match the self-signature of the previous DID document",
            ));
        }

        // Check that self.valid_from is not before the UNIX epoch.
        if self.valid_from < time::OffsetDateTime::UNIX_EPOCH {
            return Err(Error::Malformed(
                "Non-root DID document's valid_from must be before the UNIX epoch (i.e. 1970-01-01T00:00:00Z)",
            ));
        }

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
    pub fn verify_self_signatures_and_hashes<'a, 'b: 'a>(
        &'b self,
    ) -> Result<(&'a dyn selfsign::Signature, &'a dyn selfhash::Hash), Error> {
        // TODO: Impl SelfSignable etc for DIDDocument
        if self.is_root_did_document() {
            // TEMP HACK -- get rid of RootDIDDocument
            let root_did_document = RootDIDDocument::try_from(self.clone())?;
            root_did_document
                .verify_self_signatures_and_hashes()
                .map_err(|_| {
                    Error::InvalidSelfSignatureOrSelfHash(
                        "Root DID document has invalid self-signature",
                    )
                })?;
        } else {
            // TEMP HACK -- get rid of NonRootDIDDocument
            let non_root_did_document = NonRootDIDDocument::try_from(self.clone())?;
            non_root_did_document
                .verify_self_signatures_and_hashes()
                .map_err(|_| {
                    Error::InvalidSelfSignatureOrSelfHash(
                        "Non-root DID document has invalid self-signature",
                    )
                })?;
        }
        Ok((
            self.self_signature_o.as_ref().unwrap(),
            self.self_hash_o.as_ref().unwrap(),
        ))
    }
    // TEMP HACK
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("pass")
    }
}

impl TryFrom<DIDDocument> for RootDIDDocument {
    type Error = Error;
    fn try_from(did_document: DIDDocument) -> Result<Self, Self::Error> {
        if !did_document.is_root_did_document() {
            return Err(Error::Malformed(
                "Expected a root DID document, but this is a non-root DID document.",
            ));
        }
        Ok(Self {
            id: did_document.id,
            self_hash_o: did_document.self_hash_o,
            self_signature_o: did_document.self_signature_o,
            self_signature_verifier_o: did_document.self_signature_verifier_o,
            valid_from: did_document.valid_from,
            version_id: did_document.version_id,
            public_key_material: did_document.public_key_material,
        })
    }
}

impl TryFrom<DIDDocument> for NonRootDIDDocument {
    type Error = Error;
    fn try_from(did_document: DIDDocument) -> Result<Self, Self::Error> {
        if did_document.is_root_did_document() {
            return Err(Error::Malformed(
                "Expected a non-root DID document, but this is a root DID document.",
            ));
        }
        Ok(Self {
            id: did_document.id,
            self_hash_o: did_document.self_hash_o,
            self_signature_o: did_document.self_signature_o,
            self_signature_verifier_o: did_document.self_signature_verifier_o,
            prev_did_document_self_hash: did_document.prev_did_document_self_hash_o.unwrap(),
            valid_from: did_document.valid_from,
            version_id: did_document.version_id,
            public_key_material: did_document.public_key_material,
        })
    }
}

impl From<RootDIDDocument> for DIDDocument {
    fn from(root_did_document: RootDIDDocument) -> Self {
        Self {
            id: root_did_document.id,
            self_hash_o: root_did_document.self_hash_o,
            self_signature_o: root_did_document.self_signature_o,
            self_signature_verifier_o: root_did_document.self_signature_verifier_o,
            prev_did_document_self_hash_o: None,
            valid_from: root_did_document.valid_from,
            version_id: root_did_document.version_id,
            public_key_material: root_did_document.public_key_material,
        }
    }
}

impl From<NonRootDIDDocument> for DIDDocument {
    fn from(non_root_did_document: NonRootDIDDocument) -> Self {
        Self {
            id: non_root_did_document.id,
            self_hash_o: non_root_did_document.self_hash_o,
            self_signature_o: non_root_did_document.self_signature_o,
            self_signature_verifier_o: non_root_did_document.self_signature_verifier_o,
            prev_did_document_self_hash_o: Some(non_root_did_document.prev_did_document_self_hash),
            valid_from: non_root_did_document.valid_from,
            version_id: non_root_did_document.version_id,
            public_key_material: non_root_did_document.public_key_material,
        }
    }
}
