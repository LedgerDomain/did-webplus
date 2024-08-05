use crate::{DIDDocumentCreateParams, DIDDocumentUpdateParams, Error, PublicKeyMaterial, DID};
use selfsign::SelfSignAndHashable;

/// The generic data model for did:webplus DID documents.  There are additional constraints on the
/// data (it must be a root DID document or a non-root DID document), and there are conversion
/// functions to convert between this data model and the more constrained data models.
///
/// To deserialize from a string `s: &str` to DIDDocument, use `serde_json::from_str::<DIDDocument>(s)`.
///
/// Note that if you want to serialize this DID document, you MUST use serialize_canonically_to_vec
/// or serialize_canonically_to_writer.  This is because the serde_json::to_vec and serde_json::to_writer
/// methods do not produce canonical JSON.  JCS (JSON Canonicalization Scheme) is used for canonicalization,
/// and the serialize_canonically_to_vec and serialize_canonically_to_writer methods use the
/// serde_json_canonicalizer crate to do the serialization to this end.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocument {
    /// This is the DID.  This should be identical to the id field of the previous DID document.
    /// The serde-rename to "id" is intentional.  The DID spec mandates the field name "id", but the
    /// field value does have to be a DID.
    #[serde(rename = "id")]
    pub did: DID,
    /// This is the self-hash of the document.  The self-hash functions as the globally unique identifier
    /// for the DID document.
    #[serde(rename = "selfHash")]
    pub self_hash_o: Option<selfhash::KERIHash>,
    /// This is the self-signature of the document, proving control over the DID.  Because this is a
    /// non-root DID document, it will not match the self-signature that forms part of the did:webplus
    /// DID (see "id" field).
    #[serde(rename = "selfSignature")]
    pub self_signature_o: Option<selfsign::KERISignature>,
    /// This is the self-signature verifier of the document.  For a valid non-root DIDDocument (which in
    /// particular must be self-signed), this value should specify a key in in the capability_invocation_v
    /// field of the previous DID document's KeyMaterial.  Note that there is a translation step between
    /// KERIVerifier and VerificationMethod.
    #[serde(rename = "selfSignatureVerifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier>,
    /// This should be the self-signature field of the previous DID document.  This relationship is what forms
    /// the microledger.
    #[serde(rename = "prevDIDDocumentSelfHash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_did_document_self_hash_o: Option<selfhash::KERIHash>,
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
        let keri_verifier = signer.verifier().to_keri_verifier();
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
        let did = DID::new(
            did_document_create_params.did_host.as_ref(),
            did_document_create_params
                .did_path_o
                .as_ref()
                .map(|x| x.as_ref()),
            hash_function.placeholder_hash().to_keri_hash().as_ref(),
        )
        .expect("pass");
        let mut root_did_document = Self {
            did: did.clone(),
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
        // Self-sign-and-hash the new DID document.
        root_did_document.self_sign_and_hash(signer, hasher_b)?;
        // Verify just for good measure.
        root_did_document
            .verify_root_nonrecursive()
            .expect("programmer error: DID document should be valid by construction");
        Ok(root_did_document)
    }
    pub fn update_from_previous(
        prev_did_document: &DIDDocument,
        did_document_update_params: DIDDocumentUpdateParams,
        hash_function: &dyn selfhash::HashFunction,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
        prev_did_document
            .verify_self_signatures_and_hashes()
            .map_err(|_| {
                Error::InvalidDIDUpdateOperation(
                    "Previous DID document self-signatures/self-hashes not valid",
                )
            })?;
        // TODO: Put this into a function
        let keri_verifier = signer.verifier().to_keri_verifier();
        if !prev_did_document
            .public_key_material()
            .capability_invocation_key_id_fragment_v
            .iter()
            .all(|key_id_fragment| **key_id_fragment == keri_verifier)
        {
            return Err(Error::InvalidDIDUpdateOperation(
                "Unauthorized update operation; Signer's pub key not present in previous DID document's capability_invocation_v",
            ));
        }

        // Form the new DID document
        // let did = prev_did_document.parsed_did().clone();
        let mut new_non_root_did_document = Self {
            did: prev_did_document.did.clone(),
            self_hash_o: None,
            self_signature_o: None,
            self_signature_verifier_o: None,
            prev_did_document_self_hash_o: Some(prev_did_document.self_hash().clone()),
            version_id: prev_did_document.version_id() + 1,
            valid_from: did_document_update_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                prev_did_document.did.clone(),
                did_document_update_params.public_key_set,
            )?,
        };
        // Self-sign-and-hash the new DID document.
        let hasher_b = hash_function.new_hasher();
        new_non_root_did_document.self_sign_and_hash(signer, hasher_b)?;
        // Verify it against the previous DID document.
        new_non_root_did_document
            .verify_non_root_nonrecursive(prev_did_document)
            .expect("programmer error: DID document should be valid by construction");
        Ok(new_non_root_did_document)
    }

    pub fn is_root_did_document(&self) -> bool {
        self.prev_did_document_self_hash_o.is_none()
    }
    /// This method is what you should use if you want to canonically serialize this DID document (to a String).
    /// See also serialize_canonically_to_writer.
    pub fn serialize_canonically(&self) -> Result<String, Error> {
        let did_document_jcs_bytes = serde_json_canonicalizer::to_vec(self).map_err(|_| {
            Error::Serialization(
                "Failed to serialize DID document to canonical JSON (into Vec<u8>)",
            )
        })?;
        Ok(String::from_utf8(did_document_jcs_bytes).expect("this should not be possible"))
    }
    /// This method is what you should use if you want to canonically serialize this DID document (into
    /// a std::io::Writer).  See also serialize_canonically_to_vec.
    pub fn serialize_canonically_to_writer<W: std::io::Write>(
        &self,
        write: &mut W,
    ) -> Result<(), Error> {
        serde_json_canonicalizer::to_writer(self, write).map_err(|_| {
            Error::Serialization(
                "Failed to serialize DID document to canonical JSON (into std::io::Write)",
            )
        })
    }

    // TEMP METHODS
    // NOTE: This assumes this DIDDocument is self-hashed.
    pub fn self_hash(&self) -> &selfhash::KERIHash {
        self.self_hash_o.as_ref().expect("programmer error")
    }
    // NOTE: This assumes this DIDDocument is self-signed.
    pub fn self_signature(&self) -> &selfsign::KERISignature {
        self.self_signature_o.as_ref().expect("programmer error")
    }
    pub fn prev_did_document_self_hash_o(&self) -> Option<&selfhash::KERIHash> {
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
    ) -> Result<&selfhash::KERIHash, Error> {
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
    pub fn verify_root_nonrecursive(&self) -> Result<&selfhash::KERIHash, Error> {
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
        self.public_key_material.verify(&self.did)?;

        Ok(self.self_hash_o.as_ref().unwrap())
    }
    pub fn verify_non_root_nonrecursive(
        &self,
        expected_prev_did_document: &DIDDocument,
    ) -> Result<&selfhash::KERIHash, Error> {
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
        if self.did != expected_prev_did_document.did {
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
        self.public_key_material.verify(&self.did)?;
        // Now verify the self-signatures and self-hashes on this DID document.
        self.verify_self_signatures_and_hashes()?;
        assert!(self.self_hash_o.is_some());
        assert!(self.self_signature_o.is_some());
        assert!(self.self_signature_verifier_o.is_some());

        Ok(self.self_hash_o.as_ref().unwrap())
    }
}

impl selfhash::SelfHashable for DIDDocument {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        // Depending on if this is a root DID document or a non-root DID document, there are different
        // self-hash slots to return.
        if self.is_root_did_document() {
            Box::new(
                std::iter::once(Some(&self.did as &dyn selfhash::Hash))
                    .chain(std::iter::once(
                        self.self_hash_o
                            .as_ref()
                            .map(|self_hash| self_hash as &dyn selfhash::Hash),
                    ))
                    .chain(self.public_key_material.root_did_document_self_hash_oi()),
            )
        } else {
            Box::new(std::iter::once(
                self.self_hash_o
                    .as_ref()
                    .map(|self_hash| self_hash as &dyn selfhash::Hash),
            ))
        }
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        let keri_hash = hash.to_keri_hash().into_owned();
        // Depending on if this is a root DID document or a non-root DID document, there are different
        // self-hash slots to assign to.
        if self.is_root_did_document() {
            self.public_key_material
                .set_root_did_document_self_hash_slots_to(&keri_hash);
            self.did.set_self_hash(&keri_hash);
            self.self_hash_o = Some(keri_hash);
        } else {
            self.self_hash_o = Some(keri_hash);
        }
    }
}

impl selfsign::SelfSignable for DIDDocument {
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
        // Root and non-root DID documents both have the same self-signature slots.
        Box::new(std::iter::once(
            self.self_signature_o
                .as_ref()
                .map(|s| -> &dyn selfsign::Signature { s }),
        ))
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        // Root and non-root DID documents both have the same self-signature slots.
        let keri_signature = signature.to_keri_signature();
        self.self_signature_o = Some(keri_signature);
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Verifier>> + 'a> {
        // Root and non-root DID documents both have the same self-signature verifier slots.
        Box::new(std::iter::once(
            self.self_signature_verifier_o
                .as_ref()
                .map(|v| -> &dyn selfsign::Verifier { v }),
        ))
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn selfsign::Verifier) {
        // Root and non-root DID documents both have the same self-signature verifier slots.
        self.self_signature_verifier_o = Some(verifier.to_keri_verifier());
    }
}
