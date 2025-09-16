use std::ops::Deref;

use crate::{
    Error, PublicKeyMaterial, PublicKeySet, Result, RootLevelUpdateRules, ValidProofData, DID,
};

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
    pub self_hash: mbc::MBHash,
    /// This should be the self-hash of the previous DID document.  This relationship is what forms
    /// the microledger.
    #[serde(rename = "prevDIDDocumentSelfHash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_did_document_self_hash_o: Option<mbc::MBHash>,
    /// This defines the update authorization rules for this DID while this DID document is current.
    #[serde(rename = "updateRules")]
    pub update_rules: RootLevelUpdateRules,
    /// This is a list of the proofs that will be used to verify the authorization rules to update this DID
    /// while this DID document is current.
    #[serde(rename = "proofs")]
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub proof_v: Vec<String>,
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
    pub fn create_unsigned_root<'a>(
        did_hostname: &str,
        did_port_o: Option<u16>,
        did_path_o: Option<&str>,
        update_rules: RootLevelUpdateRules,
        valid_from: time::OffsetDateTime,
        public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
        hash_function: &impl selfhash::HashFunctionT<HashRef = mbc::MBHashStr>,
    ) -> Result<Self> {
        let self_hash_placeholder = hash_function.placeholder_hash();
        let did = DID::new(
            did_hostname,
            did_port_o,
            did_path_o,
            self_hash_placeholder.as_ref(),
        )
        .expect("pass");
        let self_hash_placeholder = self_hash_placeholder.into_owned();
        Ok(Self {
            did: did.clone(),
            self_hash: self_hash_placeholder,
            update_rules,
            proof_v: vec![],
            prev_did_document_self_hash_o: None,
            version_id: 0,
            valid_from,
            public_key_material: PublicKeyMaterial::new(did, public_key_set)?,
        })
    }
    pub fn create_unsigned_non_root<'a>(
        prev_did_document: &DIDDocument,
        update_rules: RootLevelUpdateRules,
        valid_from: time::OffsetDateTime,
        public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
        hash_function: &impl selfhash::HashFunctionT<HashRef = mbc::MBHashStr>,
    ) -> Result<Self> {
        use selfhash::HashRefT;
        if prev_did_document.self_hash.deref().is_placeholder() {
            return Err(Error::Malformed(
                "Previous DID document self-hash is a placeholder",
            ));
        }
        let did = prev_did_document.did.clone();
        let prev_did_document_self_hash = prev_did_document.self_hash.clone();
        let self_hash_placeholder = hash_function.placeholder_hash().into_owned();
        Ok(Self {
            did: did.clone(),
            self_hash: self_hash_placeholder,
            update_rules,
            proof_v: vec![],
            prev_did_document_self_hash_o: Some(prev_did_document_self_hash),
            version_id: prev_did_document.version_id() + 1,
            valid_from,
            public_key_material: PublicKeyMaterial::new(did, public_key_set)?,
        })
    }
    pub fn add_proof(&mut self, proof: String) {
        // TODO: Check that the proof is valid and that it matches any criteria in the update rules.
        // Or should any proofs be allowed?  They could be used for purposes outside the did:webplus spec.
        // Maybe this is only a debug check.
        self.proof_v.push(proof);
    }
    pub fn finalize(&mut self, prev_did_document_o: Option<&DIDDocument>) -> Result<&mbc::MBHash> {
        use selfhash::HashRefT;
        let hash_function = self.self_hash.hash_function();
        use selfhash::HashFunctionT;
        let hasher = hash_function.new_hasher();
        <Self as selfhash::SelfHashableT<mbc::MBHashStr>>::self_hash(self, hasher)?;
        self.verify_nonrecursive(prev_did_document_o)?;
        Ok(&self.self_hash)
    }

    pub fn is_root_did_document(&self) -> bool {
        self.prev_did_document_self_hash_o.is_none()
    }
    /// This method is what you should use if you want to canonically serialize this DID document (to a String).
    /// See also serialize_canonically_to_writer.
    pub fn serialize_canonically(&self) -> Result<String> {
        Ok(serde_json_canonicalizer::to_string(self).map_err(|_| {
            Error::Serialization("Failed to serialize DID document to canonical JSON (into String)")
        })?)
    }
    /// This method is what you should use if you want to canonically serialize this DID document (into
    /// a std::io::Writer).  See also serialize_canonically_to_vec.
    pub fn serialize_canonically_to_writer<W: std::io::Write>(&self, write: &mut W) -> Result<()> {
        serde_json_canonicalizer::to_writer(self, write).map_err(|_| {
            Error::Serialization(
                "Failed to serialize DID document to canonical JSON (into std::io::Write)",
            )
        })
    }

    // TEMP METHODS (maybe?)
    pub fn self_hash_o(&self) -> Option<&mbc::MBHash> {
        use selfhash::HashRefT;
        if self.self_hash.deref().is_placeholder() {
            None
        } else {
            Some(&self.self_hash)
        }
    }
    pub fn prev_did_document_self_hash_o(&self) -> Option<&mbc::MBHash> {
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
    ) -> Result<&mbc::MBHash> {
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
    pub fn verify_root_nonrecursive(&self) -> Result<&mbc::MBHash> {
        if !self.is_root_did_document() {
            return Err(Error::Malformed(
                "Expected a root DID document, but this is a non-root DID document.",
            ));
        }

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

        // This is the main cryptographic check, and is the most important.
        self.verify_self_hashes_and_update_rules(None)?;

        Ok(&self.self_hash)
    }
    pub fn verify_non_root_nonrecursive(
        &self,
        expected_prev_did_document: &DIDDocument,
    ) -> Result<&mbc::MBHash> {
        if self.is_root_did_document() {
            return Err(Error::Malformed(
                "Expected a non-root DID document, but this is a root DID document.",
            ));
        }
        use selfhash::SelfHashableT;
        let expected_prev_did_document_self_hash = expected_prev_did_document
            .verify_self_hashes()
            .map_err(|_| Error::Malformed("Previous DID document self-hash not valid"))?;

        // Check that id (i.e. the DID) matches the previous DID document's id (i.e. DID).
        // Note that this also implies that the hostname (and port number if present) embedded
        // in the id, matches that of the previous DID document's id.
        if self.did != expected_prev_did_document.did {
            return Err(Error::Malformed(
                "Non-root DID document's id must match the previous DID document's id",
            ));
        }

        // Check that prev_did_document_self_hash matches the expected_prev_did_document_b's self-hash.
        let prev_did_document_self_hash = self.prev_did_document_self_hash_o.as_ref().unwrap();
        if prev_did_document_self_hash.deref() != expected_prev_did_document_self_hash {
            return Err(Error::Malformed(
                "Non-root DID document's prev_did_document_self_hash must match the self-hash of the previous DID document",
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

        // This is the main cryptographic check, and is the most important.
        self.verify_self_hashes_and_update_rules(Some(expected_prev_did_document))?;

        Ok(&self.self_hash)
    }
    /// This method verifies the self-hashes, verifies all included proofs, and then verifies the
    /// update rules against the valid proof data.
    fn verify_self_hashes_and_update_rules(
        &self,
        expected_prev_did_document_o: Option<&DIDDocument>,
    ) -> Result<()> {
        // Note that if this check succeeds, then in particular, all the self-hash slots are equal,
        // and in particular, are equal to `self.self_hash`.
        use selfhash::SelfHashableT;
        self.verify_self_hashes()?;
        use selfhash::HashRefT;
        assert!(!self.self_hash.deref().is_placeholder());

        tracing::trace!(?self.self_hash, "verified self-hashes");

        if let Some(expected_prev_did_document) = expected_prev_did_document_o {
            // If this is a non-root DIDDocument, verify all proofs, storing the key IDs of the valid proofs.
            let mut valid_proof_data_v = Vec::with_capacity(self.proof_v.len());
            self.verify_proofs(Some(&mut valid_proof_data_v))?;

            tracing::trace!(?valid_proof_data_v, "verified proofs");

            // Verify the update rules using the valid proof data.
            use crate::VerifyRulesT;
            expected_prev_did_document
                .update_rules
                .verify_rules(&valid_proof_data_v)?;

            tracing::trace!(?valid_proof_data_v, "verified update rules");
        } else {
            // Even though the root DID document doesn't require any proofs, we will verify them anyway,
            // since it would not make sense to produce a root DID document with invalid proofs.
            self.verify_proofs(None)?;

            tracing::trace!("verified proofs for root DID document");
        }

        tracing::trace!("verified self-hashes and update rules");

        Ok(())
    }
    /// This will sign the DID document and return the proof (a detached, unencoded-payload JWS).
    /// It does not add the proof to the DID document.  `kid` should specify the verifier (i.e. pub key).
    pub fn sign<
        Signature: std::fmt::Debug + signature::SignatureEncoding,
        Signer: signature::Signer<Signature> + did_webplus_jws::JOSEAlgorithmT,
    >(
        &self,
        kid: String,
        signer: &Signer,
    ) -> Result<did_webplus_jws::JWS<'static>> {
        let bytes_to_sign = self.bytes_to_sign()?;
        Ok(did_webplus_jws::JWS::signed2(
            kid,
            &mut &*bytes_to_sign.as_slice(),
            did_webplus_jws::JWSPayloadPresence::Detached,
            // No reason to base64url-encode the payload, since it's detached anyway.
            did_webplus_jws::JWSPayloadEncoding::None,
            signer,
        )
        .map_err(|_| Error::SigningError("Error while signing DID document"))?)
    }
    /// If valid_proof_did_vo is Some, then it will be cleared and the DIDs of the valid proofs will be appended to it.
    // Note that the allow attributes on valid_proof_data_vo is necessary if the below feature flags are not enabled.
    fn verify_proofs(
        &self,
        #[allow(unused_mut, unused_variables)] mut valid_proof_data_vo: Option<
            &mut Vec<ValidProofData>,
        >,
    ) -> Result<()> {
        // Form the detached payload bytes.  This is done by removing all the proofs from the DID document,
        // setting all the self-hash slots to the placeholder hash value, and then serializing the DID document.
        // This allow attribute is necessary if the below feature flags are not enabled.
        #[allow(unused_variables)]
        let detached_payload_bytes = self.bytes_to_sign()?;

        for proof in self.proof_v.iter() {
            let jws = did_webplus_jws::JWS::try_from(proof.as_str())
                .map_err(|_| Error::Malformed("Failed to parse proof as JWS"))?;
            let pub_key: mbc::B64UPubKey = jws.header().kid.as_str().try_into().map_err(|_| {
                Error::Malformed(
                    "Failed to parse JWS header \"kid\" field as base64url-encoded multicodec-encoded public key",
                )
            })?;
            // TEMP HACK.  Ideally there would be a dyn version of signature::Verifier.
            let pub_key_decoded = pub_key.decoded().unwrap();
            // This allow attribute is necessary if the below feature flags are not enabled.
            #[allow(unused_variables)]
            let proof_was_verified = match pub_key_decoded.codec() {
                ssi_multicodec::ED25519_PUB => {
                    #[cfg(feature = "ed25519-dalek")]
                    {
                        let verifier = ed25519_dalek::VerifyingKey::try_from(
                            pub_key_decoded.data(),
                        )
                        .map_err(|_| {
                            Error::Malformed("Failed to parse Ed25519 public key from bytes")
                        })?;
                        let proof_was_verified = jws
                            .verify2(&verifier, Some(&mut detached_payload_bytes.as_slice()))
                            .is_ok();
                        proof_was_verified
                    }
                    #[cfg(not(feature = "ed25519-dalek"))]
                    {
                        panic!("Must enable the `ed25519-dalek` feature to verify using Ed25519 public keys");
                    }
                }
                ssi_multicodec::SECP256K1_PUB => {
                    #[cfg(feature = "k256")]
                    {
                        let verifier = k256::ecdsa::VerifyingKey::try_from(pub_key_decoded.data())
                            .map_err(|_| {
                                Error::Malformed("Failed to parse Secp256k1 public key from bytes")
                            })?;
                        let proof_was_verified = jws
                            .verify2::<k256::ecdsa::Signature, _>(
                                &verifier,
                                Some(&mut detached_payload_bytes.as_slice()),
                            )
                            .is_ok();
                        proof_was_verified
                    }
                    #[cfg(not(feature = "k256"))]
                    {
                        panic!(
                            "Must enable the `k256` feature to verify using Secp256k1 public keys"
                        );
                    }
                }
                ssi_multicodec::P256_PUB => {
                    #[cfg(feature = "p256")]
                    {
                        let verifier = p256::ecdsa::VerifyingKey::try_from(pub_key_decoded.data())
                            .map_err(|_| {
                                Error::Malformed("Failed to parse P-256 public key from bytes")
                            })?;
                        let proof_was_verified = jws
                            .verify2::<p256::ecdsa::Signature, _>(
                                &verifier,
                                Some(&mut detached_payload_bytes.as_slice()),
                            )
                            .is_ok();
                        proof_was_verified
                    }
                    #[cfg(not(feature = "p256"))]
                    {
                        panic!("Must enable the `p256` feature to verify using P-256 public keys");
                    }
                }
                _ => {
                    return Err(Error::Unsupported("Unsupported public key codec"));
                }
            };
            // This allow attribute is necessary if the above feature flags are not enabled.
            #[allow(unreachable_code)]
            if proof_was_verified {
                if let Some(valid_proof_data_vo) = valid_proof_data_vo.as_mut() {
                    valid_proof_data_vo.push(ValidProofData::from_key(pub_key));
                }
            }
        }
        Ok(())
    }
    /// Returns the bytes that should be signed to produce a proof.  In particular, this is the JCS-serialized
    /// JSON of the DID document, omitting the proofs, with the self-hash slots set to the placeholder hash value.
    fn bytes_to_sign(&self) -> Result<Vec<u8>> {
        let mut self_clone = self.clone();
        self_clone.proof_v.clear();
        // NOTE: All this could really be replaced with self.write_digest_data once that method accepts std::io::Write.
        use selfhash::HashRefT;
        let hash_function = self.self_hash.hash_function();
        use selfhash::{HashFunctionT, SelfHashableT};
        self_clone.set_self_hash_slots_to(&hash_function.placeholder_hash())?;
        Ok(self_clone.serialize_canonically()?.as_bytes().to_vec())
    }
}

impl selfhash::SelfHashableT<mbc::MBHashStr> for DIDDocument {
    fn write_digest_data(
        &self,
        hasher: &mut <<mbc::MBHashStr as selfhash::HashRefT>::HashFunction as selfhash::HashFunctionT>::Hasher,
    ) -> selfhash::Result<()> {
        selfhash::write_digest_data_using_jcs_2(self, hasher)
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> selfhash::Result<Box<dyn std::iter::Iterator<Item = Option<&'b mbc::MBHashStr>> + 'a>>
    {
        use selfhash::HashRefT;
        let self_hash_o = if self.self_hash.deref().is_placeholder() {
            None
        } else {
            Some(self.self_hash.deref())
        };
        // Depending on if this is a root DID document or a non-root DID document, there are different
        // self-hash slots to return.
        if self.is_root_did_document() {
            Ok(Box::new(
                std::iter::once(Some(self.did.root_self_hash()))
                    .chain(std::iter::once(self_hash_o))
                    .chain(self.public_key_material.root_did_document_self_hash_oi()),
            ))
        } else {
            Ok(Box::new(std::iter::once(self_hash_o)))
        }
    }
    fn set_self_hash_slots_to(&mut self, hash: &mbc::MBHashStr) -> selfhash::Result<()> {
        // Depending on if this is a root DID document or a non-root DID document, there are different
        // self-hash slots to assign to.
        if self.is_root_did_document() {
            self.public_key_material
                .set_root_did_document_self_hash_slots_to(hash)
                .map_err(|e| e.to_string())?;
            self.did.set_root_self_hash(hash);
            self.self_hash = hash.to_owned();
        } else {
            self.self_hash = hash.to_owned();
        }
        Ok(())
    }
}
