use selfsign::SelfSignAndHashable;

use crate::{DIDDocumentCreateParams, DIDWebplus, Error, PublicKeyMaterial};

/// DID document specific for did:webplus.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct RootDIDDocument {
    // Should have the form "did:webplus:host.com:<self-signature>", where the self-signature is over this
    // root DID document.  The verifier (i.e. public key) is present in and committed to by this self-signed
    // document.
    // TODO: Rename this field to 'did', and use serde rename for the JSON serialization.
    pub id: DIDWebplus,
    // This is the self-hash of the document.  It should match the self-hash that forms part of the did:webplus.
    // The self-hash functions as the globally unique identifier for the DID document.
    #[serde(rename = "selfHash")]
    pub self_hash_o: Option<selfhash::KERIHash<'static>>,
    // This is the self-signature of the document, proving control over the DID.
    #[serde(rename = "selfSignature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
    // This is the self-signature verifier of the document.  For a valid RootDIDDocument (which in particular
    // must be self-signed), this value should specify a key in in the capability_invocation_v field of the
    // KeyMaterial.  Note that there is a translation step between KERIVerifier and VerificationMethod.
    #[serde(rename = "selfSignatureVerifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    /// This defines the timestamp at which this DID document becomes valid.
    #[serde(rename = "validFrom")]
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    /// This is always 0 in the root DID document.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    /// Defines all the verification methods for this DID document.  Because VerificationMethod-s must
    /// include the DIDWebplusWithFragment, they must also be handled when determining the
    /// self-hash portion of the DID.
    #[serde(flatten)]
    pub public_key_material: PublicKeyMaterial,
}

impl RootDIDDocument {
    pub fn create<'a>(
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
        let mut root_did_document = Self {
            id: did.clone(),
            self_hash_o: None,
            self_signature_o: None,
            self_signature_verifier_o: None,
            version_id: 0,
            valid_from: did_document_create_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                did,
                did_document_create_params.public_key_set,
            )?,
        };
        let hasher_b = hash_function.new_hasher();
        root_did_document.self_sign_and_hash(signer, hasher_b)?;
        // Verify just for good measure.
        root_did_document
            .verify_nonrecursive()
            .expect("programmer error: DID document should be valid by construction");
        Ok(root_did_document)
    }
    pub fn verify_nonrecursive(&self) -> Result<&selfhash::KERIHash<'static>, Error> {
        // Note that if this check succeeds, then in particular, all the expected self-signature slots
        // are equal, all the self-signature verifier slots are equal.
        self.verify_self_signatures_and_hashes()?;
        assert!(self.self_hash_o.is_some());
        assert!(self.self_signature_o.is_some());
        assert!(self.self_signature_verifier_o.is_some());

        // TODO Check that self.valid_from is greater than 1970-01-01T00:00:00Z
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
}

impl selfhash::SelfHashable for RootDIDDocument {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        // NOTE: This is a generic JSON-serialization-based implementation.
        let mut c = self.clone();
        c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash());
        // Not sure if serde_json always produces the same output... TODO: Use JSONC or JCS probably
        serde_json::to_writer(hasher, &c).unwrap();
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        Box::new(
            std::iter::once(Some(&self.id.self_hash as &dyn selfhash::Hash))
                .chain(std::iter::once(
                    self.self_hash_o
                        .as_ref()
                        .map(|self_hash| self_hash as &dyn selfhash::Hash),
                ))
                .chain(self.public_key_material.root_did_document_self_hash_oi()),
        )
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        let keri_hash = hash.to_keri_hash().into_owned();
        self.id.self_hash = keri_hash.clone();
        self.self_hash_o = Some(keri_hash.clone());
        self.public_key_material
            .set_root_did_document_self_hash_slots_to(&keri_hash);
    }
}

impl selfsign::SelfSignable for RootDIDDocument {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn selfsign::SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        assert!(verifier.key_type() == signature_algorithm.key_type());
        assert!(signature_algorithm
            .message_digest_hash_function()
            .equals(hasher.hash_function()));
        // NOTE: This is a generic JSON-serialization-based implementation.
        let mut c = self.clone();
        c.set_self_signature_slots_to(&signature_algorithm.placeholder_keri_signature());
        c.set_self_signature_verifier_slots_to(verifier);
        // Not sure if serde_json always produces the same output... TODO: Use JSONC or JCS probably
        serde_json::to_writer(hasher, &c).unwrap();
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
