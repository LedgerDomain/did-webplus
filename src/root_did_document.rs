use selfsign::{SelfSignable, SignatureAlgorithm};

use crate::{DIDDocumentCreateParams, DIDDocumentTrait, DIDWebplus, Error, PublicKeyMaterial};

/// DID document specific for did:webplus.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct RootDIDDocument {
    // Should have the form "did:webplus:host.com:<SAID>", where SAID is derived from this root DID document.
    pub id: DIDWebplus,
    // This is the self-signature of the document.  It should match the self-signature that forms part of
    // the did:webplus DID (see "id" field).
    #[serde(rename = "selfSignature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
    // This is the self-signature verifier of the document.  For a valid RootDIDDocument (which in particular
    // must be self-signed), this value should specify a key in in the capability_invocation_v field of the
    // KeyMaterial.  Note that there is a translation step between KERIVerifier and VerificationMethod.
    #[serde(rename = "selfSignatureVerifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    #[serde(rename = "validFrom")]
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    /// This is always 0 in the root DID document.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    // Because VerificationMethod-s must include the DIDWebplusWithFragment, they must also be handled when
    // determining the self-signature portion of the DID.
    #[serde(flatten)]
    pub public_key_material: PublicKeyMaterial,
}

impl RootDIDDocument {
    pub fn create<'a>(
        did_document_create_params: DIDDocumentCreateParams<'a>,
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
            self_signature: signer.signature_algorithm().placeholder_keri_signature(),
        };
        let mut root_did_document = Self {
            id: did.clone(),
            self_signature_o: None,
            self_signature_verifier_o: None,
            version_id: 0,
            valid_from: did_document_create_params.valid_from,
            public_key_material: PublicKeyMaterial::new(
                did,
                did_document_create_params.public_key_set,
            )?,
        };
        root_did_document.self_sign(signer)?;
        // Verify just for good measure.
        root_did_document
            .verify_root()
            .expect("programmer error: DID document should be valid by construction");
        Ok(root_did_document)
    }
}

impl DIDDocumentTrait for RootDIDDocument {
    fn id(&self) -> &DIDWebplus {
        &self.id
    }
    fn self_signature(&self) -> &selfsign::KERISignature<'static> {
        self.self_signature_o.as_ref().unwrap()
    }
    fn prev_did_document_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>> {
        None
    }
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.valid_from
    }
    fn version_id(&self) -> u32 {
        self.version_id
    }
    fn public_key_material(&self) -> &PublicKeyMaterial {
        &self.public_key_material
    }
    fn verify_nonrecursive(
        &self,
        expected_prev_did_document_bo: Option<Box<&dyn DIDDocumentTrait>>,
    ) -> Result<&selfsign::KERISignature<'static>, Error> {
        if expected_prev_did_document_bo.is_some() {
            return Err(Error::Malformed(
                "Root DID document must not have a previous DID document",
            ));
        }

        // Note that if this check succeeds, then in particular, all the expected self-signature slots
        // are equal, all the self-signature verifier slots are equal.
        self.verify_self_signatures()?;
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

        Ok(self.self_signature_o.as_ref().unwrap())
    }
    fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("pass")
    }
}

impl selfsign::SelfSignable for RootDIDDocument {
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
        Box::new(
            std::iter::once(Some(&self.id.self_signature as &dyn selfsign::Signature))
                .chain(std::iter::once(
                    self.self_signature_o
                        .as_ref()
                        .map(|s| -> &dyn selfsign::Signature { s }),
                ))
                .chain(
                    self.public_key_material
                        .root_did_document_self_signature_oi(),
                ),
        )
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        let keri_signature = signature.to_keri_signature().into_owned();
        self.id.self_signature = keri_signature.clone();
        self.self_signature_o = Some(keri_signature.clone());
        self.public_key_material
            .set_root_did_document_self_signature_slots_to(&keri_signature);
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
