use crate::{DIDWebplus, PublicKeyMaterial};

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
