use crate::{DIDWebplus, PublicKeyMaterial};

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
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: time::OffsetDateTime,
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

impl selfhash::SelfHashable for RootDIDDocument {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
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
