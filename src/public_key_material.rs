use std::collections::{HashMap, HashSet};

use crate::{
    DIDKeyIdFragment, Error, KeyPurpose, KeyPurposeFlags, PublicKeySet, VerificationMethod, DID,
};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyMaterial {
    #[serde(rename = "verificationMethod")]
    pub verification_method_v: Vec<VerificationMethod>,
    #[serde(rename = "authentication")]
    pub authentication_key_id_fragment_v: Vec<DIDKeyIdFragment>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method_key_id_fragment_v: Vec<DIDKeyIdFragment>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement_key_id_fragment_v: Vec<DIDKeyIdFragment>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation_key_id_fragment_v: Vec<DIDKeyIdFragment>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation_key_id_fragment_v: Vec<DIDKeyIdFragment>,
}

impl PublicKeyMaterial {
    pub fn new<'a>(
        did: DID,
        public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
    ) -> Result<Self, Error> {
        let mut verification_method_m: HashMap<selfsign::KERIVerifier, VerificationMethod> =
            HashMap::new();
        for public_key in public_key_set.iter() {
            let verification_method =
                VerificationMethod::json_web_key_2020(did.clone(), *public_key);
            verification_method_m.insert(public_key.to_keri_verifier(), verification_method);
        }
        let verification_method_v = verification_method_m.into_values().collect();

        let authentication_key_id_fragment_v = public_key_set
            .authentication_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into())
            .collect();
        let assertion_method_key_id_fragment_v = public_key_set
            .assertion_method_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into())
            .collect();
        let key_agreement_key_id_fragment_v = public_key_set
            .key_agreement_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into())
            .collect();
        let capability_invocation_key_id_fragment_v = public_key_set
            .capability_invocation_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into())
            .collect();
        let capability_delegation_key_id_fragment_v = public_key_set
            .capability_delegation_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into())
            .collect();

        Ok(Self {
            verification_method_v,
            authentication_key_id_fragment_v,
            assertion_method_key_id_fragment_v,
            key_agreement_key_id_fragment_v,
            capability_invocation_key_id_fragment_v,
            capability_delegation_key_id_fragment_v,
        })
    }
    /// Returns the key ids for the given KeyPurpose, i.e. the elements of the "authentication", "assertionMethod",
    /// "keyAgreement", "capabilityInvocation", and "capabilityDelegation" fields of the DID document.
    pub fn key_id_fragments_for_purpose(&self, key_purpose: KeyPurpose) -> &[DIDKeyIdFragment] {
        match key_purpose {
            KeyPurpose::Authentication => self.authentication_key_id_fragment_v.as_slice(),
            KeyPurpose::AssertionMethod => self.assertion_method_key_id_fragment_v.as_slice(),
            KeyPurpose::KeyAgreement => self.key_agreement_key_id_fragment_v.as_slice(),
            KeyPurpose::CapabilityInvocation => {
                self.capability_invocation_key_id_fragment_v.as_slice()
            }
            KeyPurpose::CapabilityDelegation => {
                self.capability_delegation_key_id_fragment_v.as_slice()
            }
        }
    }
    /// Returns the KeyPurposeFlags representing all the KeyPurposes that the given verification method allows.
    /// This is defined by the the presence of the key id in the list of key ids for the specified purpose
    /// (i.e. "authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", and "capabilityDelegation"
    /// fields of the DID document).
    pub fn key_purpose_flags_for_key_id_fragment(
        &self,
        key_id_fragment: &DIDKeyIdFragment,
    ) -> KeyPurposeFlags {
        let mut key_purpose_flags = KeyPurposeFlags::NONE;
        for key_purpose in KeyPurpose::VARIANTS {
            let key_id_fragment_v = self.key_id_fragments_for_purpose(key_purpose);
            if key_id_fragment_v.contains(key_id_fragment) {
                key_purpose_flags |= KeyPurposeFlags::from(key_purpose);
            }
        }
        key_purpose_flags
    }
    pub fn verify(&self, expected_controller: &DID) -> Result<(), Error> {
        for verification_method in &self.verification_method_v {
            verification_method.verify(expected_controller)?;
        }
        let key_id_fragment_s = self
            .verification_method_v
            .iter()
            .map(|verification_method| &verification_method.id.fragment)
            .collect::<HashSet<&DIDKeyIdFragment>>();
        for key_purpose in KeyPurpose::VARIANTS {
            let key_id_fragment_v = self.key_id_fragments_for_purpose(key_purpose);
            for key_id_fragment in key_id_fragment_v.iter() {
                if !key_id_fragment_s.contains(&key_id_fragment) {
                    return Err(Error::MalformedKeyFragment(
                        key_purpose.as_str(),
                        "key id fragment does not match any listed verification method",
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn root_did_document_self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        let mut iter_chain: Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> =
            Box::new(std::iter::empty());
        for verification_method in &self.verification_method_v {
            iter_chain = Box::new(
                iter_chain.chain(
                    verification_method
                        .root_did_document_self_hash_oi()
                        .into_iter(),
                ),
            );
        }
        iter_chain
    }
    pub fn set_root_did_document_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        for verification_method in &mut self.verification_method_v {
            verification_method.set_root_did_document_self_hash_slots_to(hash);
        }
    }
}
