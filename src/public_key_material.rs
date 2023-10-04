use std::collections::{HashMap, HashSet};

use crate::{DIDKeyIdFragment, Error, KeyPurpose, PublicKeySet, VerificationMethod, DID};

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
        let mut verification_method_m: HashMap<selfsign::KERIVerifier<'a>, VerificationMethod> =
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
            .map(|v| v.to_keri_verifier().into_owned().into())
            .collect();
        let assertion_method_key_id_fragment_v = public_key_set
            .assertion_method_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into_owned().into())
            .collect();
        let key_agreement_key_id_fragment_v = public_key_set
            .key_agreement_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into_owned().into())
            .collect();
        let capability_invocation_key_id_fragment_v = public_key_set
            .capability_invocation_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into_owned().into())
            .collect();
        let capability_delegation_key_id_fragment_v = public_key_set
            .capability_delegation_v
            .into_iter()
            .map(|v| v.to_keri_verifier().into_owned().into())
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
    pub fn key_id_fragments_for_purpose(&self, key_purpose: KeyPurpose) -> &[DIDKeyIdFragment] {
        match key_purpose {
            KeyPurpose::Authentication => &self.authentication_key_id_fragment_v,
            KeyPurpose::AssertionMethod => &self.assertion_method_key_id_fragment_v,
            KeyPurpose::KeyAgreement => &self.key_agreement_key_id_fragment_v,
            KeyPurpose::CapabilityInvocation => &self.capability_invocation_key_id_fragment_v,
            KeyPurpose::CapabilityDelegation => &self.capability_delegation_key_id_fragment_v,
        }
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
        for (key_purpose_name, key_purpose_key_id_fragment_v) in [
            ("authentication", &self.authentication_key_id_fragment_v),
            ("assertion", &self.assertion_method_key_id_fragment_v),
            ("key agreement", &self.key_agreement_key_id_fragment_v),
            (
                "capability invocation",
                &self.capability_invocation_key_id_fragment_v,
            ),
            (
                "capability delegation",
                &self.capability_delegation_key_id_fragment_v,
            ),
        ] {
            for key_id_fragment in key_purpose_key_id_fragment_v.iter() {
                if !key_id_fragment_s.contains(&key_id_fragment) {
                    return Err(Error::MalformedKeyFragment(
                        key_purpose_name,
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
