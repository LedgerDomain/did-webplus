use crate::{
    DIDStr, Error, KeyPurpose, KeyPurposeFlags, PublicKeySet, RelativeKeyResource,
    RelativeKeyResourceStr, Result, VerificationMethod, DID,
};
use selfsign::KERIVerifierStr;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyMaterial {
    #[serde(rename = "verificationMethod")]
    pub verification_method_v: Vec<VerificationMethod>,
    #[serde(rename = "authentication")]
    pub authentication_relative_key_resource_v: Vec<RelativeKeyResource>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method_relative_key_resource_v: Vec<RelativeKeyResource>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement_relative_key_resource_v: Vec<RelativeKeyResource>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation_relative_key_resource_v: Vec<RelativeKeyResource>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation_relative_key_resource_v: Vec<RelativeKeyResource>,
}

impl PublicKeyMaterial {
    pub fn new<'a>(
        did: DID,
        public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
    ) -> Result<Self> {
        let mut verification_method_m: HashMap<selfsign::KERIVerifier, VerificationMethod> =
            HashMap::new();
        for &public_key in public_key_set.iter() {
            let verification_method =
                VerificationMethod::json_web_key_2020(did.clone(), public_key);
            verification_method_m.insert(
                public_key.to_keri_verifier().into_owned(),
                verification_method,
            );
        }
        let verification_method_v = verification_method_m.into_values().collect();

        let authentication_relative_key_resource_v = public_key_set
            .authentication_v
            .into_iter()
            .map(|v| RelativeKeyResource::from_fragment(&v.to_keri_verifier()))
            .collect();
        let assertion_method_relative_key_resource_v = public_key_set
            .assertion_method_v
            .into_iter()
            .map(|v| RelativeKeyResource::from_fragment(&v.to_keri_verifier()))
            .collect();
        let key_agreement_relative_key_resource_v = public_key_set
            .key_agreement_v
            .into_iter()
            .map(|v| RelativeKeyResource::from_fragment(&v.to_keri_verifier()))
            .collect();
        let capability_invocation_relative_key_resource_v = public_key_set
            .capability_invocation_v
            .into_iter()
            .map(|v| RelativeKeyResource::from_fragment(&v.to_keri_verifier()))
            .collect();
        let capability_delegation_relative_key_resource_v = public_key_set
            .capability_delegation_v
            .into_iter()
            .map(|v| RelativeKeyResource::from_fragment(&v.to_keri_verifier()))
            .collect();

        Ok(Self {
            verification_method_v,
            authentication_relative_key_resource_v,
            assertion_method_relative_key_resource_v,
            key_agreement_relative_key_resource_v,
            capability_invocation_relative_key_resource_v,
            capability_delegation_relative_key_resource_v,
        })
    }
    /// Returns the key ids for the given KeyPurpose, i.e. the elements of the "authentication", "assertionMethod",
    /// "keyAgreement", "capabilityInvocation", and "capabilityDelegation" fields of the DID document.
    pub fn relative_key_resources_for_purpose(
        &self,
        key_purpose: KeyPurpose,
    ) -> impl std::iter::Iterator<Item = &RelativeKeyResourceStr> {
        let relative_key_resource_v = match key_purpose {
            KeyPurpose::Authentication => &self.authentication_relative_key_resource_v,
            KeyPurpose::AssertionMethod => &self.assertion_method_relative_key_resource_v,
            KeyPurpose::KeyAgreement => &self.key_agreement_relative_key_resource_v,
            KeyPurpose::CapabilityInvocation => &self.capability_invocation_relative_key_resource_v,
            KeyPurpose::CapabilityDelegation => &self.capability_delegation_relative_key_resource_v,
        };
        relative_key_resource_v
            .iter()
            .map(|x| x.as_relative_resource_str())
    }
    /// Returns the KeyPurposeFlags representing all the KeyPurposes that the given verification method allows.
    /// This is defined by the the presence of the key id in the list of key ids for the specified purpose
    /// (i.e. "authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", and "capabilityDelegation"
    /// fields of the DID document).
    pub fn key_purpose_flags_for_key_id_fragment(
        &self,
        key_id_fragment: &KERIVerifierStr,
    ) -> KeyPurposeFlags {
        let mut key_purpose_flags = KeyPurposeFlags::NONE;
        for key_purpose in KeyPurpose::VARIANTS {
            if self
                .relative_key_resources_for_purpose(key_purpose)
                .any(|relative_key_resource| relative_key_resource.fragment() == key_id_fragment)
            {
                key_purpose_flags |= KeyPurposeFlags::from(key_purpose);
            }
        }
        key_purpose_flags
    }
    pub fn verify(&self, expected_controller: &DIDStr) -> Result<()> {
        for verification_method in &self.verification_method_v {
            verification_method.verify(expected_controller)?;
        }
        let relative_key_resource_s = self
            .verification_method_v
            .iter()
            .map(|verification_method| verification_method.id.relative_resource())
            .collect::<HashSet<&RelativeKeyResourceStr>>();
        for key_purpose in KeyPurpose::VARIANTS {
            for relative_key_resource in self.relative_key_resources_for_purpose(key_purpose) {
                if !relative_key_resource_s.contains(relative_key_resource) {
                    return Err(Error::MalformedKeyId(
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
    ) -> Box<dyn std::iter::Iterator<Item = Option<&'b dyn selfhash::Hash>> + 'a> {
        let mut iter_chain: Box<
            dyn std::iter::Iterator<Item = Option<&'b dyn selfhash::Hash>> + 'a,
        > = Box::new(std::iter::empty());
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
    pub fn set_root_did_document_self_hash_slots_to(
        &mut self,
        hash: &dyn selfhash::Hash,
    ) -> Result<()> {
        for verification_method in &mut self.verification_method_v {
            verification_method.set_root_did_document_self_hash_slots_to(hash)?;
        }
        Ok(())
    }
}
