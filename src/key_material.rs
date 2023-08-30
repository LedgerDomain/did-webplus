use std::collections::HashSet;

use crate::{DIDWebplus, Error, VerificationMethod};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct KeyMaterial {
    #[serde(rename = "verificationMethod")]
    pub verification_method_v: Vec<VerificationMethod>,
    #[serde(rename = "authentication")]
    pub authentication_fragment_v: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method_fragment_v: Vec<String>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement_fragment_v: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation_fragment_v: Vec<String>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation_fragment_v: Vec<String>,
}

impl KeyMaterial {
    pub fn verify(&self, expected_controller: &DIDWebplus) -> Result<(), Error> {
        for verification_method in &self.verification_method_v {
            verification_method.verify(expected_controller)?;
        }
        let fragment_s = self
            .verification_method_v
            .iter()
            .map(|verification_method| verification_method.id.components().fragment_o.unwrap())
            .collect::<HashSet<&str>>();
        for (key_purpose_name, key_purpose_fragment_v) in [
            ("authentication", &self.authentication_fragment_v),
            ("assertion", &self.assertion_method_fragment_v),
            ("key agreement", &self.key_agreement_fragment_v),
            (
                "capability invocation",
                &self.capability_invocation_fragment_v,
            ),
            (
                "capability delegation",
                &self.capability_delegation_fragment_v,
            ),
        ] {
            for fragment in key_purpose_fragment_v.iter() {
                if !fragment.starts_with("#") {
                    return Err(Error::MalformedKeyFragment(
                        key_purpose_name,
                        "key id fragment must start with '#'",
                    ));
                }
                if !fragment_s.contains(fragment.strip_prefix('#').unwrap()) {
                    return Err(Error::MalformedKeyFragment(
                        key_purpose_name,
                        "key id fragment does not match any listed verification method",
                    ));
                }
            }
        }
        Ok(())
    }
}
