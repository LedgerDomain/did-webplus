use said::sad::SAD;

use crate::{DIDDocumentTrait, DIDWebplus, Error, VerificationMethod, SAID_HASH_FUNCTION_CODE};

/// DID document specific for did:webplus.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct RootDIDDocument {
    // Should have the form "did:webplus:host.com:<SAID>", where SAID is derived from this root DID document.
    pub id: DIDWebplus,
    // This is the SAID of this document.  It should match the SAID that forms part of the did:webplus
    // DID (see "id" field).
    #[serde(rename = "said")]
    pub said_o: Option<said::SelfAddressingIdentifier>,
    #[serde(rename = "validFrom")]
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    /// This is always 0 in the root DID document.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    // Because VerificationMethod must include the DIDWebplusWithFragment, it must also be handled when
    // determining the SAID portion of the DID.
    #[serde(rename = "verificationMethod")]
    pub verification_method_v: Vec<VerificationMethod>,
    #[serde(rename = "authentication")]
    pub authentication_fragment_v: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_fragment_v: Vec<String>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement_fragment_v: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation_fragment_v: Vec<String>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation_fragment_v: Vec<String>,
}

impl RootDIDDocument {
    pub fn verify(&self) -> Result<(), Error> {
        if self.said_o.is_none() {
            return Err(Error::Malformed("Root DID document must have a SAID"));
        }
        // The path portion of the DIDWebplus should be the SAID, so it must match this DID document's SAID.
        {
            use std::str::FromStr;
            let id_component_path_said = said::SelfAddressingIdentifier::from_str(self.id.components().path).map_err(|_| Error::Malformed("Root DID document's 'id' field must be a DIDWebplus value with a well-formed SAID as its path component (usually this is a 44-digit base64 string starting with 'E')"))?;
            if *self.said_o.as_ref().unwrap() != id_component_path_said {
                return Err(Error::Malformed(
                    "Root DID document's SAID must match the SAID in the document's 'id' field",
                ));
            }
        }

        // TODO Check that self.valid_from is greater than 1970-01-01T00:00:00Z
        // Check initial version_id.
        if self.version_id != 0 {
            return Err(Error::Malformed(
                "Root DID document must have version_id == 0",
            ));
        }
        // Check verification methods.
        for verification_method in self.verification_method_v.iter() {
            verification_method.verify(&self.id)?;
        }
        // Now verify that the SAID for this DID document is correct.
        {
            let mut c = self.clone();
            c.compute_digest();
            assert!(c.said_o.is_some());
            if c.said_o.as_ref().unwrap() != self.said_o.as_ref().unwrap() {
                return Err(Error::Malformed(
                    "Root DID document SAID did not match computed SAID value",
                ));
            }
        }

        Ok(())
    }
}

impl DIDDocumentTrait for RootDIDDocument {
    fn id(&self) -> &DIDWebplus {
        &self.id
    }
    fn said(&self) -> &said::SelfAddressingIdentifier {
        self.said_o.as_ref().unwrap()
    }
    fn prev_did_document_said_o(&self) -> Option<&said::SelfAddressingIdentifier> {
        None
    }
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.valid_from
    }
    fn version_id(&self) -> u32 {
        self.version_id
    }
    fn verification_method_v(&self) -> &[VerificationMethod] {
        self.verification_method_v.as_slice()
    }
    fn authentication_fragment_v(&self) -> &[String] {
        self.authentication_fragment_v.as_slice()
    }
    fn assertion_fragment_v(&self) -> &[String] {
        self.assertion_fragment_v.as_slice()
    }
    fn key_agreement_fragment_v(&self) -> &[String] {
        self.key_agreement_fragment_v.as_slice()
    }
    fn capability_invocation_fragment_v(&self) -> &[String] {
        self.capability_invocation_fragment_v.as_slice()
    }
    fn capability_delegation_fragment_v(&self) -> &[String] {
        self.capability_delegation_fragment_v.as_slice()
    }
}

impl said::sad::SAD for RootDIDDocument {
    fn compute_digest(&mut self) {
        let said = said::derivation::HashFunction::from(SAID_HASH_FUNCTION_CODE)
            .derive(self.derivation_data().as_slice());
        let said_string = said.to_string();

        // Traverse all the SAID-containing fields and place the SAID in them.
        self.id = self
            .id
            .said_derivation_value(&SAID_HASH_FUNCTION_CODE, Some(said_string.clone().as_str()));
        self.said_o = Some(said);
        for verification_method in self.verification_method_v.iter_mut() {
            *verification_method = verification_method
                .said_derivation_value(&SAID_HASH_FUNCTION_CODE, Some(said_string.as_str()));
        }
    }
    fn derivation_data(&self) -> Vec<u8> {
        const SERIALIZATION_FORMAT: said::sad::SerializationFormats =
            said::sad::SerializationFormats::JSON;

        let mut c = self.clone();

        // Traverse all the SAID-containing fields and place the placeholder in them.
        c.id = c.id.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None);
        c.said_o = None;
        for verification_method in c.verification_method_v.iter_mut() {
            *verification_method =
                verification_method.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None);
        }

        SERIALIZATION_FORMAT.encode(&c).unwrap()
    }
}
