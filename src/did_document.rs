use crate::{
    DIDWebplus, Error, VerificationMethod, DID_DOCUMENT_HASH_FUNCTION_CODE, SAID_HASH_FUNCTION_CODE,
};
use std::collections::HashMap;

/// DID document specific for did:webplus.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DIDDocument {
    // Should have the form "did:webplus:host.com:<SAID>", where SAID is derived from the root DID document.
    pub id: DIDWebplus,
    // This is what forms the microledger.  Should be None if and only if this is the first DID document
    // in the microledger.  Should this actually be the SAID of the previous DID document?
    #[serde(rename = "prevDIDDocumentHash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_did_document_hash_o: Option<String>,
    #[serde(rename = "validFrom")]
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
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

impl DIDDocument {
    pub fn hash(&self, hash_function_code: &said::derivation::HashFunctionCode) -> String {
        said::derivation::HashFunction::from(hash_function_code.clone())
            .derive(
                said::sad::SerializationFormats::JSON
                    .encode(self)
                    .unwrap()
                    .as_slice(),
            )
            .to_string()
    }
    // TODO: This probably actually belongs in DIDWebplusMicroledger, because it needs to
    // verify the DIDDocumentMetadata too.
    pub fn verify_did_microledger(
        &self,
        // TODO: Include DID document metadata (for "updated")
        did_document_m: &HashMap<String, DIDDocument>,
    ) -> Result<(), Error> {
        if self.version_id == 0 {
            self.verify_initial()
        } else {
            // Retrieved the hash-referenced previous DID document.
            let prev_did_document = did_document_m
                .get(
                    self.prev_did_document_hash_o
                        .as_ref()
                        .map(String::as_str)
                        .unwrap(),
                )
                .ok_or_else(|| {
                    Error::InvalidDIDMicroledger(
                        "prev_did_document_hash_o does not match any known DID document",
                    )
                })?;
            // Verify this one against the previous.
            self.verify_non_initial(prev_did_document)?;
            // Recurse.
            prev_did_document.verify_did_microledger(did_document_m)
        }
    }
    pub fn verify_initial(&self) -> Result<(), Error> {
        if self.prev_did_document_hash_o.is_some() {
            return Err(Error::Malformed(
                "Initial DID document must have prev_did_document_hash_o == None",
            ));
        }
        // TODO Check that self.valid_from is greater than 1970-01-01T00:00:00Z

        if self.version_id != 0 {
            return Err(Error::Malformed(
                "Initial DID document must have version_id == 0",
            ));
        }
        self.verify_verification_methods()?;
        Ok(())
    }
    pub fn verify_non_initial(&self, prev_did_document: &DIDDocument) -> Result<(), Error> {
        if self.prev_did_document_hash_o.is_none() {
            return Err(Error::Malformed(
                "Non-initial DID document must have prev_did_document_hash_o != None",
            ));
        }
        let prev_did_document_hash = self
            .prev_did_document_hash_o
            .as_ref()
            .map(String::as_str)
            .unwrap();
        // NOTE: This produces the SAID-formatted hash value which starts with the prefix.
        // TODO: Read the prefix and determine the hash function from that.
        let computed_prev_did_document_hash =
            prev_did_document.hash(&DID_DOCUMENT_HASH_FUNCTION_CODE);
        if prev_did_document_hash != computed_prev_did_document_hash {
            return Err(Error::Malformed(
                "Non-initial DID document must have prev_did_document_hash_o == Blake3_256(prev_did_document)",
            ));
        }
        // Check monotonicity of version_time.
        if self.valid_from <= prev_did_document.valid_from {
            return Err(Error::Malformed(
                "Non-initial DID document must have version_time > prev_did_document.version_time",
            ));
        }
        // Check strict succession of version_id.
        if self.version_id != prev_did_document.version_id + 1 {
            return Err(Error::Malformed(
                "Non-initial DID document must have version_id == prev_did_document.version_id + 1",
            ));
        }
        self.verify_verification_methods()?;
        Ok(())
    }
    pub fn verify_verification_methods(&self) -> Result<(), Error> {
        for verification_method in self.verification_method_v.iter() {
            verification_method.verify(&self.id)?;
        }
        Ok(())
    }
}

impl said::sad::SAD for DIDDocument {
    fn compute_digest(&mut self) {
        let said = said::derivation::HashFunction::from(SAID_HASH_FUNCTION_CODE)
            .derive(self.derivation_data().as_slice());

        // Traverse all the SAID-containing fields and place the SAID in them.
        self.id = self
            .id
            .said_derivation_value(&SAID_HASH_FUNCTION_CODE, Some(said.to_string().as_str()));
        for verification_method in self.verification_method_v.iter_mut() {
            *verification_method = verification_method
                .said_derivation_value(&SAID_HASH_FUNCTION_CODE, Some(said.to_string().as_str()));
        }
    }
    fn derivation_data(&self) -> Vec<u8> {
        const SERIALIZATION_FORMAT: said::sad::SerializationFormats =
            said::sad::SerializationFormats::JSON;

        let mut c = self.clone();

        // Traverse all the SAID-containing fields and place the placeholder in them.
        c.id = c.id.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None);
        for verification_method in c.verification_method_v.iter_mut() {
            *verification_method =
                verification_method.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None);
        }

        SERIALIZATION_FORMAT.encode(&c).unwrap()
    }
}
