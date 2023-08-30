use crate::{DIDDocumentTrait, DIDWebplus, Error, KeyMaterial};

// TEMP hacks because of https://github.com/THCLab/cesrox/issues/5
use said::sad::{SerializationFormats, SAD};
use serde::Serialize;

/// Non-root DID document specific for did:webplus.
#[derive(Clone, Debug, said::sad::SAD, serde::Deserialize, serde::Serialize)]
pub struct NonRootDIDDocument {
    // Should have the form "did:webplus:host.com:<SAID>", where SAID is derived from the root DID document.
    pub id: DIDWebplus,
    // This is the SAID of this document.  Because this is not the root DID document, this SAID will
    // not match the SAID that forms part of the did:webplus DID (see "id" field).
    #[serde(rename = "said")]
    #[said]
    pub said_o: Option<said::SelfAddressingIdentifier>,
    // This should be the "said" field of the previous DID document.  This relationship is what forms
    // the microledger.
    #[serde(rename = "prevDIDDocumentSAID")]
    // pub prev_did_document_said: String,
    pub prev_did_document_said: said::SelfAddressingIdentifier,
    #[serde(rename = "validFrom")]
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    // This should be exactly 1 greater than the previous DID document's version_id.
    #[serde(rename = "versionId")]
    pub version_id: u32,
    #[serde(flatten)]
    pub key_material: KeyMaterial,
}

impl NonRootDIDDocument {
    /// This assumes that the expected_prev_did_document_b has already been verified, so that
    /// this call doesn't recurse fully, and only performs one level of verification for the
    /// DID's microledger.
    pub fn verify(
        &self,
        expected_prev_did_document_b: Box<&dyn DIDDocumentTrait>,
    ) -> Result<(), Error> {
        if self.said_o.is_none() {
            return Err(Error::Malformed("Non-root DID document must have a SAID"));
        }
        // Check that prev_did_document_said matches the expected_prev_did_document_b's SAID.
        if self.prev_did_document_said != *expected_prev_did_document_b.said() {
            return Err(Error::Malformed(
                "Non-root DID document's prev_did_document_said must match the SAID of the previous DID document",
            ));
        }

        // TODO Check that self.valid_from is greater than 1970-01-01T00:00:00Z

        // Check monotonicity of version_time.
        if self.valid_from <= *expected_prev_did_document_b.valid_from() {
            return Err(Error::Malformed(
                "Non-initial DID document must have version_time > prev_did_document.version_time",
            ));
        }
        // Check strict succession of version_id.
        if self.version_id != expected_prev_did_document_b.version_id() + 1 {
            return Err(Error::Malformed(
                "Non-root DID document must have version_id exactly equal to 1 plus the previous DID document's version_id",
            ));
        }
        // Check key material
        self.key_material.verify(&self.id)?;
        // Now verify that the SAID for this DID document is correct.
        {
            let mut c = self.clone();
            c.compute_digest();
            assert!(c.said_o.is_some());
            if c.said_o.as_ref().unwrap() != self.said_o.as_ref().unwrap() {
                return Err(Error::Malformed(
                    "Non-root DID document SAID did not match computed SAID value",
                ));
            }
        }

        Ok(())
    }
}

impl DIDDocumentTrait for NonRootDIDDocument {
    fn id(&self) -> &DIDWebplus {
        &self.id
    }
    fn said(&self) -> &said::SelfAddressingIdentifier {
        self.said_o.as_ref().unwrap()
    }
    fn prev_did_document_said_o(&self) -> Option<&said::SelfAddressingIdentifier> {
        Some(&self.prev_did_document_said)
    }
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.valid_from
    }
    fn version_id(&self) -> u32 {
        self.version_id
    }
    fn key_material(&self) -> &crate::KeyMaterial {
        &self.key_material
    }
}

// TODO: Consider making a formal list of constraints for all the various verification processes.
