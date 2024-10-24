use crate::{Error, Result};
use did_webplus::DIDDocument;
use time::OffsetDateTime;

#[derive(Debug)]
pub struct DIDDocRecord {
    pub self_hash: String,
    pub did: String,
    // TODO: Make this u32?  Or would it be better to just use i64 for all contexts?
    pub version_id: i64,
    pub valid_from: OffsetDateTime,
    pub did_document_jcs: String,
}

impl DIDDocRecord {
    /// This is rather pedantic, but it's important to guarantee the consistency of DIDDocRecord-s
    /// because the whole validation scheme of did:webplus depends on it.
    pub fn validate_consistency(&self) -> Result<()> {
        let did_document = serde_json::from_str::<DIDDocument>(self.did_document_jcs.as_str())
            .map_err(|err| {
                Error::RecordCorruption(
                    format!("Malformed DID doc; parse error was {}", err).into(),
                    self.self_hash.to_string().into(),
                )
            })?;

        let did_document_self_hash = did_document.self_hash_o.as_ref().ok_or_else(|| {
            Error::RecordCorruption(
                "Parsed DID doc is missing \"selfHash\" field".into(),
                self.self_hash.to_string().into(),
            )
        })?;
        if did_document_self_hash.as_str() != self.self_hash.as_str() {
            return Err(Error::RecordCorruption(
                format!(
                    "Parsed DID doc \"selfHash\" field {} doesn't match that of stored record",
                    did_document_self_hash
                )
                .into(),
                self.self_hash.to_string().into(),
            ));
        }

        if did_document.did.as_str() != self.did.as_str() {
            return Err(Error::RecordCorruption(
                format!(
                    "Parsed DID doc did (\"id\" field) {:?} doesn't match stored record's did {:?}",
                    did_document.did, self.did
                )
                .into(),
                self.self_hash.to_string().into(),
            ));
        }

        if did_document.version_id as i64 != self.version_id {
            return Err(Error::RecordCorruption(format!("Parsed DID doc \"versionId\" field {} doesn't match stored record's version_id {}", did_document.version_id, self.version_id).into(), self.self_hash.to_string().into()));
        }

        if did_document.valid_from != self.valid_from {
            return Err(Error::RecordCorruption(format!("Parsed DID doc \"validFrom\" field {} doesn't match stored record's valid_from {}", did_document.valid_from, self.valid_from).into(), self.self_hash.to_string().into()));
        }

        use selfsign::SelfSignAndHashable;
        did_document
            .verify_self_signatures_and_hashes()
            .map_err(|err| {
                Error::RecordCorruption(
                    format!(
                        "Parsed DID doc failed to verify self-signatures and hashes: {}",
                        err
                    )
                    .into(),
                    self.self_hash.to_string().into(),
                )
            })?;

        Ok(())
    }
}
