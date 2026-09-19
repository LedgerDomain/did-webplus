use did_webplus_core::DIDDocument;

/// Facts about one DID document version needed by the resolution-semantics oracle.
///
/// Built from a validated microledger; version indices are contiguous from 0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownDidDocumentVersion {
    /// `versionId` of this document (must equal its index in the microledger slice).
    pub version_id: u32,
    /// `selfHash` of this document.
    pub self_hash: mbx::MBHash,
    /// `validFrom` timestamp (millisecond precision).
    pub valid_from: time::OffsetDateTime,
    /// `true` when `updateRules` is `UpdatesDisallowed` (tombstone / deactivated).
    pub deactivated: bool,
}

impl KnownDidDocumentVersion {
    /// Extract oracle facts from a [`DIDDocument`].
    pub fn from_did_document(did_document: &DIDDocument) -> anyhow::Result<Self> {
        Ok(Self {
            version_id: did_document.version_id,
            self_hash: did_document.self_hash.clone(),
            valid_from: did_document.valid_from()?,
            deactivated: did_document.is_deactivated(),
        })
    }
}
