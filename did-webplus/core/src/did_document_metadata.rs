/// Data structure which allows precise control over what metadata is derived when resolving a DID.
/// The most expensive one will usually be `currency`, given that it has to contact the DID's VDR
/// to determine if the DID document is the latest one.
#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct RequestedDIDDocumentMetadata {
    pub constant: bool,
    pub idempotent: bool,
    pub currency: bool,
}

impl RequestedDIDDocumentMetadata {
    pub fn none() -> Self {
        Self {
            constant: false,
            idempotent: false,
            currency: false,
        }
    }
    pub fn all() -> Self {
        Self {
            constant: true,
            idempotent: true,
            currency: true,
        }
    }
}

/// The DID document metadata has three portions:
/// - data that is constant (once the DID is created, this metadata never changes).
/// - data that is idempotent (it starts unset but once it's set it never changes).
/// - data regarding its currency (it changes every time the DID document is updated).
/// See <https://www.w3.org/TR/did-core/#did-document-metadata>
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadata {
    #[serde(flatten)]
    pub constant_o: Option<DIDDocumentMetadataConstant>,
    #[serde(flatten)]
    pub idempotent_o: Option<DIDDocumentMetadataIdempotent>,
    #[serde(flatten)]
    pub currency_o: Option<DIDDocumentMetadataCurrency>,
}

/// Immutable part of DID document metadata; meaning that these values are set upon DID creation
/// and never change.  See <https://www.w3.org/TR/did-core/#did-document-metadata>
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadataConstant {
    /// This is the "validFrom" timestamp of the first DID document for the DID (i.e. the timestamp of
    /// this DID's initial creation).
    #[serde(with = "time::serde::rfc3339")]
    pub created: time::OffsetDateTime,
}

/// Idempotent part of DID document metadata; meaning that these values begin unset and once they're
/// set, they never change.  See <https://www.w3.org/TR/did-core/#did-document-metadata>
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadataIdempotent {
    /// This is the "validFrom" timestamp for DID document immediately following this one, if this
    /// is not the latest DID document (at which point, this value will never change).  If this is
    /// the latest DID document, then this field is None (but this value will change to Some(_) if
    /// this DID is ever updated).
    #[serde(rename = "nextUpdate")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_update_o: Option<time::OffsetDateTime>,
    /// This is the "versionId" value for DID document immediately following this one, if this
    /// is not the latest DID document (at which point, this value will never change).  If this is
    /// the latest DID document, then this field is None (but this value will change to Some(_) if
    /// this DID is ever updated).
    #[serde(rename = "nextVersionId")]
    pub next_version_id_o: Option<u32>,
}

/// Currency portion of DID document metadata; meaning that these values change every time the DID
/// document is updated.  See <https://www.w3.org/TR/did-core/#did-document-metadata>
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadataCurrency {
    /// This is the "validFrom" timestamp of the most recent DID document for this DID.
    #[serde(rename = "updated")]
    #[serde(with = "time::serde::rfc3339")]
    pub most_recent_update: time::OffsetDateTime,
    /// This is the "versionId" value of the most recent DID document for this DID.
    #[serde(rename = "versionId")]
    pub most_recent_version_id: u32,
    // TODO: Add "resolved at" timestamp, which is defined by the VDR's clock.
    // Or call this "current as of" or something
}
