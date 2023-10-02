/// The DID document metadata has three portions:
/// - data that is constant (once the DID is created, this metadata never changes).
/// - data that is idempotent (it starts unset but once it's set it never changes).
/// - data regarding its currency (it changes every time the DID document is updated).
/// See https://www.w3.org/TR/did-core/#did-document-metadata
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadata {
    #[serde(flatten)]
    pub constant: DIDDocumentMetadataConstant,
    #[serde(flatten)]
    pub idempotent: DIDDocumentMetadataIdempotent,
    #[serde(flatten)]
    pub currency: DIDDocumentMetadataCurrency,
}

impl DIDDocumentMetadata {
    pub fn new(
        created: time::OffsetDateTime,
        next_update_o: Option<time::OffsetDateTime>,
        next_version_id_o: Option<u32>,
        most_recent_update: time::OffsetDateTime,
        most_recent_version_id: u32,
    ) -> Self {
        Self {
            constant: DIDDocumentMetadataConstant { created },
            idempotent: DIDDocumentMetadataIdempotent {
                next_update_o,
                next_version_id_o,
            },
            currency: DIDDocumentMetadataCurrency {
                most_recent_update,
                most_recent_version_id,
            },
        }
    }
    pub fn created(&self) -> time::OffsetDateTime {
        self.constant.created
    }
    pub fn next_update_o(&self) -> Option<time::OffsetDateTime> {
        self.idempotent.next_update_o
    }
    pub fn next_version_id_o(&self) -> Option<u32> {
        self.idempotent.next_version_id_o
    }
    pub fn most_recent_update(&self) -> time::OffsetDateTime {
        self.currency.most_recent_update
    }
    pub fn most_recent_version_id(&self) -> u32 {
        self.currency.most_recent_version_id
    }
}

/// Immutable part of DID document metadata; meaning that these values are set upon DID creation
/// and never change.  See https://www.w3.org/TR/did-core/#did-document-metadata
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadataConstant {
    /// This is the "validFrom" timestamp of the first DID document for the DID (i.e. the timestamp of
    /// this DID's initial creation).
    #[serde(with = "time::serde::rfc3339")]
    pub created: time::OffsetDateTime,
}

/// Idempotent part of DID document metadata; meaning that these values begin unset and once they're
/// set, they never change.  See https://www.w3.org/TR/did-core/#did-document-metadata
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
/// document is updated.  See https://www.w3.org/TR/did-core/#did-document-metadata
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadataCurrency {
    /// This is the "validFrom" timestamp of the most recent DID document for this DID.
    #[serde(rename = "updated")]
    #[serde(with = "time::serde::rfc3339")]
    pub most_recent_update: time::OffsetDateTime,
    /// This is the "versionId" value of the most recent DID document for this DID.
    #[serde(rename = "versionId")]
    pub most_recent_version_id: u32,
}
