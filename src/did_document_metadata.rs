/// See https://www.w3.org/TR/did-core/#did-document-metadata
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadata {
    /// This is the "validFrom" timestamp of the first DID document for the DID (i.e. the timestamp of
    /// this DID's initial creation).
    #[serde(with = "time::serde::rfc3339")]
    pub created: time::OffsetDateTime,
    /// This is the "validFrom" timestamp of the most recent DID document for this DID.
    #[serde(rename = "updated")]
    #[serde(with = "time::serde::rfc3339")]
    pub most_recent_update: time::OffsetDateTime,
    /// This is the "validFrom" timestamp for DID document immediately following this one, if this
    /// is not the latest DID document.  If this is the latest DID document, then this field is None.
    #[serde(rename = "nextUpdate")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_update_o: Option<time::OffsetDateTime>,
    /// This is the "versionId" value of the most recent DID document for this DID.
    #[serde(rename = "versionId")]
    pub most_recent_version_id: u32,
    /// This is the "versionId" value for DID document immediately following this one, if this
    /// is not the latest DID document.  If this is the latest DID document, then this field is None.
    #[serde(rename = "nextVersionId")]
    pub next_version_id_o: Option<u32>,
}
