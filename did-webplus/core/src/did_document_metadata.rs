use crate::{CreationMetadata, LatestUpdateMetadata, NextUpdateMetadata};

/// See <https://www.w3.org/TR/did-1.0/#did-document-metadata> for definitions.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDDocumentMetadata {
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub creation_metadata_o: Option<CreationMetadata>,
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub next_update_metadata_o: Option<NextUpdateMetadata>,
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub latest_update_metadata_o: Option<LatestUpdateMetadata>,
    /// If a DID has been deactivated, DID document metadata MUST include this property with the
    /// boolean value true. If a DID has not been deactivated, this property is OPTIONAL, but if
    /// included, MUST have the boolean value false.
    #[serde(
        rename = "deactivated",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deactivated_o: Option<bool>,
}

impl DIDDocumentMetadata {
    pub fn creation_time_o(&self) -> Option<time::OffsetDateTime> {
        self.creation_metadata_o.as_ref().map(|x| x.creation_time())
    }
    pub fn creation_time_milliseconds_o(&self) -> Option<time::OffsetDateTime> {
        self.creation_metadata_o
            .as_ref()
            .map(|x| x.creation_time_milliseconds())
    }
    pub fn next_update_time_o(&self) -> Option<time::OffsetDateTime> {
        self.next_update_metadata_o
            .as_ref()
            .map(|x| x.next_update_time())
    }
    pub fn next_update_time_milliseconds_o(&self) -> Option<time::OffsetDateTime> {
        self.next_update_metadata_o
            .as_ref()
            .map(|x| x.next_update_time_milliseconds())
    }
    pub fn next_update_version_id_o(&self) -> Option<&str> {
        self.next_update_metadata_o
            .as_ref()
            .map(|x| x.next_version_id())
    }
    pub fn latest_update_time_o(&self) -> Option<time::OffsetDateTime> {
        self.latest_update_metadata_o
            .as_ref()
            .map(|x| x.latest_update_time())
    }
    pub fn latest_update_time_milliseconds_o(&self) -> Option<time::OffsetDateTime> {
        self.latest_update_metadata_o
            .as_ref()
            .map(|x| x.latest_update_time_milliseconds())
    }
    pub fn latest_update_version_id_o(&self) -> Option<&str> {
        self.latest_update_metadata_o
            .as_ref()
            .map(|x| x.latest_version_id())
    }
}
