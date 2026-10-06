use crate::{is_truncated_to_milliseconds, truncated_to_seconds};

/// Metadata that describes the resolved DID document version itself.
///
/// See the `did:webplus` spec section on DID Document Metadata for `versionId`, `updated`,
/// and `updatedMilliseconds`.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct ResolvedDocumentMetadata {
    /// Version of the resolved DID document. Always present. The value MUST be an ASCII string.
    ///
    /// did:webplus-specific note: The ASCII string format required by the DID spec is different
    /// than the integer-valued `versionId` field in the did:webplus DID document.
    #[serde(rename = "versionId")]
    version_id: String,
    /// Timestamp of the Update that produced this document version, i.e. the document's
    /// `validFrom` truncated to whole seconds. Omitted when `versionId` is 0 (root document;
    /// no Update has been performed for it).
    ///
    /// did:webplus-specific note: The whole-seconds precision required by the DID spec is less
    /// than the milliseconds precision used by did:webplus in its DID documents.
    #[serde(
        rename = "updated",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    updated_o: Option<time::OffsetDateTime>,
    /// did:webplus-specific extension which represents the `updated` timestamp with milliseconds
    /// precision (the document's `validFrom`). Present iff `updated` is present.
    #[serde(
        rename = "updatedMilliseconds",
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    updated_milliseconds_o: Option<time::OffsetDateTime>,
}

impl ResolvedDocumentMetadata {
    /// Build metadata for a resolved document from its `validFrom` and `versionId`.
    ///
    /// When `version_id` is 0, `updated` and `updatedMilliseconds` are omitted.
    pub fn new(valid_from: time::OffsetDateTime, version_id: u32) -> Self {
        if !is_truncated_to_milliseconds(valid_from) {
            panic!("programmer error: valid_from must have at most millisecond precision");
        }
        let (updated_o, updated_milliseconds_o) = if version_id == 0 {
            (None, None)
        } else {
            (Some(truncated_to_seconds(valid_from)), Some(valid_from))
        };
        Self {
            version_id: version_id.to_string(),
            updated_o,
            updated_milliseconds_o,
        }
    }
    /// Version id of the resolved DID document, as an ASCII string.
    pub fn version_id(&self) -> &str {
        self.version_id.as_str()
    }
    /// Whole-seconds `updated` timestamp, if present.
    pub fn updated_o(&self) -> Option<time::OffsetDateTime> {
        self.updated_o
    }
    /// Milliseconds-precision `updatedMilliseconds` timestamp, if present.
    pub fn updated_milliseconds_o(&self) -> Option<time::OffsetDateTime> {
        self.updated_milliseconds_o
    }
}
