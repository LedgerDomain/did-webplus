use crate::{is_truncated_to_milliseconds, truncated_to_seconds};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct NextUpdateMetadata {
    /// DID document metadata MAY include a nextUpdate property if the resolved document version
    /// is not the latest version of the document. It indicates the timestamp of the next Update
    /// operation. The value of the property MUST follow the same formatting rules as the created property.
    ///
    /// did:webplus-specific note: The whole-seconds precision required by the DID spec is less than the
    /// milliseconds precision used by did:webplus in its DID documents.
    #[serde(rename = "nextUpdate", with = "time::serde::rfc3339")]
    next_update_time: time::OffsetDateTime,
    /// did-webplus-specific extension which represents the `nextUpdate` timestamp with milliseconds precision.
    #[serde(rename = "nextUpdateMilliseconds", with = "time::serde::rfc3339")]
    next_update_time_milliseconds: time::OffsetDateTime,
    /// DID document metadata MAY include a nextVersionId property if the resolved document version
    /// is not the latest version of the document. It indicates the version of the next Update
    /// operation. The value of the property MUST be an ASCII string.
    ///
    /// did:webplus-specific note: The ASCII string format required by the DID spec is different than
    /// the integer-valued versionId field in the did:webplus DID document.
    #[serde(rename = "nextVersionId")]
    next_version_id: String,
}

impl NextUpdateMetadata {
    pub fn new(next_update_time_milliseconds: time::OffsetDateTime, next_version_id: u32) -> Self {
        if !is_truncated_to_milliseconds(next_update_time_milliseconds) {
            panic!(
                "programmer error: next_update_time_milliseconds must have at most millisecond precision"
            );
        }
        Self {
            next_update_time: truncated_to_seconds(next_update_time_milliseconds),
            next_update_time_milliseconds,
            next_version_id: next_version_id.to_string(),
        }
    }
    pub fn next_update_time(&self) -> time::OffsetDateTime {
        self.next_update_time
    }
    pub fn next_update_time_milliseconds(&self) -> time::OffsetDateTime {
        self.next_update_time_milliseconds
    }
    pub fn next_version_id(&self) -> &str {
        self.next_version_id.as_str()
    }
}
