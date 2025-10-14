use crate::{is_truncated_to_milliseconds, truncated_to_seconds};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct CreationMetadata {
    /// DID document metadata SHOULD include a created property to indicate the timestamp of the
    /// Create operation. The value of the property MUST be a string formatted as an XML Datetime
    /// normalized to UTC 00:00:00 and without sub-second decimal precision. For example:
    /// 2020-12-20T19:17:47Z.
    ///
    /// did:webplus-specific note: The whole-seconds precision required by the DID spec is less than the
    /// milliseconds precision used by did:webplus in its DID documents.
    #[serde(rename = "created", with = "time::serde::rfc3339")]
    creation_time: time::OffsetDateTime,
    /// did-webplus-specific extension which represents the `created` timestamp with milliseconds precision.
    #[serde(rename = "createdMilliseconds", with = "time::serde::rfc3339")]
    creation_time_milliseconds: time::OffsetDateTime,
}

impl CreationMetadata {
    pub fn new(creation_time_milliseconds: time::OffsetDateTime) -> Self {
        if !is_truncated_to_milliseconds(creation_time_milliseconds) {
            panic!(
                "programmer error: creation_time_milliseconds must have at most millisecond precision"
            );
        }
        Self {
            creation_time: truncated_to_seconds(creation_time_milliseconds),
            creation_time_milliseconds,
        }
    }
    pub fn creation_time(&self) -> time::OffsetDateTime {
        self.creation_time
    }
    pub fn creation_time_milliseconds(&self) -> time::OffsetDateTime {
        self.creation_time_milliseconds
    }
}
