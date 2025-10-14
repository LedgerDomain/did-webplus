use crate::{is_truncated_to_milliseconds, truncated_to_seconds};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct LatestUpdateMetadata {
    /// DID document metadata SHOULD include an updated property to indicate the timestamp of the
    /// last Update operation for the document version which was resolved. The value of the property
    /// MUST follow the same formatting rules as the created property. The updated property is omitted
    /// if an Update operation has never been performed on the DID document. If an updated property
    /// exists, it can be the same value as the created property when the difference between the
    /// two timestamps is less than one second.
    ///
    /// did:webplus-specific notes:
    /// - The whole-seconds precision required by the DID spec is less than the milliseconds precision
    ///   used by did:webplus in its DID documents.
    /// - This value can only be correctly populated after contacting the DID's VDR to check for the
    ///   latest DID document.
    /// - If a DID resolution was able to be completed by returning a cached DID document that has
    ///   a cached successor DID document (and therefore its validity duration is known by cached
    ///   data), and therefore the VDR doesn't need to be contacted to determine latest DID document,
    ///   then this field will be omitted.
    #[serde(rename = "updated", with = "time::serde::rfc3339")]
    latest_update_time: time::OffsetDateTime,
    /// did-webplus-specific extension which represents the `updated` timestamp with milliseconds precision.
    #[serde(rename = "updatedMilliseconds", with = "time::serde::rfc3339")]
    latest_update_time_milliseconds: time::OffsetDateTime,
    /// DID document metadata SHOULD include a versionId property to indicate the version of the
    /// last Update operation for the document version which was resolved. The value of the property
    /// MUST be an ASCII string.
    ///
    /// did:webplus-specific notes:
    /// - The ASCII string format required by the DID spec is different than the integer-valued versionId
    ///   field in the did:webplus DID document.
    /// - This value can only be correctly populated after contacting the DID's VDR to check for the
    ///   latest DID document.
    /// - If a DID resolution was able to be completed by returning a cached DID document that has
    ///   a cached successor DID document (and therefore its validity duration is known by cached
    ///   data), and therefore the VDR doesn't need to be contacted to determine latest DID document,
    ///   then this field will be omitted.
    #[serde(rename = "versionId")]
    latest_version_id: String,
}

impl LatestUpdateMetadata {
    pub fn new(
        latest_update_time_milliseconds: time::OffsetDateTime,
        latest_version_id: u32,
    ) -> Self {
        if !is_truncated_to_milliseconds(latest_update_time_milliseconds) {
            panic!(
                "programmer error: latest_update_time_milliseconds must have at most millisecond precision"
            );
        }
        Self {
            latest_update_time: truncated_to_seconds(latest_update_time_milliseconds),
            latest_update_time_milliseconds,
            latest_version_id: latest_version_id.to_string(),
        }
    }
    pub fn latest_update_time(&self) -> time::OffsetDateTime {
        self.latest_update_time
    }
    pub fn latest_update_time_milliseconds(&self) -> time::OffsetDateTime {
        self.latest_update_time_milliseconds
    }
    pub fn latest_version_id(&self) -> &str {
        self.latest_version_id.as_str()
    }
}
