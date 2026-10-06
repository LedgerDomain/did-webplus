/// JSON body returned by a successful `PUT /control/vdr-failure`.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VDRFailureControlResponse {
    /// Vector directory request path that was updated.
    pub path: String,
    /// Whether jsonl GETs for this path currently fail.
    pub fail: bool,
}
