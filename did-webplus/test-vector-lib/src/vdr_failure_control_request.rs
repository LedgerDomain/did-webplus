/// Body for `PUT /control/vdr-failure`.
///
/// `path` is the vector directory request path (no leading `/`, no filename),
/// matching keys in [`crate::TestVectorServerAppState::vector_body_m`].
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VDRFailureControlRequest {
    /// Vector directory request path (e.g. `uRootHash` or `tv/demo/uRootHash`).
    pub path: String,
    /// When `true`, GETs for this vector's `did-documents.jsonl` return HTTP 503.
    pub fail: bool,
}
