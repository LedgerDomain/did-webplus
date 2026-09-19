/// Body for `PUT /control/serve-count`.
///
/// `path` is the vector directory request path (no leading `/`, no filename),
/// matching keys in [`crate::TestVectorServerAppState::vector_body_m`] (and the
/// URL path used to fetch `did-documents.jsonl`).
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServeCountControlRequest {
    /// Vector directory request path (e.g. `uRootHash` or `tv/demo/uRootHash`).
    pub path: String,
    /// How many leading `did-documents.jsonl` lines the VDR should serve.
    pub served_did_document_count: u32,
}
