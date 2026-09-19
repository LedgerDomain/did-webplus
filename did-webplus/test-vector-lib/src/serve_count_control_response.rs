/// JSON body returned by a successful `PUT /control/serve-count`.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServeCountControlResponse {
    /// Echo of the vector directory request path that was updated.
    pub path: String,
    /// Active served DID-document (jsonl line) count after the update.
    pub served_did_document_count: u32,
    /// Byte length of the truncated jsonl body that GETs will see.
    pub served_octet_length: u64,
}
