/// JSON body returned by `GET /control/request-count`.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCountControlResponse {
    /// Vector directory request path that was queried.
    pub path: String,
    /// Number of GETs for that vector's `did-documents.jsonl` since last reset.
    pub request_count: u64,
}
