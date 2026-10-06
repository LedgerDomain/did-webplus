/// RFC 9457 problem-details object used as DID Resolution Metadata `error`.
///
/// The `type` URI is the normative conformance signal; `title` and `detail` are advisory.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDResolutionError {
    /// URI identifying the error. This is the normative conformance signal.
    #[serde(rename = "type")]
    r#type: String,
    /// Short, human-readable summary of the problem type. Advisory only.
    title: String,
    /// Human-readable explanation specific to this occurrence. Advisory only.
    detail: String,
}

impl DIDResolutionError {
    /// Malformed DID (`https://www.w3.org/ns/did#INVALID_DID`).
    pub fn invalid_did(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://www.w3.org/ns/did#INVALID_DID".to_string(),
            title: "Invalid DID".to_string(),
            detail: detail.into(),
        }
    }
    /// Malformed DID URL / query, or conflicting query params
    /// (`https://www.w3.org/ns/did#INVALID_DID_URL`).
    pub fn invalid_did_url(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://www.w3.org/ns/did#INVALID_DID_URL".to_string(),
            title: "Invalid DID URL".to_string(),
            detail: detail.into(),
        }
    }
    /// Invalid DID Resolution Options (`https://www.w3.org/ns/did#INVALID_OPTIONS`).
    pub fn invalid_options(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://www.w3.org/ns/did#INVALID_OPTIONS".to_string(),
            title: "Invalid Options".to_string(),
            detail: detail.into(),
        }
    }
    /// Requested DID document absent, or VDR `did-documents.jsonl` absent/empty
    /// (`https://www.w3.org/ns/did#NOT_FOUND`).
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://www.w3.org/ns/did#NOT_FOUND".to_string(),
            title: "Not Found".to_string(),
            detail: detail.into(),
        }
    }
    /// Fetched DID document failed validation
    /// (`https://www.w3.org/ns/did#INVALID_DID_DOCUMENT`).
    pub fn invalid_did_document(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://www.w3.org/ns/did#INVALID_DID_DOCUMENT".to_string(),
            title: "Invalid DID Document".to_string(),
            detail: detail.into(),
        }
    }
    /// Unexpected failure during resolution (`https://www.w3.org/ns/did#INTERNAL_ERROR`).
    pub fn internal_error(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://www.w3.org/ns/did#INTERNAL_ERROR".to_string(),
            title: "Internal Error".to_string(),
            detail: detail.into(),
        }
    }
    /// Local-only resolution cannot complete
    /// (`https://ledgerdomain.github.io/did-webplus-spec/#LOCAL_RESOLUTION_NOT_POSSIBLE`).
    pub fn local_resolution_not_possible(detail: impl Into<String>) -> Self {
        Self {
            r#type:
                "https://ledgerdomain.github.io/did-webplus-spec/#LOCAL_RESOLUTION_NOT_POSSIBLE"
                    .to_string(),
            title: "Local Resolution Not Possible".to_string(),
            detail: detail.into(),
        }
    }
    /// Full resolver VDR `did-documents.jsonl` fetch failed
    /// (`https://ledgerdomain.github.io/did-webplus-spec/#VDR_FETCH_FAILED`).
    pub fn vdr_fetch_failed(detail: impl Into<String>) -> Self {
        Self {
            r#type: "https://ledgerdomain.github.io/did-webplus-spec/#VDR_FETCH_FAILED".to_string(),
            title: "VDR Fetch Failed".to_string(),
            detail: detail.into(),
        }
    }
    /// URI identifying the error (`type`).
    pub fn r#type(&self) -> &str {
        self.r#type.as_str()
    }
    /// Short human-readable summary (`title`).
    pub fn title(&self) -> &str {
        self.title.as_str()
    }
    /// Occurrence-specific explanation (`detail`).
    pub fn detail(&self) -> &str {
        self.detail.as_str()
    }
    /// HTTP status code for this error `type` per the DID Resolution CR HTTPS binding.
    ///
    /// Method-specific types map as: `#VDR_FETCH_FAILED` -> 500,
    /// `#LOCAL_RESOLUTION_NOT_POSSIBLE` -> 501. Unknown types map to 500.
    pub fn http_status_code(&self) -> u16 {
        match self.r#type.as_str() {
            "https://www.w3.org/ns/did#INVALID_DID"
            | "https://www.w3.org/ns/did#INVALID_DID_URL"
            | "https://www.w3.org/ns/did#INVALID_OPTIONS"
            | "https://www.w3.org/ns/did#INVALID_DID_DOCUMENT" => 400,
            "https://www.w3.org/ns/did#NOT_FOUND" => 404,
            "https://www.w3.org/ns/did#INTERNAL_ERROR"
            | "https://ledgerdomain.github.io/did-webplus-spec/#VDR_FETCH_FAILED" => 500,
            "https://ledgerdomain.github.io/did-webplus-spec/#LOCAL_RESOLUTION_NOT_POSSIBLE" => 501,
            _ => 500,
        }
    }
}
