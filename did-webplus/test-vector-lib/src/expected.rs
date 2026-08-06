use crate::ErrorCode;

/// Machine-readable expectation for how a test vector's jsonl should validate.
///
/// - [`Self::did_document_count`] is the number of DID document lines in the vector.
/// - [`Self::valid_did_document_count`] is how many leading documents must validate:
///   equals `did_document_count` when the whole history is valid, and `0` when
///   the root itself is invalid (or the jsonl is empty).
/// - Optional [`Self::error_code_o`] / [`Self::error_version_id_o`] describe the
///   first failing document when the vector is not fully valid. Empty jsonl has
///   an error code but no `error_version_id`.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct Expected {
    /// Total number of DID documents (jsonl lines) in the vector.
    pub did_document_count: u32,
    /// Number of leading DID documents that must validate successfully.
    pub valid_did_document_count: u32,
    /// Advisory error code for the first failing document, if any.
    #[serde(rename = "error_code")]
    pub error_code_o: Option<ErrorCode>,
    /// `versionId` of the first failing document, if any.
    #[serde(rename = "error_version_id")]
    pub error_version_id_o: Option<u32>,
}

impl Expected {
    /// Expectation for a fully valid microledger of `did_document_count` documents.
    pub fn fully_valid(did_document_count: u32) -> Self {
        Self {
            did_document_count,
            valid_did_document_count: did_document_count,
            error_code_o: None,
            error_version_id_o: None,
        }
    }

    /// Expectation for a vector whose first `valid_did_document_count` documents are
    /// valid and which then fails with the given error metadata.
    pub fn reject_after(
        did_document_count: u32,
        valid_did_document_count: u32,
        error_code: ErrorCode,
        error_version_id: u32,
    ) -> Self {
        Self {
            did_document_count,
            valid_did_document_count,
            error_code_o: Some(error_code),
            error_version_id_o: Some(error_version_id),
        }
    }

    /// Expectation for an empty `did-documents.jsonl` (no root; resolution must fail).
    pub fn reject_empty(error_code: ErrorCode) -> Self {
        Self {
            did_document_count: 0,
            valid_did_document_count: 0,
            error_code_o: Some(error_code),
            error_version_id_o: None,
        }
    }

    /// `true` when every document in the vector is expected to validate.
    ///
    /// An empty jsonl with an advisory error code is not fully valid even though
    /// the accept counts are both zero.
    pub fn is_fully_valid(&self) -> bool {
        self.error_code_o.is_none() && self.valid_did_document_count == self.did_document_count
    }
}
