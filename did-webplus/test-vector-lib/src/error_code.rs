/// Stable, machine-readable taxonomy of test-vector validation failures.
///
/// Codes mirror did:webplus validation steps. Conformance for other
/// implementations is defined by the accept/reject boundary and
/// [`crate::Expected::valid_did_document_count`], not by exact error-code matching;
/// these codes are advisory metadata for harnesses and documentation.
#[derive(
    Clone, Copy, Debug, serde::Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// DID document line is not JCS-canonical JSON.
    NotJcsCanonical,
    /// `validFrom` exceeds allowed temporal precision.
    ValidFromPrecisionExceeded,
    /// `validFrom` is before the Unix epoch.
    ValidFromPreEpoch,
    /// `validFrom` is not in the required uppercase-`T`/`Z` RFC 3339 form.
    ValidFromInvalidFormat,
    /// Verification-method `id` is missing required query params.
    VmIdMissingQueryParams,
    /// Verification-method `id` query params are not in the required order.
    VmIdQueryParamOrder,
    /// Verification-method `id` `selfHash` query param does not match the document.
    VmIdSelfhashMismatch,
    /// Verification-method `id` `versionId` query param does not match the document.
    VmIdVersionIdMismatch,
    /// Verification-method `id` is missing its fragment.
    VmIdMissingFragment,
    /// Verification-method `id` controller (DID prefix) does not match the document `id`.
    VmIdControllerMismatch,
    /// Verification-method `publicKeyJwk` is missing required `kid`.
    VmMissingKid,
    /// A purpose array references a verification-method fragment that does not exist.
    DanglingPurposeRef,
    /// Document `selfHash` does not match the computed self-hash.
    SelfHashMismatch,
    /// Self-hash-bearing fields do not consistently contain the document self-hash.
    SelfHashSlotMismatch,
    /// A proof JWS signature is invalid.
    InvalidProofSignature,
    /// A proof JWS `kid` header is malformed (e.g. non-multicodec).
    MalformedProofKid,
    /// Document proofs do not satisfy `updateRules`.
    UpdateRulesNotSatisfied,
    /// An update was attempted after DID deactivation (tombstone).
    UpdateAfterDeactivation,
    /// Root DID document has `versionId != 0`.
    RootVersionIdNonzero,
    /// Non-root DID document `id` does not match the expected DID.
    NonRootIdMismatch,
    /// Non-root `prevDIDDocumentSelfHash` does not match the previous document.
    PrevDidDocumentSelfHashMismatch,
    /// Non-root `validFrom` is not strictly greater than the previous document's.
    ValidFromNotStrictlyIncreasing,
    /// Non-root `versionId` is not exactly one greater than the previous.
    VersionIdNotIncremented,
    /// A jsonl line is not valid JSON / is otherwise malformed.
    MalformedJsonlLine,
    /// Root document unexpectedly includes `prevDIDDocumentSelfHash`.
    RootPrevDidDocumentSelfHashPresent,
    /// A required DID-document field is missing.
    MissingRequiredField,
    /// `versionId` has an invalid type or value shape.
    MalformedVersionId,
    /// DID document `id` is malformed.
    MalformedId,
    /// Resolution URL root self-hash does not match the DID inside `did-documents.jsonl`.
    ///
    /// The microledger body itself may be fully valid; rejection is relative to the
    /// claimed resolution URL / served path.
    ResolutionRootSelfHashMismatch,
    /// Resolution URL path components do not match the DID path inside `did-documents.jsonl`
    /// (extra or missing path elements) while host and root self-hash agree.
    ResolutionPathMismatch,
    /// Resolution / VDR host does not match the DID host inside `did-documents.jsonl`
    /// while path and root self-hash agree.
    ResolutionHostMismatch,
    /// Resolution / VDR port does not match the DID port inside `did-documents.jsonl`
    /// while host, path, and root self-hash agree. The content DID always includes a port.
    ResolutionPortMismatch,
}

impl ErrorCode {
    /// Kebab-case wire form used in `test-vector.json`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotJcsCanonical => "not-jcs-canonical",
            ErrorCode::ValidFromPrecisionExceeded => "valid-from-precision-exceeded",
            ErrorCode::ValidFromPreEpoch => "valid-from-pre-epoch",
            ErrorCode::ValidFromInvalidFormat => "valid-from-invalid-format",
            ErrorCode::VmIdMissingQueryParams => "vm-id-missing-query-params",
            ErrorCode::VmIdQueryParamOrder => "vm-id-query-param-order",
            ErrorCode::VmIdSelfhashMismatch => "vm-id-selfhash-mismatch",
            ErrorCode::VmIdVersionIdMismatch => "vm-id-version-id-mismatch",
            ErrorCode::VmIdMissingFragment => "vm-id-missing-fragment",
            ErrorCode::VmIdControllerMismatch => "vm-id-controller-mismatch",
            ErrorCode::VmMissingKid => "vm-missing-kid",
            ErrorCode::DanglingPurposeRef => "dangling-purpose-ref",
            ErrorCode::SelfHashMismatch => "self-hash-mismatch",
            ErrorCode::SelfHashSlotMismatch => "self-hash-slot-mismatch",
            ErrorCode::InvalidProofSignature => "invalid-proof-signature",
            ErrorCode::MalformedProofKid => "malformed-proof-kid",
            ErrorCode::UpdateRulesNotSatisfied => "update-rules-not-satisfied",
            ErrorCode::UpdateAfterDeactivation => "update-after-deactivation",
            ErrorCode::RootVersionIdNonzero => "root-version-id-nonzero",
            ErrorCode::NonRootIdMismatch => "non-root-id-mismatch",
            ErrorCode::PrevDidDocumentSelfHashMismatch => "prev-did-document-self-hash-mismatch",
            ErrorCode::ValidFromNotStrictlyIncreasing => "valid-from-not-strictly-increasing",
            ErrorCode::VersionIdNotIncremented => "version-id-not-incremented",
            ErrorCode::MalformedJsonlLine => "malformed-jsonl-line",
            ErrorCode::RootPrevDidDocumentSelfHashPresent => {
                "root-prev-did-document-self-hash-present"
            }
            ErrorCode::MissingRequiredField => "missing-required-field",
            ErrorCode::MalformedVersionId => "malformed-version-id",
            ErrorCode::MalformedId => "malformed-id",
            ErrorCode::ResolutionRootSelfHashMismatch => "resolution-root-self-hash-mismatch",
            ErrorCode::ResolutionPathMismatch => "resolution-path-mismatch",
            ErrorCode::ResolutionHostMismatch => "resolution-host-mismatch",
            ErrorCode::ResolutionPortMismatch => "resolution-port-mismatch",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ErrorCode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "not-jcs-canonical" => Ok(ErrorCode::NotJcsCanonical),
            "valid-from-precision-exceeded" => Ok(ErrorCode::ValidFromPrecisionExceeded),
            "valid-from-pre-epoch" => Ok(ErrorCode::ValidFromPreEpoch),
            "valid-from-invalid-format" => Ok(ErrorCode::ValidFromInvalidFormat),
            "vm-id-missing-query-params" => Ok(ErrorCode::VmIdMissingQueryParams),
            "vm-id-query-param-order" => Ok(ErrorCode::VmIdQueryParamOrder),
            "vm-id-selfhash-mismatch" => Ok(ErrorCode::VmIdSelfhashMismatch),
            "vm-id-version-id-mismatch" => Ok(ErrorCode::VmIdVersionIdMismatch),
            "vm-id-missing-fragment" => Ok(ErrorCode::VmIdMissingFragment),
            "vm-id-controller-mismatch" => Ok(ErrorCode::VmIdControllerMismatch),
            "vm-missing-kid" => Ok(ErrorCode::VmMissingKid),
            "dangling-purpose-ref" => Ok(ErrorCode::DanglingPurposeRef),
            "self-hash-mismatch" => Ok(ErrorCode::SelfHashMismatch),
            "self-hash-slot-mismatch" => Ok(ErrorCode::SelfHashSlotMismatch),
            "invalid-proof-signature" => Ok(ErrorCode::InvalidProofSignature),
            "malformed-proof-kid" => Ok(ErrorCode::MalformedProofKid),
            "update-rules-not-satisfied" => Ok(ErrorCode::UpdateRulesNotSatisfied),
            "update-after-deactivation" => Ok(ErrorCode::UpdateAfterDeactivation),
            "root-version-id-nonzero" => Ok(ErrorCode::RootVersionIdNonzero),
            "non-root-id-mismatch" => Ok(ErrorCode::NonRootIdMismatch),
            "prev-did-document-self-hash-mismatch" => {
                Ok(ErrorCode::PrevDidDocumentSelfHashMismatch)
            }
            "valid-from-not-strictly-increasing" => Ok(ErrorCode::ValidFromNotStrictlyIncreasing),
            "version-id-not-incremented" => Ok(ErrorCode::VersionIdNotIncremented),
            "malformed-jsonl-line" => Ok(ErrorCode::MalformedJsonlLine),
            "root-prev-did-document-self-hash-present" => {
                Ok(ErrorCode::RootPrevDidDocumentSelfHashPresent)
            }
            "missing-required-field" => Ok(ErrorCode::MissingRequiredField),
            "malformed-version-id" => Ok(ErrorCode::MalformedVersionId),
            "malformed-id" => Ok(ErrorCode::MalformedId),
            "resolution-root-self-hash-mismatch" => Ok(ErrorCode::ResolutionRootSelfHashMismatch),
            "resolution-path-mismatch" => Ok(ErrorCode::ResolutionPathMismatch),
            "resolution-host-mismatch" => Ok(ErrorCode::ResolutionHostMismatch),
            "resolution-port-mismatch" => Ok(ErrorCode::ResolutionPortMismatch),
            other => anyhow::bail!("unknown error code: {:?}", other),
        }
    }
}
