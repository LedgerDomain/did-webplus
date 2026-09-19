use crate::ExpectedResolutionOutcome;

/// One ordered resolution attempt within a [`crate::ResolutionScenario`].
///
/// During this step the VDR serves the first
/// [`Self::served_did_document_count`] lines of the vector's
/// `did-documents.jsonl`. Across a scenario, this count MUST be monotonically
/// non-decreasing. The harness then resolves [`Self::did_query`] with
/// [`Self::resolution_options`] and checks [`Self::expected`].
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionStep {
    /// How many leading jsonl lines the VDR serves during this step.
    ///
    /// Must be monotonically non-decreasing across steps in a scenario.
    pub served_did_document_count: u32,
    /// DID URL string to resolve, possibly with `selfHash` and/or `versionId`
    /// query params.
    pub did_query: String,
    /// DID Resolution Options for this step.
    ///
    /// Reuses [`did_webplus_core::DIDResolutionOptions`] for wire-exact JSON
    /// (`requestCreate`, `requestNext`, `requestLatest`, `requestDeactivated`,
    /// `localResolutionOnly`).
    pub resolution_options: did_webplus_core::DIDResolutionOptions,
    /// Expected resolution outcome for a conforming full resolver.
    pub expected: ExpectedResolutionOutcome,
}
