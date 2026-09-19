use crate::ResolutionStep;

/// Format identifier written into every `resolution-scenario.json`.
pub const RESOLUTION_SCENARIO_FORMAT: &str = "did-webplus-resolution-scenario/1";

/// Catalog category and index v2 group name for resolution-scenario vectors.
///
/// These vectors are body-positive (fully valid microledgers); group membership
/// under this name distinguishes them from ordinary positive conformance vectors.
pub const RESOLUTION_SCENARIO_CATEGORY: &str = "resolution-scenario";

/// Stateful resolution scenario for a single test-vector microledger.
///
/// Written beside `did-documents.jsonl` / `test-vector.json` as
/// `resolution-scenario.json`. A conforming full resolver starts with an empty
/// DID document store and executes [`Self::step_v`] in order, retaining store
/// state across steps.
///
/// Schema (`did-webplus-resolution-scenario/1`):
/// ```json
/// {
///   "format": "did-webplus-resolution-scenario/1",
///   "name": "...",
///   "description": "...",
///   "specRef": ["..."],
///   "did": "did:webplus:...",
///   "steps": [ { "...": "..." } ]
/// }
/// ```
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionScenario {
    /// Format / schema version string; must be [`RESOLUTION_SCENARIO_FORMAT`].
    pub format: String,
    /// Stable catalog name (matches the owning test vector).
    pub name: String,
    /// Human-readable description of what this scenario exercises.
    pub description: String,
    /// Spec section anchors this scenario relates to.
    #[serde(rename = "specRef")]
    pub spec_ref_v: Vec<String>,
    /// DID identity for the owning microledger.
    pub did: did_webplus_core::DID,
    /// Ordered resolution steps executed against a fresh, then persistent, store.
    #[serde(rename = "steps")]
    pub step_v: Vec<ResolutionStep>,
}

impl ResolutionScenario {
    /// Build a scenario with [`RESOLUTION_SCENARIO_FORMAT`] and the given fields.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        spec_ref_v: Vec<String>,
        did: did_webplus_core::DID,
        step_v: Vec<ResolutionStep>,
    ) -> Self {
        Self {
            format: RESOLUTION_SCENARIO_FORMAT.to_string(),
            name: name.into(),
            description: description.into(),
            spec_ref_v,
            did,
            step_v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExpectedResolutionOutcome;
    use did_webplus_core::{DIDResolutionMetadata, DIDResolutionOptions};

    fn sample_did() -> did_webplus_core::DID {
        "did:webplus:example.com:uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg"
            .parse()
            .expect("sample DID")
    }

    fn sample_resolution_metadata(error_o: Option<String>) -> DIDResolutionMetadata {
        DIDResolutionMetadata {
            content_type: "application/did+json".to_string(),
            error_o,
            fetched_updates_from_vdr: true,
            did_document_resolved_locally: false,
            did_document_metadata_resolved_locally: true,
        }
    }

    #[test]
    fn resolution_scenario_serde_round_trip() {
        let scenario = ResolutionScenario::new(
            "cold-plain-did-no-metadata",
            "Cold resolve of a plain DID with no metadata requested.",
            vec!["#did-resolution-metadata".to_string()],
            sample_did(),
            vec![ResolutionStep {
                served_did_document_count: 3,
                did_query: sample_did().to_string(),
                resolution_options: DIDResolutionOptions::no_metadata(false),
                expected: ExpectedResolutionOutcome::failure(
                    sample_resolution_metadata(Some("advisory message".to_string())),
                    1,
                ),
            }],
        );

        let json = serde_json::to_value(&scenario).expect("serialize");
        assert_eq!(json["format"], RESOLUTION_SCENARIO_FORMAT);
        assert_eq!(json["steps"][0]["servedDidDocumentCount"], 3);
        assert_eq!(
            json["steps"][0]["resolutionOptions"]["localResolutionOnly"],
            false
        );
        assert_eq!(json["steps"][0]["expected"]["vdrRequestCount"], 1);
        assert!(json["steps"][0]["expected"]["didDocumentVersionId"].is_null());

        let decoded: ResolutionScenario = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded, scenario);
    }

    #[test]
    fn success_outcome_includes_document_fields() {
        let self_hash = mbx::MBHash::try_from("uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg")
            .expect("sample self-hash");
        let outcome = ExpectedResolutionOutcome::success(
            0,
            self_hash.clone(),
            did_webplus_core::DIDDocumentMetadata {
                creation_metadata_o: None,
                next_update_metadata_o: None,
                latest_update_metadata_o: None,
                deactivated_o: None,
            },
            sample_resolution_metadata(None),
            0,
        );
        let json = serde_json::to_value(&outcome).expect("serialize");
        assert_eq!(json["success"], true);
        assert_eq!(json["didDocumentVersionId"], 0);
        assert_eq!(json["didDocumentSelfHash"], self_hash.to_string());
        assert!(json["didDocumentMetadata"].is_object());
        assert_eq!(json["vdrRequestCount"], 0);
    }
}
