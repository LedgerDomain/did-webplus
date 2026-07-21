use crate::{CRATE_VERSION, ErrorCode, Expected, TestVector};

/// Format identifier written into every `test-vector.json`.
pub const TEST_VECTOR_FORMAT: &str = "did-webplus-test-vector/1";

/// Generator tool name recorded in metadata (binary package name, not the lib).
pub const GENERATOR_NAME: &str = "did-webplus-test-vector";

/// Metadata serialized next to each vector's `did-documents.jsonl` as `test-vector.json`.
///
/// This file is **authoritative** for expectations. Host `index.json` is derived
/// discovery only. Normative harness fields are
/// [`ExpectedSummary::valid_did_document_count`] / [`ExpectedSummary::valid`];
/// [`ExpectedSummary::error_code_o`] / [`ExpectedSummary::error_version_id_o`] are
/// advisory. [`GeneratorInfo::seed`] stores the original CLI `--seed` string
/// (for fuzz-lite, that string must match the hex decoded from the vector name —
/// see [`Self::validate_fuzz_lite_seed`]).
///
/// Schema:
/// ```json
/// {
///   "format": "did-webplus-test-vector/1",
///   "did": "did:webplus:...",
///   "name": "...",
///   "category": "...",
///   "description": "...",
///   "specRef": ["..."],
///   "didDocumentCount": 3,
///   "expected": {
///     "validDidDocumentCount": 2,
///     "valid": false,
///     "errorCode": "...",
///     "errorVersionId": 2
///   },
///   "keyTypes": ["Ed25519"],
///   "hashFunctions": ["BLAKE3"],
///   "generator": { "name": "...", "version": "...", "seed": "..." }
/// }
/// ```
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestVectorMetadata {
    /// Format / schema version string.
    pub format: String,
    /// DID for this vector.
    pub did: String,
    /// Catalog name.
    pub name: String,
    /// Catalog category.
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Spec section references.
    #[serde(rename = "specRef")]
    pub spec_ref_v: Vec<String>,
    /// Number of DID documents in the jsonl.
    pub did_document_count: u32,
    /// Expected validation outcome summary.
    pub expected: ExpectedSummary,
    /// Key types used while generating this vector.
    #[serde(rename = "keyTypes")]
    pub key_type_v: Vec<String>,
    /// Hash functions used while generating this vector.
    #[serde(rename = "hashFunctions")]
    pub hash_function_v: Vec<String>,
    /// Generator identity and seed for reproducibility.
    pub generator: GeneratorInfo,
}

/// The `expected` object embedded in [`TestVectorMetadata`].
///
/// `valid_did_document_count` / `valid` are normative for harness accept/reject
/// checks; `error_code_o` / `error_version_id_o` are advisory taxonomy only.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedSummary {
    /// Number of leading DID documents that must validate successfully.
    pub valid_did_document_count: u32,
    /// `true` when the entire history is expected to validate.
    pub valid: bool,
    /// Advisory error code for the first failing document, if any.
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code_o: Option<ErrorCode>,
    /// `versionId` of the first failing document, if any.
    #[serde(rename = "errorVersionId", skip_serializing_if = "Option::is_none")]
    pub error_version_id_o: Option<u32>,
}

impl ExpectedSummary {
    /// Build a summary from a full [`Expected`] value.
    pub fn from_expected(expected: &Expected) -> Self {
        Self {
            valid_did_document_count: expected.valid_did_document_count,
            valid: expected.is_fully_valid(),
            error_code_o: expected.error_code_o,
            error_version_id_o: expected.error_version_id_o,
        }
    }
}

/// Generator identity recorded in [`TestVectorMetadata`].
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorInfo {
    /// Generator package name.
    pub name: String,
    /// Generator package version.
    pub version: String,
    /// Original CLI `--seed` string used for deterministic generation.
    ///
    /// For fuzz-lite this is the human-readable seed (not the hex form in the
    /// vector name); see [`TestVectorMetadata::validate_fuzz_lite_seed`].
    pub seed: String,
}

impl TestVectorMetadata {
    /// Build metadata for a generated [`TestVector`] and the global seed that produced it.
    pub fn from_test_vector(test_vector: &TestVector, seed: &str) -> Self {
        Self {
            format: TEST_VECTOR_FORMAT.to_string(),
            did: test_vector.did.to_string(),
            name: test_vector.name.clone(),
            category: test_vector.category.clone(),
            description: test_vector.description.clone(),
            spec_ref_v: test_vector.spec_ref_v.clone(),
            did_document_count: test_vector.expected.did_document_count,
            expected: ExpectedSummary::from_expected(&test_vector.expected),
            key_type_v: vec![test_vector.params.key_type.as_str().to_string()],
            hash_function_v: vec![test_vector.params.hash_function.as_str().to_string()],
            generator: GeneratorInfo {
                name: GENERATOR_NAME.to_string(),
                version: CRATE_VERSION.to_string(),
                seed: seed.to_string(),
            },
        }
    }

    /// Validate that fuzz-lite metadata retains the seed encoded in its vector name.
    ///
    /// Other vector categories do not encode the generator seed in their names and
    /// therefore pass this category-specific validation unchanged.
    pub fn validate_fuzz_lite_seed(&self) -> anyhow::Result<()> {
        if self.category != "fuzz-lite" {
            return Ok(());
        }
        let name_seed = crate::fuzz_lite_catalog::seed_from_vector_name(&self.name)?;
        anyhow::ensure!(
            self.generator.seed == name_seed,
            "fuzz-lite generator.seed {:?} does not match seed {:?} encoded in name {}",
            self.generator.seed,
            name_seed,
            self.name
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(name: &str, category: &str, seed: &str) -> TestVectorMetadata {
        TestVectorMetadata {
            format: TEST_VECTOR_FORMAT.to_owned(),
            did: "did:webplus:example.com:uRoot".to_owned(),
            name: name.to_owned(),
            category: category.to_owned(),
            description: "metadata unit test".to_owned(),
            spec_ref_v: Vec::new(),
            did_document_count: 1,
            expected: ExpectedSummary {
                valid_did_document_count: 0,
                valid: false,
                error_code_o: None,
                error_version_id_o: None,
            },
            key_type_v: Vec::new(),
            hash_function_v: Vec::new(),
            generator: GeneratorInfo {
                name: GENERATOR_NAME.to_owned(),
                version: CRATE_VERSION.to_owned(),
                seed: seed.to_owned(),
            },
        }
    }

    #[test]
    fn fuzz_lite_seed_validation_round_trips_original_string() {
        let metadata = metadata(
            "fuzz-lite-63616d706169676e2df09f8cb1-00042",
            "fuzz-lite",
            "campaign-🌱",
        );
        assert!(metadata.validate_fuzz_lite_seed().is_ok());
    }

    #[test]
    fn fuzz_lite_seed_validation_rejects_mismatch_and_bad_name() {
        let mismatch = metadata("fuzz-lite-736565642d61-00000", "fuzz-lite", "seed-b");
        assert!(mismatch.validate_fuzz_lite_seed().is_err());

        let malformed = metadata("fuzz-lite-not-hex-00000", "fuzz-lite", "not-hex");
        assert!(malformed.validate_fuzz_lite_seed().is_err());
    }

    #[test]
    fn fuzz_lite_seed_validation_does_not_apply_to_other_categories() {
        let metadata = metadata("conformance-happy-path", "conformance", "any-seed");
        assert!(metadata.validate_fuzz_lite_seed().is_ok());
    }
}
