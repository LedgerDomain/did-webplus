use crate::{Expected, TestVectorParams};

/// A generated did:webplus test vector: ordered jsonl lines plus expectation metadata.
///
/// Each vector has its own DID and records the [`TestVectorParams`] it was generated with.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct TestVector {
    /// Stable catalog name (also used to derive the per-vector RNG seed).
    pub name: String,
    /// Catalog category (e.g. `conformance`, `coverage-matrix`, `jsonl-structural`, `stress`, `fuzz-lite`).
    pub category: String,
    /// Human-readable description of what this vector exercises.
    pub description: String,
    /// Spec section anchors this vector relates to (e.g. `#validation-of-did-documents`).
    #[serde(rename = "spec_refs")]
    pub spec_ref_v: Vec<String>,
    /// Ordered DID-document lines that form the microledger jsonl body.
    #[serde(rename = "jsonl_lines")]
    pub jsonl_line_v: Vec<String>,
    /// DID identity for this vector (includes root self-hash).
    ///
    /// For most categories this matches the DID inside `jsonl_line_v`. For
    /// `resolution` vectors this is the **resolution** DID implied by the serving
    /// host and on-disk path; the microledger body intentionally uses a different DID.
    pub did: did_webplus_core::DID,
    /// How a conforming validator should treat this vector's jsonl.
    pub expected: Expected,
    /// Generation parameters recorded with the vector.
    pub params: TestVectorParams,
}

impl TestVector {
    /// Join [`Self::jsonl_line_v`] with `\n`, including a trailing newline when non-empty.
    pub fn jsonl_body(&self) -> String {
        if self.jsonl_line_v.is_empty() {
            return String::new();
        }
        let mut body = self.jsonl_line_v.join("\n");
        body.push('\n');
        body
    }
}
