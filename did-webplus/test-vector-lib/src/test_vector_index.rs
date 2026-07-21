use std::collections::BTreeMap;

use crate::{TestVector, TestVectorMetadata};

/// Format identifier written into every target-directory `index.json`.
pub const TEST_VECTOR_INDEX_FORMAT: &str = "did-webplus-test-vector-index/2";

/// Name of the group that lists every fully valid vector.
pub const POSITIVE_GROUP_NAME: &str = "positive";

/// Name of the group that lists every vector expected to fail validation.
pub const NEGATIVE_GROUP_NAME: &str = "negative";

/// Root `index.json` enumerating every test vector under a target directory.
///
/// This is derived discovery data; each vector's `test-vector.json` remains the
/// authoritative record of its expectations. A harness fetches this document,
/// selects a group (e.g. `positive`, `negative`, or a category such as
/// `conformance`), and resolves each listed name through [`Self::vector_m`] to
/// find the directory holding `did-documents.jsonl` and `test-vector.json`.
///
/// Schema (`did-webplus-test-vector-index/2`):
/// ```json
/// {
///   "format": "did-webplus-test-vector-index/2",
///   "vectors": {
///     "<name>": { "did": "<did>", "path": "<relative-dir>" }
///   },
///   "groups": {
///     "positive": ["..."],
///     "negative": ["..."],
///     "conformance": ["..."]
///   }
/// }
/// ```
///
/// Invariants (enforced by [`Self::build`]):
/// - Every name listed in any group exists in [`Self::vector_m`].
/// - Every vector appears in exactly one of `positive` / `negative`.
/// - Every vector appears in the group named after its category.
/// - Maps are key-sorted ([`BTreeMap`]) and group name lists are sorted.
/// - Vector names are unique across the target tree.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestVectorIndex {
    /// Format / schema version string.
    pub format: String,
    /// Location of every vector under this target directory, keyed by catalog name.
    #[serde(rename = "vectors")]
    pub vector_m: BTreeMap<String, TestVectorLocation>,
    /// Group name -> sorted list of vector names. Contains `positive` / `negative`
    /// validity groups and one group per category present in the tree.
    #[serde(rename = "groups")]
    pub group_m: BTreeMap<String, Vec<String>>,
}

impl TestVectorIndex {
    /// Build an index from per-vector records, enforcing the type-level invariants.
    ///
    /// Groups are derived: each vector is placed in `positive` or `negative`
    /// according to [`TestVectorIndexRecord::positive`], and in the group named
    /// after its category. Errors on duplicate vector names and on categories that
    /// collide with the reserved validity group names.
    ///
    /// Callers typically obtain records from generated [`TestVector`]s or by
    /// scanning on-disk [`TestVectorMetadata`] (see
    /// [`crate::TestVectorWriter::rebuild_index`]).
    pub fn build(record_v: Vec<TestVectorIndexRecord>) -> anyhow::Result<Self> {
        let mut vector_m: BTreeMap<String, TestVectorLocation> = BTreeMap::new();
        let mut group_m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for record in record_v {
            anyhow::ensure!(
                record.category != POSITIVE_GROUP_NAME && record.category != NEGATIVE_GROUP_NAME,
                "test vector {:?} has category {:?}, which collides with a reserved validity group name",
                record.name,
                record.category
            );
            let validity_group_name = if record.positive {
                POSITIVE_GROUP_NAME
            } else {
                NEGATIVE_GROUP_NAME
            };
            if vector_m
                .insert(
                    record.name.clone(),
                    TestVectorLocation {
                        did: record.did,
                        path: record.path,
                    },
                )
                .is_some()
            {
                anyhow::bail!("duplicate test vector name {:?} in target tree", record.name);
            }
            group_m
                .entry(validity_group_name.to_owned())
                .or_default()
                .push(record.name.clone());
            group_m
                .entry(record.category)
                .or_default()
                .push(record.name);
        }
        for name_v in group_m.values_mut() {
            name_v.sort();
        }
        Ok(Self {
            format: TEST_VECTOR_INDEX_FORMAT.to_owned(),
            vector_m,
            group_m,
        })
    }
}

/// Location of one vector inside a [`TestVectorIndex`].
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestVectorLocation {
    /// DID for this vector.
    pub did: String,
    /// Path relative to the target directory (forward-slash separators, no `..`),
    /// naming the directory that contains `did-documents.jsonl` and `test-vector.json`.
    pub path: String,
}

/// Per-vector facts consumed by [`TestVectorIndex::build`].
///
/// Constructed either from an in-memory [`TestVector`] (generation path) or from
/// an on-disk [`TestVectorMetadata`] (index rebuild path).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestVectorIndexRecord {
    /// Catalog name (unique within a target tree).
    pub name: String,
    /// DID for this vector.
    pub did: String,
    /// Target-dir-relative, `/`-separated directory holding the vector's files.
    pub path: String,
    /// Catalog category; becomes the vector's category group name.
    pub category: String,
    /// `true` when the whole history is expected to validate (`positive` group),
    /// `false` otherwise (`negative` group).
    pub positive: bool,
}

impl TestVectorIndexRecord {
    /// Build a record for a generated vector and its target-dir-relative path.
    pub fn from_test_vector(test_vector: &TestVector, path: impl Into<String>) -> Self {
        Self {
            name: test_vector.name.clone(),
            did: test_vector.did.to_string(),
            path: path.into(),
            category: test_vector.category.clone(),
            positive: test_vector.expected.is_fully_valid(),
        }
    }

    /// Build a record from on-disk metadata and its target-dir-relative path.
    pub fn from_metadata(metadata: &TestVectorMetadata, path: impl Into<String>) -> Self {
        Self {
            name: metadata.name.clone(),
            did: metadata.did.clone(),
            path: path.into(),
            category: metadata.category.clone(),
            positive: metadata.expected.valid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, category: &str, positive: bool) -> TestVectorIndexRecord {
        TestVectorIndexRecord {
            name: name.to_owned(),
            did: format!("did:webplus:example.com:uRoot-{name}"),
            path: format!("uRoot-{name}"),
            category: category.to_owned(),
            positive,
        }
    }

    #[test]
    fn build_derives_sorted_vectors_and_groups() {
        let index = TestVectorIndex::build(vec![
            record("b-vector", "conformance", true),
            record("a-vector", "conformance", false),
            record("c-vector", "stress", true),
        ])
        .expect("build");

        assert_eq!(index.format, TEST_VECTOR_INDEX_FORMAT);
        assert_eq!(
            index.vector_m.keys().collect::<Vec<_>>(),
            ["a-vector", "b-vector", "c-vector"]
        );
        assert_eq!(index.vector_m["a-vector"].path, "uRoot-a-vector");
        assert_eq!(
            index.vector_m["a-vector"].did,
            "did:webplus:example.com:uRoot-a-vector"
        );
        assert_eq!(
            index.group_m.keys().collect::<Vec<_>>(),
            ["conformance", "negative", "positive", "stress"]
        );
        assert_eq!(index.group_m["positive"], ["b-vector", "c-vector"]);
        assert_eq!(index.group_m["negative"], ["a-vector"]);
        assert_eq!(index.group_m["conformance"], ["a-vector", "b-vector"]);
        assert_eq!(index.group_m["stress"], ["c-vector"]);

        // Every group member must exist in `vector_m`.
        for name in index.group_m.values().flatten() {
            assert!(index.vector_m.contains_key(name));
        }
    }

    #[test]
    fn build_rejects_duplicate_names() {
        let result_r = TestVectorIndex::build(vec![
            record("dup", "conformance", true),
            record("dup", "stress", false),
        ]);
        assert!(result_r.is_err());
    }

    #[test]
    fn build_rejects_reserved_category_names() {
        assert!(TestVectorIndex::build(vec![record("v", "positive", true)]).is_err());
        assert!(TestVectorIndex::build(vec![record("v", "negative", false)]).is_err());
    }
}
