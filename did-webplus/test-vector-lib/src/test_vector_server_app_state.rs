use std::{collections::HashMap, sync::Arc};

use crate::{
    Catalog, DID_DOCUMENTS_JSONL_FILENAME, INDEX_JSON_FILENAME, TEST_VECTOR_JSON_FILENAME,
    TestVectorIndex, TestVectorIndexRecord, TestVectorMetadata, TestVectorServerConfig,
    TestVectorWriter,
};

/// In-memory bodies for one vector directory (`did-documents.jsonl` + `test-vector.json`).
#[derive(Clone, Debug)]
pub struct TestVectorServerVectorBodies {
    /// Full `did-documents.jsonl` body (UTF-8).
    pub jsonl: String,
    /// Pretty-printed `test-vector.json` body (UTF-8, trailing newline).
    pub test_vector_json: String,
}

/// Eagerly generated catalog served by the test-vector HTTP server.
///
/// Built once at spawn from [`TestVectorServerConfig`]: index bytes plus a map from
/// request path (no leading `/`) to vector file bodies. Paths match V1 URL layout:
/// optional `--did-path` as slash-separated prefix, then the target-dir-relative
/// vector directory, then the filename.
#[derive(Clone, Debug)]
pub struct TestVectorServerAppState {
    /// Serialized `index.json` (pretty JSON + trailing newline).
    pub index_json: Arc<str>,
    /// Request path (no leading `/`) for `index.json`, e.g. `index.json` or `tv/demo/index.json`.
    pub index_request_path: Arc<str>,
    /// Map from vector-directory request path → file bodies.
    ///
    /// Keys are paths like `uRootHash` or `tv/demo/uRootHash` (no filename).
    pub vector_body_m: Arc<HashMap<String, TestVectorServerVectorBodies>>,
}

impl TestVectorServerAppState {
    /// Generate the catalog and build an in-memory app state (no disk I/O).
    pub fn generate(config: &TestVectorServerConfig) -> anyhow::Result<Self> {
        let params = config.params();
        let path_component_v = config.path_component_v();
        let stress_config = config.stress_config();

        tracing::info!(
            host = %config.host,
            listen_port = config.listen_port,
            fuzz_lite_count = config.fuzz_lite_count,
            "generating test-vector catalog for HTTP serve"
        );

        let vector_v = Catalog::generate_with_progress(
            &params,
            &config.seed,
            &stress_config,
            config.fuzz_lite_count,
            |message| {
                tracing::info!(%message, "test-vector catalog progress");
            },
        )?;

        // Reuse writer path logic (no filesystem writes) for index-relative paths.
        let path_writer = TestVectorWriter::new(".").with_base_path_components(path_component_v.clone());

        let mut record_v = Vec::with_capacity(vector_v.len());
        let mut vector_body_m = HashMap::with_capacity(vector_v.len());

        let url_prefix = if path_component_v.is_empty() {
            String::new()
        } else {
            path_component_v.join("/")
        };

        for vector in &vector_v {
            let relative_path = path_writer.vector_relative_path(&vector.did)?;
            let request_dir = if url_prefix.is_empty() {
                relative_path.clone()
            } else {
                format!("{url_prefix}/{relative_path}")
            };

            let metadata = TestVectorMetadata::from_test_vector(vector, &config.seed);
            metadata.validate_fuzz_lite_seed()?;
            let metadata_json = serde_json::to_string_pretty(&metadata)?;
            let test_vector_json = format!("{metadata_json}\n");

            vector_body_m.insert(
                request_dir,
                TestVectorServerVectorBodies {
                    jsonl: vector.jsonl_body(),
                    test_vector_json,
                },
            );
            record_v.push(TestVectorIndexRecord::from_test_vector(vector, relative_path));
        }

        let index = TestVectorIndex::build(record_v)?;
        let index_json = format!("{}\n", serde_json::to_string_pretty(&index)?);
        let index_request_path = if url_prefix.is_empty() {
            INDEX_JSON_FILENAME.to_owned()
        } else {
            format!("{url_prefix}/{INDEX_JSON_FILENAME}")
        };

        tracing::info!(
            vector_count = vector_v.len(),
            index_path = %index_request_path,
            "test-vector catalog ready in memory"
        );

        Ok(Self {
            index_json: Arc::from(index_json),
            index_request_path: Arc::from(index_request_path),
            vector_body_m: Arc::new(vector_body_m),
        })
    }

    /// Look up a vector directory by its request path (no leading `/`, no filename).
    pub fn vector_bodies(&self, request_dir: &str) -> Option<&TestVectorServerVectorBodies> {
        self.vector_body_m.get(request_dir)
    }
}

/// Filename helpers used by route handlers when splitting catch-all paths.
pub(crate) fn is_did_documents_jsonl(filename: &str) -> bool {
    filename == DID_DOCUMENTS_JSONL_FILENAME
}

pub(crate) fn is_test_vector_json(filename: &str) -> bool {
    filename == TEST_VECTOR_JSON_FILENAME
}
