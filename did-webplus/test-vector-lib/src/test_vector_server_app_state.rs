use std::{collections::HashMap, sync::Arc};

use crate::{
    Catalog, DID_DOCUMENTS_JSONL_FILENAME, INDEX_JSON_FILENAME, RESOLUTION_SCENARIO_JSON_FILENAME,
    TEST_VECTOR_JSON_FILENAME, TestVectorIndex, TestVectorIndexRecord, TestVectorMetadata,
    TestVectorServerConfig, TestVectorServerVectorRuntime, TestVectorWriter,
};

/// In-memory bodies for one vector directory (`did-documents.jsonl` + `test-vector.json`
/// and optional `resolution-scenario.json`).
#[derive(Clone, Debug)]
pub struct TestVectorServerVectorBodies {
    /// Full `did-documents.jsonl` body (UTF-8).
    pub jsonl: String,
    /// Pretty-printed `test-vector.json` body (UTF-8, trailing newline).
    pub test_vector_json: String,
    /// Pretty-printed `resolution-scenario.json` when this vector has a scenario.
    pub resolution_scenario_json_o: Option<String>,
    /// Number of newline-terminated lines in [`Self::jsonl`].
    pub did_document_count: u32,
    /// Inclusive end octet offset after each leading document line.
    ///
    /// `jsonl_line_end_octet_v[i]` is the byte length of the prefix containing the
    /// first `i + 1` lines (each line includes its trailing `\n`).
    pub jsonl_line_end_octet_v: Vec<usize>,
}

impl TestVectorServerVectorBodies {
    /// Build bodies from raw file contents, deriving line-end octet offsets from `jsonl`.
    pub fn new(
        jsonl: String,
        test_vector_json: String,
        resolution_scenario_json_o: Option<String>,
    ) -> Self {
        let jsonl_line_end_octet_v = jsonl_line_end_octets(&jsonl);
        let did_document_count = jsonl_line_end_octet_v.len() as u32;
        Self {
            jsonl,
            test_vector_json,
            resolution_scenario_json_o,
            did_document_count,
            jsonl_line_end_octet_v,
        }
    }

    /// Byte length of the jsonl prefix containing the first `served_did_document_count` lines.
    ///
    /// Counts above [`Self::did_document_count`] are clamped to the full body.
    pub fn served_octet_length(&self, served_did_document_count: u32) -> usize {
        if served_did_document_count == 0 || self.jsonl_line_end_octet_v.is_empty() {
            return 0;
        }
        let index = (served_did_document_count as usize).min(self.jsonl_line_end_octet_v.len());
        self.jsonl_line_end_octet_v[index - 1]
    }

    /// UTF-8 prefix of [`Self::jsonl`] for the given served document count.
    pub fn served_jsonl(&self, served_did_document_count: u32) -> &str {
        let len = self.served_octet_length(served_did_document_count);
        &self.jsonl[..len]
    }
}

/// Eagerly generated catalog served by the test-vector HTTP server.
///
/// Built once at spawn from [`TestVectorServerConfig`]: index bytes plus a map from
/// request path (no leading `/`) to vector file bodies. Paths match V1 URL layout:
/// optional `--did-path` as slash-separated prefix, then the target-dir-relative
/// vector directory, then the filename.
///
/// Mutable per-vector VDR simulation state lives in [`Self::vector_runtime_m`]
/// (serve-count truncation + jsonl GET counters), driven by `/control/*` routes.
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
    /// Mutable serve-count / request-count state keyed like [`Self::vector_body_m`].
    pub vector_runtime_m: Arc<HashMap<String, TestVectorServerVectorRuntime>>,
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

        let generation = Catalog::generate_with_progress(
            &params,
            &config.seed,
            &stress_config,
            config.fuzz_lite_count,
            |message| {
                tracing::info!(%message, "test-vector catalog progress");
            },
        )?;
        let vector_v = &generation.vector_v;

        // Reuse writer path logic (no filesystem writes) for index-relative paths.
        let path_writer =
            TestVectorWriter::new(".").with_base_path_components(path_component_v.clone());

        let mut record_v = Vec::with_capacity(vector_v.len());
        let mut vector_body_m = HashMap::with_capacity(vector_v.len());
        let mut vector_runtime_m = HashMap::with_capacity(vector_v.len());

        let url_prefix = if path_component_v.is_empty() {
            String::new()
        } else {
            path_component_v.join("/")
        };

        for vector in vector_v {
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

            let resolution_scenario_json_o =
                match generation.resolution_scenario_m.get(&vector.name) {
                    Some(scenario) => {
                        let scenario_json = serde_json::to_string_pretty(scenario)?;
                        Some(format!("{scenario_json}\n"))
                    }
                    None => None,
                };

            let bodies = TestVectorServerVectorBodies::new(
                vector.jsonl_body(),
                test_vector_json,
                resolution_scenario_json_o,
            );
            let runtime = TestVectorServerVectorRuntime::new(bodies.did_document_count);
            vector_runtime_m.insert(request_dir.clone(), runtime);
            vector_body_m.insert(request_dir, bodies);
            record_v.push(TestVectorIndexRecord::from_test_vector(
                vector,
                relative_path,
            ));
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
            vector_runtime_m: Arc::new(vector_runtime_m),
        })
    }

    /// Build app state from precomputed bodies (for tests / custom catalogs).
    pub fn from_parts(
        index_json: impl Into<Arc<str>>,
        index_request_path: impl Into<Arc<str>>,
        vector_body_m: HashMap<String, TestVectorServerVectorBodies>,
    ) -> Self {
        let mut vector_runtime_m = HashMap::with_capacity(vector_body_m.len());
        for (path, bodies) in &vector_body_m {
            vector_runtime_m.insert(
                path.clone(),
                TestVectorServerVectorRuntime::new(bodies.did_document_count),
            );
        }
        Self {
            index_json: index_json.into(),
            index_request_path: index_request_path.into(),
            vector_body_m: Arc::new(vector_body_m),
            vector_runtime_m: Arc::new(vector_runtime_m),
        }
    }

    /// Look up a vector directory by its request path (no leading `/`, no filename).
    pub fn vector_bodies(&self, request_dir: &str) -> Option<&TestVectorServerVectorBodies> {
        self.vector_body_m.get(request_dir)
    }

    /// Look up mutable runtime state for a vector directory request path.
    pub fn vector_runtime(&self, request_dir: &str) -> Option<&TestVectorServerVectorRuntime> {
        self.vector_runtime_m.get(request_dir)
    }

    /// Set the served DID-document count for `request_dir`.
    ///
    /// Returns `(served_did_document_count, served_octet_length)` on success.
    pub fn set_serve_count(
        &self,
        request_dir: &str,
        served_did_document_count: u32,
    ) -> Result<(u32, u64), ServeCountError> {
        let bodies = self
            .vector_bodies(request_dir)
            .ok_or(ServeCountError::UnknownPath)?;
        if served_did_document_count > bodies.did_document_count {
            return Err(ServeCountError::CountExceedsDocuments {
                count: served_did_document_count,
                did_document_count: bodies.did_document_count,
            });
        }
        let runtime = self
            .vector_runtime(request_dir)
            .ok_or(ServeCountError::UnknownPath)?;
        runtime.set_served_did_document_count(served_did_document_count);
        let served_octet_length = bodies.served_octet_length(served_did_document_count) as u64;
        Ok((served_did_document_count, served_octet_length))
    }

    /// Current jsonl GET count for `request_dir`.
    pub fn request_count(&self, request_dir: &str) -> Option<u64> {
        self.vector_runtime(request_dir)
            .map(|runtime| runtime.jsonl_request_count())
    }

    /// Reset serve-count (to full) and jsonl request counters for every vector.
    pub fn reset_all(&self) {
        for runtime in self.vector_runtime_m.values() {
            runtime.reset();
        }
    }

    /// Record a jsonl GET and return the served jsonl prefix for the current serve-count.
    pub fn take_served_jsonl_for_request(&self, request_dir: &str) -> Option<&str> {
        let bodies = self.vector_bodies(request_dir)?;
        let runtime = self.vector_runtime(request_dir)?;
        runtime.increment_jsonl_request_count();
        let count = runtime.served_did_document_count();
        Some(bodies.served_jsonl(count))
    }
}

/// Errors from [`TestVectorServerAppState::set_serve_count`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServeCountError {
    /// No vector is registered under the given request path.
    UnknownPath,
    /// Requested count exceeds the vector's jsonl line count.
    CountExceedsDocuments {
        /// Requested serve count.
        count: u32,
        /// Available DID documents / jsonl lines.
        did_document_count: u32,
    },
}

impl std::fmt::Display for ServeCountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPath => write!(f, "vector path not found"),
            Self::CountExceedsDocuments {
                count,
                did_document_count,
            } => write!(
                f,
                "servedDidDocumentCount {count} exceeds did document count {did_document_count}"
            ),
        }
    }
}

/// End octet offsets after each newline-terminated line in `jsonl`.
fn jsonl_line_end_octets(jsonl: &str) -> Vec<usize> {
    let mut end_v = Vec::new();
    for (i, byte) in jsonl.as_bytes().iter().enumerate() {
        if *byte == b'\n' {
            end_v.push(i + 1);
        }
    }
    end_v
}

/// Filename helpers used by route handlers when splitting catch-all paths.
pub(crate) fn is_did_documents_jsonl(filename: &str) -> bool {
    filename == DID_DOCUMENTS_JSONL_FILENAME
}

pub(crate) fn is_test_vector_json(filename: &str) -> bool {
    filename == TEST_VECTOR_JSON_FILENAME
}

pub(crate) fn is_resolution_scenario_json(filename: &str) -> bool {
    filename == RESOLUTION_SCENARIO_JSON_FILENAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_octet_length_from_line_ends() {
        let bodies = TestVectorServerVectorBodies::new(
            "aa\nbbb\ncccc\n".to_owned(),
            "{}\n".to_owned(),
            None,
        );
        assert_eq!(bodies.did_document_count, 3);
        assert_eq!(bodies.jsonl_line_end_octet_v, vec![3, 7, 12]);
        assert_eq!(bodies.served_octet_length(0), 0);
        assert_eq!(bodies.served_octet_length(1), 3);
        assert_eq!(bodies.served_octet_length(2), 7);
        assert_eq!(bodies.served_octet_length(3), 12);
        assert_eq!(bodies.served_octet_length(99), 12);
        assert_eq!(bodies.served_jsonl(2), "aa\nbbb\n");
    }

    #[test]
    fn set_serve_count_and_request_count_round_trip() {
        let mut body_m = HashMap::new();
        body_m.insert(
            "vec".to_owned(),
            TestVectorServerVectorBodies::new("a\nb\nc\n".to_owned(), "{}\n".to_owned(), None),
        );
        let state = TestVectorServerAppState::from_parts("{}\n", "index.json", body_m);

        assert_eq!(state.request_count("vec"), Some(0));
        assert_eq!(state.take_served_jsonl_for_request("vec"), Some("a\nb\nc\n"));
        assert_eq!(state.request_count("vec"), Some(1));

        let (count, octet_len) = state.set_serve_count("vec", 1).expect("set");
        assert_eq!(count, 1);
        assert_eq!(octet_len, 2);
        assert_eq!(state.take_served_jsonl_for_request("vec"), Some("a\n"));
        assert_eq!(state.request_count("vec"), Some(2));

        state.reset_all();
        assert_eq!(state.request_count("vec"), Some(0));
        assert_eq!(state.take_served_jsonl_for_request("vec"), Some("a\nb\nc\n"));
    }

    #[test]
    fn set_serve_count_rejects_unknown_path_and_overflow() {
        let mut body_m = HashMap::new();
        body_m.insert(
            "vec".to_owned(),
            TestVectorServerVectorBodies::new("a\n".to_owned(), "{}\n".to_owned(), None),
        );
        let state = TestVectorServerAppState::from_parts("{}\n", "index.json", body_m);
        assert_eq!(
            state.set_serve_count("missing", 0),
            Err(ServeCountError::UnknownPath)
        );
        assert_eq!(
            state.set_serve_count("vec", 2),
            Err(ServeCountError::CountExceedsDocuments {
                count: 2,
                did_document_count: 1,
            })
        );
    }
}
