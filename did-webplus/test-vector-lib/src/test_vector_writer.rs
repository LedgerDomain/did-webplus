use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{TestVector, TestVectorIndex, TestVectorIndexRecord, TestVectorMetadata};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Filename for the microledger body next to each vector's metadata.
pub const DID_DOCUMENTS_JSONL_FILENAME: &str = "did-documents.jsonl";

/// Filename for per-vector expectation metadata.
pub const TEST_VECTOR_JSON_FILENAME: &str = "test-vector.json";

/// Filename for the catalog discovery index at the target-dir root.
pub const INDEX_JSON_FILENAME: &str = "index.json";

/// Writes generated [`TestVector`]s into a filesystem tree suitable for static HTTP serving.
///
/// A single hostname+port is generated per invocation, so there is no
/// `<hostname>[:<port>]` directory. Everything is written under [`Self::target_dir`]:
///
/// ```text
/// <target-dir>/
///   index.json
///   [<extra-path...>/]<root-self-hash>/
///     did-documents.jsonl
///     test-vector.json
/// ```
///
/// [`Self::base_path_component_v`] is the `--did-path` prefix that `target_dir` already
/// represents on the serving host. Those components appear in every DID but are **not**
/// re-created as directories under `target_dir`. Only path components beyond that prefix
/// (e.g. from `did-multi-path-components` or `stress-long-did-path`) become nested dirs.
///
/// `index.json` is **derived**: [`Self::write_all`] and [`Self::rebuild_index`] scan
/// `target_dir` for `test-vector.json` and emit [`TestVectorIndex`] v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestVectorWriter {
    target_dir: PathBuf,
    /// DID path components that `target_dir` already corresponds to (from `--did-path`).
    base_path_component_v: Vec<String>,
}

impl TestVectorWriter {
    /// Create a writer that places vectors and `index.json` directly under `target_dir`.
    pub fn new(target_dir: impl Into<PathBuf>) -> Self {
        Self {
            target_dir: target_dir.into(),
            base_path_component_v: Vec::new(),
        }
    }

    /// Set the `--did-path` prefix that [`Self::target_dir`] already represents on disk.
    ///
    /// These components are stripped from each DID's path when forming on-disk directories
    /// and `index.json` relative paths.
    pub fn with_base_path_components(
        mut self,
        base_path_component_v: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.base_path_component_v = base_path_component_v
            .into_iter()
            .map(Into::into)
            .collect();
        self
    }

    /// Root directory under which vectors and `index.json` are written.
    pub fn target_dir(&self) -> &Path {
        &self.target_dir
    }

    /// DID path components that [`Self::target_dir`] represents (from `--did-path`).
    pub fn base_path_component_v(&self) -> &[String] {
        &self.base_path_component_v
    }

    /// Path relative to [`Self::target_dir`] for `did`, using `/` separators.
    ///
    /// This is the directory that contains `did-documents.jsonl` and `test-vector.json`
    /// (i.e. `[<extra-path...>/]<root-self-hash>`), with the configured base `--did-path`
    /// prefix stripped. Suitable for embedding in `index.json` and for constructing
    /// resolution URLs relative to the served `target_dir`.
    pub fn vector_relative_path(&self, did: &did_webplus_core::DID) -> anyhow::Result<String> {
        let mut part_v = self.path_components_beyond_base(did)?;
        part_v.push(did.root_self_hash().as_str().to_owned());
        Ok(part_v.join("/"))
    }

    /// Absolute directory that holds this vector's `did-documents.jsonl` and `test-vector.json`.
    pub fn vector_dir_path(&self, did: &did_webplus_core::DID) -> anyhow::Result<PathBuf> {
        let relative = self.vector_relative_path(did)?;
        let mut dir = self.target_dir.clone();
        for component in relative.split('/') {
            dir.push(component);
        }
        Ok(dir)
    }

    /// Write `did-documents.jsonl` and `test-vector.json` for one vector.
    ///
    /// Returns the absolute path of the vector directory that was written. Does not
    /// update `index.json`; use [`Self::write_all`] or [`Self::write_index`] for that.
    pub fn write_vector(&self, vector: &TestVector, seed: &str) -> anyhow::Result<PathBuf> {
        let metadata = TestVectorMetadata::from_test_vector(vector, seed);
        metadata.validate_fuzz_lite_seed()?;

        let dir = self.vector_dir_path(&vector.did)?;
        std::fs::create_dir_all(&dir).map_err(|error| {
            anyhow::anyhow!(
                "failed to create vector directory {}: {}",
                dir.display(),
                error
            )
        })?;

        let jsonl_path = dir.join(DID_DOCUMENTS_JSONL_FILENAME);
        std::fs::write(&jsonl_path, vector.jsonl_body()).map_err(|error| {
            anyhow::anyhow!("failed to write {}: {}", jsonl_path.display(), error)
        })?;

        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        let metadata_path = dir.join(TEST_VECTOR_JSON_FILENAME);
        std::fs::write(&metadata_path, format!("{metadata_json}\n")).map_err(|error| {
            anyhow::anyhow!("failed to write {}: {}", metadata_path.display(), error)
        })?;

        Ok(dir)
    }

    /// Atomically write `index.json` under `index_dir`, creating the directory if needed.
    pub fn write_index(&self, index_dir: &Path, index: &TestVectorIndex) -> anyhow::Result<()> {
        std::fs::create_dir_all(index_dir).map_err(|error| {
            anyhow::anyhow!(
                "failed to create index directory {}: {}",
                index_dir.display(),
                error
            )
        })?;
        let index_json = serde_json::to_string_pretty(index)?;
        let index_path = index_dir.join(INDEX_JSON_FILENAME);
        let temp_file_id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = index_dir.join(format!(
            ".{INDEX_JSON_FILENAME}.{}.{}.tmp",
            std::process::id(),
            temp_file_id
        ));
        let write_r = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)?;
            file.write_all(index_json.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()
        })();
        if let Err(error) = write_r {
            let _ = std::fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "failed to write temporary index {}: {}",
                temp_path.display(),
                error
            ));
        }
        if let Err(error) = std::fs::rename(&temp_path, &index_path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "failed to replace {} with {}: {}",
                index_path.display(),
                temp_path.display(),
                error
            ));
        }
        Ok(())
    }

    /// Write every vector, then rebuild [`Self::target_dir`]'s `index.json` from disk.
    ///
    /// Rebuilding scans the complete tree, so vectors from earlier calls remain
    /// discoverable when new vectors are added incrementally.
    pub fn write_all(&self, vector_v: &[TestVector], seed: &str) -> anyhow::Result<()> {
        for vector in vector_v {
            self.write_vector(vector, seed)?;
        }
        self.rebuild_index()?;
        Ok(())
    }

    /// Rebuild `index.json` under [`Self::target_dir`] by scanning for `test-vector.json`.
    ///
    /// Walks `target_dir`, loads each metadata file, builds a [`TestVectorIndex`] via
    /// [`TestVectorIndex::build`], and writes it atomically. Relative `path` values
    /// are target-dir-relative (`/` separators, no `..`). Used by [`Self::write_all`]
    /// and the CLI `rebuild-index` command.
    pub fn rebuild_index(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.target_dir).map_err(|error| {
            anyhow::anyhow!(
                "failed to create target directory {}: {}",
                self.target_dir.display(),
                error
            )
        })?;
        let mut record_v = Vec::new();
        collect_metadata_under(&self.target_dir, &self.target_dir, &mut record_v)?;
        self.write_index(&self.target_dir, &TestVectorIndex::build(record_v)?)?;
        Ok(())
    }

    /// Rebuild `index.json` under [`Self::target_dir`].
    ///
    /// Returns `1` when an index was written (including an empty catalog), matching the
    /// historical "number of indexes rebuilt" return type of the multi-host API.
    pub fn rebuild_indexes_under(&self) -> anyhow::Result<usize> {
        self.rebuild_index()?;
        Ok(1)
    }

    /// DID path components after stripping [`Self::base_path_component_v`].
    fn path_components_beyond_base(
        &self,
        did: &did_webplus_core::DID,
    ) -> anyhow::Result<Vec<String>> {
        let did_component_v: Vec<String> = match did.path_o() {
            Some(path) => path.split(':').map(str::to_owned).collect(),
            None => Vec::new(),
        };
        if self.base_path_component_v.is_empty() {
            return Ok(did_component_v);
        }
        anyhow::ensure!(
            did_component_v.starts_with(&self.base_path_component_v),
            "DID path {:?} does not start with configured --did-path {:?}",
            did_component_v,
            self.base_path_component_v
        );
        Ok(did_component_v[self.base_path_component_v.len()..].to_vec())
    }
}

fn collect_metadata_under(
    root_dir: &Path,
    dir: &Path,
    record_v: &mut Vec<TestVectorIndexRecord>,
) -> anyhow::Result<()> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "failed to read directory {}: {}",
                dir.display(),
                error
            ));
        }
    };
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            anyhow::anyhow!(
                "failed to read directory entry under {}: {}",
                dir.display(),
                error
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| anyhow::anyhow!("failed to stat {}: {}", path.display(), error))?;
        if file_type.is_dir() {
            collect_metadata_under(root_dir, &path, record_v)?;
        } else if file_type.is_file() && entry.file_name() == TEST_VECTOR_JSON_FILENAME {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| anyhow::anyhow!("failed to read {}: {}", path.display(), error))?;
            let metadata: TestVectorMetadata = serde_json::from_str(&text).map_err(|error| {
                anyhow::anyhow!("failed to parse {}: {}", path.display(), error)
            })?;
            metadata.validate_fuzz_lite_seed().map_err(|error| {
                anyhow::anyhow!("invalid metadata in {}: {}", path.display(), error)
            })?;
            let vector_dir = path.parent().ok_or_else(|| {
                anyhow::anyhow!("test-vector.json has no parent: {}", path.display())
            })?;
            let relative = vector_dir.strip_prefix(root_dir).map_err(|_| {
                anyhow::anyhow!(
                    "vector directory {} is not under {}",
                    vector_dir.display(),
                    root_dir.display()
                )
            })?;
            let relative_path = relative
                .components()
                .map(|component| {
                    let std::path::Component::Normal(os) = component else {
                        anyhow::bail!(
                            "invalid relative path component in {}: {:?}",
                            vector_dir.display(),
                            component
                        );
                    };
                    os.to_str().ok_or_else(|| {
                        anyhow::anyhow!("non-UTF-8 path component in {}", vector_dir.display())
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .join("/");
            validate_relative_path(&relative_path).map_err(|error| {
                anyhow::anyhow!(
                    "invalid target-relative path for {}: {}",
                    path.display(),
                    error
                )
            })?;
            record_v.push(TestVectorIndexRecord::from_metadata(
                &metadata,
                relative_path,
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(relative_path: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!relative_path.is_empty(), "path is empty");
    anyhow::ensure!(
        !relative_path.contains('\\'),
        "path must use forward-slash separators"
    );
    for component in relative_path.split('/') {
        anyhow::ensure!(!component.is_empty(), "path contains an empty component");
        anyhow::ensure!(
            component != "." && component != "..",
            "path contains forbidden component {component:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeterministicRng, Expected, MicroledgerBuilder, TEST_VECTOR_FORMAT, TestVectorParams,
    };

    fn sample_vector(params: TestVectorParams, name: &str) -> TestVector {
        let rng = DeterministicRng::for_vector("writer-test-seed", name);
        let builder =
            MicroledgerBuilder::create_with_updates(params.clone(), rng, 1).expect("builder");
        let did = builder.did().clone();
        let jsonl_line_v = builder.canonical_jsonl_lines().expect("jsonl");
        TestVector {
            name: name.to_owned(),
            category: "conformance".to_owned(),
            description: "writer unit test vector".to_owned(),
            spec_ref_v: vec!["#validation-of-did-documents".to_owned()],
            expected: Expected::fully_valid(jsonl_line_v.len() as u32),
            jsonl_line_v,
            did,
            params,
        }
    }

    fn temp_target_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "did-webplus-test-vector-writer-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn write_all_layout_metadata_and_index() {
        let target = temp_target_dir("layout");
        let mut params = TestVectorParams::baseline("example.com");
        params.port_o = Some(3000);
        params.path_component_v = vec!["tv".to_owned(), "demo".to_owned()];
        let vector = sample_vector(params, "writer-layout");

        let writer = TestVectorWriter::new(&target)
            .with_base_path_components(["tv".to_owned(), "demo".to_owned()]);
        writer
            .write_all(std::slice::from_ref(&vector), "writer-test-seed")
            .expect("write_all");

        // Base --did-path is stripped: only the root self-hash remains under target-dir.
        let relative = writer.vector_relative_path(&vector.did).expect("relative");
        assert_eq!(relative, vector.did.root_self_hash().as_str());

        let vector_dir = writer.vector_dir_path(&vector.did).expect("vector dir");
        assert_eq!(vector_dir, target.join(vector.did.root_self_hash().as_str()));
        assert!(vector_dir.join(DID_DOCUMENTS_JSONL_FILENAME).is_file());
        assert!(vector_dir.join(TEST_VECTOR_JSON_FILENAME).is_file());
        // No hostname:port directory.
        assert!(!target.join("example.com:3000").exists());
        assert!(!target.join("tv").exists());

        let jsonl =
            std::fs::read_to_string(vector_dir.join(DID_DOCUMENTS_JSONL_FILENAME)).expect("jsonl");
        assert_eq!(jsonl, vector.jsonl_body());

        let metadata: TestVectorMetadata = serde_json::from_str(
            &std::fs::read_to_string(vector_dir.join(TEST_VECTOR_JSON_FILENAME)).expect("meta"),
        )
        .expect("parse meta");
        assert_eq!(metadata.format, TEST_VECTOR_FORMAT);
        assert_eq!(metadata.did, vector.did.to_string());
        assert_eq!(metadata.name, "writer-layout");
        assert_eq!(metadata.generator.seed, "writer-test-seed");

        let index: TestVectorIndex = serde_json::from_str(
            &std::fs::read_to_string(target.join(INDEX_JSON_FILENAME)).expect("index"),
        )
        .expect("parse index");
        assert_eq!(index.format, crate::TEST_VECTOR_INDEX_FORMAT);
        assert_eq!(index.vector_m.len(), 1);
        let location = &index.vector_m["writer-layout"];
        assert_eq!(location.path, relative);
        assert_eq!(location.did, vector.did.to_string());
        assert_eq!(index.group_m["positive"], ["writer-layout"]);
        assert_eq!(index.group_m["conformance"], ["writer-layout"]);
        assert!(!index.group_m.contains_key("negative"));

        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn write_all_extra_path_components_under_base() {
        let target = temp_target_dir("extra-path");
        let mut params = TestVectorParams::baseline("example.com");
        params.path_component_v = vec![
            "tv".to_owned(),
            "demo".to_owned(),
            "teams".to_owned(),
            "identity".to_owned(),
            "alice".to_owned(),
        ];
        let vector = sample_vector(params, "multi-path");

        let writer = TestVectorWriter::new(&target)
            .with_base_path_components(["tv".to_owned(), "demo".to_owned()]);
        writer
            .write_all(std::slice::from_ref(&vector), "seed")
            .expect("write_all");

        let relative = writer.vector_relative_path(&vector.did).expect("relative");
        assert_eq!(
            relative,
            format!("teams/identity/alice/{}", vector.did.root_self_hash())
        );
        assert!(
            writer
                .vector_dir_path(&vector.did)
                .expect("dir")
                .join(DID_DOCUMENTS_JSONL_FILENAME)
                .is_file()
        );
        assert!(target.join(INDEX_JSON_FILENAME).is_file());

        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn write_all_port_does_not_create_host_subdir() {
        let target = temp_target_dir("port");
        let mut with_port_params = TestVectorParams::baseline("example.com");
        with_port_params.port_o = Some(8443);
        let with_port = sample_vector(with_port_params, "with-port");
        let no_port = sample_vector(TestVectorParams::baseline("example.com"), "no-port");

        TestVectorWriter::new(&target)
            .write_all(&[no_port.clone(), with_port.clone()], "seed")
            .expect("write_all");

        assert!(target.join(INDEX_JSON_FILENAME).is_file());
        assert!(!target.join("example.com").exists());
        assert!(!target.join("example.com:8443").exists());
        assert!(
            TestVectorWriter::new(&target)
                .vector_dir_path(&no_port.did)
                .expect("dir")
                .join(DID_DOCUMENTS_JSONL_FILENAME)
                .is_file()
        );
        assert!(
            TestVectorWriter::new(&target)
                .vector_dir_path(&with_port.did)
                .expect("dir")
                .join(DID_DOCUMENTS_JSONL_FILENAME)
                .is_file()
        );

        let _ = std::fs::remove_dir_all(&target);
    }

    fn read_index(target_dir: &Path) -> TestVectorIndex {
        serde_json::from_str(
            &std::fs::read_to_string(target_dir.join(INDEX_JSON_FILENAME)).expect("index"),
        )
        .expect("parse index")
    }

    #[test]
    fn write_all_subset_preserves_preexisting_vectors_in_index() {
        let target = temp_target_dir("incremental");
        let writer = TestVectorWriter::new(&target);
        let first = sample_vector(TestVectorParams::baseline("example.com"), "first");
        let second = sample_vector(TestVectorParams::baseline("example.com"), "second");

        writer
            .write_all(std::slice::from_ref(&first), "writer-test-seed")
            .expect("write first");
        let index_after_first = read_index(&target);
        assert_eq!(index_after_first.vector_m.len(), 1);
        assert!(index_after_first.vector_m.contains_key("first"));

        writer
            .write_all(std::slice::from_ref(&second), "writer-test-seed")
            .expect("write second subset");
        let index_after_second = read_index(&target);
        assert_eq!(index_after_second.vector_m.len(), 2);
        assert_eq!(
            index_after_second.vector_m["first"].did,
            first.did.to_string()
        );
        assert_eq!(
            index_after_second.vector_m["first"].path,
            writer.vector_relative_path(&first.did).unwrap()
        );
        assert_eq!(
            index_after_second.vector_m["second"].did,
            second.did.to_string()
        );
        assert_eq!(
            index_after_second.vector_m["second"].path,
            writer.vector_relative_path(&second.did).unwrap()
        );
        assert_eq!(index_after_second.group_m["positive"], ["first", "second"]);
        assert_eq!(
            index_after_second.group_m["conformance"],
            ["first", "second"]
        );

        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn rebuild_indexes_under_matches_write_all_disk_scan() {
        let target = temp_target_dir("rebuild");
        let writer = TestVectorWriter::new(&target);
        let a = sample_vector(TestVectorParams::baseline("alpha.example"), "alpha-vec");
        let mut beta_params = TestVectorParams::baseline("beta.example");
        beta_params.port_o = Some(443);
        let b = sample_vector(beta_params, "beta-vec");

        writer
            .write_all(&[a.clone(), b.clone()], "writer-test-seed")
            .expect("write_all");
        let index_before = read_index(&target);

        std::fs::remove_file(target.join(INDEX_JSON_FILENAME)).expect("remove index");

        let rebuilt = writer.rebuild_indexes_under().expect("rebuild_indexes_under");
        assert_eq!(rebuilt, 1);
        assert_eq!(read_index(&target), index_before);

        let _ = std::fs::remove_dir_all(&target);
    }

    /// Hand-place vectors with `write_vector` (no index), rebuild, and match `write_all`.
    #[test]
    fn rebuild_from_hand_built_tree_matches_write_all() {
        let seed = "writer-test-seed";
        let positive = sample_vector(TestVectorParams::baseline("example.com"), "hand-positive");
        let mut negative = sample_vector(TestVectorParams::baseline("example.com"), "hand-negative");
        negative.category = "jsonl-structural".to_owned();
        negative.expected = Expected::reject_after(
            negative.expected.did_document_count,
            0,
            crate::ErrorCode::MalformedId,
            0,
        );

        let write_all_dir = temp_target_dir("hand-write-all");
        TestVectorWriter::new(&write_all_dir)
            .write_all(&[positive.clone(), negative.clone()], seed)
            .expect("write_all");
        let expected = read_index(&write_all_dir);

        let hand_dir = temp_target_dir("hand-built");
        let hand_writer = TestVectorWriter::new(&hand_dir);
        hand_writer.write_vector(&positive, seed).expect("write positive");
        hand_writer
            .write_vector(&negative, seed)
            .expect("write negative");
        assert!(!hand_dir.join(INDEX_JSON_FILENAME).exists());
        hand_writer.rebuild_index().expect("rebuild hand-built tree");
        let rebuilt = read_index(&hand_dir);

        assert_eq!(rebuilt.format, crate::TEST_VECTOR_INDEX_FORMAT);
        assert_eq!(rebuilt, expected);
        assert_eq!(rebuilt.group_m["positive"], ["hand-positive"]);
        assert_eq!(rebuilt.group_m["negative"], ["hand-negative"]);
        assert_eq!(rebuilt.group_m["conformance"], ["hand-positive"]);
        assert_eq!(rebuilt.group_m["jsonl-structural"], ["hand-negative"]);

        let _ = std::fs::remove_dir_all(&write_all_dir);
        let _ = std::fs::remove_dir_all(&hand_dir);
    }

    #[test]
    fn vector_relative_path_rejects_missing_base_prefix() {
        let writer = TestVectorWriter::new(".").with_base_path_components(["tv".to_owned()]);
        let vector = sample_vector(TestVectorParams::baseline("example.com"), "no-prefix");
        assert!(writer.vector_relative_path(&vector.did).is_err());
    }

    #[test]
    fn validate_relative_path_rejects_empty_dotdot_and_backslash() {
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("a/../b").is_err());
        assert!(validate_relative_path("a/./b").is_err());
        assert!(validate_relative_path("a\\b").is_err());
        assert!(validate_relative_path("/a").is_err());
        assert!(validate_relative_path("a//b").is_err());
        assert!(validate_relative_path("tv/demo/hash").is_ok());
    }
}
