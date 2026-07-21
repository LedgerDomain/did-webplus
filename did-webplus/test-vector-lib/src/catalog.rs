use crate::{DeterministicRng, StressConfig, TestVector, TestVectorParams};

/// A named deterministic test-vector factory.
#[derive(Clone, Copy)]
pub struct VectorDefinition {
    /// Stable vector name used for catalog lookup and RNG derivation.
    pub name: &'static str,
    /// Human-readable summary of the vector's purpose.
    pub description: &'static str,
    /// `true` when the vector is expected to fully validate.
    pub positive: bool,
    /// Factory which generates the vector from parameters and a per-vector RNG.
    pub factory: fn(TestVectorParams, DeterministicRng) -> anyhow::Result<TestVector>,
}

impl std::fmt::Debug for VectorDefinition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VectorDefinition")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("positive", &self.positive)
            .finish_non_exhaustive()
    }
}

/// Cheap catalog listing entry for `--dry-run` (no crypto / microledger generation).
///
/// Produced by [`Catalog::list`]. Stress and fuzz-lite names are derived from
/// [`CatalogListRequest`] size/seed knobs alone — no [`crate::MicroledgerBuilder`]
/// work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogDescriptor {
    /// Stable vector name.
    pub name: String,
    /// Catalog category (`conformance`, `stress`, …).
    pub category: String,
    /// Human-readable summary.
    pub description: String,
    /// `true` when the vector is expected to fully validate.
    pub positive: bool,
}

/// Size and seed knobs for [`Catalog::list`].
///
/// Always lists every category. `fuzz_lite_count` of `0` omits fuzz-lite names;
/// `stress_config` and `seed` shape stress / fuzz-lite names only so dry-run and
/// generation agree without running factories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogListRequest {
    /// Number of fuzz-lite vectors (`0` means none).
    pub fuzz_lite_count: u32,
    /// CLI seed used to qualify fuzz-lite vector names (`fuzz-lite-<seed_hex>-…`).
    pub seed: String,
    /// Stress size overrides (affects stress names).
    pub stress_config: StressConfig,
}

/// Enumerates and generates the deterministic test-vector catalog.
///
/// See the [crate-level design](crate) for determinism, categories, and harness
/// consumption. Generation methods use [`DeterministicRng::for_vector`] with the
/// global seed and vector name, except fuzz-lite (name embeds the seed; RNG from
/// the final name only — see [`Self::generate_fuzz_lite`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct Catalog;

impl Catalog {
    /// Return every conformance vector definition in stable catalog order.
    pub fn conformance_definitions() -> &'static [VectorDefinition] {
        crate::conformance_catalog::definitions()
    }

    /// Generate the complete conformance catalog.
    ///
    /// Each definition receives an independently derived RNG, so adding or
    /// reordering definitions cannot change an existing vector.
    pub fn generate_conformance(
        params: &TestVectorParams,
        global_seed: &str,
    ) -> anyhow::Result<Vec<TestVector>> {
        Self::conformance_definitions()
            .iter()
            .map(|definition| {
                (definition.factory)(
                    params.clone(),
                    DeterministicRng::for_vector(global_seed, definition.name),
                )
            })
            .collect()
    }

    /// Return every positive coverage-matrix vector definition in stable catalog order.
    pub fn coverage_matrix_definitions() -> &'static [VectorDefinition] {
        crate::coverage_matrix_catalog::definitions()
    }

    /// Generate the complete positive coverage matrix.
    ///
    /// Each definition receives an independently derived RNG, so adding or
    /// reordering definitions cannot change an existing vector.
    pub fn generate_coverage_matrix(
        params: &TestVectorParams,
        global_seed: &str,
    ) -> anyhow::Result<Vec<TestVector>> {
        Self::coverage_matrix_definitions()
            .iter()
            .map(|definition| {
                (definition.factory)(
                    params.clone(),
                    DeterministicRng::for_vector(global_seed, definition.name),
                )
            })
            .collect()
    }

    /// Return every jsonl-structural vector definition in stable catalog order.
    pub fn jsonl_structural_definitions() -> &'static [VectorDefinition] {
        crate::jsonl_structural_catalog::definitions()
    }

    /// Generate the complete jsonl-structural catalog.
    ///
    /// Each definition receives an independently derived RNG, so adding or
    /// reordering definitions cannot change an existing vector.
    pub fn generate_jsonl_structural(
        params: &TestVectorParams,
        global_seed: &str,
    ) -> anyhow::Result<Vec<TestVector>> {
        Self::jsonl_structural_definitions()
            .iter()
            .map(|definition| {
                (definition.factory)(
                    params.clone(),
                    DeterministicRng::for_vector(global_seed, definition.name),
                )
            })
            .collect()
    }

    /// Return every resolution-URL relative vector definition in stable catalog order.
    pub fn resolution_definitions() -> &'static [VectorDefinition] {
        crate::resolution_catalog::definitions()
    }

    /// Generate the complete resolution-URL relative catalog.
    ///
    /// Each definition receives an independently derived RNG, so adding or
    /// reordering definitions cannot change an existing vector. Bodies are fully
    /// valid microledgers; [`TestVector::did`] is the mismatched resolution DID.
    pub fn generate_resolution(
        params: &TestVectorParams,
        global_seed: &str,
    ) -> anyhow::Result<Vec<TestVector>> {
        Self::resolution_definitions()
            .iter()
            .map(|definition| {
                (definition.factory)(
                    params.clone(),
                    DeterministicRng::for_vector(global_seed, definition.name),
                )
            })
            .collect()
    }

    /// Stable stress-vector names for the given configurable bounds.
    pub fn stress_vector_names(config: &StressConfig) -> Vec<String> {
        crate::stress_catalog::vector_names(config)
    }

    /// Generate the bounded stress catalog using `config` size overrides.
    ///
    /// Version-count tiers and other sizes come from [`StressConfig`] so a CLI
    /// can later override defaults (e.g. `--stress-versions`) without changing
    /// factories. Each vector still uses an independently derived RNG keyed by
    /// its stable name.
    pub fn generate_stress(
        params: &TestVectorParams,
        global_seed: &str,
        config: &StressConfig,
    ) -> anyhow::Result<Vec<TestVector>> {
        crate::stress_catalog::generate(params, global_seed, config)
    }

    /// Generate the bounded stress catalog and report each vector before work begins.
    ///
    /// The callback allows interactive clients to provide progress feedback during
    /// expensive vectors while keeping the library independent of any logging policy.
    pub fn generate_stress_with_progress(
        params: &TestVectorParams,
        global_seed: &str,
        config: &StressConfig,
        on_start: impl FnMut(&str),
    ) -> anyhow::Result<Vec<TestVector>> {
        crate::stress_catalog::generate_with_progress(params, global_seed, config, on_start)
    }

    /// Generate `count` fuzz-lite (seeded structured-mutation) vectors.
    ///
    /// Names are `fuzz-lite-<seed_hex>-{index:05}` (see [`Self::fuzz_lite_vector_names`]).
    /// The RNG is `DeterministicRng::for_vector("", name)` so the seed embedded in
    /// the name is not hashed a second time. The original `seed` string is recorded
    /// in each vector's `generator.seed` metadata. Reproducible from
    /// `(seed, count, params)` alone.
    pub fn generate_fuzz_lite(
        params: &TestVectorParams,
        seed: &str,
        count: u32,
    ) -> anyhow::Result<Vec<TestVector>> {
        crate::fuzz_lite_catalog::generate(params, seed, count)
    }

    /// Stable, seed-qualified fuzz-lite vector names for `count` (no generation).
    ///
    /// Format: `fuzz-lite-<seed_hex>-{index:05}`, where `seed_hex` is the full
    /// lowercase hex of `seed`'s UTF-8 bytes. Cheap enough for `--dry-run` and
    /// index listing; the CLI seed remains reconstructible by hex-decoding the
    /// middle component.
    pub fn fuzz_lite_vector_names(seed: &str, count: u32) -> Vec<String> {
        crate::fuzz_lite_catalog::vector_names(seed, count)
    }

    /// Generate the full catalog (all categories; fuzz-lite size from `fuzz_lite_count`).
    ///
    /// Category order matches [`Self::list`]. Reports progress via `on_progress`
    /// before each category (and before each stress vector). `fuzz_lite_count` of
    /// `0` skips fuzz-lite.
    pub fn generate_with_progress(
        params: &TestVectorParams,
        seed: &str,
        stress: &StressConfig,
        fuzz_lite_count: u32,
        mut on_progress: impl FnMut(&str),
    ) -> anyhow::Result<Vec<TestVector>> {
        let mut vector_v = Vec::new();

        on_progress("generating conformance vectors...");
        vector_v.extend(Self::generate_conformance(params, seed)?);

        on_progress("generating coverage-matrix vectors...");
        vector_v.extend(Self::generate_coverage_matrix(params, seed)?);

        on_progress("generating JSONL-structural vectors...");
        vector_v.extend(Self::generate_jsonl_structural(params, seed)?);

        on_progress("generating resolution-URL vectors...");
        vector_v.extend(Self::generate_resolution(params, seed)?);

        on_progress("generating stress vectors (this may take a while)...");
        vector_v.extend(Self::generate_stress_with_progress(
            params,
            seed,
            stress,
            |name| {
                on_progress(&format!("generating {name}..."));
            },
        )?);

        if fuzz_lite_count > 0 {
            on_progress(&format!("generating {fuzz_lite_count} fuzz-lite vector(s)..."));
            vector_v.extend(Self::generate_fuzz_lite(params, seed, fuzz_lite_count)?);
        }

        Ok(vector_v)
    }

    /// List planned vectors without generating keys or microledgers.
    ///
    /// Returns [`CatalogDescriptor`] rows for the full catalog in generation order
    /// (conformance → coverage-matrix → jsonl-structural → resolution → stress →
    /// fuzz-lite). Stress / fuzz-lite names come from config and seed only;
    /// `fuzz_lite_count` of `0` omits fuzz-lite.
    pub fn list(request: &CatalogListRequest) -> Vec<CatalogDescriptor> {
        let mut descriptor_v = Vec::new();

        for definition in Self::conformance_definitions() {
            descriptor_v.push(CatalogDescriptor {
                name: definition.name.to_owned(),
                category: "conformance".to_owned(),
                description: definition.description.to_owned(),
                positive: definition.positive,
            });
        }
        for definition in Self::coverage_matrix_definitions() {
            descriptor_v.push(CatalogDescriptor {
                name: definition.name.to_owned(),
                category: "coverage-matrix".to_owned(),
                description: definition.description.to_owned(),
                positive: definition.positive,
            });
        }
        for definition in Self::jsonl_structural_definitions() {
            descriptor_v.push(CatalogDescriptor {
                name: definition.name.to_owned(),
                category: "jsonl-structural".to_owned(),
                description: definition.description.to_owned(),
                positive: definition.positive,
            });
        }
        for definition in Self::resolution_definitions() {
            descriptor_v.push(CatalogDescriptor {
                name: definition.name.to_owned(),
                category: "resolution".to_owned(),
                description: definition.description.to_owned(),
                positive: definition.positive,
            });
        }
        descriptor_v.extend(crate::stress_catalog::descriptors(&request.stress_config));
        if request.fuzz_lite_count > 0 {
            for name in Self::fuzz_lite_vector_names(&request.seed, request.fuzz_lite_count) {
                descriptor_v.push(CatalogDescriptor {
                    name,
                    category: "fuzz-lite".to_owned(),
                    description: "Seeded single-field structured mutation.".to_owned(),
                    positive: false,
                });
            }
        }

        descriptor_v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_matches_definition_metadata_and_name_helpers() {
        let seed = "list-seed";
        let fuzz_lite_count = 4;
        let stress_config = StressConfig {
            version_count_v: vec![3, 7],
            ..StressConfig::default()
        };
        let descriptor_v = Catalog::list(&CatalogListRequest {
            fuzz_lite_count,
            seed: seed.to_owned(),
            stress_config: stress_config.clone(),
        });

        let conformance_n = Catalog::conformance_definitions().len();
        let coverage_n = Catalog::coverage_matrix_definitions().len();
        let jsonl_n = Catalog::jsonl_structural_definitions().len();
        let resolution_n = Catalog::resolution_definitions().len();
        let stress_n = Catalog::stress_vector_names(&stress_config).len();
        assert_eq!(
            descriptor_v.len(),
            conformance_n + coverage_n + jsonl_n + resolution_n + stress_n + fuzz_lite_count as usize
        );

        let mut index = 0;
        for definition in Catalog::conformance_definitions() {
            let descriptor = &descriptor_v[index];
            assert_eq!(descriptor.name, definition.name);
            assert_eq!(descriptor.category, "conformance");
            assert_eq!(descriptor.description, definition.description);
            assert_eq!(descriptor.positive, definition.positive);
            index += 1;
        }
        for definition in Catalog::coverage_matrix_definitions() {
            let descriptor = &descriptor_v[index];
            assert_eq!(descriptor.name, definition.name);
            assert_eq!(descriptor.category, "coverage-matrix");
            assert_eq!(descriptor.description, definition.description);
            assert_eq!(descriptor.positive, definition.positive);
            index += 1;
        }
        for definition in Catalog::jsonl_structural_definitions() {
            let descriptor = &descriptor_v[index];
            assert_eq!(descriptor.name, definition.name);
            assert_eq!(descriptor.category, "jsonl-structural");
            assert_eq!(descriptor.description, definition.description);
            assert_eq!(descriptor.positive, definition.positive);
            index += 1;
        }
        for definition in Catalog::resolution_definitions() {
            let descriptor = &descriptor_v[index];
            assert_eq!(descriptor.name, definition.name);
            assert_eq!(descriptor.category, "resolution");
            assert_eq!(descriptor.description, definition.description);
            assert_eq!(descriptor.positive, definition.positive);
            index += 1;
        }

        let stress_name_v = Catalog::stress_vector_names(&stress_config);
        for (offset, name) in stress_name_v.iter().enumerate() {
            let descriptor = &descriptor_v[index + offset];
            assert_eq!(&descriptor.name, name);
            assert_eq!(descriptor.category, "stress");
            assert!(descriptor.positive);
            assert!(!descriptor.description.is_empty());
        }
        index += stress_n;

        let fuzz_name_v = Catalog::fuzz_lite_vector_names(seed, fuzz_lite_count);
        for (offset, name) in fuzz_name_v.iter().enumerate() {
            let descriptor = &descriptor_v[index + offset];
            assert_eq!(&descriptor.name, name);
            assert_eq!(descriptor.category, "fuzz-lite");
            assert!(!descriptor.positive);
            assert!(!descriptor.description.is_empty());
            assert!(name.starts_with("fuzz-lite-"));
            assert!(name.ends_with(&format!("-{offset:05}")));
        }
    }

    #[test]
    fn list_omits_fuzz_lite_when_count_is_zero() {
        let descriptor_v = Catalog::list(&CatalogListRequest {
            fuzz_lite_count: 0,
            seed: "unused".to_owned(),
            stress_config: StressConfig::default(),
        });
        assert!(
            descriptor_v
                .iter()
                .all(|descriptor| descriptor.category != "fuzz-lite")
        );
        assert!(!descriptor_v.is_empty());
    }

    #[test]
    fn list_fuzz_names_match_generated_vector_names() {
        let seed = "align-seed";
        let count = 3;
        let descriptor_v = Catalog::list(&CatalogListRequest {
            fuzz_lite_count: count,
            seed: seed.to_owned(),
            stress_config: StressConfig::default(),
        });
        let fuzz_descriptor_v: Vec<_> = descriptor_v
            .into_iter()
            .filter(|descriptor| descriptor.category == "fuzz-lite")
            .collect();
        let params = crate::TestVectorParams::baseline("example.com");
        let vector_v = Catalog::generate_fuzz_lite(&params, seed, count).unwrap();
        assert_eq!(fuzz_descriptor_v.len(), vector_v.len());
        for (descriptor, vector) in fuzz_descriptor_v.iter().zip(vector_v.iter()) {
            assert_eq!(descriptor.name, vector.name);
            assert_eq!(descriptor.category, vector.category);
            assert!(!descriptor.positive);
            assert!(!vector.expected.is_fully_valid());
        }
    }

    /// `--dry-run` must stay cheap: listing derives stress names from config alone.
    ///
    /// A version count this large would hang (or OOM) if `Catalog::list` invoked
    /// stress factories / `MicroledgerBuilder`. Completing with the expected names
    /// proves the dry-run path does not call those factories.
    #[test]
    fn list_does_not_invoke_stress_factories() {
        let stress_config = StressConfig {
            version_count_v: vec![1_000_000],
            ..StressConfig::default()
        };
        let expected_name_v = Catalog::stress_vector_names(&stress_config);
        let descriptor_v = Catalog::list(&CatalogListRequest {
            fuzz_lite_count: 0,
            seed: "unused".to_owned(),
            stress_config,
        });
        let stress_descriptor_v: Vec<_> = descriptor_v
            .into_iter()
            .filter(|descriptor| descriptor.category == "stress")
            .collect();
        assert_eq!(stress_descriptor_v.len(), expected_name_v.len());
        for (descriptor, name) in stress_descriptor_v.iter().zip(expected_name_v.iter()) {
            assert_eq!(&descriptor.name, name);
            assert!(descriptor.positive);
        }
        assert_eq!(stress_descriptor_v[0].name, "stress-many-versions-1000000");
    }
}
