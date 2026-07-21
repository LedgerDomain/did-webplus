/// Configurable bounds for bounded stress-vector generation.
///
/// Defaults match the catalog plan (~100 / ~1,000 version tiers, hundreds of
/// verification methods). The CLI can override these later (e.g.
/// `--stress-versions`) without changing catalog factories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StressConfig {
    /// Document counts for `stress-many-versions-{n}` vectors.
    ///
    /// Each entry `n` produces a fully valid microledger with `n` versions
    /// (root plus `n - 1` updates). Default: `[100, 1000]`.
    pub version_count_v: Vec<u32>,
    /// Number of verification methods in the large-document stress vector.
    ///
    /// Default: `200` (hundreds).
    pub verification_method_count: u32,
    /// Target bytes of additional known-field material in the large-document
    /// vector, realized as unused `updateRules` keys under an `any` rule.
    ///
    /// Default: `65536` (64 KiB).
    pub extra_field_byte_count: u32,
    /// Nesting depth for the deeply-nested `updateRules` stress vector.
    ///
    /// Default: `32`.
    pub update_rules_nesting_depth: u32,
    /// Number of authorizing proofs (and matching `all` keys) in the
    /// many-proofs stress vector.
    ///
    /// Default: `32`.
    pub proof_count: u32,
    /// Number of DID path components in the long-DID-path stress vector.
    ///
    /// Default: `32`.
    pub did_path_component_count: u32,
}

impl Default for StressConfig {
    fn default() -> Self {
        Self {
            version_count_v: vec![100, 1000],
            verification_method_count: 200,
            extra_field_byte_count: 64 * 1024,
            update_rules_nesting_depth: 32,
            proof_count: 32,
            did_path_component_count: 32,
        }
    }
}

impl StressConfig {
    /// Compact bounds suitable for unit tests (avoids multi-second generation).
    pub fn for_tests() -> Self {
        Self {
            version_count_v: vec![3, 5],
            verification_method_count: 8,
            extra_field_byte_count: 512,
            update_rules_nesting_depth: 4,
            proof_count: 4,
            did_path_component_count: 6,
        }
    }
}
