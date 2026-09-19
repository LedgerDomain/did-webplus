use std::collections::BTreeMap;

use crate::{ResolutionScenario, TestVector};

/// Result of a full catalog generation pass ([`crate::Catalog::generate_with_progress`]).
///
/// [`Self::vector_v`] is every generated vector in catalog order.
/// [`Self::resolution_scenario_m`] holds oracle-filled scenarios keyed by owning
/// vector name (only entries for the `resolution-scenario` category).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogGeneration {
    /// All generated vectors in catalog order.
    pub vector_v: Vec<TestVector>,
    /// Resolution scenarios keyed by owning [`TestVector::name`].
    pub resolution_scenario_m: BTreeMap<String, ResolutionScenario>,
}

impl CatalogGeneration {
    /// Empty generation result (no vectors, no scenarios).
    pub fn new() -> Self {
        Self::default()
    }
}
