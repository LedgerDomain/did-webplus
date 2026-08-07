use crate::{DEFAULT_FUZZ_LITE_COUNT, DEFAULT_SEED, StressConfig, TestVectorParams};

/// Default listen port for the test-vector HTTP service (unprivileged local serving).
const DEFAULT_LISTEN_PORT: u16 = 3000;

/// Configuration for the in-memory test-vector HTTP server.
///
/// Generation uses [`Self::host`] and [`Self::listen_port`] as the DID hostname and
/// DID port (same listen/DID-port pairing as the VDR). Optional [`Self::did_path_o`]
/// becomes every vector's shared DID path prefix. At spawn time the full catalog is
/// materialized eagerly into memory (V2 MVP); size caps are [`StressConfig`] and
/// [`Self::fuzz_lite_count`].
#[derive(clap::Args, Clone, Debug)]
pub struct TestVectorServerConfig {
    /// Hostname that appears in generated DIDs (no scheme or port).
    #[arg(
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_HOST",
        value_name = "HOST",
        default_value = "localhost"
    )]
    pub host: String,

    /// TCP listen port; also the DID port embedded in every generated DID.
    #[arg(
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_LISTEN_PORT",
        value_name = "PORT",
        default_value_t = DEFAULT_LISTEN_PORT
    )]
    pub listen_port: u16,

    /// Optional DID path components, colon-separated (e.g. `tv:demo`).
    ///
    /// These appear in every DID and as the URL path prefix for served bodies.
    #[arg(
        name = "did-path",
        long = "did-path",
        env = "DID_WEBPLUS_TEST_VECTOR_DID_PATH",
        value_name = "PATH"
    )]
    pub did_path_o: Option<String>,

    /// Global seed for deterministic per-vector RNG derivation.
    #[arg(
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_SEED",
        value_name = "STRING",
        default_value = DEFAULT_SEED
    )]
    pub seed: String,

    /// Number of fuzz-lite vectors to include (`0` skips fuzz-lite).
    #[arg(
        name = "fuzz-lite-count",
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_FUZZ_LITE_COUNT",
        value_name = "N",
        default_value_t = DEFAULT_FUZZ_LITE_COUNT
    )]
    pub fuzz_lite_count: u32,

    /// Override stress-catalog version-count tiers (comma-separated), e.g. `100,1000`.
    #[arg(
        name = "stress-versions",
        long = "stress-versions",
        env = "DID_WEBPLUS_TEST_VECTOR_STRESS_VERSIONS",
        value_name = "N",
        value_delimiter = ','
    )]
    pub stress_version_vo: Option<Vec<u32>>,

    /// When set (typically by tests), used as the full stress config instead of
    /// [`StressConfig::default`] plus [`Self::stress_version_vo`].
    #[arg(skip)]
    pub stress_config_o: Option<StressConfig>,
}

impl TestVectorServerConfig {
    /// DID path components from [`Self::did_path_o`] (colon-separated).
    pub fn path_component_v(&self) -> Vec<String> {
        match self.did_path_o.as_deref() {
            None => Vec::new(),
            Some(path) if path.is_empty() => Vec::new(),
            Some(path) => path
                .split(':')
                .filter(|component| !component.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }

    /// Generation params: baseline crypto with this host, listen port as DID port,
    /// and configured path components.
    pub fn params(&self) -> TestVectorParams {
        let mut params = TestVectorParams::baseline(self.host.clone());
        params.port_o = Some(self.listen_port);
        params.path_component_v = self.path_component_v();
        params
    }

    /// Stress bounds: [`Self::stress_config_o`] if set, otherwise default with optional
    /// version-count override from [`Self::stress_version_vo`].
    pub fn stress_config(&self) -> StressConfig {
        if let Some(stress_config) = &self.stress_config_o {
            return stress_config.clone();
        }
        let mut config = StressConfig::default();
        if let Some(version_count_v) = &self.stress_version_vo {
            config.version_count_v = version_count_v.clone();
        }
        config
    }
}
