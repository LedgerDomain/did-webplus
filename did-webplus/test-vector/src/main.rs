//! Thin CLI over [`did_webplus_test_vector_lib`].
//!
//! Design, schemas, determinism, and harness consumption are documented in the
//! library crate (`did-webplus-test-vector-lib`); this binary only parses flags
//! and calls [`Catalog`] / [`TestVectorWriter`].
//!
//! Environment variables use the `DID_WEBPLUS_TEST_VECTOR_*` prefix (via clap `env`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use did_webplus_test_vector_lib::{
    Catalog, CatalogDescriptor, CatalogListRequest, DEFAULT_SEED, StressConfig, TestVectorParams,
    TestVectorWriter,
};

/// Default number of fuzz-lite vectors included by `generate`.
const DEFAULT_FUZZ_LITE_COUNT: u32 = 128;

/// did:webplus test vector generator.
///
/// Generates a comprehensive, servable catalog of did:webplus test-vector microledgers.
#[derive(Debug, Parser)]
#[command(
    name = "did-webplus-test-vector",
    version,
    about = "Generate did:webplus test-vector microledgers"
)]
struct Root {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate the deterministic catalog (all categories) and write it.
    Generate(GenerateArgs),
    /// Rebuild `index.json` from on-disk `test-vector.json` metadata under `--target-dir`.
    RebuildIndex(RebuildIndexArgs),
}

/// Arguments shared by generation (host identity and stress overrides).
#[derive(Args, Clone, Debug)]
struct SharedArgs {
    /// DID hostname (e.g. `example.com`, `localhost`).
    #[arg(long, env = "DID_WEBPLUS_TEST_VECTOR_HOST", value_name = "HOST")]
    host: String,

    /// Optional DID port (percent-encoded as `%3A<port>` in the DID).
    ///
    /// Port presence in generated DIDs is controlled exclusively by this flag.
    #[arg(
        long = "port",
        env = "DID_WEBPLUS_TEST_VECTOR_PORT",
        value_name = "PORT"
    )]
    port_o: Option<u16>,

    /// Optional DID path components, colon-separated (e.g. `tv:demo`).
    ///
    /// These components appear in every DID. `--target-dir` is the on-disk directory
    /// that already corresponds to this path on the serving host (they are not
    /// re-created as subdirectories under `--target-dir`).
    #[arg(
        name = "did-path",
        long = "did-path",
        env = "DID_WEBPLUS_TEST_VECTOR_DID_PATH",
        value_name = "PATH"
    )]
    did_path_o: Option<String>,

    /// Directory under which vectors and `index.json` are written.
    ///
    /// There is no `<hostname>[:<port>]` subdirectory; everything is placed directly
    /// under this directory. When `--did-path` is set, this should be the directory
    /// that will be served at that DID path.
    #[arg(
        name = "target-dir",
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_TARGET_DIR",
        value_name = "DIR",
        default_value = "."
    )]
    target_dir: PathBuf,

    /// Global seed for deterministic per-vector RNG derivation.
    #[arg(
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_SEED",
        value_name = "STRING",
        default_value = DEFAULT_SEED
    )]
    seed: String,

    /// Override stress-catalog version-count tiers (comma-separated), e.g. `100,1000`.
    #[arg(
        name = "stress-versions",
        long = "stress-versions",
        env = "DID_WEBPLUS_TEST_VECTOR_STRESS_VERSIONS",
        value_name = "N",
        value_delimiter = ','
    )]
    stress_version_vo: Option<Vec<u32>>,
}

#[derive(Args, Debug)]
struct GenerateArgs {
    #[command(flatten)]
    shared: SharedArgs,

    /// Print planned vectors (name, category, positive|negative, description) and exit.
    ///
    /// No file I/O and no crypto / microledger generation.
    #[arg(long, env = "DID_WEBPLUS_TEST_VECTOR_DRY_RUN")]
    dry_run: bool,

    /// Number of fuzz-lite vectors to include (`0` skips fuzz-lite).
    #[arg(
        name = "fuzz-lite-count",
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_FUZZ_LITE_COUNT",
        value_name = "N",
        default_value_t = DEFAULT_FUZZ_LITE_COUNT
    )]
    fuzz_lite_count: u32,
}

#[derive(Args, Debug)]
struct RebuildIndexArgs {
    /// Directory to scan for `test-vector.json` and rewrite `index.json`.
    #[arg(
        name = "target-dir",
        long,
        env = "DID_WEBPLUS_TEST_VECTOR_TARGET_DIR",
        value_name = "DIR",
        default_value = "."
    )]
    target_dir: PathBuf,
}

impl SharedArgs {
    fn params(&self) -> TestVectorParams {
        let mut params = TestVectorParams::baseline(self.host.clone());
        params.port_o = self.port_o;
        params.path_component_v = parse_did_path(self.did_path_o.as_deref());
        params
    }

    fn stress_config(&self) -> StressConfig {
        let mut config = StressConfig::default();
        if let Some(version_count_v) = &self.stress_version_vo {
            config.version_count_v = version_count_v.clone();
        }
        config
    }

    fn writer(&self) -> TestVectorWriter {
        TestVectorWriter::new(&self.target_dir)
            .with_base_path_components(parse_did_path(self.did_path_o.as_deref()))
    }
}

fn main() -> anyhow::Result<()> {
    // Ignore errors: there may not be a .env file (e.g. in CI or a docker image).
    let _ = dotenvy::dotenv();

    let root = Root::parse();
    match root.command {
        Command::Generate(args) => run_generate(args),
        Command::RebuildIndex(args) => run_rebuild_index(args),
    }
}

fn run_generate(args: GenerateArgs) -> anyhow::Result<()> {
    let shared = &args.shared;

    if args.dry_run {
        return run_dry_run(&args);
    }

    eprintln!("generating test-vector catalog...");
    let vector_v = Catalog::generate_with_progress(
        &shared.params(),
        &shared.seed,
        &shared.stress_config(),
        args.fuzz_lite_count,
        |message| {
            eprintln!("  {message}");
        },
    )?;
    let count = vector_v.len();
    eprintln!("writing {count} test vector(s)...");
    shared.writer().write_all(&vector_v, &shared.seed)?;
    eprintln!(
        "wrote {count} test vector(s) under {}",
        shared.target_dir.display()
    );
    Ok(())
}

fn run_dry_run(args: &GenerateArgs) -> anyhow::Result<()> {
    let mut descriptor_v = Catalog::list(&CatalogListRequest {
        fuzz_lite_count: args.fuzz_lite_count,
        seed: args.shared.seed.clone(),
        stress_config: args.shared.stress_config(),
    });
    descriptor_v.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.name.cmp(&right.name))
    });

    for descriptor in &descriptor_v {
        print_dry_run_entry(descriptor);
    }
    eprintln!("planned {} vector(s)", descriptor_v.len());
    Ok(())
}

fn print_dry_run_entry(descriptor: &CatalogDescriptor) {
    let outcome = if descriptor.positive {
        "positive"
    } else {
        "negative"
    };
    println!(
        "{}\t{}\t{}\t{}",
        descriptor.name, descriptor.category, outcome, descriptor.description
    );
}

fn run_rebuild_index(args: RebuildIndexArgs) -> anyhow::Result<()> {
    let writer = TestVectorWriter::new(&args.target_dir);
    eprintln!(
        "rebuilding index.json under {}...",
        args.target_dir.display()
    );
    writer.rebuild_index()?;
    eprintln!("rebuilt index.json");
    Ok(())
}

fn parse_did_path(did_path_o: Option<&str>) -> Vec<String> {
    match did_path_o {
        None => Vec::new(),
        Some(path) if path.is_empty() => Vec::new(),
        Some(path) => path
            .split(':')
            .filter(|component| !component.is_empty())
            .map(str::to_owned)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_path_splits_on_colon() {
        assert_eq!(parse_did_path(None), Vec::<String>::new());
        assert_eq!(
            parse_did_path(Some("tv:demo")),
            vec!["tv".to_owned(), "demo".to_owned()]
        );
        assert_eq!(parse_did_path(Some("")), Vec::<String>::new());
    }

    #[test]
    fn dry_run_list_omits_fuzz_lite_when_count_is_zero() {
        let descriptor_v = Catalog::list(&CatalogListRequest {
            fuzz_lite_count: 0,
            seed: DEFAULT_SEED.to_owned(),
            stress_config: StressConfig::default(),
        });
        assert!(
            descriptor_v
                .iter()
                .all(|descriptor| descriptor.category != "fuzz-lite")
        );
        assert!(
            descriptor_v
                .iter()
                .any(|descriptor| descriptor.category == "conformance")
        );
    }

    #[test]
    fn dry_run_list_includes_requested_fuzz_lite_count() {
        let fuzz_lite_count = 4;
        let descriptor_v = Catalog::list(&CatalogListRequest {
            fuzz_lite_count,
            seed: DEFAULT_SEED.to_owned(),
            stress_config: StressConfig::default(),
        });
        assert_eq!(
            descriptor_v
                .iter()
                .filter(|descriptor| descriptor.category == "fuzz-lite")
                .count(),
            fuzz_lite_count as usize
        );
    }
}
