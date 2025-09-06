use did_webplus_vdg_lib::{LogFormat, VDGConfig};

/// did:webplus Verifiable Data Gateway (VDG) service.
/// See https://github.com/LedgerDomain/did-webplus?tab=readme-ov-file#verifiable-data-gateway-vdg for details.
#[derive(clap::Parser)]
pub struct Root {
    #[command(flatten)]
    pub vdg_config: VDGConfig,
    /// Specify the format of the logs.
    #[arg(
        name = "log-format",
        env = "DID_WEBPLUS_VDG_LOG_FORMAT",
        long,
        value_name = "FORMAT",
        default_value = "compact",
        value_enum
    )]
    pub log_format: LogFormat,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    let tracing_subscriber_fmt = tracing_subscriber::fmt()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());

    use clap::Parser;
    let root = Root::parse();

    match root.log_format {
        LogFormat::Compact => tracing_subscriber_fmt.compact().init(),
        LogFormat::Pretty => tracing_subscriber_fmt.pretty().init(),
    }

    // Spawn the VDG, returning a JoinHandle to the task.
    let vdg_join_handle = did_webplus_vdg_lib::spawn_vdg(root.vdg_config).await?;
    // Join the task by awaiting it.
    vdg_join_handle.await?;

    Ok(())
}
