use did_webplus_vdr_lib::{LogFormat, VDRConfig};

/// did:webplus Verifiable Data Registry (VDR) service.
/// See https://github.com/LedgerDomain/did-webplus?tab=readme-ov-file#verifiable-data-registry-vdr for details.
#[derive(clap::Parser)]
pub struct Root {
    #[command(flatten)]
    pub vdr_config: VDRConfig,
    /// Specify the format of the logs.
    #[arg(
        name = "log-format",
        env = "DID_WEBPLUS_VDR_LOG_FORMAT",
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
        LogFormat::JSON => tracing_subscriber_fmt.json().init(),
        LogFormat::Pretty => tracing_subscriber_fmt.pretty().init(),
    };

    // Spawn the VDR, returning a JoinHandle to the task.
    let vdr_join_handle = did_webplus_vdr_lib::spawn_vdr(root.vdr_config).await?;
    // Join the task by awaiting it.
    vdr_join_handle.await?;

    Ok(())
}
