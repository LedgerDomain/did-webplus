/// did:webplus Verifiable Data Gateway (VDG) service.
#[derive(clap::Parser)]
pub struct Root {
    #[command(flatten)]
    pub vdg_config: did_webplus_vdg_lib::VDGConfig,
    /// Specify the format of the logs.  Valid values are "compact" or "pretty".
    #[arg(
        name = "log-format",
        env = "DID_WEBPLUS_VDG_LOG_FORMAT",
        long,
        value_name = "FORMAT",
        default_value = "compact"
    )]
    pub log_format: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    let tracing_subscriber_fmt = tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());

    use clap::Parser;
    let root = Root::parse();

    match root.log_format.as_str() {
        "compact" => tracing_subscriber_fmt.compact().init(),
        "pretty" => tracing_subscriber_fmt.pretty().init(),
        _ => {
            tracing::warn!(
                "DID_WEBPLUS_VDG_LOG_FORMAT {:?} unrecognized; expected 'compact' or 'pretty'.  defaulting to 'compact'",
                root.log_format
            );
            tracing_subscriber_fmt.compact().init()
        }
    }

    // Spawn the VDG, returning a JoinHandle to the task.
    let vdg_join_handle = did_webplus_vdg_lib::spawn_vdg(root.vdg_config).await?;
    // Join the task by awaiting it.
    vdg_join_handle.await?;

    Ok(())
}
