use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        tracing::info!("Reading config from file: {:?}", args[1]);
        Some(&args[1])
    } else {
        tracing::info!("No config file found");
        None
    };

    let config =
        did_webplus_vdr_lib::AppConfig::new(config_path).context("Failed to load configuration")?;

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    let tracing_subscriber_fmt = tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
    match config.log_format {
        did_webplus_vdr_lib::LogFormat::Compact => tracing_subscriber_fmt.compact().init(),
        did_webplus_vdr_lib::LogFormat::Pretty => tracing_subscriber_fmt.pretty().init(),
    }

    // Spawn the VDR, returning a JoinHandle to the task.
    let vdr_join_handle = did_webplus_vdr_lib::spawn_vdr(config).await?;
    // Join the task by awaiting it.
    vdr_join_handle.await?;

    Ok(())
}
