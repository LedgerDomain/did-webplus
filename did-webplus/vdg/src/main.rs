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

    // Initialize logging based on format
    match root.log_format {
        LogFormat::Compact => tracing_subscriber_fmt.compact().init(),
        LogFormat::JSON => tracing_subscriber_fmt.json().init(),
        LogFormat::Pretty => tracing_subscriber_fmt.pretty().init(),
    }

    // Log startup banner
    tracing::info!("=================================================");
    tracing::info!("  did:webplus Verifiable Data Gateway (VDG)");
    tracing::info!("=================================================");
    tracing::info!("test1");

    // Log configuration details
    tracing::info!("Starting VDG service with configuration:");
    tracing::info!("  Listen Port: {}", root.vdg_config.listen_port);
    tracing::info!("  Log Format: {:?}", root.log_format);
    tracing::info!("  Database URL: {}", mask_database_url(&root.vdg_config.database_url));
    tracing::info!("  Database Max Connections: {}", root.vdg_config.database_max_connections);

    // Log HTTP scheme overrides if configured
    tracing::info!("  HTTP Scheme Overrides: {:?}", root.vdg_config.http_scheme_override);

    if root.vdg_config.test_authz_api_key_vo.is_some() {
        tracing::info!("  Authorization: Enabled (test mode with API keys)");
    } else {
        tracing::info!("  Authorization: Disabled");
    }

    tracing::info!("=================================================");

    // Spawn the VDG, returning a JoinHandle to the task.
    tracing::info!("Spawning VDG service...");
    let vdg_join_handle = did_webplus_vdg_lib::spawn_vdg(root.vdg_config).await?;
    tracing::info!("VDG service spawned successfully");

    // Join the task by awaiting it.
    tracing::info!("VDG service is now running and accepting requests");
    let result = vdg_join_handle.await;

    match &result {
        Ok(_) => tracing::info!("VDG service shut down gracefully"),
        Err(e) => tracing::error!("VDG service terminated with error: {}", e),
    }

    result?;
    Ok(())
}

/// Masks sensitive parts of the database URL for logging
fn mask_database_url(url: &str) -> String {
    // Parse the URL and mask password if present
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            // Found password, mask it
            let mut masked = String::from(&url[..colon_pos + 1]);
            masked.push_str("****");
            masked.push_str(&url[at_pos..]);
            return masked;
        }
    }
    // No password found or it's a simple URL like sqlite, return as-is
    url.to_string()
}
