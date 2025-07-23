lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}

pub async fn service_is_up(service_health_endpoint_url: &str) -> bool {
    match REQWEST_CLIENT.get(service_health_endpoint_url).send().await {
        Ok(health_response) => health_response.status() == reqwest::StatusCode::OK,
        Err(_) => false,
    }
}

pub async fn wait_until_service_is_up(service_name: &str, service_health_endpoint_url: &str) {
    loop {
        tracing::info!(
            "Checking if service \"{}\" is up via HTTP GET {}",
            service_name,
            service_health_endpoint_url
        );
        if service_is_up(service_health_endpoint_url).await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tracing::info!("Service \"{}\" is up", service_name);
}

/// Load .env file and initialize logging.
pub fn ctor_overall_init() {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // NOTE: We use pretty() here for maximal debug information.  It might be useful to specify
    // pretty vs compact via env var.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .pretty()
        .init();
}
