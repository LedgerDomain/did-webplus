lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}

/// Spins up a VDG with the given listen port and database URL, and returns
/// the VDG host, VDG base URL, and the join handle for the VDG task.
pub async fn spin_up_vdg(
    listen_port: u16,
    database_url: String,
) -> (String, url::Url, tokio::task::JoinHandle<()>) {
    let vdg_config = did_webplus_vdg_lib::VDGConfig {
        listen_port,
        database_url,
        database_max_connections: 10,
        http_headers_for: Default::default(),
        http_scheme_override: Default::default(),
        test_authz_api_key_vo: None,
    };
    let vdg_host = format!("localhost:{}", listen_port);
    let vdg_base_url = url::Url::parse(&format!("http://{}", vdg_host)).expect("pass");
    let vdg_h = did_webplus_vdg_lib::spawn_vdg(vdg_config.clone())
        .await
        .expect("pass");
    (vdg_host, vdg_base_url, vdg_h)
}

/// Spins up a VDR with the given listen port, database URL, and VDG base URL,
/// and returns the VDR URL and the join handle for the VDR task.
pub async fn spin_up_vdr(
    listen_port: u16,
    database_url: String,
    vdg_base_url_o: Option<url::Url>,
) -> (url::Url, tokio::task::JoinHandle<()>) {
    let vdg_base_url_v = if let Some(vdg_base_url) = vdg_base_url_o {
        vec![vdg_base_url]
    } else {
        Vec::new()
    };
    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(listen_port),
        listen_port,
        database_url,
        database_max_connections: 10,
        vdg_base_url_v,
        http_scheme_override: Default::default(),
        test_authz_api_key_vo: None,
    };
    let vdr_url = url::Url::parse(&format!(
        "http://{}:{}",
        vdr_config.did_hostname, vdr_config.listen_port
    ))
    .expect("pass");
    let vdr_h = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");
    (vdr_url, vdr_h)
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
