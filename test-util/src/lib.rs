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
