use crate::VDRConfig;

#[derive(Clone)]
pub struct VDRAppState {
    pub did_doc_store: did_webplus_doc_store::DIDDocStore,
    pub vdr_config: VDRConfig,
}

impl VDRAppState {
    pub fn verify_authorization(
        &self,
        header_map: &axum::http::HeaderMap,
    ) -> Result<(), (axum::http::StatusCode, String)> {
        if let Some(test_api_keys) = self.vdr_config.test_authz_api_key_vo.as_deref() {
            tracing::trace!("VDR test API keys are enabled; conducting authorization check");
            if let Some(api_key) = header_map.get("x-api-key") {
                let api_key_string = api_key
                    .to_str()
                    .map_err(|_| {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            "malformed API key".to_string(),
                        )
                    })?
                    .to_string();
                if !test_api_keys.contains(&api_key_string) {
                    tracing::error!("API key not authorized");
                    Err((
                        axum::http::StatusCode::UNAUTHORIZED,
                        "API key not authorized".to_string(),
                    ))
                } else {
                    tracing::debug!("API key authorized");
                    Ok(())
                }
            } else {
                tracing::error!("required API key not provided");
                Err((
                    axum::http::StatusCode::UNAUTHORIZED,
                    "API key not provided".to_string(),
                ))
            }
        } else {
            tracing::trace!(
                "VDR test API keys are disabled; no authorization check will be performed"
            );
            Ok(())
        }
    }
}
