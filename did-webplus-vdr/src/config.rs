use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Deserializer};
use serde_inline_default::serde_inline_default;

#[serde_inline_default]
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    #[serde_inline_default(vec![])]
    pub gateways: Vec<String>,
    pub service_domain: String,
    #[serde_inline_default(LogFormat::Compact)]
    #[serde(deserialize_with = "validate_log_format")]
    pub log_format: LogFormat,
    pub database_url: String,
    #[serde_inline_default(10)]
    pub max_connections: u32,
    #[serde_inline_default(80)]
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum LogFormat {
    Compact,
    Pretty,
}

fn validate_log_format<'de, D>(deserializer: D) -> Result<LogFormat, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer);
    if value.is_err() {
        tracing::error!("No log_format specified. Defaulting to 'compact'.");
        Ok(LogFormat::Compact)
    } else {
        let value = value.unwrap();
        match value.as_str() {
            "compact" => Ok(LogFormat::Compact),
            "pretty" => Ok(LogFormat::Pretty),
            _ => {
                tracing::error!("Invalid log format: {}. Valid values are 'compact' and 'pretty'. Defaulting to 'compact'.", value);
                Ok(LogFormat::Compact)
            }
        }
    }
}

impl AppConfig {
    pub fn new(path: Option<&String>) -> Result<Self, ConfigError> {
        let builder = if let Some(path) = path {
            Config::builder()
                // later sources override earlier ones
                .add_source(
                    Environment::with_prefix("DID_WEBPLUS_VDR")
                        .prefix_separator("_")
                        .convert_case(config::Case::Snake),
                )
                .add_source(File::with_name(path))
        } else {
            Config::builder().add_source(Environment::with_prefix("DID_WEBPLUS_VDR"))
        };

        builder.build()?.try_deserialize()
    }
}
