use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Config {
    pub gateways: Vec<String>,
    pub host: String,
}

impl Config {
    pub fn from_file(path: &str) -> Self {
        let contents = fs::read_to_string(path).expect("Failed to read config file");
        serde_yaml::from_str(&contents).expect("Failed to parse config file")
    }
}
