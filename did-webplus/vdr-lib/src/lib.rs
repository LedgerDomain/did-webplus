pub(crate) mod services;
mod spawn_vdr;
mod vdr_app_state;
mod vdr_config;

pub use crate::{spawn_vdr::spawn_vdr, vdr_app_state::VDRAppState, vdr_config::VDRConfig};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum LogFormat {
    Compact,
    Pretty,
}
