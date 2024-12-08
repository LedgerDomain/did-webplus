pub(crate) mod services;
mod spawn_vdg;
mod vdg_config;

pub use crate::{spawn_vdg::spawn_vdg, vdg_config::VDGConfig};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum LogFormat {
    Compact,
    Pretty,
}

lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}
