mod did;
mod did_create;
mod did_key_exchange;
mod did_list;
mod did_list_local;
mod did_list_resolved;
mod did_resolve;
mod did_resolve_args;
mod did_sign;
mod did_update;
mod verify;
mod verify_jws;
mod verify_jwt;

pub use crate::{
    did::DID, did_create::DIDCreate, did_key_exchange::DIDKeyExchange, did_list::DIDList,
    did_list_local::DIDListLocal, did_list_resolved::DIDListResolved, did_resolve::DIDResolve,
    did_resolve_args::DIDResolveArgs, did_sign::DIDSign, did_update::DIDUpdate, verify::Verify,
    verify_jws::VerifyJWS, verify_jwt::VerifyJWT,
};
pub use anyhow::Result;

lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}

/// did-webplus CLI tool for all client-side operations and a few others.
#[derive(clap::Parser)]
enum Root {
    #[command(subcommand)]
    DID(DID),
    #[command(subcommand)]
    Verify(Verify),
}

impl Root {
    async fn handle(self) -> Result<()> {
        match self {
            Root::DID(x) => x.handle().await,
            Root::Verify(x) => x.handle().await,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .with_writer(std::io::stderr)
        .init();

    use clap::Parser;
    // Note that if the env var RUST_BACKTRACE is set to 1 (or "full"), then the backtrace will be printed
    // to stderr if this returns error.
    Root::parse().handle().await
}
