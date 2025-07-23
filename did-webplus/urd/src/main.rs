mod listen;
mod logging;
mod resolve;

pub use crate::{
    listen::Listen,
    logging::{LogFormat, init_logging},
    resolve::Resolve,
};
pub use anyhow::{Error, Result};

/// This is the universal resolver driver for `did:webplus`.
#[derive(Debug, clap::Parser)]
enum Root {
    Listen(Listen),
    Resolve(Resolve),
}

impl Root {
    pub async fn handle(self) -> Result<()> {
        match self {
            Root::Listen(listen) => listen.handle().await,
            Root::Resolve(resolve) => resolve.handle().await,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // Parse commandline options
    use clap::Parser;
    let root = Root::parse();
    tracing::debug!("Parsed commandline options: {:?}", root);
    // Note that if the env var RUST_BACKTRACE is set to 1 (or "full"), then the backtrace will be printed
    // to stderr if this returns error.
    root.handle().await?;
    Ok(())
}
