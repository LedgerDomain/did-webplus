mod listen;
mod logging;

pub use crate::{
    listen::Listen,
    logging::{LogFormat, init_logging},
};
pub use anyhow::{Error, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // Parse commandline options
    use clap::Parser;
    let listen = Listen::parse();
    tracing::debug!("Parsed commandline options: {:?}", listen);
    // Note that if the env var RUST_BACKTRACE is set to 1 (or "full"), then the backtrace will be printed
    // to stderr if this returns error.
    listen.handle().await?;

    Ok(())
}
