use crate::{NewlineArgs, Result};
use std::io::Write;

/// Print to stdout the VJSON for the Default schema for VJSON.
#[derive(clap::Args)]
pub struct VJSONDefaultSchema {
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl VJSONDefaultSchema {
    pub async fn handle(self) -> Result<()> {
        // There are no CLI args to handle.

        // There is no processing to do (vjson::DEFAULT_SCHEMA exists already).

        // Print the VJSON and optional newline.
        std::io::stdout()
            .write_all(&vjson_core::DEFAULT_SCHEMA.jcs.as_bytes())
            .unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
