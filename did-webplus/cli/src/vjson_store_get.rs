use crate::{NewlineArgs, Result, VJSONStoreArgs};
use std::io::Write;

/// Retrieve the specified VJSON from the VJSON store (which implicitly means it's valid) and write it to stdout.
#[derive(clap::Args)]
pub struct VJSONStoreGet {
    /// Specify the VJSON to get -- this must be either the self-hash of the VJSON or its self-hash URL.
    pub vjson_specifier: String,
    #[command(flatten)]
    pub vjson_store_args: VJSONStoreArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl VJSONStoreGet {
    pub fn vjson_specifier_self_hash(&self) -> Result<&mbx::MBHashStr> {
        if let Ok(self_hash) = mbx::MBHashStr::new_ref(&self.vjson_specifier) {
            Ok(self_hash)
        } else if let Ok(self_hash_url) = selfhash::SelfHashURLStr::new_ref(&self.vjson_specifier) {
            self_hash_url.mb_hash_o().ok_or_else(|| {
                anyhow::anyhow!("Self-hash URL must have a well-formed self-hash component")
            })
        } else {
            anyhow::bail!("VJSON specifier must be a valid self-hash or self-hash URL")
        }
    }
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let self_hash = self.vjson_specifier_self_hash()?;
        let vjson_store = self.vjson_store_args.get_vjson_store().await?;

        // Do the processing
        let vjson_record =
            did_webplus_cli_lib::vjson_store_get_record(self_hash, &vjson_store).await?;

        // Print the VJSON and optional newline.
        std::io::stdout()
            .write_all(&vjson_record.vjson_jcs.as_bytes())
            .unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
