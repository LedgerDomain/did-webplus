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
    pub async fn handle(self) -> Result<()> {
        // Parse the vjson_specifier.
        let self_hash = if let Ok(self_hash) = selfhash::KERIHashStr::new_ref(&self.vjson_specifier)
        {
            self_hash
        } else if let Ok(self_hash_url) = selfhash::SelfHashURLStr::new_ref(&self.vjson_specifier) {
            self_hash_url.keri_hash_o().ok_or_else(|| {
                anyhow::anyhow!("Self-hash URL must have a well-formed self-hash component")
            })?
        } else {
            anyhow::bail!("VJSON specifier must be a valid self-hash or self-hash URL")
        };

        // Retrieve the specified Add the VJSON to the VJSON store.  This validates it before adding it.
        let vjson_store = self.vjson_store_args.get_vjson_store().await?;
        let mut transaction = vjson_store.begin_transaction(None).await?;
        let vjson_record = vjson_store
            .get_vjson_str(&mut transaction, &self_hash)
            .await?;

        // Print the VJSON and optional newline.
        std::io::stdout()
            .write_all(&vjson_record.vjson_jcs.as_bytes())
            .unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
