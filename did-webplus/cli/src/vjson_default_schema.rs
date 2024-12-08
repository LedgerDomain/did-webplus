use crate::{NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs};
use std::io::Write;
use vjson_store::{VJSONStorage, DEFAULT_SCHEMA};

/// Generate the VJSON for the default schema for VJSON, writing it to stdout.  If requested, it will
/// also be stored in the VJSON store (default behavior is to store).  This is its own operation because
/// it's self-referential and for now, bootstrapping it generically is too hard.
#[derive(clap::Args)]
pub struct VJSONDefaultSchema {
    #[command(flatten)]
    pub vjson_store_args: VJSONStoreArgs,
    #[command(flatten)]
    pub vjson_storage_behavior_args: VJSONStorageBehaviorArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl VJSONDefaultSchema {
    pub async fn handle(self) -> Result<()> {
        if !self.vjson_storage_behavior_args.dont_store {
            let already_exists_policy = if self.vjson_storage_behavior_args.fail_if_exists {
                vjson_store::AlreadyExistsPolicy::Fail
            } else {
                vjson_store::AlreadyExistsPolicy::DoNothing
            };

            // TEMP HACK -- bypass the VJSONStore interface and just use VJSONStorage directly,
            // so that it doesn't do any validation.  It is valid by construction.
            let vjson_storage = self.vjson_store_args.get_vjson_storage().await?;
            let mut transaction = vjson_storage.begin_transaction(None).await?;
            let vjson_record = vjson_store::VJSONRecord {
                self_hash: DEFAULT_SCHEMA.self_hash.clone(),
                added_at: time::OffsetDateTime::now_utc(),
                vjson_jcs: DEFAULT_SCHEMA.jcs.clone(),
            };
            vjson_storage
                .add_vjson_str(&mut transaction, vjson_record, already_exists_policy)
                .await?;
            transaction.commit().await?;
        }

        // Print the VJSON and optional newline.
        std::io::stdout()
            .write_all(&vjson_store::DEFAULT_SCHEMA.jcs.as_bytes())
            .unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
