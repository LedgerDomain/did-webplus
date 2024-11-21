use crate::Result;

// TODO: This is a dumb name, rename it.
#[derive(clap::Args, Debug)]
pub struct VJSONStorageBehaviorArgs {
    /// Don't store the signed VJSON in the VJSON store.  The default (for convenience) is to store it.
    #[arg(name = "dont-store", env = "DID_WEBPLUS_VJSON_DONT_STORE", long)]
    pub dont_store: bool,
    /// Fail if the VJSON already exists in the VJSON store.  The default is to allow it to already exist.
    #[arg(
        name = "fail-if-exists",
        env = "DID_WEBPLUS_VJSON_FAIL_IF_EXISTS",
        long
    )]
    pub fail_if_exists: bool,
}

impl VJSONStorageBehaviorArgs {
    // Store the signed VJSON in the VJSON store, if requested.
    pub async fn store_if_requested(
        &self,
        vjson_store: &vjson_store::VJSONStore<vjson_storage_sqlite::VJSONStorageSQLite>,
        vjson_value: &serde_json::Value,
    ) -> Result<()> {
        if !self.dont_store {
            let already_exists_policy = if self.fail_if_exists {
                vjson_store::AlreadyExistsPolicy::Fail
            } else {
                vjson_store::AlreadyExistsPolicy::DoNothing
            };

            let mut transaction = vjson_store.begin_transaction(None).await?;
            vjson_store
                .add_vjson_value(&mut transaction, vjson_value, already_exists_policy)
                .await?;
            vjson_store.commit_transaction(transaction).await?;
        }
        Ok(())
    }
}
