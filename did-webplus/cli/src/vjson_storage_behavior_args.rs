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
    /// Translate the fail_if_exists arg into the appropriate vjson_store::AlreadyExistsPolicy.
    pub fn already_exists_policy(&self) -> vjson_store::AlreadyExistsPolicy {
        if self.fail_if_exists {
            vjson_store::AlreadyExistsPolicy::Fail
        } else {
            vjson_store::AlreadyExistsPolicy::DoNothing
        }
    }
    /// Translate the dont_store arg into a positive "should store" boolean.
    pub fn should_store(&self) -> bool {
        !self.dont_store
    }
    // Store the signed VJSON in the VJSON store, if requested.
    pub async fn store_if_requested(
        &self,
        vjson_value: &serde_json::Value,
        vjson_store: &vjson_store::VJSONStore<vjson_storage_sqlite::VJSONStorageSQLite>,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    ) -> Result<()> {
        if self.should_store() {
            did_webplus_cli_lib::vjson_store_add_value(
                vjson_value,
                vjson_store,
                verifier_resolver,
                self.already_exists_policy(),
            )
            .await?;
        }
        Ok(())
    }
}
