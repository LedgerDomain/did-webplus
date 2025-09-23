use crate::{DIDDocStoreArgs, Result};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DIDResolverType {
    Full,
    Thin,
    Raw,
}

#[derive(clap::Args, Clone, Debug)]
pub struct DIDResolverArgs {
    /// Specify which type of DID resolver to use.  The "full" resolver fetches, validates, and
    /// stores DID docs to the local DID doc store.  The "thin" resolver relies on a VDG (Verifiable
    /// Data Gateway) to perform fetching, validation, and storage.  The "raw" resolver does NOT
    /// perform any validation or storage, and should only be used for testing and development.
    #[arg(
        name = "resolver",
        env = "DID_WEBPLUS_RESOLVER",
        short,
        long,
        default_value = "full"
    )]
    pub did_resolver_type: DIDResolverType,
    /// Specify the URL to the SQLite DID doc store to use for "full" DID resolver operations.  This
    /// is only required if the resolver is set to "full".  The DID doc store is what stores validated
    /// DID docs locally.  The URL should have the form `sqlite://<local-path>`.
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "did-doc-store",
        env = "DID_WEBPLUS_DID_DOC_STORE",
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/did-doc-store.db?mode=rwc"
    )]
    pub did_doc_store_db_url_o: Option<String>,
    /// Specify the host of the VDG to use (host is a hostname and optional port number).  URLs for various operations
    /// of the VDG will be constructed from this.  This should not include the scheme (i.e. the "https://" part).
    /// This is required if the resolver is set to "thin", but is optional if the resolver is set to "full".
    #[arg(name = "vdg", env = "DID_WEBPLUS_VDG", long, value_name = "HOST")]
    pub vdg_host_o: Option<String>,
}

impl DIDResolverArgs {
    pub async fn get_did_resolver(
        self,
        http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<Box<dyn did_webplus_resolver::DIDResolver>> {
        match self.did_resolver_type {
            DIDResolverType::Full => {
                anyhow::ensure!(
                    self.did_doc_store_db_url_o.is_some(),
                    "When using the \"full\" resolver, the \"--did-doc-store\" argument is required"
                );
                let did_doc_store_args = DIDDocStoreArgs {
                    did_doc_store_db_url: self.did_doc_store_db_url_o.unwrap(),
                };
                let did_doc_store = did_doc_store_args.open_did_doc_store().await?;
                Ok(Box::new(did_webplus_resolver::DIDResolverFull::new(
                    did_doc_store,
                    self.vdg_host_o.as_deref(),
                    http_scheme_override_o,
                    did_webplus_resolver::FetchPattern::Batch,
                )?))
            }
            DIDResolverType::Thin => {
                anyhow::ensure!(
                    self.vdg_host_o.is_some(),
                    "When using the \"thin\" resolver, the \"--vdg\" argument is required"
                );
                if self.did_doc_store_db_url_o.is_some() {
                    tracing::warn!(
                        "Ignoring \"--did-doc-store\" argument since the resolver is set to \"thin\", which doesn't use a DID doc store"
                    );
                }

                let vdg_host = self.vdg_host_o.unwrap();
                anyhow::ensure!(vdg_host.find("://").is_none(), "VDG host must not contain a scheme; i.e. it must omit the \"https://\" portion");

                Ok(Box::new(did_webplus_resolver::DIDResolverThin::new(
                    &vdg_host,
                    http_scheme_override_o.as_ref(),
                )?))
            }
            DIDResolverType::Raw => {
                // No extra validation needed.
                Ok(Box::new(did_webplus_resolver::DIDResolverRaw {
                    http_scheme_override_o,
                }))
            }
        }
    }
}
