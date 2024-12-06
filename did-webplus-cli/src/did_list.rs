use crate::{DIDDocStoreArgs, NewlineArgs, Result};
use std::io::Write;

/// List all DID documents in the specified DID doc store.  These are the DID documents that have
/// been fetched, validated, and stored in that DID doc store.
// TODO: This should actually list DIDs in the DID doc store, and there should be a separate
// command to list DID documents
#[derive(Debug, clap::Parser)]
pub struct DIDList {
    #[command(flatten)]
    pub did_doc_store_args: DIDDocStoreArgs,
    /// If specified, limit results to DID documents for the given DID.
    #[arg(name = "did", long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
    /// If specified, limit results to DID documents having the given self-hash.
    #[arg(name = "self-hash", long, value_name = "HASH")]
    pub self_hash_o: Option<String>,
    /// If specified, limit results to DID documents having the given version ID.
    #[arg(name = "version-id", long, value_name = "ID")]
    pub version_id_o: Option<u32>,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDList {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        if let Some(self_hash_str) = self.self_hash_o.as_deref() {
            selfhash::KERIHashStr::new_ref(self_hash_str).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid --self-hash argument value {}; error was: {}",
                    self_hash_str,
                    e
                )
            })?;
        }

        let did_doc_storage = self.did_doc_store_args.get_did_doc_storage().await?;
        use did_webplus_doc_store::DIDDocStorage;
        let mut transaction = did_doc_storage.begin_transaction(None).await?;
        let did_doc_record_v = did_doc_storage
            .get_did_doc_records(
                &mut transaction,
                &did_webplus_doc_store::DIDDocRecordFilter {
                    did_o: self.did_o.map(|did| did.to_string()),
                    self_hash_o: self.self_hash_o.map(|self_hash| self_hash.to_string()),
                    version_id_o: self.version_id_o,
                },
            )
            .await?;
        transaction.commit().await?;

        let did_document_jcs_v = did_doc_record_v
            .into_iter()
            .map(|did_doc_record| did_doc_record.did_document_jcs)
            .collect::<Vec<_>>();

        // Because each DID document is a JCS string, we can create the serialized JSON output directly.
        std::io::stdout().write_all(b"[")?;
        for (i, did_document_jcs) in did_document_jcs_v.iter().enumerate() {
            std::io::stdout().write_all(did_document_jcs.as_bytes())?;
            if i + 1 < did_document_jcs_v.len() {
                std::io::stdout().write_all(b",")?;
            }
        }
        std::io::stdout().write_all(b"]")?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
