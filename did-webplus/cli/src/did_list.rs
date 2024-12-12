use crate::{DIDDocStoreArgs, NewlineArgs, Result};
use std::{collections::BTreeSet, io::Write};

/// List the DID for each DID document in the specified DID doc store, subject to the optional filter
/// arguments.  These correspond to the DID documents that have been fetched, validated, and stored
/// in that DID doc store.
#[derive(Debug, clap::Parser)]
pub struct DIDList {
    #[command(flatten)]
    pub did_doc_store_args: DIDDocStoreArgs,
    /// If specified, limit results to DID documents for the given DID.
    #[arg(name = "did", long, value_name = "DID")]
    pub did_o: Option<did_webplus_core::DID>,
    /// If specified, limit results to DID documents having the given self-hash.
    #[arg(name = "self-hash", long, value_name = "HASH", value_parser = parse_keri_hash_from_string)]
    pub self_hash_o: Option<selfhash::KERIHash>,
    /// If specified, limit results to DID documents having the given version ID.
    #[arg(name = "version-id", long, value_name = "ID")]
    pub version_id_o: Option<u32>,
    /// If specified, print the fully-qualified DID for each DID document in the store.
    /// The default behavior is to just print the base DID, which has potentially many
    /// corresponding DID documents in the store.
    #[arg(long)]
    pub fully_qualified: bool,
    // TODO: A "latest only" flag, to print only the DIDFullyQualified of the latest DID doc
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

fn parse_keri_hash_from_string(s: &str) -> Result<selfhash::KERIHash> {
    selfhash::KERIHash::try_from(s)
        .map_err(|e| anyhow::anyhow!("Invalid --self-hash argument value {}; error was: {}", s, e))
}

impl DIDList {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let did_doc_storage = self.did_doc_store_args.get_did_doc_storage().await?;
        let did_doc_record_filter = did_webplus_doc_store::DIDDocRecordFilter {
            did_o: self.did_o.map(|did| did.to_string()),
            self_hash_o: self.self_hash_o.map(|self_hash| self_hash.to_string()),
            version_id_o: self.version_id_o,
        };

        // Do the processing
        let did_doc_record_v =
            did_webplus_cli_lib::did_list(&did_doc_storage, &did_doc_record_filter).await?;

        let mut did_string_s = BTreeSet::new();
        for did_doc_record in did_doc_record_v.into_iter() {
            let did = did_webplus_core::DIDStr::new_ref(&did_doc_record.did).unwrap();
            let did_string = if self.fully_qualified {
                let query_self_hash =
                    selfhash::KERIHashStr::new_ref(&did_doc_record.self_hash).unwrap();
                let did_fully_qualified =
                    did.with_queries(query_self_hash, did_doc_record.version_id as u32);
                did_fully_qualified.to_string()
            } else {
                did.to_string()
            };
            did_string_s.insert(did_string);
        }

        // We can create the serialized JSON output directly.
        std::io::stdout().write_all(b"[")?;
        for (i, did_string) in did_string_s.iter().enumerate() {
            write!(std::io::stdout(), "{:?}", did_string)?;
            if i + 1 < did_string_s.len() {
                std::io::stdout().write_all(b",")?;
            }
        }
        std::io::stdout().write_all(b"]")?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
