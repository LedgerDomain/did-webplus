use crate::{determine_http_scheme, get_did_doc_store, Result};
use std::io::Read;

/// Verify a JWS signed by a did:webplus DID.
#[derive(clap::Parser)]
pub struct VerifyJWS {
    /// Specify the URL to the SQLite DID doc store to use for the "full" resolver to use in this
    /// verify operation.  This is what stores validated DID docs.  It should have the form
    /// `sqlite://<local-path>`.
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "doc-store",
        env = "DID_WEBPLUS_DOC_STORE",
        short,
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/doc-store.db"
    )]
    pub did_doc_store_db_url: String,
    // TODO: Implement this
    // /// Optionally specify the URL of the "resolve" endpoint of the VDG to use for DID resolution
    // /// during this verify operation.  The URL can omit the scheme (i.e. the "https://" portion).
    // /// The URL must not contain a query string or fragment.
    // #[arg(
    //     name = "vdg",
    //     env = "DID_WEBPLUS_VDG",
    //     short,
    //     long,
    //     value_name = "URL",
    //     value_parser = parse_url_o(s),
    // )]
    // pub vdg_resolve_endpoint_o: Option<url::Url>,
    /// Specify the JWS detached payload directly on the command line.  This is only suitable for small
    /// payloads that don't contain sensitive information, since typically the commandline that invoked
    /// a process is visible in the process list on a Unix system.  This argument is mutually exclusive
    /// with the `--detached-payload-file` argument.  If either this or the `--detached-payload-file`
    /// argument is specified, then the JWS will be interpreted as having a detached payload, and in that
    /// case the JWS must not have an attached payload.
    #[arg(name = "detached-payload", short = 'p', long, value_name = "PAYLOAD")]
    pub detached_payload_o: Option<String>,
    /// Specify the file from which to read the JWS detached payload.  This is suitable for larger
    /// payloads or payloads that contain sensitive information.  This argument is mutually exclusive
    /// with the `--detached-payload` argument.  If either this or the `--detached-payload`
    /// argument is specified, then the JWS will be interpreted as having a detached payload, and in that
    /// case the JWS must not have an attached payload.
    #[arg(name = "detached-payload-file", short = 'f', long, value_name = "FILE")]
    pub detached_payload_file_o: Option<std::path::PathBuf>,
}

impl VerifyJWS {
    pub async fn handle(self) -> Result<()> {
        // Read the JWS from stdin, making sure to trim whitespace off the ends.
        let mut jws_string = String::new();
        std::io::stdin().read_to_string(&mut jws_string)?;
        let jws_str = jws_string.trim();
        let jws = did_webplus_jws::JWS::try_from(jws_str)?;

        let http_scheme = determine_http_scheme();

        let did_doc_store = get_did_doc_store(&self.did_doc_store_db_url).await?;

        // Use "full" DID resolver to resolve the key specified in the JWS header.
        let mut transaction = did_doc_store.begin_transaction(None).await?;
        let _did_doc_record = did_webplus_resolver::resolve_did(
            &did_doc_store,
            &mut transaction,
            jws.header().kid.without_fragment().as_str(),
            http_scheme,
        )
        .await?;
        transaction.commit().await?;

        // Part of DID doc verification is ensuring that the key ID represents the same public key as
        // the JsonWebKey2020 value.  So we can use the key ID KERIVerifier value as the public key.
        // TODO: Assert that this is actually the case.
        let verifier = jws.header().kid.fragment();

        // Handle the attached/detached payload logic.

        anyhow::ensure!(
            self.detached_payload_o.is_none() || self.detached_payload_file_o.is_none(),
            "Cannot specify both --detached-payload and --detached-payload-file"
        );
        let detached_payload_bytes_o = if let Some(detached_payload) = self.detached_payload_o {
            Some(detached_payload.as_bytes().to_vec())
        } else if let Some(detached_payload_file) = self.detached_payload_file_o {
            // Read the file into memory.
            let mut detached_payload_file = std::fs::File::open(detached_payload_file)?;
            let mut detached_payload_bytes = Vec::new();
            detached_payload_file.read_to_end(&mut detached_payload_bytes)?;
            Some(detached_payload_bytes)
        } else {
            None
        };

        // Finally, verify the JWS.  Is there a smarter way to do this as a one-liner?
        if let Some(detached_payload_bytes) = &detached_payload_bytes_o {
            let mut detached_payload_bytes_slice = detached_payload_bytes.as_slice();
            jws.verify(&verifier, Some(&mut detached_payload_bytes_slice))?;
        } else {
            jws.verify(&verifier, None)?;
        }

        Ok(())
    }
}
