use crate::{DIDResolverArgs, HTTPSchemeArgs, Result};
use did_webplus::DIDKeyResourceFullyQualifiedStr;
use std::io::Read;

/// Verify a JWS signed by a did:webplus DID, using the "full" resolver with the specified DID doc store.
#[derive(clap::Parser)]
pub struct JWSVerify {
    #[command(flatten)]
    pub did_resolver_args: DIDResolverArgs,
    #[command(flatten)]
    pub http_scheme_args: HTTPSchemeArgs,
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

impl JWSVerify {
    pub async fn handle(self) -> Result<()> {
        // Read the JWS from stdin, making sure to trim whitespace off the ends.
        let mut jws_string = String::new();
        std::io::stdin().read_to_string(&mut jws_string)?;
        let jws_str = jws_string.trim();
        let jws = did_webplus_jws::JWS::try_from(jws_str)?;

        anyhow::ensure!(jws.header().kid.starts_with("did:"), "JWS header \"kid\" field (which was {:?}) is expected to be a DID, i.e. start with \"did:\"", jws.header().kid);

        // Depending on the DID method specified by the JWS header kid field, use different resolution methods.
        let verifier_b: Box<dyn selfsign::Verifier> = if jws.header().kid.starts_with("did:key:") {
            log::debug!(
                "JWS header \"kid\" was {:?}; verifying using did:key method",
                jws.header().kid
            );
            let did_resource = did_key::DIDResourceStr::new_ref(&jws.header().kid)?;
            did_resource.did().to_verifier()
        } else if jws.header().kid.starts_with("did:webplus:") {
            log::debug!(
                "JWS header \"kid\" was {:?}; verifying using did:webplus method",
                jws.header().kid
            );
            let did_key_resource_fully_qualified =
                DIDKeyResourceFullyQualifiedStr::new_ref(&jws.header().kid)?;

            // Use DID resolver to resolve the key specified in the JWS header.
            let http_scheme = self.http_scheme_args.determine_http_scheme();
            let did_resolver_b = self.did_resolver_args.get_did_resolver(http_scheme).await?;
            let (_did_document, _did_doc_metadata) = did_resolver_b
                .resolve_did_document(
                    did_key_resource_fully_qualified.without_fragment().as_str(),
                    did_webplus::RequestedDIDDocumentMetadata::none(),
                )
                .await?;
            // Part of DID doc verification is ensuring that the key ID represents the same public key as
            // the JsonWebKey2020 value.  So we can use the key ID KERIVerifier value as the public key.
            // TODO: Assert that this is actually the case.

            Box::new(did_key_resource_fully_qualified.fragment())
        } else {
            anyhow::bail!(
                "JWS header \"kid\" field was {}, which uses an unsupported DID method",
                jws.header().kid
            );
        };

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
            jws.verify(verifier_b.as_ref(), Some(&mut detached_payload_bytes_slice))?;
        } else {
            jws.verify(verifier_b.as_ref(), None)?;
        }
        log::info!("Input JWS was successfully validated.");

        Ok(())
    }
}
