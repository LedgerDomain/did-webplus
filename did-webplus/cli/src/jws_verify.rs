use crate::{NewlineArgs, Result, VerifierResolverArgs};
use std::io::{Read, Write};

/// Verify a JWS signed by a did:webplus DID.  If the JWS is valid, then the JWS is written to stdout.
#[derive(clap::Parser)]
pub struct JWSVerify {
    #[command(flatten)]
    pub verifier_resolver_args: VerifierResolverArgs,
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
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl JWSVerify {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input

        // Read the JWS from stdin, making sure to trim whitespace off the ends.
        let mut jws_string = String::new();
        std::io::stdin().read_to_string(&mut jws_string)?;
        let jws_str = jws_string.trim();
        let jws = did_webplus_jws::JWS::try_from(jws_str)?;

        let verifier_resolver = self.verifier_resolver_args.get_verifier_resolver_map();

        anyhow::ensure!(
            self.detached_payload_o.is_none() || self.detached_payload_file_o.is_none(),
            "Cannot specify both --detached-payload and --detached-payload-file"
        );
        let mut detached_payload_o;
        let mut detached_payload_file_o;
        // Depending on the arguments, there might be a detached payload that is literal content (a String in memory),
        // or it might be a detached payload that is read in from a file, or there might be no detached payload.
        let detached_payload_bytes_o: Option<&mut dyn std::io::Read> =
            if let Some(detached_payload) = self.detached_payload_o.as_deref() {
                detached_payload_o = Some(detached_payload.as_bytes());
                Some(detached_payload_o.as_mut().unwrap())
            } else if let Some(detached_payload_file) = self.detached_payload_file_o {
                detached_payload_file_o = Some(std::fs::File::open(detached_payload_file)?);
                Some(detached_payload_file_o.as_mut().unwrap())
            } else {
                None
            };

        // Do the processing
        did_webplus_cli_lib::jws_verify(&jws, detached_payload_bytes_o, &verifier_resolver).await?;
        tracing::info!("Input JWS was successfully validated.");

        // Print the JWS and optional newline.
        std::io::stdout().write_all(jws_str.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
