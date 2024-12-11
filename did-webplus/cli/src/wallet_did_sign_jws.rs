use crate::{NewlineArgs, Result, VerificationMethodArgs, WalletArgs};
use did_webplus_wallet_store::LocallyControlledVerificationMethodFilter;
use std::io::Write;

/// Sign a JWS using the specified DID and specified key purpose from the specified wallet.  The payload
/// for the JWS will be read from stdin.  The JWS will be written to stdout.  If no --wallet-uuid
/// argument is specified, then there must only be one wallet in the database, and that wallet will be
/// used.  If there is more than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDSignJWS {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    // TODO: The default behavior should be to fetch the latest DID document for the DID being used to
    // sign before signing, so that the latest version is used, and there should be an argument to disable
    // this behavior.
    #[command(flatten)]
    pub verification_method_args: VerificationMethodArgs,
    /// Specify if the payload is "attached" (meaning included in the JWS itself) or "detached" (meaning
    /// omitted from the JWS itself).
    // TODO: Use enums
    #[arg(long, value_name = "VALUE", default_value = "attached")]
    pub payload: String,
    /// Specify how the payload should be interpreted -- "none" means that the bytes of the payload should
    /// not be base64url-nopad-decoded before processing.  "base64" means that the bytes of the payload
    /// should be base64url-nopad-decoded before processing.
    // TODO: Use enums
    #[arg(long, value_name = "ENCODING", default_value = "base64")]
    pub encoding: String,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletDIDSignJWS {
    pub async fn handle(self) -> Result<()> {
        let key_id_o = self
            .verification_method_args
            .key_id_o
            .map(|key_id| selfsign::KERIVerifier::try_from(key_id))
            .transpose()
            .map_err(|e| anyhow::anyhow!("Parse error in --key-id argument; error was: {}", e))?;

        let wallet = self.wallet_args.get_wallet().await?;

        use did_webplus_wallet::Wallet;
        let controlled_did = wallet
            .get_controlled_did(self.verification_method_args.did_o.as_deref())
            .await?;

        let payload_presence = if self.payload.eq_ignore_ascii_case("attached") {
            did_webplus_jws::JWSPayloadPresence::Attached
        } else if self.payload.eq_ignore_ascii_case("detached") {
            did_webplus_jws::JWSPayloadPresence::Detached
        } else {
            anyhow::bail!(
                "Invalid value {:?} for --payload argument; expected \"attached\" or \"detached\"",
                self.payload
            );
        };

        let payload_encoding = if self.encoding.eq_ignore_ascii_case("none") {
            did_webplus_jws::JWSPayloadEncoding::None
        } else if self.encoding.eq_ignore_ascii_case("base64") {
            did_webplus_jws::JWSPayloadEncoding::Base64URL
        } else {
            anyhow::bail!(
                "Invalid value {:?} for --encoding argument; expected \"none\" or \"base64\"",
                self.encoding
            );
        };

        // Get the specified signing key.
        let (verification_method_record, signer_b) = {
            let query_result_v = wallet
                .get_locally_controlled_verification_methods(
                    &LocallyControlledVerificationMethodFilter {
                        did_o: Some(controlled_did.did().to_owned()),
                        key_purpose_o: Some(self.verification_method_args.key_purpose),
                        version_id_o: None,
                        key_id_o,
                        result_limit_o: Some(2),
                    },
                )
                .await?;
            if query_result_v.is_empty() {
                anyhow::bail!(
                    "No locally controlled verification method found for KeyPurpose \"{}\" and {}",
                    self.verification_method_args.key_purpose,
                    controlled_did
                );
            }
            if query_result_v.len() > 1 {
                anyhow::bail!("Multiple locally controlled verification methods found for KeyPurpose \"{}\" and {}; use --key-id to select a single key", self.verification_method_args.key_purpose, controlled_did);
            }
            query_result_v.into_iter().next().unwrap()
        };

        let jws = did_webplus_jws::JWS::signed(
            verification_method_record
                .did_key_resource_fully_qualified
                .to_string(),
            &mut std::io::stdin(),
            payload_presence,
            payload_encoding,
            signer_b.as_ref(),
        )?;

        std::io::stdout().write_all(jws.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
