use did_webplus_wallet_storage::LocallyControlledVerificationMethodFilter;

use crate::{get_wallet, Result};
use std::io::Write;

/// Sign a JWS using the specified DID and specified key purpose from the specified wallet.  The payload
/// for the JWS will be read from stdin.  The JWS will be written to stdout.
#[derive(clap::Parser)]
pub struct WalletDIDSignJWS {
    /// Specify the URL to the wallet database.  The URL must start with "sqlite://".
    #[arg(
        short = 'u',
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/wallet.db"
    )]
    pub wallet_db_url: String,
    /// Specify the UUID of the wallet within the database to use.  If not specified, then either the
    /// only wallet in the database will be used, or a new wallet will be created.  If there is more
    /// than one wallet in the database, an error will be returned.
    #[arg(name = "wallet-uuid", short = 'w', long, value_name = "UUID")]
    pub wallet_uuid_o: Option<String>,
    /// Specify the DID to be used for signing.  If not specified and there is exactly one DID controlled by
    /// the wallet, then that DID will be used -- it is uniquely determinable.  If there is no uniquely
    /// determinable DID, then an error will be returned.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
    /// Specify which key purpose to use when signing the JWS.  Valid values are "authentication",
    /// "assertionMethod", "keyAgreement", "capabilityInvocation", and "capabilityDelegation".
    #[arg(short, long, value_name = "PURPOSE")]
    pub key_purpose: did_webplus::KeyPurpose,
    /// If specified, then use key with the given public key when signing the JWS.  If not specified,
    /// then use the uniquely determinable key if there is one.  Otherwise return error.
    pub key_id_o: Option<String>,
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
    /// Do not print a newline at the end of the output.
    #[arg(short, long)]
    pub no_newline: bool,
}

impl WalletDIDSignJWS {
    pub async fn handle(self) -> Result<()> {
        let wallet_uuid_o = self
            .wallet_uuid_o
            .map(|wallet_uuid_string| uuid::Uuid::parse_str(&wallet_uuid_string))
            .transpose()?;
        let key_id_o = self
            .key_id_o
            .map(|key_id| selfsign::KERIVerifier::try_from(key_id))
            .transpose()
            .map_err(|e| anyhow::anyhow!("Parse error in --key-id argument; error was {}", e))?;

        let wallet = get_wallet(&self.wallet_db_url, wallet_uuid_o.as_ref()).await?;

        use did_webplus_wallet::Wallet;
        let controlled_did = wallet.get_controlled_did(self.did_o.as_deref()).await?;

        let payload_presence = if self.payload.eq_ignore_ascii_case("attached") {
            did_webplus_mock::JWSPayloadPresence::Attached
        } else if self.payload.eq_ignore_ascii_case("detached") {
            did_webplus_mock::JWSPayloadPresence::Detached
        } else {
            anyhow::bail!(
                "Invalid value {:?} for --payload argument; expected \"attached\" or \"detached\"",
                self.payload
            );
        };

        let payload_encoding = if self.encoding.eq_ignore_ascii_case("none") {
            did_webplus_mock::JWSPayloadEncoding::None
        } else if self.encoding.eq_ignore_ascii_case("base64") {
            did_webplus_mock::JWSPayloadEncoding::Base64URL
        } else {
            anyhow::bail!(
                "Invalid value {:?} for --encoding argument; expected \"none\" or \"base64\"",
                self.encoding
            );
        };

        // Get the specified signing key.
        let (verification_method_record, priv_key_record) = {
            let query_result_v = wallet
                .get_locally_controlled_verification_methods(
                    &LocallyControlledVerificationMethodFilter {
                        did_o: Some(controlled_did.did().to_owned()),
                        key_purpose_o: Some(self.key_purpose),
                        version_id_o: None,
                        key_id_o,
                        result_limit_o: Some(2),
                    },
                )
                .await?;
            if query_result_v.is_empty() {
                anyhow::bail!(
                    "No locally controlled verification method found for KeyPurpose \"{}\" and {}",
                    self.key_purpose,
                    controlled_did
                );
            }
            if query_result_v.len() > 1 {
                anyhow::bail!("Multiple locally controlled verification methods found for KeyPurpose \"{}\" and {}; use --key-id to select a single key", self.key_purpose, controlled_did);
            }
            query_result_v.into_iter().next().unwrap()
        };

        let signer = priv_key_record.private_key_bytes_o.unwrap();
        let jws = did_webplus_mock::JWS::signed(
            verification_method_record.did_key_resource_fully_qualified,
            &mut std::io::stdin(),
            payload_presence,
            payload_encoding,
            &signer,
        )?;

        std::io::stdout().write_all(jws.as_bytes())?;
        if !self.no_newline {
            std::io::stdout().write_all(b"\n")?;
        }

        Ok(())
    }
}
