mod cmd;
mod did_doc_store_args;
mod did_key_from_private;
mod did_key_generate;
mod did_key_sign_jws;
mod did_key_sign_vjson;
mod did_list;
mod did_resolve_full;
mod did_resolve_raw;
mod did_resolve_thin;
mod newline_args;
mod private_key_file_args;
mod self_hash_args;
mod verification_method_args;
mod verify_jws;
mod verify_vjson;
mod vjson_self_hash;
mod wallet_args;
mod wallet_did_create;
mod wallet_did_list;
mod wallet_did_sign_jws;
mod wallet_did_sign_vjson;
mod wallet_did_update;
mod wallet_list;

pub use crate::did_resolve_full::DIDResolveFull;
pub use crate::{
    did_doc_store_args::DIDDocStoreArgs, did_key_from_private::DIDKeyFromPrivate,
    did_key_generate::DIDKeyGenerate, did_key_sign_jws::DIDKeySignJWS,
    did_key_sign_vjson::DIDKeySignVJSON, did_list::DIDList, did_resolve_raw::DIDResolveRaw,
    did_resolve_thin::DIDResolveThin, newline_args::NewlineArgs,
    private_key_file_args::PrivateKeyFileArgs, self_hash_args::SelfHashArgs,
    verification_method_args::VerificationMethodArgs, verify_jws::VerifyJWS,
    verify_vjson::VerifyVJSON, vjson_self_hash::VJSONSelfHash, wallet_args::WalletArgs,
    wallet_did_create::WalletDIDCreate, wallet_did_list::WalletDIDList,
    wallet_did_sign_jws::WalletDIDSignJWS, wallet_did_sign_vjson::WalletDIDSignVJSON,
    wallet_did_update::WalletDIDUpdate, wallet_list::WalletList,
};
pub use anyhow::{Error, Result};

lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}

pub(crate) fn parse_url(s: &str) -> anyhow::Result<url::Url> {
    let parsed_url = if !s.contains("://") {
        // If no scheme was specified, slap "https://" on the front before parsing.
        url::Url::parse(format!("https://{}", s).as_str())?
    } else {
        // Otherwise, parse directly.
        url::Url::parse(s)?
    };
    Ok(parsed_url)
}

pub(crate) fn determine_http_scheme() -> &'static str {
    // TODO: Make this debug-build-only.
    // Secret env var for overriding the scheme of HTTP requests for development/testing purposes.
    let http_scheme: &'static str = match std::env::var("DID_WEBPLUS_HTTP_SCHEME_OVERRIDE") {
        Ok(http_scheme) => match http_scheme.as_str() {
            "http" => "http",
            "https" => "https",
            _ => {
                panic!("If specified, DID_WEBPLUS_HTTP_SCHEME_OVERRIDE env var must be set to http or https, and defines what scheme to use for all HTTP requests.  If the env var is unspecified, then https will be used.");
            }
        },
        Err(_) => "https",
    };
    http_scheme
}

/// INCOMPLETE, TEMP HACK
pub(crate) fn temp_hack_incomplete_url_encoded(s: &str) -> String {
    s.replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
}

async fn get_uniquely_determinable_did(
    wallet: &did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
    did_o: Option<did_webplus::DID>,
) -> Result<did_webplus::DID> {
    use did_webplus_wallet::Wallet;
    let did = if let Some(did) = did_o {
        did
    } else {
        let controlled_did_v = wallet.get_controlled_dids(None).await?;
        if controlled_did_v.len() != 1 {
            anyhow::bail!(
                "No DID specified and wallet controls {} DIDs, so there is no uniquely determinable DID, and this process can't continue.",
                controlled_did_v.len()
            );
        }
        controlled_did_v
            .into_iter()
            .next()
            .unwrap()
            .did()
            .to_owned()
    };
    Ok(did)
}

#[tokio::main]
async fn main() -> Result<()> {
    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .with_writer(std::io::stderr)
        .init();

    use clap::Parser;
    // Note that if the env var RUST_BACKTRACE is set to 1 (or "full"), then the backtrace will be printed
    // to stderr if this returns error.
    cmd::Root::parse().handle().await
}
