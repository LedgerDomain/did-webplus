mod cmd;
mod did_doc_store_args;
mod did_key_from_private;
mod did_key_generate;
mod did_key_sign_jws;
mod did_key_sign_vjson;
mod did_list;
mod did_resolve;
mod did_resolver_args;
mod did_resolver_factory;
mod did_webplus_verifier_resolver;
mod http_scheme_override_args;
mod jws_payload_args;
mod jws_verify;
mod newline_args;
mod private_key_file_args;
mod self_hash_args;
mod verification_method_args;
mod verifier_resolver_args;
mod vjson_default_schema;
mod vjson_self_hash;
mod vjson_storage_behavior_args;
mod vjson_store_args;
mod vjson_store_get;
mod vjson_verify;
mod wallet_args;
mod wallet_did_create;
mod wallet_did_list;
mod wallet_did_sign_jws;
mod wallet_did_sign_vjson;
mod wallet_did_update;
mod wallet_list;

pub use crate::{
    did_doc_store_args::DIDDocStoreArgs,
    did_key_from_private::DIDKeyFromPrivate,
    did_key_generate::DIDKeyGenerate,
    did_key_sign_jws::DIDKeySignJWS,
    did_key_sign_vjson::DIDKeySignVJSON,
    did_list::DIDList,
    did_resolve::DIDResolve,
    did_resolver_args::{DIDResolverArgs, DIDResolverType},
    did_resolver_factory::DIDResolverFactory,
    did_webplus_verifier_resolver::DIDWebplusVerifierResolver,
    http_scheme_override_args::HTTPSchemeOverrideArgs,
    jws_payload_args::JWSPayloadArgs,
    jws_verify::JWSVerify,
    newline_args::NewlineArgs,
    private_key_file_args::PrivateKeyFileArgs,
    self_hash_args::SelfHashArgs,
    verification_method_args::VerificationMethodArgs,
    verifier_resolver_args::VerifierResolverArgs,
    vjson_default_schema::VJSONDefaultSchema,
    vjson_self_hash::VJSONSelfHash,
    vjson_storage_behavior_args::VJSONStorageBehaviorArgs,
    vjson_store_args::VJSONStoreArgs,
    vjson_store_get::VJSONStoreGet,
    vjson_verify::VJSONVerify,
    wallet_args::WalletArgs,
    wallet_did_create::WalletDIDCreate,
    wallet_did_list::WalletDIDList,
    wallet_did_sign_jws::WalletDIDSignJWS,
    wallet_did_sign_vjson::WalletDIDSignVJSON,
    wallet_did_update::WalletDIDUpdate,
    wallet_list::WalletList,
};
pub use anyhow::{Error, Result};

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

async fn get_uniquely_determinable_did(
    wallet: &did_webplus_software_wallet::SoftwareWallet,
    did_o: Option<did_webplus_core::DID>,
) -> Result<did_webplus_core::DID> {
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
    // NOTE: We currently don't use dotenvy to load a .env file, but that could be added here.

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .compact()
        .init();

    use clap::Parser;
    // Note that if the env var RUST_BACKTRACE is set to 1 (or "full"), then the backtrace will be printed
    // to stderr if this returns error.
    cmd::Root::parse().handle().await
}
