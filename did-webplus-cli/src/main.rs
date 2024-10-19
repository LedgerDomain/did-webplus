mod did;
mod did_key_exchange;
mod did_list;
mod did_resolve;
mod did_resolve_full;
mod did_resolve_raw;
mod did_resolve_thin;
mod jws;
mod self_hash_args;
mod verify;
mod verify_jws;
mod verify_vjson;
mod vjson;
mod vjson_self_hash;
mod wallet;
mod wallet_did;
mod wallet_did_create;
mod wallet_did_list;
mod wallet_did_sign;
mod wallet_did_sign_jws;
mod wallet_did_sign_vjson;
mod wallet_did_update;
mod wallet_list;

pub use crate::did_resolve_full::DIDResolveFull;
pub use crate::{
    did::DID, did_key_exchange::DIDKeyExchange, did_list::DIDList, did_resolve::DIDResolve,
    did_resolve_raw::DIDResolveRaw, did_resolve_thin::DIDResolveThin, jws::JWS,
    self_hash_args::SelfHashArgs, verify::Verify, verify_jws::VerifyJWS, verify_vjson::VerifyVJSON,
    vjson::VJSON, vjson_self_hash::VJSONSelfHash, wallet::Wallet, wallet_did::WalletDID,
    wallet_did_create::WalletDIDCreate, wallet_did_list::WalletDIDList,
    wallet_did_sign::WalletDIDSign, wallet_did_sign_jws::WalletDIDSignJWS,
    wallet_did_sign_vjson::WalletDIDSignVJSON, wallet_did_update::WalletDIDUpdate,
    wallet_list::WalletList,
};
pub use anyhow::Result;

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

pub async fn get_did_doc_storage(
    did_doc_store_db_url: &str,
) -> Result<did_webplus_doc_storage_sqlite::DIDDocStorageSQLite> {
    log::debug!(
        "get_did_doc_storage; did_doc_store_db_url: {}",
        did_doc_store_db_url
    );
    let sqlite_pool = if let Some(did_doc_db_path_str) =
        did_doc_store_db_url.strip_prefix("sqlite://")
    {
        // Apply tilde expansion to the path.
        let did_doc_store_db_path = expanduser::expanduser(did_doc_db_path_str)?;
        // See https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        // TODO: Use std::path::Diplay via Path::display method.
        let did_doc_store_db_path_str = did_doc_store_db_path.as_os_str().to_str().unwrap();
        log::debug!(
            "Tilde-expanded did_doc_store DB path: {}",
            did_doc_store_db_path_str
        );
        if !did_doc_store_db_path.exists() {
            if let Some(did_doc_db_url_parent) = did_doc_store_db_path.parent() {
                log::debug!(
                    "Ensuring did_doc_store DB parent directory exists: {}",
                    did_doc_db_url_parent.as_os_str().to_str().unwrap()
                );
                // TODO: Probably if the dir exists already this will return an error.
                std::fs::create_dir_all(did_doc_db_url_parent)?;
            }
            log::debug!(
                "Creating and connecting to did_doc_store DB at {}",
                did_doc_store_db_path_str
            );
            sqlx::SqlitePool::connect(format!("{}?mode=rwc", did_doc_store_db_path_str).as_str())
                .await?
        } else {
            log::debug!(
                "Connecting to did_doc_store DB at {}",
                did_doc_store_db_path_str
            );
            sqlx::SqlitePool::connect(did_doc_store_db_path_str).await?
        }
    } else {
        unimplemented!("non-SQLite did_doc_store DBs are not yet supported.");
    };
    Ok(
        did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(sqlite_pool)
            .await?,
    )
}

pub async fn get_did_doc_store(
    did_doc_store_db_url: &str,
) -> Result<did_webplus_doc_store::DIDDocStore<did_webplus_doc_storage_sqlite::DIDDocStorageSQLite>>
{
    let storage = get_did_doc_storage(did_doc_store_db_url).await?;
    Ok(did_webplus_doc_store::DIDDocStore::new(storage))
}

pub async fn get_wallet_storage(
    wallet_db_url: &str,
) -> Result<did_webplus_wallet_storage_sqlite::WalletStorageSQLite> {
    log::debug!("get_wallet_storage; wallet_db_url: {}", wallet_db_url);
    let sqlite_pool = if let Some(wallet_db_path_str) = wallet_db_url.strip_prefix("sqlite://") {
        // Apply tilde expansion to the path.
        let wallet_db_path = expanduser::expanduser(wallet_db_path_str)?;
        // See https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        // TODO: Use std::path::Diplay via Path::display method.
        let wallet_db_path_str = wallet_db_path.as_os_str().to_str().unwrap();
        log::debug!("Tilde-expanded wallet DB path: {}", wallet_db_path_str);
        if !wallet_db_path.exists() {
            if let Some(wallet_db_url_parent) = wallet_db_path.parent() {
                log::debug!(
                    "Ensuring wallet DB parent directory exists: {}",
                    wallet_db_url_parent.as_os_str().to_str().unwrap()
                );
                // TODO: Probably if the dir exists already this will return an error.
                std::fs::create_dir_all(wallet_db_url_parent)?;
            }
            log::debug!(
                "Creating and connecting to wallet DB at {}",
                wallet_db_path_str
            );
            sqlx::SqlitePool::connect(format!("{}?mode=rwc", wallet_db_path_str).as_str()).await?
        } else {
            log::debug!("Connecting to wallet DB at {}", wallet_db_path_str);
            sqlx::SqlitePool::connect(wallet_db_path_str).await?
        }
    } else {
        unimplemented!("non-SQLite wallet DBs are not yet supported.");
    };
    Ok(
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
            sqlite_pool,
        )
        .await?,
    )
}

pub async fn get_wallet(
    wallet_db_url: &str,
    wallet_uuid_o: Option<&uuid::Uuid>,
) -> Result<
    did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
> {
    if let Some(wallet_uuid) = wallet_uuid_o {
        get_existing_wallet(wallet_db_url, wallet_uuid).await
    } else {
        get_or_create_wallet(wallet_db_url).await
    }
}

pub async fn get_existing_wallet(
    wallet_db_url: &str,
    wallet_uuid: &uuid::Uuid,
) -> Result<
    did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
> {
    let storage = get_wallet_storage(wallet_db_url).await?;

    // Find the rowid of the requested wallet.
    let ctx = {
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = storage.begin_transaction(None).await?;
        let ctx = storage
            .get_wallet(&mut transaction, &wallet_uuid)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "wallet_uuid {} not found in wallet database",
                    wallet_uuid.as_hyphenated()
                )
            })?
            .0;
        transaction.commit().await?;
        ctx
    };
    Ok(did_webplus_software_wallet::SoftwareWallet::new(
        ctx, storage,
    ))
}

pub async fn get_or_create_wallet(
    wallet_db_url: &str,
) -> Result<
    did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
> {
    let storage = get_wallet_storage(wallet_db_url).await?;

    // If there are no wallets in the DB, then create one, and use it.
    // If there is exactly one wallet in the DB, then use it.
    // Otherwise there is more than wallet in the DB, and that's an error with respect to this function.
    let ctx = {
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = storage.begin_transaction(None).await?;
        let wallet_v = storage
            .get_wallets(
                &mut transaction,
                &did_webplus_wallet_storage::WalletRecordFilter::default(),
            )
            .await?;
        anyhow::ensure!(
            wallet_v.len() <= 1,
            "This function can't return successfully if there is more than one wallet in the DB"
        );
        let ctx = if wallet_v.is_empty() {
            // Create a wallet.
            let wallet_record = did_webplus_wallet_storage::WalletRecord {
                wallet_uuid: uuid::Uuid::new_v4(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
                deleted_at_o: None,
                wallet_name_o: None,
            };
            storage.add_wallet(&mut transaction, wallet_record).await?
        } else {
            wallet_v.into_iter().next().unwrap().0
        };
        transaction.commit().await?;
        ctx
    };

    Ok(did_webplus_software_wallet::SoftwareWallet::new(
        ctx, storage,
    ))
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

/// did:webplus CLI tool for all client-side operations and related utility operations.  Note that some subcommands
/// appear at  multiple places in the command hierarchy so each command group is "complete".
#[derive(clap::Parser)]
enum Root {
    #[command(subcommand)]
    DID(DID),
    #[command(subcommand)]
    JWS(JWS),
    #[command(subcommand)]
    Verify(Verify),
    #[command(subcommand)]
    VJSON(VJSON),
    #[command(subcommand)]
    Wallet(Wallet),
}

impl Root {
    async fn handle(self) -> Result<()> {
        match self {
            Self::DID(x) => x.handle().await,
            Self::JWS(x) => x.handle().await,
            Self::Verify(x) => x.handle().await,
            Self::VJSON(x) => x.handle().await,
            Self::Wallet(x) => x.handle().await,
        }
    }
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
    Root::parse().handle().await
}
