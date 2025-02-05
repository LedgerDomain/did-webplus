use crate::Result;
use did_webplus_software_wallet::SoftwareWallet;
use std::sync::Arc;

/// Args common to wallet-specifying CLI commands.
#[derive(clap::Args)]
pub struct WalletArgs {
    /// Specify the URL to the wallet database.  The URL must start with "sqlite://".
    #[arg(
        env = "DID_WEBPLUS_WALLET_DB_URL",
        short = 'u',
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/wallet-store.db?mode=rwc"
    )]
    pub wallet_db_url: String,
    /// Optionally specify the UUID of the wallet within the database to use.
    #[arg(
        name = "wallet-uuid",
        env = "DID_WEBPLUS_WALLET_UUID",
        short = 'w',
        long,
        value_name = "UUID",
        value_parser = parse_hyphenated_uuid
    )]
    pub wallet_uuid_o: Option<uuid::Uuid>,
}

fn parse_hyphenated_uuid(s: &str) -> Result<uuid::Uuid> {
    Ok(uuid::Uuid::parse_str(s)?)
}

impl WalletArgs {
    pub async fn open_wallet_storage(
        &self,
    ) -> Result<Arc<dyn did_webplus_wallet_store::WalletStorage>> {
        tracing::debug!(
            "WalletArgs::get_wallet_storage; wallet_db_url: {}",
            self.wallet_db_url
        );
        let sqlite_pool = if let Some(wallet_db_path_str) =
            self.wallet_db_url.as_str().strip_prefix("sqlite://")
        {
            // Apply tilde expansion to the path.
            let wallet_db_path = expanduser::expanduser(wallet_db_path_str)?;
            // See https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
            // TODO: Use std::path::Diplay via Path::display method.
            let wallet_db_path_str = wallet_db_path.as_os_str().to_str().unwrap();
            tracing::debug!("Tilde-expanded wallet DB path: {}", wallet_db_path_str);
            if !wallet_db_path.exists() {
                if let Some(wallet_db_url_parent) = wallet_db_path.parent() {
                    tracing::debug!(
                        "Ensuring wallet DB parent directory exists: {}",
                        wallet_db_url_parent.as_os_str().to_str().unwrap()
                    );
                    // TODO: Probably if the dir exists already this will return an error.
                    std::fs::create_dir_all(wallet_db_url_parent)?;
                }
            }
            tracing::debug!("Connecting to wallet DB at {}", wallet_db_path_str);
            sqlx::SqlitePool::connect(wallet_db_path_str).await?
        } else {
            unimplemented!("non-SQLite wallet DBs are not yet supported.");
        };
        let wallet_storage =
            did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await?;
        Ok(Arc::new(wallet_storage))
    }
    pub async fn open_wallet(&self) -> Result<did_webplus_software_wallet::SoftwareWallet> {
        let wallet_storage_a = self.open_wallet_storage().await?;
        if let Some(wallet_uuid) = self.wallet_uuid_o.as_ref() {
            let mut transaction_b = wallet_storage_a.begin_transaction().await?;
            let wallet =
                SoftwareWallet::open(transaction_b.as_mut(), wallet_storage_a, wallet_uuid).await?;
            transaction_b.commit().await?;
            Ok(wallet)
        } else {
            open_or_create_wallet(wallet_storage_a).await
        }
    }
}

async fn open_or_create_wallet(
    wallet_storage_a: Arc<dyn did_webplus_wallet_store::WalletStorage>,
) -> Result<did_webplus_software_wallet::SoftwareWallet> {
    // If there are no wallets in the DB, then create one, and use it.
    // If there is exactly one wallet in the DB, then use it.
    // Otherwise there is more than wallet in the DB, and that's an error with respect to this function.

    let mut transaction_b = wallet_storage_a.begin_transaction().await?;
    let wallet_v = wallet_storage_a
        .get_wallets(
            Some(transaction_b.as_mut()),
            &did_webplus_wallet_store::WalletRecordFilter::default(),
        )
        .await?;
    anyhow::ensure!(
        wallet_v.len() <= 1,
        "This function can't return successfully if there is more than one wallet in the DB"
    );
    let software_wallet = if wallet_v.is_empty() {
        SoftwareWallet::create(
            transaction_b.as_mut(),
            wallet_storage_a,
            Some("Default Wallet".to_string()),
        )
        .await?
    } else {
        let wallet_uuid = wallet_v.into_iter().next().unwrap().1.wallet_uuid;
        SoftwareWallet::open(transaction_b.as_mut(), wallet_storage_a, &wallet_uuid).await?
    };
    transaction_b.commit().await?;
    Ok(software_wallet)
}
