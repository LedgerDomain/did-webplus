use did_webplus_software_wallet::SoftwareWallet;

use crate::Result;

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
    // TODO: Parse into hypenated UUID
    #[arg(
        name = "wallet-uuid",
        env = "DID_WEBPLUS_WALLET_UUID",
        short = 'w',
        long,
        value_name = "UUID"
    )]
    pub wallet_uuid_o: Option<String>,
}

impl WalletArgs {
    pub fn get_wallet_uuid_o(&self) -> Result<Option<uuid::Uuid>> {
        Ok(self
            .wallet_uuid_o
            .as_deref()
            .map(|wallet_uuid_str| uuid::Uuid::parse_str(wallet_uuid_str))
            .transpose()?)
    }
    pub async fn get_wallet_storage(
        &self,
    ) -> Result<did_webplus_wallet_storage_sqlite::WalletStorageSQLite> {
        log::debug!(
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
            }
            log::debug!("Connecting to wallet DB at {}", wallet_db_path_str);
            sqlx::SqlitePool::connect(wallet_db_path_str).await?
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
        &self,
    ) -> Result<
        did_webplus_software_wallet::SoftwareWallet<
            did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
        >,
    > {
        let wallet_uuid_o = self.get_wallet_uuid_o()?;
        let wallet_storage = self.get_wallet_storage().await?;
        if let Some(wallet_uuid) = wallet_uuid_o {
            use did_webplus_doc_store::DIDDocStorage;
            let mut transaction = wallet_storage.begin_transaction(None).await?;
            let wallet =
                SoftwareWallet::open(&mut transaction, &wallet_storage, &wallet_uuid).await?;
            wallet_storage.commit_transaction(transaction).await?;
            Ok(wallet)
        } else {
            get_or_create_wallet(&wallet_storage).await
        }
    }
}

async fn get_or_create_wallet(
    wallet_storage: &did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
) -> Result<
    did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
> {
    // If there are no wallets in the DB, then create one, and use it.
    // If there is exactly one wallet in the DB, then use it.
    // Otherwise there is more than wallet in the DB, and that's an error with respect to this function.

    use did_webplus_doc_store::DIDDocStorage;
    use did_webplus_wallet_store::WalletStorage;
    let mut transaction = wallet_storage.begin_transaction(None).await?;
    let wallet_v = wallet_storage
        .get_wallets(
            &mut transaction,
            &did_webplus_wallet_store::WalletRecordFilter::default(),
        )
        .await?;
    anyhow::ensure!(
        wallet_v.len() <= 1,
        "This function can't return successfully if there is more than one wallet in the DB"
    );
    let software_wallet = if wallet_v.is_empty() {
        SoftwareWallet::create(
            &mut transaction,
            wallet_storage,
            Some("Default Wallet".to_string()),
        )
        .await?
    } else {
        let wallet_uuid = wallet_v.into_iter().next().unwrap().1.wallet_uuid;
        SoftwareWallet::open(&mut transaction, wallet_storage, &wallet_uuid).await?
    };
    wallet_storage.commit_transaction(transaction).await?;
    Ok(software_wallet)
}
