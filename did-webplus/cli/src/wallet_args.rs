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
        default_value = "sqlite://~/.did-webplus/wallet.db?mode=rwc"
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
            get_existing_wallet(wallet_storage, &wallet_uuid).await
        } else {
            get_or_create_wallet(wallet_storage).await
        }
    }
}

async fn get_existing_wallet(
    wallet_storage: did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    wallet_uuid: &uuid::Uuid,
) -> Result<
    did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
> {
    // Find the rowid of the requested wallet.
    let ctx = {
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = wallet_storage.begin_transaction(None).await?;
        let ctx = wallet_storage
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
        ctx,
        wallet_storage,
    ))
}

async fn get_or_create_wallet(
    wallet_storage: did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
) -> Result<
    did_webplus_software_wallet::SoftwareWallet<
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite,
    >,
> {
    // If there are no wallets in the DB, then create one, and use it.
    // If there is exactly one wallet in the DB, then use it.
    // Otherwise there is more than wallet in the DB, and that's an error with respect to this function.
    let ctx = {
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = wallet_storage.begin_transaction(None).await?;
        let wallet_v = wallet_storage
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
            wallet_storage
                .add_wallet(&mut transaction, wallet_record)
                .await?
        } else {
            wallet_v.into_iter().next().unwrap().0
        };
        transaction.commit().await?;
        ctx
    };

    Ok(did_webplus_software_wallet::SoftwareWallet::new(
        ctx,
        wallet_storage,
    ))
}
