use did_webplus_wallet_storage::WalletRecord;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();
}

#[tokio::test]
async fn test_software_wallet() {
    let sqlite_pool = sqlx::SqlitePool::connect("did_webplus_software_wallet_tests.db?mode=rwc")
        .await
        .expect("pass");
    let storage = did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
        sqlite_pool,
    )
    .await
    .expect("pass");

    // Create a new Wallet (this needs a better name -- directory? sub-wallet?)
    let ctx = {
        let utc_now = time::OffsetDateTime::now_utc();
        let wallet_record = WalletRecord {
            wallet_uuid: uuid::Uuid::new_v4(),
            created_at: utc_now,
            updated_at: utc_now,
            deleted_at_o: None,
            wallet_name_o: Some("fancy wallet".to_string()),
        };
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = storage.begin_transaction(None).await.expect("pass");
        let ctx = storage
            .add_wallet(&mut transaction, wallet_record)
            .await
            .expect("pass");
        transaction.commit().await.expect("pass");
        ctx
    };

    let software_wallet = did_webplus_software_wallet::SoftwareWallet::new(ctx, storage);

    let vdr_scheme = "http";
    let vdr_did_create_endpoint = format!("{}://localhost", vdr_scheme);

    use did_webplus_wallet::Wallet;

    let controlled_did = software_wallet
        .create_did(vdr_did_create_endpoint.as_str())
        .await
        .expect("pass");
    let did = controlled_did.without_query();
    tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);

    let controlled_did = software_wallet
        .update_did(&did, vdr_scheme)
        .await
        .expect("pass");
    tracing::debug!("updated DID: {}", controlled_did);
}
