use rand::Rng;
use selfhash::{HashFunction, SelfHashable};
use vjson_store::AlreadyExistsPolicy;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    env_logger::init();
}

#[tokio::test]
async fn test_vjson_store_0() {
    let vjson_store_path = "tests/test_vjson_store_0.db";

    if std::fs::exists(vjson_store_path).expect("pass") {
        std::fs::remove_file(vjson_store_path).expect("pass");
    }

    let sqlite_pool =
        sqlx::SqlitePool::connect(format!("sqlite://{}?mode=rwc", vjson_store_path).as_str())
            .await
            .unwrap();
    let storage = vjson_storage_sqlite::VJSONStorageSQLite::open_and_run_migrations(sqlite_pool)
        .await
        .expect("pass");

    // Note that this adds the Default schema to the VJSONStorage, so it's not necessary to do so explicitly.
    let vjson_store = vjson_store::VJSONStore::new(storage).await.expect("pass");

    // Create an arbitrary VJSON doc, implicitly using the Default schema.
    {
        let value =
            serde_json::json!({ "blah": rand::thread_rng().gen::<f64>(), "$id": "vjson:///" });

        // let mut transaction = vjson_store.begin_transaction(None).await.expect("pass");
        let (mut self_hashable_json, _schema_value) =
            vjson_core::self_hashable_json_from(value, &vjson_store)
                .await
                .expect("pass");
        let self_hash = self_hashable_json
            .self_hash(selfhash::Blake3.new_hasher())
            .expect("pass")
            .to_keri_hash()
            .expect("pass")
            .into_owned();
        let mut transaction = vjson_store.begin_transaction(None).await.expect("pass");
        vjson_store
            .add_vjson_value(
                &mut transaction,
                self_hashable_json.value(),
                &verifier_resolver::VerifierResolverMap::new(),
                AlreadyExistsPolicy::Fail,
            )
            .await
            .expect("pass");
        transaction.commit().await.expect("pass");
        let vjson_url = format!("vjson:///{}", self_hash);
        tracing::info!("Added VJSON doc {}", vjson_url);
    }
}
