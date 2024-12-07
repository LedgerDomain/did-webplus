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
    let sqlite_pool = sqlx::SqlitePool::connect("test_vjson_store_0.db?mode=rwc")
        .await
        .unwrap();
    let storage = vjson_storage_sqlite::VJSONStorageSQLite::open_and_run_migrations(sqlite_pool)
        .await
        .expect("pass");

    // Make sure the Default schema is in the VJSONStorage.  It's valid by construction, so there's
    // no problem with bypassing the validation done by VJSONStore.
    {
        use vjson_store::VJSONStorage;
        let mut transaction = storage.begin_transaction(None).await.expect("pass");
        storage
            .add_vjson_str(
                &mut transaction,
                vjson_store::VJSONRecord {
                    self_hash: vjson_store::DEFAULT_SCHEMA.self_hash.clone(),
                    added_at: time::OffsetDateTime::now_utc(),
                    vjson_jcs: vjson_store::DEFAULT_SCHEMA.jcs.clone(),
                },
                AlreadyExistsPolicy::DoNothing,
            )
            .await
            .expect("pass");
        transaction.commit().await.expect("pass");
        log::info!(
            "Ensured Default schema ({}) is present in storage.",
            vjson_store::DEFAULT_SCHEMA.vjson_url
        );
    }

    let vjson_store = vjson_store::VJSONStore::new(storage);

    // Create an arbitrary VJSON doc, implicitly using the Default schema.
    {
        let value =
            serde_json::json!({ "blah": rand::thread_rng().gen::<f64>(), "$id": "vjson:///" });

        let mut transaction = vjson_store.begin_transaction(None).await.expect("pass");
        let (mut self_hashable_json, _schema_value) =
            vjson_store::self_hashable_json_from(value, &mut transaction, &vjson_store)
                .await
                .expect("pass");
        let self_hash = self_hashable_json
            .self_hash(selfhash::Blake3.new_hasher())
            .expect("pass")
            .to_keri_hash()
            .expect("pass")
            .into_owned();
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
        log::info!("Added VJSON doc {}", vjson_url);
    }
}
