use std::{collections::HashMap, sync::Arc};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

// TODO: Maybe this stuff belongs in test-util
#[derive(Clone, Debug)]
struct ServicesConfig {
    vdg_listen_port_o: Option<u16>,
    vdg_database_url_o: Option<String>,
    vdg_gets_updates_from_vdr_o: Option<bool>,
    vdr_listen_port: u16,
    vdr_database_url: String,
}

impl ServicesConfig {
    fn with_vdg_and_vdr(
        vdg_listen_port: u16,
        vdg_database_url: String,
        vdg_gets_updates_from_vdr: bool,
        vdr_listen_port: u16,
        vdr_database_url: String,
    ) -> Self {
        Self {
            vdg_listen_port_o: Some(vdg_listen_port),
            vdg_database_url_o: Some(vdg_database_url),
            vdg_gets_updates_from_vdr_o: Some(vdg_gets_updates_from_vdr),
            vdr_listen_port,
            vdr_database_url,
        }
    }
    fn with_vdr(vdr_listen_port: u16, vdr_database_url: String) -> Self {
        Self {
            vdg_listen_port_o: None,
            vdg_database_url_o: None,
            vdg_gets_updates_from_vdr_o: None,
            vdr_listen_port,
            vdr_database_url,
        }
    }
}

// TODO: Maybe this stuff belongs in test-util
struct Services {
    #[allow(dead_code)]
    services_config: ServicesConfig,
    vdg_handle_o: Option<tokio::task::JoinHandle<()>>,
    vdg_host_o: Option<String>,
    vdr_handle: tokio::task::JoinHandle<()>,
    vdr_url: url::Url,
}

impl Services {
    async fn spin_up(services_config: ServicesConfig) -> Self {
        assert_eq!(
            services_config.vdg_listen_port_o.is_some(),
            services_config.vdg_database_url_o.is_some()
        );
        assert_eq!(
            services_config.vdg_listen_port_o.is_some(),
            services_config.vdg_gets_updates_from_vdr_o.is_some()
        );
        let spin_up_vdg = services_config.vdg_listen_port_o.is_some();

        // Delete any existing database files so that we're starting from a consistent, blank start every time.
        // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
        // TODO: postgres drop schema

        let (vdg_handle_o, vdg_host_o, vdg_base_url_o, vdg_gets_updates_from_vdr_o) = if spin_up_vdg
        {
            let vdg_listen_port = services_config.vdg_listen_port_o.unwrap();
            let vdg_database_url = services_config.vdg_database_url_o.clone().unwrap();
            let vdg_gets_updates_from_vdr = services_config.vdg_gets_updates_from_vdr_o.unwrap();

            let vdg_config = did_webplus_vdg_lib::VDGConfig {
                listen_port: vdg_listen_port,
                database_url: vdg_database_url,
                database_max_connections: 10,
                http_scheme_override: Default::default(),
            };
            let vdg_handle = did_webplus_vdg_lib::spawn_vdg(vdg_config.clone())
                .await
                .expect("pass");
            let vdg_host = format!("localhost:{}", vdg_config.listen_port);
            let vdg_base_url = url::Url::parse(&format!("http://{}", vdg_host)).expect("pass");

            (
                Some(vdg_handle),
                Some(vdg_host),
                Some(vdg_base_url),
                Some(vdg_gets_updates_from_vdr),
            )
        } else {
            (None, None, None, None)
        };

        assert_eq!(
            vdg_base_url_o.is_some(),
            vdg_gets_updates_from_vdr_o.is_some()
        );
        let vdg_base_url_v = if let (Some(vdg_base_url), Some(vdg_gets_updates_from_vdr)) =
            (vdg_base_url_o.as_ref(), vdg_gets_updates_from_vdr_o)
        {
            if vdg_gets_updates_from_vdr {
                vec![vdg_base_url.clone()]
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let vdr_config = did_webplus_vdr_lib::VDRConfig {
            did_hostname: "localhost".to_string(),
            did_port_o: Some(services_config.vdr_listen_port),
            listen_port: services_config.vdr_listen_port,
            database_url: services_config.vdr_database_url.clone(),
            database_max_connections: 10,
            vdg_base_url_v,
            http_scheme_override: Default::default(),
        };
        let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
            .await
            .expect("pass");
        let vdr_url =
            url::Url::parse(&format!("http://localhost:{}", vdr_config.listen_port)).expect("pass");

        if spin_up_vdg {
            let vdg_base_url = vdg_base_url_o.unwrap();
            test_util::wait_until_service_is_up(
                "VDG",
                vdg_base_url.join("health").expect("pass").as_str(),
            )
            .await;
            tracing::info!("VDG is up");
        }
        test_util::wait_until_service_is_up("VDR", vdr_url.join("health").expect("pass").as_str())
            .await;
        tracing::info!("VDR is up");

        Services {
            services_config,
            vdg_handle_o,
            vdg_host_o,
            vdr_handle,
            vdr_url,
        }
    }
    fn vdg_host(&self) -> &str {
        self.vdg_host_o
            .as_deref()
            .expect("no VDG was spun up in this configuration")
    }
    fn abort(self) {
        tracing::info!("Shutting down VDR");
        self.vdr_handle.abort();
        if let Some(vdg_handle) = self.vdg_handle_o {
            tracing::info!("Shutting down VDG");
            vdg_handle.abort();
        }
    }
    // TODO: Shutdown and retrieve and surface errors?
}

async fn create_in_memory_software_wallet() -> (
    Arc<did_webplus_wallet_storage_sqlite::WalletStorageSQLite>,
    did_webplus_software_wallet::SoftwareWallet,
) {
    let sqlite_pool = sqlx::SqlitePool::connect("sqlite://:memory:")
        .await
        .expect("pass");
    let wallet_storage_a = Arc::new(
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
            sqlite_pool,
        )
        .await
        .expect("pass"),
    );
    use storage_traits::StorageDynT;
    let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
    let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
        transaction_b.as_mut(),
        wallet_storage_a.clone(),
        Some("Test wallet for test_did_resolver".to_string()),
        None,
    )
    .await
    .expect("pass");
    transaction_b.commit().await.expect("pass");

    (wallet_storage_a, software_wallet)
}

/// Integration and performance test for DIDResolverFull operating against a VDR and a VDG.
#[tokio::test(flavor = "multi_thread")]
async fn test_did_resolver() {
    let services_config = ServicesConfig::with_vdg_and_vdr(
        50001,
        "postgres:///test_did_resolver_vdg".to_string(),
        true,
        50000,
        "postgres:///test_did_resolver_vdr".to_string(),
    );
    let services = Services::spin_up(services_config).await;

    //
    // Now that the VDR is up, create a DID and verify that it can be resolved.
    //

    // Create an in-memory SoftwareWallet.
    let (wallet_storage_a, software_wallet) = create_in_memory_software_wallet().await;

    // Create a DID.
    use did_webplus_wallet::Wallet;
    let mut controlled_did = software_wallet
        .create_did(services.vdr_url.as_str(), None)
        .await
        .expect("pass");
    let did = controlled_did.did().to_owned();
    tracing::info!("Created DID: {} (fully qualified: {})", did, controlled_did);

    // Create DIDResolverFull for having a VDG host and not.
    let did_resolver_full_m = {
        let mut did_resolver_full_m = HashMap::with_capacity(2);
        for vdg_host_o in [None, Some(services.vdg_host().to_string())] {
            let sqlite_pool = sqlx::SqlitePool::connect("sqlite://:memory:")
                .await
                .expect("pass");
            let did_doc_storage =
                did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
                    sqlite_pool,
                )
                .await
                .expect("pass");
            let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
            let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
                did_doc_store,
                vdg_host_o.as_deref(),
                None,
            )
            .unwrap();
            did_resolver_full_m.insert(vdg_host_o, did_resolver_full);
        }
        did_resolver_full_m
    };

    // Now update it many times.
    let big_update_count = std::env::var("UPDATE_COUNT")
        .unwrap_or("10".to_string())
        .parse::<usize>()
        .unwrap();

    for update_count in [big_update_count, 1, 0] {
        tracing::info!("Updating DID {} times", update_count);
        // Start a timer just to see how long it takes to create the DID and update it many times.
        let time_start = time::OffsetDateTime::now_utc();
        for _ in 0..update_count {
            controlled_did = software_wallet.update_did(&did, None).await.expect("pass");
        }
        // Stop the timer.
        let duration = time::OffsetDateTime::now_utc() - time_start;
        tracing::info!(
            "-- Time taken to update DID {} times: {:.3} -------------------------",
            update_count,
            duration
        );

        // Retrieve the latest DID doc from the wallet's doc store.  This will be a sanity check for the performance test.
        let expected_latest_did_document_jcs = {
            use did_webplus_wallet_store::WalletStorage;
            let did_doc_record = wallet_storage_a
                .as_did_doc_storage()
                .get_latest_known_did_doc_record(None, controlled_did.did())
                .await
                .expect("pass")
                .expect("pass");
            did_doc_record.did_document_jcs
        };

        let mut timing_result_v = Vec::with_capacity(4);
        for vdg_host_o in [None, Some(services.vdg_host().to_string())] {
            let did_resolver_full = did_resolver_full_m.get(&vdg_host_o).expect("pass");
            tracing::trace!(
                "resolving DID using DIDResolverFull with vdg_host_o: {:?}",
                vdg_host_o
            );

            // Start the timer
            let time_start = std::time::SystemTime::now();

            // Resolve the DID.
            use did_webplus_resolver::DIDResolver;
            let (did_document_body, _did_document_metadata, _did_resolution_metadata) =
                did_resolver_full
                    .resolve_did_document_string(
                        &did,
                        did_webplus_core::DIDResolutionOptions::no_metadata(false),
                    )
                    .await
                    .expect("pass");

            // Stop the timer.
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::debug!("Time taken: {:?}", duration);
            timing_result_v.push((
                format!("DIDResolverFull {{ vdg_host_o: {:?} }}", vdg_host_o),
                duration,
            ));

            // Verify that the DID document body is the expected value.
            assert_eq!(did_document_body, expected_latest_did_document_jcs);
        }

        // Now to test DIDResolverThin:
        {
            let did_resolver_thin =
                did_webplus_resolver::DIDResolverThin::new(services.vdg_host(), None)
                    .expect("pass");

            // Start the timer
            let time_start = std::time::SystemTime::now();

            // Resolve the DID.
            use did_webplus_resolver::DIDResolver;
            let (did_document_body, _did_document_metadata, _did_resolution_metadata) =
                did_resolver_thin
                    .resolve_did_document_string(
                        &did,
                        did_webplus_core::DIDResolutionOptions::no_metadata(false),
                    )
                    .await
                    .expect("pass");

            // Stop the timer.
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::debug!("Time taken: {:.3} seconds", duration.as_secs_f64());
            timing_result_v.push(("DIDResolverThin".to_string(), duration));

            // Verify that the DID document body is the expected value.
            assert_eq!(did_document_body, expected_latest_did_document_jcs);
        }

        // Print the timing results.
        for (resolver_name, duration) in timing_result_v {
            tracing::info!(
                "{}: Time taken: {:.3} seconds",
                resolver_name,
                duration.as_secs_f64()
            );
        }
    }

    //
    // Tests are done, so shut down.
    //

    services.abort();
}

async fn create_did_resolver_full(
    vdg_host_o: Option<&str>,
) -> did_webplus_resolver::DIDResolverFull {
    let sqlite_pool = sqlx::SqlitePool::connect("sqlite://:memory:")
        .await
        .expect("pass");
    let did_doc_storage =
        did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(sqlite_pool)
            .await
            .expect("pass");
    let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
    did_webplus_resolver::DIDResolverFull::new(did_doc_store, vdg_host_o, None).expect("pass")
}

async fn create_did_resolver_thin(vdg_host: &str) -> did_webplus_resolver::DIDResolverThin {
    did_webplus_resolver::DIDResolverThin::new(vdg_host, None).expect("pass")
}

async fn test_did_resolver_impl(
    services: &Services,
    did_resolver: &dyn did_webplus_resolver::DIDResolver,
) {
    // Create an in-memory SoftwareWallet.
    let (_wallet_storage_a, software_wallet) = create_in_memory_software_wallet().await;

    // Create a DID.
    use did_webplus_wallet::Wallet;
    let controlled_did_0 = software_wallet
        .create_did(services.vdr_url.as_str(), None)
        .await
        .expect("pass");
    let did = controlled_did_0.did().to_owned();
    tracing::info!(
        "Created DID: {} (fully qualified: {})",
        did,
        controlled_did_0
    );

    {
        tracing::debug!("1; Resolving DID --------------------------");
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(false),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(false));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, true);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, false);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            false
        );
    }

    {
        tracing::debug!("2; Resolving DID again --------------------------");
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(false),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(false));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, true);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, false);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            false
        );
    }

    {
        tracing::debug!("3a; Resolving DID with selfHash query param --------------------------");
        let did_query = format!("{}?selfHash={}", did, controlled_did_0.query_self_hash());
        tracing::debug!("did_query: {}", did_query);
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(false),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(false));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, true);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, true);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            false
        );
    }

    {
        tracing::debug!("3b; Resolving DID with versionId query param --------------------------");
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(false),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(false));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, true);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, true);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            false
        );
    }

    {
        tracing::debug!(
            "4; Resolving DID with query params and maximal metadata request that still allows local resolution --------------------------"
        );
        let did_query = format!("{}?selfHash={}", did, controlled_did_0.query_self_hash());
        tracing::debug!("did_query: {}", did_query);
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: false,
                    request_latest: false,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_none());
        assert_eq!(did_document_metadata.deactivated_o, None);
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, false);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, true);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            true
        );
    }

    {
        tracing::debug!(
            "5a; Resolving DID with query params and local-only metadata request that produces an error --------------------------"
        );
        let did_query = format!("{}?selfHash={}", did, controlled_did_0.query_self_hash());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: true,
                    request_latest: false,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    {
        tracing::debug!(
            "5b; Resolving DID with query params and local-only metadata request that produces an error --------------------------"
        );
        let did_query = format!("{}?selfHash={}", did, controlled_did_0.query_self_hash());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: false,
                    request_latest: true,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    {
        tracing::debug!(
            "5c; Resolving DID with query params and local-only metadata request that produces an error --------------------------"
        );
        let did_query = format!("{}?selfHash={}", did, controlled_did_0.query_self_hash());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: false,
                    request_latest: false,
                    request_deactivated: true,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    // Update the DID so that resolution produces different results.
    let controlled_did_1 = software_wallet.update_did(&did, None).await.expect("pass");
    tracing::info!(
        "Updated DID: {} (fully qualified: {})",
        did,
        controlled_did_1
    );

    // Execute all the locally-resolvable test cases again.

    {
        tracing::debug!(
            "6; Resolving DID with selfHash query param and maximal local-only metadata request --------------------------"
        );
        let did_query = format!("{}?selfHash={}", did, controlled_did_0.query_self_hash());
        tracing::debug!("did_query: {}", did_query);
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: false,
                    request_latest: false,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_none());
        assert_eq!(did_document_metadata.deactivated_o, None);
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, false);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, true);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            true
        );
    }

    {
        tracing::debug!(
            "7a; Resolving DID with versionId query param and metadata request that can't be fulfilled locally --------------------------"
        );
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: true,
                    request_latest: false,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    {
        tracing::debug!(
            "7b; Resolving DID with versionId query param and metadata request that can't be fulfilled locally --------------------------"
        );
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: false,
                    request_latest: true,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    {
        tracing::debug!(
            "7c; Resolving DID with versionId query param and metadata request that can't be fulfilled locally --------------------------"
        );
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: false,
                    request_latest: false,
                    request_deactivated: true,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    {
        tracing::debug!("8; Resolving DID --------------------------");
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(false),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(false));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, true);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, false);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            false
        );
    }

    // Now run the metadata requests; positive and negative test cases.
    {
        tracing::debug!(
            "9; Resolving DID with maximal local-only metadata request --------------------------"
        );
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: true,
                    request_latest: false,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_some());
        assert!(did_document_metadata.latest_update_metadata_o.is_none());
        assert_eq!(did_document_metadata.deactivated_o, None);
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, false);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, true);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            true
        );
    }

    {
        tracing::debug!(
            "10a; Resolving DID with metadata requests that can't be fulfilled locally --------------------------"
        );
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: true,
                    request_latest: true,
                    request_deactivated: false,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    {
        tracing::debug!(
            "10b; Resolving DID with metadata requests that can't be fulfilled locally --------------------------"
        );
        let did_query = format!("{}?versionId={}", did, controlled_did_0.query_version_id());
        tracing::debug!("did_query: {}", did_query);
        let err = did_resolver
            .resolve_did_document_string(
                did_query.as_str(),
                did_webplus_core::DIDResolutionOptions {
                    request_creation: true,
                    request_next: true,
                    request_latest: false,
                    request_deactivated: true,
                    local_resolution_only: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("pass");
        tracing::debug!("error: {:?}", err);
    }

    // Deactivate the DID.  This changes what metadata can be resolved locally.
    let controlled_did_2 = software_wallet
        .deactivate_did(&did, None)
        .await
        .expect("pass");
    tracing::info!(
        "Deactivated DID: {} (fully qualified: {})",
        did,
        controlled_did_2
    );

    {
        tracing::debug!(
            "11; Resolving DID (should be deactivated at this point) --------------------------"
        );
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(false),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(true));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, true);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, false);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            false
        );
    }

    {
        tracing::debug!(
            "12; Resolving DID with maximal metadata request, but locally-only (which is now possible because the DID is deactivated) --------------------------"
        );
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = did_resolver
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::all_metadata(true),
            )
            .await
            .expect("pass");
        tracing::debug!("did_document_jcs: {}", did_document_jcs);
        tracing::debug!(
            "did_document_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );
        tracing::debug!(
            "did_resolution_metadata as json:\n{}",
            serde_json::to_string_pretty(&did_resolution_metadata).expect("pass")
        );
        assert!(did_document_metadata.creation_metadata_o.is_some());
        assert!(did_document_metadata.next_update_metadata_o.is_none());
        assert!(did_document_metadata.latest_update_metadata_o.is_some());
        assert_eq!(did_document_metadata.deactivated_o, Some(true));
        assert_eq!(did_resolution_metadata.fetched_updates_from_vdr, false);
        assert_eq!(did_resolution_metadata.did_document_resolved_locally, true);
        assert_eq!(
            did_resolution_metadata.did_document_metadata_resolved_locally,
            true
        );
    }
}

#[tokio::test]
async fn test_did_resolver_full_vdr_only() {
    let services_config = ServicesConfig::with_vdr(
        50010,
        "postgres:///test_vdr_for_did_resolver_full_vdr_only".to_string(),
    );
    let services = Services::spin_up(services_config).await;

    let did_resolver_full = create_did_resolver_full(None).await;
    test_did_resolver_impl(&services, &did_resolver_full).await;

    services.abort();
}

// TODO: Write a test for DIDResolverFull with a VDG -- this will have different resolution
// metadata than the VDR-only test, so it would require more work to specify.

#[tokio::test]
async fn test_did_resolver_thin() {
    let services_config = ServicesConfig::with_vdg_and_vdr(
        50031,
        "postgres:///test_vdg_for_did_resolver_thin".to_string(),
        false,
        50030,
        "postgres:///test_vdr_for_did_resolver_thin".to_string(),
    );
    let services = Services::spin_up(services_config).await;

    let did_resolver_thin = create_did_resolver_thin(services.vdg_host()).await;
    test_did_resolver_impl(&services, &did_resolver_thin).await;

    services.abort();
}
