use std::{collections::HashMap, sync::Arc};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

async fn create_in_memory_software_wallet() -> (
    Arc<did_webplus_wallet_storage_sqlite::WalletStorageSQLite>,
    did_webplus_software_wallet::SoftwareWallet,
) {
    let db_url = "sqlite://:memory:";
    let wallet_storage =
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_url_and_run_migrations(db_url)
            .await
            .expect("pass");
    let wallet_storage_a = Arc::new(wallet_storage);
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
    let (vdg_host, vdg_base_url, vdg_h) =
        test_util::spin_up_vdg(50001, "postgres:///test_did_resolver_vdg".to_string()).await;
    let (vdr_url, vdr_h) = test_util::spin_up_vdr(
        50000,
        "postgres:///test_did_resolver_vdr".to_string(),
        // VDR sends updates to VDG.
        Some(vdg_base_url.clone()),
    )
    .await;

    //
    // Now that the VDR is up, create a DID and verify that it can be resolved.
    //

    // Create an in-memory SoftwareWallet.
    let (wallet_storage_a, software_wallet) = create_in_memory_software_wallet().await;

    // Create a DID.
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
    use did_webplus_wallet::Wallet;
    let mut controlled_did = software_wallet
        .create_did(
            did_webplus_wallet::CreateDIDParameters {
                vdr_did_create_endpoint: vdr_url.as_str(),
                mb_hash_function_for_did: &mb_hash_function,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            None,
        )
        .await
        .expect("pass");
    let did = controlled_did.did().to_owned();
    tracing::info!("Created DID: {} (fully qualified: {})", did, controlled_did);

    // Create DIDResolverFull for having a VDG host and not.
    let did_resolver_full_m = {
        let mut did_resolver_full_m = HashMap::with_capacity(2);
        for vdg_host_o in [None, Some(vdg_host.as_str())] {
            let did_doc_storage =
                did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_url_and_run_migrations(
                    "sqlite://:memory:",
                    None,
                )
                .await
                .expect("pass");
            let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
            let did_resolver_full =
                did_webplus_resolver::DIDResolverFull::new(did_doc_store, vdg_host_o, None)
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
            controlled_did = software_wallet
                .update_did(
                    did_webplus_wallet::UpdateDIDParameters {
                        did: &did,
                        change_mb_hash_function_for_self_hash_o: None,
                        mb_hash_function_for_update_key_o: Some(&mb_hash_function),
                    },
                    None,
                )
                .await
                .expect("pass");
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

        #[cfg(not(target_arch = "wasm32"))]
        let mut timing_result_v = Vec::with_capacity(4);

        for vdg_host_o in [None, Some(vdg_host.as_str())] {
            let did_resolver_full = did_resolver_full_m.get(&vdg_host_o).expect("pass");
            tracing::trace!(
                "resolving DID using DIDResolverFull with vdg_host_o: {:?}",
                vdg_host_o
            );

            // Start the timer
            #[cfg(not(target_arch = "wasm32"))]
            let time_start = time::OffsetDateTime::now_utc();

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
            #[cfg(not(target_arch = "wasm32"))]
            {
                let duration = time::OffsetDateTime::now_utc() - time_start;
                tracing::debug!("Time taken: {:?}", duration);
                timing_result_v.push((
                    format!("DIDResolverFull {{ vdg_host_o: {:?} }}", vdg_host_o),
                    duration,
                ));
            }

            // Verify that the DID document body is the expected value.
            assert_eq!(did_document_body, expected_latest_did_document_jcs);
        }

        // Now to test DIDResolverThin:
        {
            let did_resolver_thin =
                did_webplus_resolver::DIDResolverThin::new(vdg_host.as_str(), None).expect("pass");

            // Start the timer
            #[cfg(not(target_arch = "wasm32"))]
            let time_start = time::OffsetDateTime::now_utc();

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
            #[cfg(not(target_arch = "wasm32"))]
            {
                let duration = time::OffsetDateTime::now_utc() - time_start;
                tracing::debug!("Time taken: {:.3}", duration);
                timing_result_v.push(("DIDResolverThin".to_string(), duration));
            }

            // Verify that the DID document body is the expected value.
            assert_eq!(did_document_body, expected_latest_did_document_jcs);
        }

        // Print the timing results.
        #[cfg(not(target_arch = "wasm32"))]
        {
            for (resolver_name, duration) in timing_result_v {
                tracing::info!("{}: Time taken: {:.3}", resolver_name, duration);
            }
        }
    }

    //
    // Tests are done, so shut down.
    //

    vdr_h.abort();
    vdg_h.abort();
}

async fn create_did_resolver_full(
    vdg_host_o: Option<&str>,
) -> did_webplus_resolver::DIDResolverFull {
    let did_doc_storage =
        did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_url_and_run_migrations(
            "sqlite://:memory:",
            None,
        )
        .await
        .expect("pass");
    let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
    did_webplus_resolver::DIDResolverFull::new(did_doc_store, vdg_host_o, None).expect("pass")
}

async fn create_did_resolver_thin(vdg_host: &str) -> did_webplus_resolver::DIDResolverThin {
    did_webplus_resolver::DIDResolverThin::new(vdg_host, None).expect("pass")
}

async fn test_did_resolver_impl(
    vdr_url: &url::Url,
    did_resolver: &dyn did_webplus_resolver::DIDResolver,
) {
    // Create an in-memory SoftwareWallet.
    let (_wallet_storage_a, software_wallet) = create_in_memory_software_wallet().await;

    // Create a DID.
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
    use did_webplus_wallet::Wallet;
    let controlled_did_0 = software_wallet
        .create_did(
            did_webplus_wallet::CreateDIDParameters {
                vdr_did_create_endpoint: vdr_url.as_str(),
                mb_hash_function_for_did: &mb_hash_function,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            None,
        )
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
    let controlled_did_1 = software_wallet
        .update_did(
            did_webplus_wallet::UpdateDIDParameters {
                did: &did,
                change_mb_hash_function_for_self_hash_o: None,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            None,
        )
        .await
        .expect("pass");
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
        .deactivate_did(
            did_webplus_wallet::DeactivateDIDParameters {
                did: &did,
                change_mb_hash_function_for_self_hash_o: None,
            },
            None,
        )
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

#[tokio::test(flavor = "multi_thread")]
async fn test_did_resolver_full_vdr_only() {
    let (vdr_url, vdr_h) = test_util::spin_up_vdr(
        50010,
        "postgres:///test_vdr_for_did_resolver_full_vdr_only".to_string(),
        None,
    )
    .await;

    let did_resolver_full = create_did_resolver_full(None).await;
    test_did_resolver_impl(&vdr_url, &did_resolver_full).await;

    vdr_h.abort();
}

// TODO: Write a test for DIDResolverFull with a VDG -- this will have different resolution
// metadata than the VDR-only test, so it would require more work to specify.

#[tokio::test(flavor = "multi_thread")]
async fn test_did_resolver_thin() {
    let (vdg_host, _vdg_base_url, vdg_h) = test_util::spin_up_vdg(
        50031,
        "postgres:///test_vdg_for_did_resolver_thin".to_string(),
    )
    .await;
    let (vdr_url, vdr_h) = test_util::spin_up_vdr(
        50030,
        "postgres:///test_vdr_for_did_resolver_thin".to_string(),
        // VDR doesn't send updates to VDG.
        None,
    )
    .await;

    let did_resolver_thin = create_did_resolver_thin(vdg_host.as_str()).await;
    test_did_resolver_impl(&vdr_url, &did_resolver_thin).await;

    vdg_h.abort();
    vdr_h.abort();
}

/// Black-box resolver compliance against the in-memory test-vector HTTP server.
///
/// `resolve(did)` must succeed iff the vector is in `groups.positive` (equivalently
/// `expected.valid`). Do not assert exact accept-prefix counts via resolve — that is
/// what library self_check covers.
async fn assert_resolver_against_test_vector_catalog(
    tvs_base_url: &url::Url,
    did_resolver: &dyn did_webplus_resolver::DIDResolver,
) {
    let index_url = tvs_base_url.join("index.json").expect("pass");
    let index_response = test_util::REQWEST_CLIENT
        .get(index_url)
        .send()
        .await
        .expect("fetch index.json")
        .error_for_status()
        .expect("index.json status");
    let index_text = index_response.text().await.expect("index.json text");
    let index_json: serde_json::Value =
        serde_json::from_str(&index_text).expect("parse index.json");

    let vector_m = index_json
        .get("vectors")
        .and_then(|v| v.as_object())
        .expect("vectors object");
    let positive_s: std::collections::HashSet<&str> = index_json
        .pointer("/groups/positive")
        .and_then(|v| v.as_array())
        .expect("groups.positive")
        .iter()
        .map(|v| v.as_str().expect("positive name"))
        .collect();

    use did_webplus_core::DID;
    use std::str::FromStr;

    for (name, location) in vector_m {
        let did_str = location
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("vector {name} missing did"));
        let path = location
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("vector {name} missing path"));
        let did = DID::from_str(did_str).unwrap_or_else(|e| panic!("parse DID for {name}: {e}"));
        let expect_ok = positive_s.contains(name.as_str());

        let resolve_r = did_resolver
            .resolve_did_document_string(
                &did,
                did_webplus_core::DIDResolutionOptions::no_metadata(false),
            )
            .await;

        if expect_ok {
            let (did_document_body, _meta, _res_meta) = resolve_r.unwrap_or_else(|e| {
                panic!("expected resolve success for positive vector {name} ({did}): {e}")
            });
            let jsonl_url = tvs_base_url
                .join(&format!("{path}/did-documents.jsonl"))
                .expect("jsonl url");
            let jsonl = test_util::REQWEST_CLIENT
                .get(jsonl_url)
                .send()
                .await
                .expect("fetch jsonl")
                .error_for_status()
                .expect("jsonl status")
                .text()
                .await
                .expect("jsonl text");
            let latest_line = jsonl
                .lines()
                .rev()
                .find(|line| !line.is_empty())
                .unwrap_or_else(|| panic!("positive vector {name} has no JSONL lines"));
            assert_eq!(
                did_document_body, latest_line,
                "resolved body must equal latest JSONL line for {name}"
            );
        } else {
            assert!(
                resolve_r.is_err(),
                "expected resolve failure for negative vector {name} ({did})"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_did_resolver_full_against_test_vectors() {
    let config = test_util::TestVectorServerConfig {
        host: "localhost".to_owned(),
        listen_port: 50100,
        did_path_o: None,
        seed: test_util::DEFAULT_SEED.to_owned(),
        fuzz_lite_count: did_webplus_test_vector_lib::DEFAULT_FUZZ_LITE_COUNT,
        stress_version_vo: None,
        stress_config_o: Some(test_util::StressConfig::for_tests()),
    };
    let (tvs_base_url, tvs_h) = test_util::spin_up_test_vector_server(config).await;

    let did_resolver_full = create_did_resolver_full(None).await;
    assert_resolver_against_test_vector_catalog(&tvs_base_url, &did_resolver_full).await;

    tvs_h.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_did_resolver_thin_against_test_vectors() {
    let config = test_util::TestVectorServerConfig {
        host: "localhost".to_owned(),
        listen_port: 50110,
        did_path_o: None,
        seed: test_util::DEFAULT_SEED.to_owned(),
        fuzz_lite_count: did_webplus_test_vector_lib::DEFAULT_FUZZ_LITE_COUNT,
        stress_version_vo: None,
        stress_config_o: Some(test_util::StressConfig::for_tests()),
    };
    let (tvs_base_url, tvs_h) = test_util::spin_up_test_vector_server(config).await;
    let (vdg_host, _vdg_base_url, vdg_h) = test_util::spin_up_vdg(
        50111,
        "postgres:///test_did_resolver_thin_against_test_vectors_vdg".to_string(),
    )
    .await;

    let did_resolver_thin = create_did_resolver_thin(vdg_host.as_str()).await;
    assert_resolver_against_test_vector_catalog(&tvs_base_url, &did_resolver_thin).await;

    vdg_h.abort();
    tvs_h.abort();
}
