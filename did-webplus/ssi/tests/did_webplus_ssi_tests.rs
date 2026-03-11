use std::{str::FromStr, sync::Arc};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
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
async fn test_ssi_jwt_issue_example() {
    // Defines the shape of our custom claims.
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct Claims {
        name: String,
        email: String,
    }

    // Create JWT claims from our custom ("private") claims.
    let claims = ssi_claims::JWTClaims::from_private_claims(Claims {
        name: "Grunty McParty".to_owned(),
        email: "g@mc-p.org".to_owned(),
    });

    // Create a random signing key, and turn its public part into a DID URL.
    let mut key = ssi_jwk::JWK::generate_p256(); // requires the `p256` feature.
    let did = ssi_dids::DIDJWK::generate_url(&key.to_public());
    key.key_id = Some(did.into());

    // Sign the claims.
    use ssi_claims::JwsPayload;
    let jwt = claims.sign(&key).await.expect("signature failed");

    tracing::info!("jwt: {}", jwt);

    // Create a verification method resolver, which will be in charge of
    // decoding the DID back into a public key.
    use ssi_dids::DIDResolver;
    let vm_resolver = ssi_dids::DIDJWK.into_vm_resolver::<ssi_verification_methods::AnyJwkMethod>();

    // Setup the verification parameters.
    let params = ssi_claims::VerificationParameters::from_resolver(vm_resolver);

    // Verify the JWT.
    assert!(jwt
        .verify(&params)
        .await
        .expect("verification failed")
        .is_ok());
}

async fn test_ssi_jwt_issue_did_webplus_impl(
    software_wallet: &did_webplus_software_wallet::SoftwareWallet,
    vdr_did_create_endpoint: &str,
) {
    // Have the wallet create a DID.
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
    use did_webplus_wallet::Wallet;
    let controlled_did = software_wallet
        .create_did(
            did_webplus_wallet::CreateDIDParameters {
                vdr_did_create_endpoint: vdr_did_create_endpoint,
                mb_hash_function_for_did: &mb_hash_function,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            None,
        )
        .await
        .expect("pass");

    // Defines the shape of our custom claims.
    #[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
    pub struct Claims {
        name: String,
        email: String,
    }

    // Create JWT claims from our custom ("private") claims.
    let claims = ssi_claims::JWTClaims::from_private_claims(Claims {
        name: "Grunty McParty".to_owned(),
        email: "g@mc-p.org".to_owned(),
    });

    let wallet_based_signer = did_webplus_wallet::WalletBasedSigner::new(
        software_wallet.clone(),
        controlled_did.did(),
        did_webplus_core::KeyPurpose::AssertionMethod,
        None,
        None,
    )
    .await
    .expect("pass");

    // Sign the claims.
    let jwt = did_webplus_ssi::sign_jwt(&claims, &wallet_based_signer)
        .await
        .expect("signature failed");
    tracing::info!("jwt: {}", jwt);

    // Create a verification method resolver, which will be in charge of
    // decoding the DID back into a public key.
    let did_resolver_a = {
        let db_url = "sqlite://:memory:";
        let did_doc_storage =
            did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_url_and_run_migrations(
                db_url, None,
            )
            .await
            .expect("pass");
        let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
        let did_resolver_full =
            did_webplus_resolver::DIDResolverFull::new(did_doc_store, None, None).expect("pass");
        Arc::new(did_resolver_full)
    };

    let jwt = did_webplus_ssi::verify_jwt(jwt.as_str(), did_resolver_a.clone())
        .await
        .expect("pass");

    // Decode the jwt into claims.
    let decoded_jwt = did_webplus_ssi::decode_jwt::<Claims>(&jwt)
        .await
        .expect("pass");
    let decoded_claims = decoded_jwt.payload;
    tracing::info!("decoded claims: {:?}", decoded_claims);
    assert_eq!(decoded_claims, claims);
}

#[tokio::test]
async fn test_ssi_jwt_issue_did_webplus() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let vdr_database_url = "postgres:///test_ssi_jwt_issue_did_webplus_vdr";
    let vdr_port = 14085;
    let wallet_store_database_path = "tests/test_ssi_jwt_issue_did_webplus.wallet-store.db";

    let (vdr_handle, vdr_did_create_endpoint, software_wallet) =
        setup_vdr_and_wallet(vdr_database_url, vdr_port, wallet_store_database_path).await;

    test_ssi_jwt_issue_did_webplus_impl(&software_wallet, &vdr_did_create_endpoint).await;

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

async fn test_ssi_vc_issue_0_impl(
    software_wallet: &did_webplus_software_wallet::SoftwareWallet,
    vdr_did_create_endpoint: &str,
) {
    use ssi_claims::VerificationParameters;
    use ssi_dids::DIDResolver;

    // This will be used in signing and verification.
    let did_resolver_a = {
        let db_url = "sqlite://:memory:";
        let did_doc_storage =
            did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_url_and_run_migrations(
                db_url, None,
            )
            .await
            .expect("pass");
        let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
        let did_resolver_full =
            did_webplus_resolver::DIDResolverFull::new(did_doc_store, None, None).expect("pass");
        Arc::new(did_resolver_full)
    };
    // Create a verification method resolver, which will be in charge of
    // decoding the DID back into a public key.
    let did_resolver = did_webplus_ssi::DIDWebplus {
        did_resolver_a: did_resolver_a.clone(),
    };
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();

    // Have the wallet create a DID.
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
    let controlled_did = software_wallet
        .create_did(
            did_webplus_wallet::CreateDIDParameters {
                vdr_did_create_endpoint: vdr_did_create_endpoint,
                mb_hash_function_for_did: &mb_hash_function,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            None,
        )
        .await
        .expect("pass");
    // Get the appropriate signing key.
    use did_webplus_wallet::Wallet;
    let wallet_based_signer = did_webplus_wallet::WalletBasedSigner::new(
        software_wallet.clone(),
        controlled_did.did(),
        did_webplus_core::KeyPurpose::AssertionMethod,
        None,
        None,
    )
    .await
    .expect("pass");

    let unsigned_credential = {
        let issuance_date = time::OffsetDateTime::now_utc();
        let expiration_date = issuance_date + time::Duration::days(365);
        did_webplus_ssi::new_unsigned_credential(
            None,
            "https://example.org/#CredentialId",
            issuance_date,
            expiration_date,
            serde_json::json!({
                "id": "https://example.org/#CredentialSubjectId",
                "https://example.org/#name": "Grunty McParty",
                "https://example.org/#email": "g@mc-p.org",
            }),
        )
    };

    let vc_ldp = did_webplus_ssi::issue_vc_ldp(
        unsigned_credential.clone(),
        &wallet_based_signer,
        did_resolver_a.clone(),
    )
    .await
    .expect("pass");
    tracing::debug!("vc_ldp: {:?}", vc_ldp);

    let vc_ldp_json = serde_json::to_string(&vc_ldp).expect("pass");
    tracing::info!("vc_ldp_json (vc_ldp as JSON): {}", vc_ldp_json);

    let vc_jwt = did_webplus_ssi::issue_vc_jwt(unsigned_credential.clone(), &wallet_based_signer)
        .await
        .expect("pass");
    tracing::info!("vc_jwt: {}", vc_jwt);

    let verification_params = VerificationParameters::from_resolver(&vm_resolver);
    // Verify vc_ldp
    {
        let vc_ldp_verify_r = did_webplus_ssi::verify_vc_ldp(&vc_ldp, did_resolver_a.clone()).await;
        tracing::debug!("vc_ldp_verify_r: {:?}", vc_ldp_verify_r);
        assert!(vc_ldp_verify_r.is_ok());
        let vc_ldp_verify_proof_r = vc_ldp_verify_r.unwrap();
        tracing::debug!("vc_ldp_verify_proof_r: {:?}", vc_ldp_verify_proof_r);
        assert!(vc_ldp_verify_proof_r.is_ok());
    }
    // Verify vc_jwt
    {
        let vc_jwt_verify_r = did_webplus_ssi::verify_vc_jwt(&vc_jwt, did_resolver_a.clone()).await;
        tracing::debug!("vc_jwt_verify_r: {:?}", vc_jwt_verify_r);
        assert!(vc_jwt_verify_r.is_ok());
        let vc_jwt_verify_proof_r = vc_jwt_verify_r.unwrap();
        tracing::debug!("vc_jwt_verify_proof_r: {:?}", vc_jwt_verify_proof_r);
        assert!(vc_jwt_verify_proof_r.is_ok());
    }

    // Also read it in from the JSON string and verify it.
    {
        let parsed_vc_ldp =
            ssi_claims::vc::v1::data_integrity::any_credential_from_json_str(&vc_ldp_json)
                .expect("pass");
        tracing::debug!("parsed_vc_ldp: {:?}", parsed_vc_ldp);
        // TODO: Somehow assert that parsed_vc equals vc
        let parsed_vc_ldp_verify_r = parsed_vc_ldp.verify(&verification_params).await;
        tracing::debug!("parsed_vc_ldp_verify_r: {:?}", parsed_vc_ldp_verify_r);
        assert!(parsed_vc_ldp_verify_r.is_ok());
        let parsed_vc_ldp_verify_proof_r = parsed_vc_ldp_verify_r.unwrap();
        tracing::debug!(
            "parsed_vc_ldp_verify_proof_r: {:?}",
            parsed_vc_ldp_verify_proof_r
        );
        assert!(parsed_vc_ldp_verify_proof_r.is_ok());
    }

    // Present vc_ldp as an LDP format VP.
    {
        // NOTE: It seems like it's necessary to deserialize the VC into a "generic" type, not the
        // "specialized" type with SimpleCredentialSubject as above.
        let parsed_vc_ldp: ssi_claims::data_integrity::AnyDataIntegrity<
            ssi_claims::vc::AnyJsonCredential,
        > = serde_json::from_str(&vc_ldp_json).expect("pass");
        let json_credential_or_jws =
            ssi_claims::JsonCredentialOrJws::Credential(Box::new(parsed_vc_ldp));
        let unsigned_presentation = ssi_claims::vc::v1::JsonPresentation::new(
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass")),
            None,
            vec![json_credential_or_jws],
        );
        // NOTE: The VerifiablePresentation data model DOES NOT include issuanceDate, expirationDate, or audience.
        // See <https://www.w3.org/2018/credentials/v1> (this is the JSON-LD context URL for VCs and VPs).

        let vp_ldp_of_vc_ldp = did_webplus_ssi::issue_vp_ldp(
            unsigned_presentation.clone(),
            did_webplus_ssi::IssueVPParameters {
                challenge_o: Some("1234567890".to_string()),
                domains_vo: Some(vec!["example.org".to_string()]),
                nonce_o: Some("abcdefghijklmnopqrstuvwxyz".to_string()),
            },
            &wallet_based_signer,
            did_resolver_a.clone(),
        )
        .await
        .expect("pass");
        tracing::debug!("vp_ldp_of_vc_ldp: {:?}", vp_ldp_of_vc_ldp);

        // Verify vp_ldp_of_vc_ldp
        {
            let vp_ldp_of_vc_ldp_verify_r =
                did_webplus_ssi::verify_vp_ldp(&vp_ldp_of_vc_ldp, did_resolver_a.clone()).await;
            tracing::debug!("vp_ldp_of_vc_ldp_verify_r: {:?}", vp_ldp_of_vc_ldp_verify_r);
            assert!(vp_ldp_of_vc_ldp_verify_r.is_ok());
            let vp_ldp_of_vc_ldp_verify_proof_r = vp_ldp_of_vc_ldp_verify_r.unwrap();
            tracing::debug!(
                "vp_ldp_of_vc_ldp_verify_proof_r: {:?}",
                vp_ldp_of_vc_ldp_verify_proof_r
            );
            assert!(vp_ldp_of_vc_ldp_verify_proof_r.is_ok());
        }
    }
    // Present vc_ldp as a JWT format VP.
    {
        // NOTE: It seems like it's necessary to deserialize the VC into a "generic" type, not the
        // "specialized" type with SimpleCredentialSubject as above.
        let parsed_vc_ldp: ssi_claims::data_integrity::AnyDataIntegrity<
            ssi_claims::vc::AnyJsonCredential,
        > = serde_json::from_str(&vc_ldp_json).expect("pass");
        let json_credential_or_jws =
            ssi_claims::JsonCredentialOrJws::Credential(Box::new(parsed_vc_ldp));
        let unsigned_presentation = ssi_claims::vc::v1::JsonPresentation::new(
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass")),
            None,
            vec![json_credential_or_jws],
        );

        let vp_jwt_of_vc_ldp = did_webplus_ssi::issue_vp_jwt(
            unsigned_presentation.clone(),
            did_webplus_ssi::IssueVPParameters {
                challenge_o: Some("1234567890".to_string()),
                domains_vo: Some(vec!["example.org".to_string()]),
                nonce_o: Some("abcdefghijklmnopqrstuvwxyz".to_string()),
            },
            &wallet_based_signer,
        )
        .await
        .expect("pass");
        tracing::info!("vp_jwt_of_vc_ldp: {}", vp_jwt_of_vc_ldp);

        // Verify vp_jwt_of_vc_ldp
        {
            let vp_jwt_of_vc_ldp_verify_r =
                did_webplus_ssi::verify_vp_jwt(&vp_jwt_of_vc_ldp, did_resolver_a.clone()).await;
            tracing::debug!("vp_jwt_of_vc_ldp_verify_r: {:?}", vp_jwt_of_vc_ldp_verify_r);
            assert!(vp_jwt_of_vc_ldp_verify_r.is_ok());
            let vp_jwt_of_vc_ldp_verify_proof_r = vp_jwt_of_vc_ldp_verify_r.unwrap();
            tracing::debug!(
                "vp_jwt_of_vc_ldp_verify_proof_r: {:?}",
                vp_jwt_of_vc_ldp_verify_proof_r
            );
            assert!(vp_jwt_of_vc_ldp_verify_proof_r.is_ok());
        }
    }
    // Present vc_jwt as an LDP format VP.
    {
        let json_credential_or_jws =
            ssi_claims::JsonCredentialOrJws::<ssi_claims::data_integrity::AnySuite>::Jws(
                ssi_jws::JwsString::try_from(vc_jwt.clone().into_string()).expect("pass"),
            );
        let unsigned_presentation = ssi_claims::vc::v1::JsonPresentation::new(
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass")),
            None,
            vec![json_credential_or_jws],
        );
        // TODO: Add iat, nbf, exp (or whatever the LDP equivalent is)

        let vp_ldp_of_vc_jwt = did_webplus_ssi::issue_vp_ldp(
            unsigned_presentation.clone(),
            did_webplus_ssi::IssueVPParameters {
                challenge_o: Some("1234567890".to_string()),
                domains_vo: Some(vec!["example.org".to_string()]),
                nonce_o: Some("abcdefghijklmnopqrstuvwxyz".to_string()),
            },
            &wallet_based_signer,
            did_resolver_a.clone(),
        )
        .await
        .expect("pass");
        tracing::debug!("vp_ldp_of_vc_jwt: {:?}", vp_ldp_of_vc_jwt);
        tracing::info!(
            "vp_ldp_of_vc_jwt as JSON: {}",
            serde_json::to_string(&vp_ldp_of_vc_jwt).expect("pass")
        );

        // Verify vp_ldp_of_vc_jwt
        {
            let vp_ldp_of_vc_jwt_verify_r =
                did_webplus_ssi::verify_vp_ldp(&vp_ldp_of_vc_jwt, did_resolver_a.clone()).await;
            tracing::debug!("vp_ldp_of_vc_jwt_verify_r: {:?}", vp_ldp_of_vc_jwt_verify_r);
            assert!(vp_ldp_of_vc_jwt_verify_r.is_ok());
            let vp_ldp_of_vc_jwt_verify_proof_r = vp_ldp_of_vc_jwt_verify_r.unwrap();
            tracing::debug!(
                "vp_ldp_of_vc_jwt_verify_proof_r: {:?}",
                vp_ldp_of_vc_jwt_verify_proof_r
            );
            assert!(vp_ldp_of_vc_jwt_verify_proof_r.is_ok());
        }
    }
    // Present vc_jwt as a JWT format VP.
    {
        let json_credential_or_jws =
            ssi_claims::JsonCredentialOrJws::<ssi_claims::data_integrity::AnySuite>::Jws(
                ssi_jws::JwsString::try_from(vc_jwt.clone().into_string()).expect("pass"),
            );
        let mut unsigned_presentation = ssi_claims::vc::v1::JsonPresentation::new(
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass")),
            None,
            vec![json_credential_or_jws],
        );
        let nbf = time::OffsetDateTime::now_utc();
        let exp = nbf + time::Duration::days(1);
        unsigned_presentation.additional_properties.insert(
            "iat".to_string(),
            nbf.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
                .into(),
        );
        unsigned_presentation.additional_properties.insert(
            "nbf".to_string(),
            nbf.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
                .into(),
        );
        unsigned_presentation.additional_properties.insert(
            "exp".to_string(),
            exp.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
                .into(),
        );

        let vp_jwt_of_vc_jwt = did_webplus_ssi::issue_vp_jwt(
            unsigned_presentation.clone(),
            did_webplus_ssi::IssueVPParameters {
                challenge_o: Some("1234567890".to_string()),
                domains_vo: Some(vec!["example.org".to_string()]),
                nonce_o: Some("abcdefghijklmnopqrstuvwxyz".to_string()),
            },
            &wallet_based_signer,
        )
        .await
        .expect("pass");
        tracing::info!("vp_jwt_of_vc_jwt: {}", vp_jwt_of_vc_jwt);

        // Verify vp_jwt_of_vc_jwt
        {
            let vp_jwt_of_vc_jwt_verify_r =
                did_webplus_ssi::verify_vp_jwt(&vp_jwt_of_vc_jwt, did_resolver_a.clone()).await;
            tracing::debug!("vp_jwt_of_vc_jwt_verify_r: {:?}", vp_jwt_of_vc_jwt_verify_r);
            assert!(vp_jwt_of_vc_jwt_verify_r.is_ok());
            let vp_jwt_of_vc_jwt_verify_proof_r = vp_jwt_of_vc_jwt_verify_r.unwrap();
            tracing::debug!(
                "vp_jwt_of_vc_jwt_verify_proof_r: {:?}",
                vp_jwt_of_vc_jwt_verify_proof_r
            );
            assert!(vp_jwt_of_vc_jwt_verify_proof_r.is_ok());
        }
    }

    // Update the wallet's DID and attempt to verify the same VC again.
    // TODO: Figure out how to un-hack ssi crate so this works without hack.
    // See https://github.com/spruceid/ssi/issues/687 and also the did-webplus-changes
    // branch on the LedgerDomain fork of the ssi crate.
    {
        let _updated_controlled_did = software_wallet
            .update_did(
                did_webplus_wallet::UpdateDIDParameters {
                    did: &controlled_did.did(),
                    change_mb_hash_function_for_self_hash_o: None,
                    mb_hash_function_for_update_key_o: Some(&mb_hash_function),
                },
                None,
            )
            .await
            .expect("pass");
        // Verify
        {
            let vc_ldp_verify_r =
                did_webplus_ssi::verify_vc_ldp(&vc_ldp, did_resolver_a.clone()).await;
            tracing::debug!("vc_ldp_verify_r: {:?}", vc_ldp_verify_r);
            assert!(vc_ldp_verify_r.is_ok());
            let vc_ldp_verify_proof_r = vc_ldp_verify_r.unwrap();
            tracing::debug!("vc_ldp_verify_proof_r: {:?}", vc_ldp_verify_proof_r);
            assert!(vc_ldp_verify_proof_r.is_ok());
        }
    }
}

#[tokio::test]
async fn test_ssi_vc_issue_0() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let vdr_database_url = "postgres:///test_ssi_vc_issue_0_vdr";
    let vdr_port = 13085;
    let wallet_store_database_path = "tests/test_ssi_vc_issue_0.wallet-store.db";

    let (vdr_handle, vdr_did_create_endpoint, software_wallet) =
        setup_vdr_and_wallet(vdr_database_url, vdr_port, wallet_store_database_path).await;

    test_ssi_vc_issue_0_impl(&software_wallet, &vdr_did_create_endpoint).await;

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

async fn setup_vdr_and_wallet(
    vdr_database_url: &str,
    vdr_port: u16,
    wallet_store_database_path: &str,
) -> (
    tokio::task::JoinHandle<()>,
    String,
    did_webplus_software_wallet::SoftwareWallet,
) {
    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema if possible.
    if std::fs::exists(wallet_store_database_path).expect("pass") {
        std::fs::remove_file(wallet_store_database_path).expect("pass");
    }

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(vdr_port),
        listen_port: vdr_port,
        database_url: vdr_database_url.to_string(),
        database_max_connections: 10,
        vdg_base_url_v: Vec::new(),
        http_scheme_override: Default::default(),
        test_authz_api_key_vo: None,
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    // While that's spinning up, let's create the wallet.
    let wallet_storage_a = {
        let db_url = format!("sqlite://{}?mode=rwc", wallet_store_database_path);
        let wallet_storage =
            did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_url_and_run_migrations(
                db_url.as_str(),
            )
            .await
            .expect("pass");
        Arc::new(wallet_storage)
    };

    let software_wallet = {
        use storage_traits::StorageDynT;
        let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
        let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
            transaction_b.as_mut(),
            wallet_storage_a,
            Some("fancy wallet".to_string()),
            None,
        )
        .await
        .expect("pass");
        transaction_b.commit().await.expect("pass");
        software_wallet
    };

    test_util::wait_until_service_is_up(
        "VDR",
        format!("http://localhost:{}/health", vdr_config.listen_port).as_str(),
    )
    .await;

    let vdr_scheme = "http";
    let vdr_did_create_endpoint = format!(
        "{}://{}:{}",
        vdr_scheme, vdr_config.did_hostname, vdr_config.listen_port
    );

    (vdr_handle, vdr_did_create_endpoint, software_wallet)
}
