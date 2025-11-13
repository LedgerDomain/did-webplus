use std::sync::Arc;

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
    let controlled_did = software_wallet
        .create_did(vdr_did_create_endpoint, None)
        .await
        .expect("pass");
    // Get an appropriate signing key.
    use did_webplus_wallet::Wallet;
    let (verification_method_record, signer_bytes) = {
        let locally_controlled_verification_method_filter =
            did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                did_o: Some(controlled_did.did().to_owned()),
                version_id_o: Some(controlled_did.query_version_id()),
                key_purpose_o: Some(did_webplus_core::KeyPurpose::AssertionMethod),
                key_id_o: None,
                result_limit_o: None,
            };
        software_wallet
            .get_locally_controlled_verification_method(
                locally_controlled_verification_method_filter,
            )
            .await
            .expect("pass")
    };

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

    let priv_jwk = to_ssi_jwk(
        Some(
            verification_method_record
                .did_key_resource_fully_qualified
                .as_str(),
        ),
        &signer_bytes,
    )
    .expect("pass");

    // Sign the claims.
    use ssi_claims::JwsPayload;
    let jwt = claims.sign(&priv_jwk).await.expect("signature failed");

    tracing::info!("jwt: {}", jwt);

    // Create a verification method resolver, which will be in charge of
    // decoding the DID back into a public key.
    let did_resolver = {
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
        let did_resolver_full =
            did_webplus_resolver::DIDResolverFull::new(did_doc_store, None, None).expect("pass");
        let did_resolver_a = Arc::new(did_resolver_full);
        did_webplus_ssi::DIDWebplus { did_resolver_a }
    };
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyJwkMethod>();

    // Setup the verification parameters.
    let params = ssi_claims::VerificationParameters::from_resolver(vm_resolver);

    // Verify the JWT.
    let verification_r = jwt.verify(&params).await.expect("pass");
    tracing::debug!("verification_r: {:?}", verification_r);
    assert!(verification_r.is_ok());
}

#[tokio::test]
async fn test_ssi_jwt_issue_did_webplus() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let wallet_store_database_path = "tests/test_ssi_jwt_issue_did_webplus.wallet-store.db";

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema
    if std::fs::exists(wallet_store_database_path).expect("pass") {
        std::fs::remove_file(wallet_store_database_path).expect("pass");
    }

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(14085),
        listen_port: 14085,
        database_url: "postgres:///test_ssi_jwt_issue_did_webplus_vdr".to_string(),
        database_max_connections: 10,
        vdg_base_url_v: Vec::new(),
        http_scheme_override: Default::default(),
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    // While that's spinning up, let's create the wallet.
    let wallet_storage_a = {
        // TODO: Make this into a function, since it's a lot of duplication everywhere, and requires
        // importing a bunch of crates.
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", wallet_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        let wallet_storage =
            did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await
            .expect("pass");
        Arc::new(wallet_storage)
    };

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

    test_ssi_jwt_issue_did_webplus_impl(&software_wallet, &vdr_did_create_endpoint).await;

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

// TEMP HACK
pub fn to_ssi_jwk(
    kid_o: Option<&str>,
    signer_bytes: &signature_dyn::SignerBytes<'_>,
) -> anyhow::Result<ssi_jwk::JWK> {
    match signer_bytes.key_type() {
        signature_dyn::KeyType::Ed25519 => {
            // #[cfg(feature = "ed25519-dalek")]
            {
                let secret_key = ed25519_dalek::SecretKey::try_from(signer_bytes.bytes())
                    .expect("this should not fail because of check in new");
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
                let verifying_key = signing_key.verifying_key();
                let mut jwk = ssi_jwk::JWK::from(ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
                    curve: "Ed25519".to_string(),
                    public_key: ssi_jwk::Base64urlUInt(verifying_key.to_bytes().to_vec()),
                    private_key: Some(ssi_jwk::Base64urlUInt(signing_key.to_bytes().to_vec())),
                }));
                if let Some(kid_o) = kid_o {
                    jwk.key_id = Some(kid_o.to_string());
                }
                jwk.algorithm = Some(ssi_jwk::algorithm::Algorithm::EdDSA);
                Ok(jwk)
            }
            // #[cfg(not(feature = "ed25519-dalek"))]
            // {
            //     panic!("ed25519-dalek feature not enabled");
            // }
        }
        signature_dyn::KeyType::Secp256k1 => {
            // #[cfg(feature = "k256")]
            {
                let signing_key = k256::ecdsa::SigningKey::from_slice(signer_bytes.bytes())
                    .expect("this should not fail because of check in new");
                let secret_key = k256::SecretKey::from(signing_key);
                let public_key = secret_key.public_key();
                let mut ec_params = ssi_jwk::ECParams::from(&public_key);
                ec_params.ecc_private_key =
                    Some(ssi_jwk::Base64urlUInt(signer_bytes.bytes().to_vec()));
                let mut jwk = ssi_jwk::JWK::from(ssi_jwk::Params::EC(ec_params));
                if let Some(kid_o) = kid_o {
                    jwk.key_id = Some(kid_o.to_string());
                }
                // jwk.algorithm = Some(ssi_jwk::algorithm::Algorithm::ES256);
                Ok(jwk)
            }
            // #[cfg(not(feature = "k256"))]
            // {
            //     panic!("k256 feature not enabled");
            // }
        }
        _ => anyhow::bail!("unsupported key type: {:?}", signer_bytes.key_type()),
    }
}

async fn test_ssi_vc_issue_0_impl(
    software_wallet: &did_webplus_software_wallet::SoftwareWallet,
    vdr_did_create_endpoint: &str,
) {
    use serde::{Deserialize, Serialize};
    // use ssi::{
    //     claims::{
    //         data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
    //         vc::syntax::NonEmptyVec,
    //         VerificationParameters,
    //     },
    //     dids::DIDResolver,
    //     verification_methods::SingleSecretSigner,
    //     xsd::DateTime,
    // };
    use ssi_claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::syntax::NonEmptyVec,
        VerificationParameters,
    };
    use ssi_dids::DIDResolver;
    use ssi_verification_methods::SingleSecretSigner;
    // use static_iref::uri;
    use xsd_types::DateTime;

    // Have the wallet create a DID.
    let controlled_did = software_wallet
        .create_did(vdr_did_create_endpoint, None)
        .await
        .expect("pass");
    // Get an appropriate signing key.
    use did_webplus_wallet::Wallet;
    let (verification_method_record, signer_bytes) = {
        let locally_controlled_verification_method_filter =
            did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                did_o: Some(controlled_did.did().to_owned()),
                version_id_o: Some(controlled_did.query_version_id()),
                key_purpose_o: Some(did_webplus_core::KeyPurpose::AssertionMethod),
                key_id_o: None,
                result_limit_o: None,
            };
        software_wallet
            .get_locally_controlled_verification_method(
                locally_controlled_verification_method_filter,
            )
            .await
            .expect("pass")
    };
    // Create the DID URL which fully qualifies the specific key to be used.
    let did_url = ssi_dids::DIDURLBuf::from_string(
        verification_method_record
            .did_key_resource_fully_qualified
            .to_string(),
    )
    .expect("pass");

    // Get the private JWK from the Signer.
    let priv_jwk = to_ssi_jwk(
        Some(
            verification_method_record
                .did_key_resource_fully_qualified
                .as_str(),
        ),
        &signer_bytes,
    )
    .expect("pass");
    tracing::debug!("priv_jwk: {:#?}", priv_jwk);

    // Create a verification method resolver, which will be in charge of
    // decoding the DID back into a public key.
    // let vm_resolver = DIDJWK.into_vm_resolver();
    let did_resolver = {
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
        let did_resolver_full =
            did_webplus_resolver::DIDResolverFull::new(did_doc_store, None, None).expect("pass");
        let did_resolver_a = Arc::new(did_resolver_full);
        did_webplus_ssi::DIDWebplus { did_resolver_a }
    };
    let vm_resolver = did_resolver.into_vm_resolver();

    // Create a signer from the secret key.
    // Here we use the simple `SingleSecretSigner` signer type which always uses
    // the same provided secret key to sign messages.
    let signer = SingleSecretSigner::new(priv_jwk.clone()).into_local();

    // Turn the DID URL into a verification method reference.
    let verification_method = did_url.clone().into_iri().into();

    // Automatically pick a suitable Data-Integrity signature suite for our key.
    let cryptosuite = AnySuite::pick(&priv_jwk, Some(&verification_method))
        .expect("could not find appropriate cryptosuite");
    // let cryptosuite = ssi::claims::data_integrity::suites::JsonWebSignature2020;

    // Defines the shape of our custom claims.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct MyCredentialSubject {
        #[serde(rename = "https://example.org/#name")]
        name: String,

        #[serde(rename = "https://example.org/#email")]
        email: String,
    }

    let credential = ssi_claims::vc::v1::JsonCredential::<MyCredentialSubject>::new(
        Some(static_iref::uri!("https://example.org/#CredentialId").to_owned()),
        // Apparently this issuer field doesn't matter for the verification process.
        // TODO: Make this the issuer DID and verify that it gets checked, or if we have to check the relationship.
        static_iref::uri!("https://example.org/#Issuer")
            .to_owned()
            .into(),
        DateTime::now().into(),
        NonEmptyVec::new(MyCredentialSubject {
            name: "Grunty McParty".to_owned(),
            email: "g@mc-p.org".to_owned(),
        }),
    );

    let vc = cryptosuite
        .sign(
            credential,
            &vm_resolver,
            &signer,
            ProofOptions::from_method(verification_method),
        )
        .await
        .expect("signature failed");

    tracing::debug!("vc: {:?}", vc);
    let vc_json = serde_json::to_string(&vc).expect("pass");
    tracing::info!("vc as JSON: {}", vc_json);

    // Verify the VC
    let verification_params = VerificationParameters::from_resolver(vm_resolver);
    {
        let vc_verify_r = vc.verify(&verification_params).await;
        tracing::debug!("vc_verify_r: {:?}", vc_verify_r);
        assert!(vc_verify_r.is_ok());
        let vc_verify_proof_r = vc_verify_r.unwrap();
        tracing::debug!("vc_verify_proof_r: {:?}", vc_verify_proof_r);
        assert!(vc_verify_proof_r.is_ok());
    }

    // Update the wallet's DID and attempt to verify the same VC again.
    // TODO: Figure out how to un-hack ssi crate so this works without hack.
    {
        let _updated_controlled_did = software_wallet
            .update_did(controlled_did.did(), None)
            .await
            .expect("pass");
        // Verify
        {
            let vc_verify_r = vc.verify(&verification_params).await;
            tracing::debug!("vc_verify_r: {:?}", vc_verify_r);
            assert!(vc_verify_r.is_ok());
            let vc_verify_proof_r = vc_verify_r.unwrap();
            tracing::debug!("vc_verify_proof_r: {:?}", vc_verify_proof_r);
            assert!(vc_verify_proof_r.is_ok());
        }
    }
}

#[tokio::test]
async fn test_ssi_vc_issue_0() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let wallet_store_database_path = "tests/test_ssi_vc_issue_0.wallet-store.db";

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema
    if std::fs::exists(wallet_store_database_path).expect("pass") {
        std::fs::remove_file(wallet_store_database_path).expect("pass");
    }

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(13085),
        listen_port: 13085,
        database_url: "postgres:///test_ssi_vc_issue_0_vdr".to_string(),
        database_max_connections: 10,
        vdg_base_url_v: Vec::new(),
        http_scheme_override: Default::default(),
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    // While that's spinning up, let's create the wallet.
    let wallet_storage_a = {
        // TODO: Make this into a function, since it's a lot of duplication everywhere, and requires
        // importing a bunch of crates.
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", wallet_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        let wallet_storage =
            did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await
            .expect("pass");
        Arc::new(wallet_storage)
    };

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

    test_ssi_vc_issue_0_impl(&software_wallet, &vdr_did_create_endpoint).await;

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}
