use std::{str::FromStr, sync::Arc};

use ssi_vc::v1::ToJwtClaims;

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
        .create_did(vdr_did_create_endpoint, None, None)
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
            did_webplus_resolver::DIDResolverFull::new(did_doc_store, None, None, None)
                .expect("pass");
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
    use serde::{Deserialize, Serialize};
    use ssi_claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        VerificationParameters,
    };
    use ssi_dids::DIDResolver;
    use ssi_verification_methods::SingleSecretSigner;
    use xsd_types::DateTime;

    // Have the wallet create a DID.
    let controlled_did = software_wallet
        .create_did(vdr_did_create_endpoint, None, None)
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
            did_webplus_resolver::DIDResolverFull::new(did_doc_store, None, None, None)
                .expect("pass");
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

    // Defines the shape of our custom claims.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SimpleCredentialSubject {
        #[serde(rename = "id")]
        id: String,
        #[serde(rename = "https://example.org/#name")]
        name: String,
        #[serde(rename = "https://example.org/#email")]
        email: String,
    }

    // This is the type-generic way to create a credential with custom credential subject type.
    let unsigned_credential: ssi_claims::vc::v1::SpecializedJsonCredential = {
        let now = DateTime::now();
        let mut expiration_date = now.clone();
        expiration_date.date_time += chrono::Duration::days(365);
        let credential_subject = SimpleCredentialSubject {
            id: "https://example.org/#CredentialSubjectId".to_owned(),
            name: "Grunty McParty".to_owned(),
            email: "g@mc-p.org".to_owned(),
        };
        serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": "VerifiableCredential",
            "id": "https://example.org/#CredentialId",
            // Apparently this issuer field doesn't matter for the verification process.
            // TODO: Make this the issuer DID and verify that it gets checked, or if we have to check the relationship.
            "issuer": "https://example.org/#Issuer",
            "issuanceDate": now,
            "expirationDate": expiration_date,
            "credentialSubject": serde_json::to_value(credential_subject).expect("pass")
        }))
        .expect("pass")
    };

    let vc_ldp = {
        cryptosuite
            .sign(
                unsigned_credential.clone(),
                &vm_resolver,
                &signer,
                ProofOptions::from_method(verification_method.clone()),
            )
            .await
            .expect("signature failed")
    };

    tracing::debug!("vc_ldp: {:?}", vc_ldp);
    let vc_ldp_json = serde_json::to_string(&vc_ldp).expect("pass");
    tracing::info!("vc_ldp_json (vc_ldp as JSON): {}", vc_ldp_json);

    use ssi_claims::JwsPayload;
    let vc_jwt = unsigned_credential
        .to_jwt_claims()
        .unwrap()
        .sign(&priv_jwk)
        .await
        .expect("pass");
    tracing::info!("vc_jwt: {}", vc_jwt);

    let verification_params = VerificationParameters::from_resolver(&vm_resolver);
    // Verify vc_ldp
    {
        let vc_ldp_verify_r = vc_ldp.verify(&verification_params).await;
        tracing::debug!("vc_ldp_verify_r: {:?}", vc_ldp_verify_r);
        assert!(vc_ldp_verify_r.is_ok());
        let vc_ldp_verify_proof_r = vc_ldp_verify_r.unwrap();
        tracing::debug!("vc_ldp_verify_proof_r: {:?}", vc_ldp_verify_proof_r);
        assert!(vc_ldp_verify_proof_r.is_ok());
    }
    // Verify vc_jwt
    {
        let vc_jwt_verify_r = vc_jwt.verify(&verification_params).await;
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
        // tracing::debug!("parsed_vc_ldp: {:?}", parsed_vc_ldp);
        let json_credential_or_jws =
            ssi_claims::JsonCredentialOrJws::Credential(Box::new(parsed_vc_ldp));
        let mut unsigned_presentation =
            ssi_claims::vc::v1::JsonPresentation::new(None, None, vec![json_credential_or_jws]);
        unsigned_presentation.holder =
            Some(iref::UriBuf::from_str("https://example.org/#Holder").expect("pass"));
        unsigned_presentation.id =
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass"));
        // NOTE: The VerifiablePresentation data model DOES NOT include issuanceDate, expirationDate, or audience.
        // See <https://www.w3.org/2018/credentials/v1> (this is the JSON-LD context URL for VCs and VPs).

        let proof_options = {
            let mut proof_options = ProofOptions::from_method(verification_method.clone());
            proof_options.proof_purpose = ssi_verification_methods::ProofPurpose::Authentication;
            proof_options.challenge = Some("1234567890".to_string());
            proof_options.domains.push("example.org".to_string());
            proof_options.nonce = Some("abcdefghijklmnopqrstuvwxyz".to_string());
            proof_options
        };

        let vp_ldp_of_vc_ldp = cryptosuite
            .sign(unsigned_presentation, &vm_resolver, &signer, proof_options)
            .await
            .expect("signature failed");
        tracing::debug!("vp_ldp_of_vc_ldp: {:?}", vp_ldp_of_vc_ldp);
        tracing::info!(
            "vp_ldp_of_vc_ldp as JSON: {}",
            serde_json::to_string(&vp_ldp_of_vc_ldp).expect("pass")
        );

        // Verify vp_ldp_of_vc_ldp
        {
            let vp_ldp_of_vc_ldp_verify_r = vp_ldp_of_vc_ldp.verify(&verification_params).await;
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
        let mut unsigned_presentation =
            ssi_claims::vc::v1::JsonPresentation::new(None, None, vec![json_credential_or_jws]);
        unsigned_presentation.holder =
            Some(iref::UriBuf::from_str("https://example.org/#Holder").expect("pass"));
        unsigned_presentation.id =
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass"));
        // SEE: <https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#jwt-encoding> for the JWT field mapping.
        {
            let issuance_date = DateTime::now();
            let mut expiration_date = issuance_date.clone();
            expiration_date.date_time += chrono::Duration::days(1);
            unsigned_presentation
                .additional_properties
                .insert("issuanceDate".to_string(), issuance_date.to_string().into());
            unsigned_presentation.additional_properties.insert(
                "expirationDate".to_string(),
                expiration_date.to_string().into(),
            );
            unsigned_presentation.additional_properties.insert(
                "audience".to_string(),
                "bob@lablaugh.law".to_string().into(),
            );
        }
        tracing::debug!("unsigned_presentation: {:?}", unsigned_presentation);
        tracing::debug!(
            "unsigned_presentation as JSON: {}",
            serde_json::to_string(&unsigned_presentation).expect("pass")
        );

        let vp_jwt_of_vc_ldp = unsigned_presentation
            .to_jwt_claims()
            .unwrap()
            .sign(&priv_jwk)
            .await
            .expect("signature failed");
        tracing::info!("vp_jwt_of_vc_ldp: {}", vp_jwt_of_vc_ldp);

        // Verify vp_jwt_of_vc_ldp
        {
            let vp_jwt_of_vc_ldp_verify_r = vp_jwt_of_vc_ldp.verify(&verification_params).await;
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
        let json_credential_or_jws = ssi_claims::JsonCredentialOrJws::<AnySuite>::Jws(
            ssi_jws::JwsString::try_from(vc_jwt.clone().into_string()).expect("pass"),
        );
        let mut unsigned_presentation =
            ssi_claims::vc::v1::JsonPresentation::new(None, None, vec![json_credential_or_jws]);
        unsigned_presentation.holder =
            Some(iref::UriBuf::from_str("https://example.org/#Holder").expect("pass"));
        unsigned_presentation.id =
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass"));
        // TODO: Add iat, nbf, exp (or whatever the LDP equivalent is)

        let proof_options = {
            let mut proof_options = ProofOptions::from_method(verification_method);
            proof_options.proof_purpose = ssi_verification_methods::ProofPurpose::Authentication;
            proof_options.challenge = Some("1234567890".to_string());
            proof_options.domains.push("example.org".to_string());
            proof_options.nonce = Some("abcdefghijklmnopqrstuvwxyz".to_string());
            proof_options
        };

        let vp_ldp_of_vc_jwt = cryptosuite
            .sign(unsigned_presentation, &vm_resolver, &signer, proof_options)
            .await
            .expect("signature failed");
        tracing::debug!("vp_ldp_of_vc_jwt: {:?}", vp_ldp_of_vc_jwt);
        tracing::info!(
            "vp_ldp_of_vc_jwt as JSON: {}",
            serde_json::to_string(&vp_ldp_of_vc_jwt).expect("pass")
        );

        // Verify vp_ldp_of_vc_jwt
        {
            let vp_ldp_of_vc_jwt_verify_r = vp_ldp_of_vc_jwt.verify(&verification_params).await;
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
        let json_credential_or_jws = ssi_claims::JsonCredentialOrJws::<AnySuite>::Jws(
            ssi_jws::JwsString::try_from(vc_jwt.clone().into_string()).expect("pass"),
        );
        let mut unsigned_presentation =
            ssi_claims::vc::v1::JsonPresentation::new(None, None, vec![json_credential_or_jws]);
        unsigned_presentation.holder =
            Some(iref::UriBuf::from_str("https://example.org/#Holder").expect("pass"));
        unsigned_presentation.id =
            Some(iref::UriBuf::from_str("https://example.org/#PresentationId").expect("pass"));
        // TODO: Add iat, nbf, exp.

        let vp_jwt_of_vc_jwt = unsigned_presentation
            .to_jwt_claims()
            .unwrap()
            .sign(&priv_jwk)
            .await
            .expect("signature failed");
        tracing::info!("vp_jwt_of_vc_jwt: {}", vp_jwt_of_vc_jwt);

        // Verify vp_jwt_of_vc_jwt
        {
            let vp_jwt_of_vc_jwt_verify_r = vp_jwt_of_vc_jwt.verify(&verification_params).await;
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
            .update_did(controlled_did.did(), None, None)
            .await
            .expect("pass");
        // Verify
        {
            let vc_ldp_verify_r = vc_ldp.verify(&verification_params).await;
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
