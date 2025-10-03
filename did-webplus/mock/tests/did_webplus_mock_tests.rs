use std::{
    borrow::Cow,
    collections::HashMap,
    ops::Deref,
    sync::{Arc, RwLock},
};

use did_webplus_core::{
    now_utc_milliseconds, DIDDocument, DIDDocumentMetadata, DIDKeyResourceFullyQualified,
    DIDKeyResourceFullyQualifiedStr, Error, KeyPurpose, MicroledgerMutView, MicroledgerView,
    PublicKeySet, RequestedDIDDocumentMetadata, RootLevelUpdateRules, UpdateKey,
};
use did_webplus_jws::{JWSPayloadEncoding, JWSPayloadPresence, JWS};
use did_webplus_mock::{
    Microledger, MockResolverFull, MockResolverThin, MockVDG, MockVDR, MockVDRClient,
    MockVerifiedCache, MockWallet,
};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    env_logger::init();
}

#[derive(serde::Serialize)]
struct DecodedDetachedJWS {
    header: serde_json::Value,
    payload: serde_json::Value,
    signature: String,
}

fn decode_detached_jws(jws: &JWS<'_>) -> DecodedDetachedJWS {
    let header = serde_json::to_value(jws.header()).expect("pass");
    let payload = serde_json::Value::Null;
    let signature = jws.raw_signature_base64().to_string();
    DecodedDetachedJWS {
        header,
        payload,
        signature,
    }
}

fn priv_jwk_from_ed25519_signing_key(
    ed25519_signing_key: &ed25519_dalek::SigningKey,
) -> ssi_jwk::JWK {
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    ssi_jwk::JWK::from(ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
        curve: "Ed25519".to_string(),
        public_key: ssi_jwk::Base64urlUInt(ed25519_verifying_key.to_bytes().to_vec()),
        private_key: Some(ssi_jwk::Base64urlUInt(
            ed25519_signing_key.to_bytes().to_vec(),
        )),
    }))
}

/// Resolves the DID of the signer to the appropriate DID document, then uses the appropriate public key
/// to verify the signature.  If the verification succeeds, then the resolved DID document is returned, along
/// with the metadata of the DID document.  This can be used to check other constraints pertaining to the
/// DID document, such as the KeyPurpose of the signing key or its validity time range.
fn resolve_did_and_verify_jws<'r, 'p>(
    jws: &JWS<'_>,
    resolver: &'r mut dyn did_webplus_mock::Resolver,
    verification_key_purpose: KeyPurpose,
    requested_did_document_metadata: RequestedDIDDocumentMetadata,
    detached_payload_bytes_o: Option<&'p mut dyn std::io::Read>,
) -> Result<(Cow<'r, DIDDocument>, DIDDocumentMetadata), Error> {
    let did_key_resource_fully_qualified =
        DIDKeyResourceFullyQualifiedStr::new_ref(&jws.header().kid)?;
    let did_fully_qualified = did_key_resource_fully_qualified.without_fragment();
    let did = did_fully_qualified.did();
    let key_id_fragment = did_key_resource_fully_qualified.fragment();

    log::debug!(
        "resolve_did_and_verify_jws; JWS kid field is DID query: {}",
        jws.header().kid
    );
    let (did_document, did_document_metadata) = resolver.resolve_did_document(
        did,
        Some(did_key_resource_fully_qualified.query_self_hash()),
        Some(did_key_resource_fully_qualified.query_version_id()),
        requested_did_document_metadata,
    )?;
    log::trace!("resolved DID document: {:?}", did_document);
    log::trace!(
        "resolved DID document metadata: {:?}",
        did_document_metadata
    );
    // TODO: Probably sanity-check that the DIDDocument is valid (i.e. all its DID-specific constraints are satisfied),
    // though this should be guaranteed by the resolver.  In particular, that each key_id listed in each verification
    // key purpose is present in the verification method list of the DID document.

    if !did_document
        .public_key_material
        .relative_key_resources_for_purpose(verification_key_purpose)
        .any(|relative_key_resource| relative_key_resource.fragment() == key_id_fragment)
    {
        return Err(Error::Invalid(
            "signing key is not present in specified verification method in resolved DID document",
        ));
    }

    // Retrieve the appropriate verifier from the DID document.
    let verification_method = did_document
        .public_key_material
        .verification_method_v
        .iter()
        .find(|&verification_method| verification_method.id.fragment() == key_id_fragment)
        .expect("programmer error: this key_id should be present in the verification method list; this should have been guaranteed by the resolver");
    let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk).expect("pass");
    let verifier_bytes = signature_dyn::VerifierBytes::try_from(&pub_key).expect("pass");

    // Finally, verify the signature using the resolved verifier.
    jws.verify(&verifier_bytes, detached_payload_bytes_o)
        .expect("pass");

    Ok((did_document, did_document_metadata))
}

// NOTE: This test is a rather low-level test of Microledger.  It's more complex than the one that uses MockWallet,
// but it's probably still useful to do these lower-level tests.
#[test]
#[serial_test::serial]
fn test_example_creating_and_updating_a_did() {
    println!("# Example: Creating and Updating a DID\n\nThis example can be run via command:\n\n    cargo test -p did-webplus-mock --all-features -- --nocapture test_example_creating_and_updating_a_did\n\n## Creating a DID\n");

    let update_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_pub_key_0 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_key_0.verifying_key(),
    );

    let signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_0 = signing_key_0.verifying_key();
    let pub_key_0 =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_0);

    // Create a DID and its associated Microledger
    let (mut microledger, mut priv_jwk_0) = {
        let mut priv_jwk_0 = priv_jwk_from_ed25519_signing_key(&signing_key_0);
        println!(
            "For now, let's generate a single Ed25519 key to use in all the verification methods for the DID we will create.  In JWK format, the private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_0).expect("pass")
        );
        println!("We'll also need a key that is authorized to update the DID document.  In publicKeyMultibase format, the public key is:\n\n```\n{}\n```\n", update_pub_key_0);
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: update_pub_key_0.clone(),
        });
        let mut did_document = DIDDocument::create_unsigned_root(
            "example.com",
            None,
            Some("hey"),
            update_rules,
            now_utc_milliseconds(),
            PublicKeySet {
                authentication_v: vec![&pub_key_0],
                assertion_method_v: vec![&pub_key_0],
                key_agreement_v: vec![&pub_key_0],
                capability_invocation_v: vec![&pub_key_0],
                capability_delegation_v: vec![&pub_key_0],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("pass");
        // No need to sign the root DID document, but it is allowed.
        did_document.finalize(None).expect("pass");
        did_document.verify_root_nonrecursive().expect("pass");
        let microledger = Microledger::create(did_document).expect("pass");
        let did = microledger.view().did();
        let latest_did_document = microledger.view().latest_did_document();
        println!("Creating a DID produces the root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n\nNote that the `updateRules` field is what defines update authorization for this DID document.\n", serde_json::to_string_pretty(&latest_did_document).expect("pass"));
        println!("The associated DID document metadata (at the time of DID creation) is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(&latest_did_document, RequestedDIDDocumentMetadata::all())).expect("pass"));
        // Add query params to bind this JWK to the latest DID doc.
        // Add (key ID) fragment to identify which key it is.
        let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
            .with_queries(
                &latest_did_document.self_hash,
                latest_did_document.version_id,
            )
            // TODO: Retrieve this fragment from the key itself, not just a hardcoded string.
            .with_fragment("0");
        priv_jwk_0.key_id = Some(did_key_resource_fully_qualified.to_string());
        println!("We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"));
        (microledger, priv_jwk_0)
    };

    let update_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_pub_key_1 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_key_1.verifying_key(),
    );

    let signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_1 = signing_key_1.verifying_key();
    let pub_key_1 =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_1);

    println!("## Updating the DID\n");
    // Update the Microledger.
    let mut priv_jwk_1 = {
        let mut priv_jwk_1 = priv_jwk_from_ed25519_signing_key(&signing_key_1);
        println!(
            "Let's generate another key to rotate in for some verification methods.  In JWK format, the new private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_1).expect("pass")
        );
        println!("A new update key is also needed.  In publicKeyMultibase format, the new public key is:\n\n```\n{}\n```\n", update_pub_key_1);

        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: update_pub_key_1.clone(),
        });
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            microledger.view().latest_did_document(),
            update_rules,
            now_utc_milliseconds(),
            PublicKeySet {
                authentication_v: vec![&pub_key_0, &pub_key_1],
                assertion_method_v: vec![&pub_key_0],
                key_agreement_v: vec![&pub_key_0],
                capability_invocation_v: vec![&pub_key_1],
                capability_delegation_v: vec![&pub_key_0],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("pass");
        // Sign the updated DID document.
        let jws = new_did_document
            .sign(update_pub_key_0.to_string(), &update_key_0)
            .expect("pass");
        // Add the proof to the DID document.
        new_did_document.add_proof(jws.as_str().to_string());
        // Finalize the updated DID document.
        new_did_document
            .finalize(Some(microledger.view().latest_did_document()))
            .expect("pass");
        new_did_document
            .verify_non_root_nonrecursive(microledger.view().latest_did_document())
            .expect("pass");
        microledger
            .mut_view()
            .update(new_did_document)
            .expect("pass");
        let did = microledger.view().did();

        let latest_did_document = microledger.view().latest_did_document();
        println!("Updating a DID produces the next DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n\nNote that the `proofs` field contains signatures (in JWS format) that are to be validated and used with the `updateRules` field of the previous DID document to verify update authorization.  Note that the JWS proof has a detached payload, and decodes as:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&latest_did_document).expect("pass"), serde_json::to_string_pretty(&decode_detached_jws(&jws)).expect("pass"));
        println!("The associated DID document metadata (at the time of DID update) is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(&latest_did_document, RequestedDIDDocumentMetadata::all())).expect("pass"));
        println!("However, the DID document metadata associated with the root DID document has now become:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(microledger.view().root_did_document(), RequestedDIDDocumentMetadata::all())).expect("pass"));
        {
            let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
                .with_queries(
                    &latest_did_document.self_hash,
                    latest_did_document.version_id,
                )
                // NOTE: This is hardcoded, and depends on the order the keys were added to the DID document.
                .with_fragment("0");
            priv_jwk_0.key_id = Some(did_key_resource_fully_qualified.to_string());
        }
        {
            let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
                .with_queries(
                    &latest_did_document.self_hash,
                    latest_did_document.version_id,
                )
                // TODO: Retrieve this fragment from the key itself, not just a hardcoded string.
                .with_fragment("1");
            priv_jwk_1.key_id = Some(did_key_resource_fully_qualified.to_string());
        }
        println!("We set the `kid` field of each private JWK to point to the current DID document:\n\n```json\n{}\n```\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"), serde_json::to_string_pretty(&priv_jwk_1).expect("pass"));
        priv_jwk_1
    };

    let update_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_pub_key_2 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_key_2.verifying_key(),
    );

    let signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_2 = signing_key_2.verifying_key();
    let pub_key_2 =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_2);

    println!("## Updating the DID Again\n");
    // Update the Microledger.
    let _priv_jwk_2 = {
        let mut priv_jwk_2 = priv_jwk_from_ed25519_signing_key(&signing_key_2);
        println!(
            "Let's generate a third key to rotate in for some verification methods.  In JWK format, the new private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_2).expect("pass")
        );
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: update_pub_key_2.clone(),
        });
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            microledger.view().latest_did_document(),
            update_rules,
            now_utc_milliseconds(),
            PublicKeySet {
                authentication_v: vec![&pub_key_0, &pub_key_1],
                assertion_method_v: vec![&pub_key_0],
                key_agreement_v: vec![&pub_key_2],
                capability_invocation_v: vec![&pub_key_2],
                capability_delegation_v: vec![&pub_key_0],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("pass");
        let jws = new_did_document
            .sign(update_pub_key_1.to_string(), &update_key_1)
            .expect("pass");
        new_did_document.add_proof(jws.as_str().to_string());
        new_did_document
            .finalize(Some(microledger.view().latest_did_document()))
            .expect("pass");
        new_did_document
            .verify_non_root_nonrecursive(microledger.view().latest_did_document())
            .expect("pass");
        microledger
            .mut_view()
            .update(new_did_document)
            .expect("pass");
        let did = microledger.view().did();
        let latest_did_document = microledger.view().latest_did_document();
        println!("Updated DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n\nNote that the `proofs` field contains signatures (in JWS format) that are to be validated and used with the `updateRules` field of the previous DID document to verify update authorization.  Note that the JWS proof has a detached payload, and decodes as:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&latest_did_document).expect("pass"), serde_json::to_string_pretty(&decode_detached_jws(&jws)).expect("pass"));
        println!("The associated DID document metadata (at the time of DID update) is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(&latest_did_document, RequestedDIDDocumentMetadata::all())).expect("pass"));
        println!("Similarly, the DID document metadata associated with the previous DID document has now become:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(microledger.view().did_document_for_version_id(1).expect("pass"), RequestedDIDDocumentMetadata::all())).expect("pass"));
        println!("However, the DID document metadata associated with the root DID document has now become:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(microledger.view().root_did_document(), RequestedDIDDocumentMetadata::all())).expect("pass"));
        {
            let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
                .with_queries(
                    &latest_did_document.self_hash,
                    latest_did_document.version_id,
                )
                // TODO: Retrieve this fragment from the key itself, not just a hardcoded string.
                .with_fragment("0");
            priv_jwk_0.key_id = Some(did_key_resource_fully_qualified.to_string());
        }
        {
            let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
                .with_queries(
                    &latest_did_document.self_hash,
                    latest_did_document.version_id,
                )
                // TODO: Retrieve this fragment from the key itself, not just a hardcoded string.
                .with_fragment("1");
            priv_jwk_1.key_id = Some(did_key_resource_fully_qualified.to_string());
        }
        {
            let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
                .with_queries(
                    &latest_did_document.self_hash,
                    latest_did_document.version_id,
                )
                // TODO: Retrieve this fragment from the key itself, not just a hardcoded string.
                .with_fragment("2");
            priv_jwk_2.key_id = Some(did_key_resource_fully_qualified.to_string());
        }
        println!("We set the `kid` field of each private JWK to point to the current DID document:\n\n```json\n{}\n```\n\n```json\n{}\n```\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"), serde_json::to_string_pretty(&priv_jwk_1).expect("pass"), serde_json::to_string_pretty(&priv_jwk_2).expect("pass"));
        priv_jwk_2
    };
}

#[test]
#[serial_test::serial]
fn test_did_operations() {
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_hostname(
        "example.com".into(),
        None,
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert("example.com".to_string(), mock_vdr_la.clone());
        mock_vdr_lam
    };
    let mock_vdg_la = Arc::new(RwLock::new(MockVDG::new(
        "mock.vdg.org".into(),
        mock_vdr_lam.clone(),
        None,
    )));
    let mock_vdr_client_a = Arc::new(MockVDRClient::new(
        "Alice's MockVDRClient".to_string(),
        mock_vdr_lam.clone(),
    ));
    let mut mock_verified_cache = MockVerifiedCache::empty("MockVerifiedCache".to_string());
    println!("----------------------------------------------------");
    println!("-- Wallet creation ---------------------------------");
    println!("----------------------------------------------------");
    let mut alice_wallet = MockWallet::new("Alice's Wallet".to_string(), mock_vdr_client_a.clone());
    let alice_did = alice_wallet
        .create_did("example.com".to_string(), None, Some("user".to_string()))
        .expect("pass");

    // This Resolver keeps its own local MockVerifiedCache, and talks to the VDRs directly.
    let mut mock_resolver_full = MockResolverFull::new(
        "Bob's Resolver".to_string(),
        // Some(mock_vdg_la.clone()),
        None,
        mock_vdr_lam.clone(),
    );

    // This MockResolverThin doesn't keep a local MockVerifiedCache, and instead uses a VDG to do its resolution.
    let mut mock_resolver_thin = MockResolverThin::new(
        "Charlie's MockResolverThin".to_string(),
        mock_vdg_la.clone(),
    );

    // Sign and verify a JWS.
    {
        let message = "This Alice is the best Alice.";
        let (signer_bytes, kid) = alice_wallet
            .controlled_did(&alice_did)
            .expect("pass")
            .signer_and_key_id_for_key_purpose(KeyPurpose::Authentication);
        let jws = JWS::signed(
            kid.to_string(),
            &mut message.as_bytes(),
            JWSPayloadPresence::Attached,
            JWSPayloadEncoding::Base64,
            signer_bytes,
        )
        .expect("pass");

        // Directly verify the JWS
        use signature_dyn::SignerDynT;
        let verifier_bytes = signer_bytes.verifier_bytes().expect("pass");
        jws.verify(&verifier_bytes, None).expect("pass");

        let jws_signing_time = now_utc_milliseconds();
        println!("jws_string: {}", jws);

        // Type-forget the JWS, so that it has to go through the whole code path from String.
        let jws_string = jws.into_string();

        let jws = JWS::try_from(jws_string).expect("pass");

        // Verify the JWS using the full resolver.
        let (did_document, did_document_metadata) = resolve_did_and_verify_jws(
            &jws,
            &mut mock_resolver_full,
            did_webplus_core::KeyPurpose::Authentication,
            did_webplus_core::RequestedDIDDocumentMetadata::all(),
            None,
        )
        .expect("pass");

        // Also resolve using mock_resolver_thin.
        let (did_document_2, did_document_metadata_2) = resolve_did_and_verify_jws(
            &jws,
            &mut mock_resolver_thin,
            did_webplus_core::KeyPurpose::Authentication,
            did_webplus_core::RequestedDIDDocumentMetadata::all(),
            None,
        )
        .expect("pass");

        assert_eq!(did_document, did_document_2);
        assert_eq!(did_document_metadata, did_document_metadata_2);
        assert!(did_document_metadata.idempotent_o.is_some());
        let did_document_metadata_idempotent = did_document_metadata.idempotent_o.as_ref().unwrap();

        assert!(did_document.valid_from <= jws_signing_time);
        match did_document_metadata_idempotent.next_update_o.as_ref() {
            Some(&next_update) => {
                assert!(jws_signing_time < next_update);
            }
            None => {
                // Nothing to check, this DID document is the latest.
            }
        }
    }

    // Do some resolutions.
    println!("-- Let's do some DID resolutions ---------------------------------");
    let mut mock_resolver_full = MockResolverFull::new(
        "MockVerifiedCache's MockResolverFull".to_string(),
        // No VDG, only VDRs.
        None,
        mock_vdr_lam.clone(),
    );
    {
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve_did_document(
                &alice_did,
                None,
                None,
                RequestedDIDDocumentMetadata::all(),
                &mut mock_resolver_full,
            )
            .expect("pass");
        // This Cow::into_owned is necessary here to release the mutable borrow of mock_verified_cache.
        let did_document = did_document.into_owned();
        println!(
            "LATEST (which is root) did_document: {}",
            serde_json::to_string_pretty(&did_document).expect("pass")
        );
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        // Do a resolution against specific query params
        if false {
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve_did_document(
                        &alice_did,
                        Some(0),
                        None,
                        RequestedDIDDocumentMetadata::all(),
                        &mut mock_resolver_full,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve_did_document(
                        &alice_did,
                        None,
                        Some(did_document.self_hash.deref()),
                        RequestedDIDDocumentMetadata::all(),
                        &mut mock_resolver_full,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) =
            // Both query params
            mock_verified_cache
                .resolve_did_document(&alice_did, Some(0), Some(did_document.self_hash.deref()), RequestedDIDDocumentMetadata::all(), &mut mock_resolver_full)
                .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
        }
    }

    println!("----------------------------------------------------");
    println!("-- Wallet updates its DID (first update) -----------");
    println!("----------------------------------------------------");
    alice_wallet.update_did(&alice_did).expect("pass");

    // Do some resolutions.
    println!("-- Let's do some more resolutions ---------------------------------");
    {
        println!("-- First, we'll resolve the root DID document -----------------");
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve_did_document(
                &alice_did,
                Some(0),
                None,
                RequestedDIDDocumentMetadata::all(),
                &mut mock_resolver_full,
            )
            .expect("pass");
        println!(
            "ROOT did_document: {}",
            serde_json::to_string_pretty(&did_document).expect("pass")
        );
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        println!("-- Now, we'll resolve the latest DID document -----------------");
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve_did_document(
                &alice_did,
                None,
                None,
                RequestedDIDDocumentMetadata::all(),
                &mut mock_resolver_full,
            )
            .expect("pass");
        println!(
            "LATEST did_document: {}",
            serde_json::to_string_pretty(&did_document).expect("pass")
        );
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        println!("-- Finally, we'll resolve the latest DID document again -------");
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve_did_document(
                &alice_did,
                None,
                None,
                RequestedDIDDocumentMetadata::all(),
                &mut mock_resolver_full,
            )
            .expect("pass");
        // This Cow::into_owned is necessary here to release the mutable borrow of mock_verified_cache.
        let did_document = did_document.into_owned();
        println!(
            "LATEST did_document: {}",
            serde_json::to_string_pretty(&did_document).expect("pass")
        );
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        // Do a resolution against specific query params
        if false {
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve_did_document(
                        &alice_did,
                        Some(did_document.version_id),
                        None,
                        RequestedDIDDocumentMetadata::all(),
                        &mut mock_resolver_full,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve_did_document(
                        &alice_did,
                        None,
                        Some(did_document.self_hash.deref()),
                        RequestedDIDDocumentMetadata::all(),
                        &mut mock_resolver_full,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) =
            // Both query params
            mock_verified_cache
                .resolve_did_document(&alice_did, Some(did_document.version_id), Some(did_document.self_hash.deref()), RequestedDIDDocumentMetadata::all(), &mut mock_resolver_full)
                .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
        }
    }
}
