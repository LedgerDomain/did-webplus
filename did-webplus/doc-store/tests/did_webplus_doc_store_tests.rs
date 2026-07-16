use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus_core::DIDDocument;
use did_webplus_doc_store::{DIDDocStorage, DIDDocStore, Error};
use did_webplus_mock::{MicroledgerView, MockVDR, MockVDRClient, MockWallet};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

/// Build a valid create → update → deactivate microledger via MockWallet / MockVDR, returning
/// owned DID documents and their JCS serializations.
fn build_valid_create_update_deactivate_microledger() -> (Vec<DIDDocument>, Vec<String>) {
    let hostname = "example.com".to_string();
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with(
        hostname.clone(),
        None,
        None,
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert(hostname.clone(), mock_vdr_la);
        mock_vdr_lam
    };
    let mock_vdr_client_a = Arc::new(MockVDRClient::new(
        "doc-store test MockVDRClient".to_string(),
        mock_vdr_lam,
    ));
    let mut wallet = MockWallet::new("doc-store test wallet".to_string(), mock_vdr_client_a);

    let key_type = signature_dyn::KeyType::Ed25519;
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);

    let did = wallet
        .create_did(hostname, None, None, key_type, &mb_hash_function)
        .expect("pass");
    wallet.update_did(&did, key_type).expect("pass");
    wallet.deactivate_did(&did).expect("pass");

    let did_document_v: Vec<DIDDocument> = wallet
        .controlled_did(&did)
        .expect("pass")
        .microledger()
        .view()
        .select_did_documents(None, None)
        .1
        .cloned()
        .collect();
    assert_eq!(
        did_document_v.len(),
        3,
        "expected create/update/deactivate microledger of height 3"
    );

    let did_document_jcs_v: Vec<String> = did_document_v
        .iter()
        .map(|did_document| did_document.serialize_canonically().expect("pass"))
        .collect();

    (did_document_v, did_document_jcs_v)
}

/// Mutate the signature portion of a detached JWS proof, keeping it syntactically base64url.
fn mutate_detached_jws_signature(proof: &str) -> String {
    let parts: Vec<&str> = proof.splitn(3, '.').collect();
    assert_eq!(
        parts.len(),
        3,
        "expected detached JWS with three '.'-separated parts"
    );
    let signature = parts[2];
    assert!(
        !signature.is_empty(),
        "expected non-empty JWS signature part"
    );
    let mut signature_bytes = signature.as_bytes().to_vec();
    let last = signature_bytes.last_mut().expect("non-empty signature");
    *last = match *last {
        b'A' => b'B',
        _ => b'A',
    };
    format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        std::str::from_utf8(&signature_bytes).expect("pass")
    )
}

/// Copy of a valid microledger with the middle document's proof signature corrupted.
/// Recomputes the middle document's self-hash so validation fails on proof/update-rules
/// checks rather than on a trivial self-hash mismatch from the mutation alone.
fn invalid_microledger_with_mutated_middle_proof(
    valid_did_document_v: &[DIDDocument],
) -> (Vec<DIDDocument>, Vec<String>) {
    assert_eq!(valid_did_document_v.len(), 3);
    let mut invalid_did_document_v = valid_did_document_v.to_vec();
    {
        let middle = &mut invalid_did_document_v[1];
        assert!(
            !middle.proof_v.is_empty(),
            "middle (update) DID document must have a proof"
        );
        middle.proof_v[0] = mutate_detached_jws_signature(&middle.proof_v[0]);

        use selfhash::{HashFunctionT, HashRefT, SelfHashableT};
        let mb_hash_function = middle.self_hash.hash_function();
        let hasher = mb_hash_function.new_hasher();
        middle.self_hash(hasher).expect("pass");
    }

    let invalid_did_document_jcs_v: Vec<String> = invalid_did_document_v
        .iter()
        .map(|did_document| did_document.serialize_canonically().expect("pass"))
        .collect();

    (invalid_did_document_v, invalid_did_document_jcs_v)
}

async fn test_doc_store_validate_and_add_did_docs_impl(
    did_doc_storage_a: Arc<dyn DIDDocStorage>,
) {
    let did_doc_store = DIDDocStore::new(did_doc_storage_a);

    let (valid_did_document_v, valid_did_document_jcs_v) =
        build_valid_create_update_deactivate_microledger();
    let valid_did_document_jcs_ref_v: Vec<&str> = valid_did_document_jcs_v
        .iter()
        .map(String::as_str)
        .collect();

    // Positive: valid create/update/deactivate microledger is accepted.
    did_doc_store
        .validate_and_add_did_docs(
            None,
            &valid_did_document_jcs_ref_v,
            &valid_did_document_v,
            None,
        )
        .await
        .expect("valid create/update/deactivate microledger should be accepted");

    // Negative: mutated middle-document proof must return InvalidDIDDocument (not panic).
    let (invalid_did_document_v, invalid_did_document_jcs_v) =
        invalid_microledger_with_mutated_middle_proof(&valid_did_document_v);
    let invalid_did_document_jcs_ref_v: Vec<&str> = invalid_did_document_jcs_v
        .iter()
        .map(String::as_str)
        .collect();

    let result = did_doc_store
        .validate_and_add_did_docs(
            None,
            &invalid_did_document_jcs_ref_v,
            &invalid_did_document_v,
            None,
        )
        .await;
    assert!(
        matches!(result, Err(Error::InvalidDIDDocument(_))),
        "expected Err(InvalidDIDDocument), got: {:?}",
        result
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_doc_store_validate_and_add_did_docs_with_storage_mock() {
    let did_doc_storage = did_webplus_doc_storage_mock::DIDDocStorageMock::new();
    test_doc_store_validate_and_add_did_docs_impl(Arc::new(did_doc_storage)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_doc_store_validate_and_add_did_docs_with_storage_sqlite() {
    let did_doc_store_database_path = "tests/test_doc_store_validate_and_add_did_docs.db";
    if std::fs::exists(did_doc_store_database_path).expect("pass") {
        std::fs::remove_file(did_doc_store_database_path).expect("pass");
    }
    let db_url = format!("sqlite://{}?mode=rwc", did_doc_store_database_path);
    let did_doc_storage =
        did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_url_and_run_migrations(
            db_url.as_str(),
            None,
        )
        .await
        .expect("pass");
    test_doc_store_validate_and_add_did_docs_impl(Arc::new(did_doc_storage)).await;
}
