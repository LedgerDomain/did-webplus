use std::sync::Arc;

use did_webplus_core::DIDDocument;
use did_webplus_doc_storage_mock::DIDDocStorageMock;
use did_webplus_doc_store::DIDDocStore;
use did_webplus_mock::MicroledgerView;
use did_webplus_test_vector_lib::{
    Catalog, DEFAULT_SEED, DeterministicRng, ErrorCode, Expected, MicroledgerBuilder,
    RawDidDocument, StressConfig, StructuredMutation, TestVector, TestVectorMetadata,
    TestVectorParams,
};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

const FUZZ_LITE_COUNT: u32 = 16;

fn generate_catalog(seed: &str) -> anyhow::Result<Vec<TestVector>> {
    let params = TestVectorParams::baseline("example.com");
    let mut vector_v = Catalog::generate_conformance(&params, seed)?;
    vector_v.extend(Catalog::generate_coverage_matrix(&params, seed)?);
    vector_v.extend(Catalog::generate_jsonl_structural(&params, seed)?);
    vector_v.extend(Catalog::generate_resolution(&params, seed)?);

    // Exercise every stress-vector shape without making the integration test
    // validate the default 100- and 1,000-version histories.
    vector_v.extend(Catalog::generate_stress(
        &params,
        seed,
        &StressConfig::for_tests(),
    )?);
    vector_v.extend(Catalog::generate_fuzz_lite(&params, seed, FUZZ_LITE_COUNT)?);
    Ok(vector_v)
}

async fn accepted_did_document_count(vector: &TestVector) -> (usize, Option<String>) {
    let store = DIDDocStore::new(Arc::new(DIDDocStorageMock::new()));
    let mut previous_o: Option<DIDDocument> = None;

    for (index, line) in vector.jsonl_line_v.iter().enumerate() {
        let document = match did_webplus_doc_store::parse_did_document(line) {
            Ok(document) => document,
            Err(error) => return (index, Some(format!("parse error: {error}"))),
        };
        let result = store
            .validate_and_add_did_docs(
                None,
                &[line.as_str()],
                std::slice::from_ref(&document),
                previous_o.as_ref(),
            )
            .await;
        match result {
            Ok(()) => previous_o = Some(document),
            Err(error) => return (index, Some(format!("validation error: {error}"))),
        }
    }

    (vector.jsonl_line_v.len(), None)
}

#[tokio::test]
async fn every_catalog_vector_matches_reference_implementation() {
    let vector_v = generate_catalog(DEFAULT_SEED).expect("the self-check catalog should generate");
    let mut failure_v = Vec::new();

    for vector in vector_v {
        tracing::debug!("checking test vector: {}", vector.name);
        if vector.expected.did_document_count as usize != vector.jsonl_line_v.len() {
            failure_v.push(format!(
                "{}: metadata declares {} documents but contains {} lines",
                vector.name,
                vector.expected.did_document_count,
                vector.jsonl_line_v.len()
            ));
            continue;
        }

        if vector.category == "resolution" {
            if let Some(failure) = check_resolution_vector(&vector).await {
                failure_v.push(failure);
            }
            continue;
        }

        let (accepted, rejection_o) = accepted_did_document_count(&vector).await;
        let expected = vector.expected.valid_did_document_count as usize;
        if accepted != expected {
            failure_v.push(format!(
                "{}: expected acceptance of exactly {expected} documents, accepted {accepted}; {}",
                vector.name,
                rejection_o.as_deref().unwrap_or("no rejection occurred")
            ));
        } else if expected < vector.jsonl_line_v.len() && rejection_o.is_none() {
            failure_v.push(format!(
                "{}: expected rejection at document {expected}, but no rejection occurred",
                vector.name
            ));
        }
    }

    assert!(
        failure_v.is_empty(),
        "{} self-check failure(s):\n{}",
        failure_v.len(),
        failure_v.join("\n")
    );
}

/// Resolution vectors: body must fully validate; `TestVector.did` is the mismatched
/// resolution DID and must disagree with the content DID along the declared dimension.
async fn check_resolution_vector(vector: &TestVector) -> Option<String> {
    let (accepted, rejection_o) = accepted_did_document_count(vector).await;
    if accepted != vector.jsonl_line_v.len() {
        return Some(format!(
            "{}: resolution body must fully validate, accepted {accepted}/{}; {}",
            vector.name,
            vector.jsonl_line_v.len(),
            rejection_o.as_deref().unwrap_or("no rejection occurred")
        ));
    }
    if vector.expected.valid_did_document_count != 0 || vector.expected.is_fully_valid() {
        return Some(format!(
            "{}: resolution vectors must expect rejection relative to the resolution DID",
            vector.name
        ));
    }

    let content_did = match did_webplus_doc_store::parse_did_document(&vector.jsonl_line_v[0]) {
        Ok(document) => document.did,
        Err(error) => {
            return Some(format!("{}: failed to parse root document: {error}", vector.name));
        }
    };
    if content_did == vector.did {
        return Some(format!(
            "{}: content DID unexpectedly equals resolution DID {}",
            vector.name, vector.did
        ));
    }

    match vector.expected.error_code_o {
        Some(ErrorCode::ResolutionRootSelfHashMismatch) => {
            if content_did.hostname() != vector.did.hostname()
                || content_did.path_o() != vector.did.path_o()
                || content_did.root_self_hash() == vector.did.root_self_hash()
            {
                return Some(format!(
                    "{}: expected host+path match with differing root self-hash",
                    vector.name
                ));
            }
        }
        Some(ErrorCode::ResolutionPathMismatch) => {
            if content_did.hostname() != vector.did.hostname()
                || content_did.root_self_hash() != vector.did.root_self_hash()
                || content_did.path_o() == vector.did.path_o()
            {
                return Some(format!(
                    "{}: expected host+root-self-hash match with differing path",
                    vector.name
                ));
            }
        }
        Some(ErrorCode::ResolutionHostMismatch) => {
            if content_did.path_o() != vector.did.path_o()
                || content_did.root_self_hash() != vector.did.root_self_hash()
                || content_did.hostname() == vector.did.hostname()
            {
                return Some(format!(
                    "{}: expected path+root-self-hash match with differing host",
                    vector.name
                ));
            }
        }
        Some(ErrorCode::ResolutionPortMismatch) => {
            if content_did.hostname() != vector.did.hostname()
                || content_did.path_o() != vector.did.path_o()
                || content_did.root_self_hash() != vector.did.root_self_hash()
                || content_did.port_o().is_none()
                || content_did.port_o() == vector.did.port_o()
            {
                return Some(format!(
                    "{}: expected host+path+root-self-hash match with differing ports (content must have a port)",
                    vector.name
                ));
            }
        }
        other => {
            return Some(format!(
                "{}: unexpected resolution error code {other:?}",
                vector.name
            ));
        }
    }
    None
}

#[test]
fn generation_is_byte_identical_for_the_same_seed() {
    let first_v = generate_catalog(DEFAULT_SEED).expect("the first catalog should generate");
    let second_v = generate_catalog(DEFAULT_SEED).expect("the second catalog should generate");
    let first_bytes = serde_json::to_vec(&first_v).expect("the first catalog should serialize");
    let second_bytes = serde_json::to_vec(&second_v).expect("the second catalog should serialize");

    assert_eq!(first_bytes, second_bytes);
}

/// Every [`StructuredMutation`] must reject at the predicted document index against
/// the reference `DIDDocStore` validator (covers mutations not yet wired into the
/// conformance catalog).
#[tokio::test]
async fn every_structured_mutation_rejects_at_expected_document() {
    let params = TestVectorParams::baseline("example.com");
    let mut failure_v = Vec::new();

    for (index, &mutation) in StructuredMutation::ALL.iter().enumerate() {
        let name = format!("mutation-self-check-{index:04}-{}", mutation.as_str());
        let vector = match generate_structured_mutation_vector(params.clone(), &name, mutation) {
            Ok(vector) => vector,
            Err(error) => {
                failure_v.push(format!("{name}: generation failed: {error:#}"));
                continue;
            }
        };

        let (accepted, rejection_o) = accepted_did_document_count(&vector).await;
        let expected = vector.expected.valid_did_document_count as usize;
        if accepted != expected {
            failure_v.push(format!(
                "{name}: expected acceptance of exactly {expected} documents, accepted {accepted}; {}",
                rejection_o.as_deref().unwrap_or("no rejection occurred")
            ));
        } else if expected < vector.jsonl_line_v.len() && rejection_o.is_none() {
            failure_v.push(format!(
                "{name}: expected rejection at document {expected}, but no rejection occurred"
            ));
        }
    }

    assert!(
        failure_v.is_empty(),
        "{} structured-mutation self-check failure(s):\n{}",
        failure_v.len(),
        failure_v.join("\n")
    );
}

fn generate_structured_mutation_vector(
    params: TestVectorParams,
    name: &str,
    mutation: StructuredMutation,
) -> anyhow::Result<TestVector> {
    let update_count = mutation.update_count();
    let rng = DeterministicRng::for_vector("mutation-self-check", name);
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, update_count)?;
    let mut did = builder.did().clone();
    let mut line_v = builder.canonical_jsonl_lines()?;
    let target_index = update_count as usize;

    let document = builder
        .microledger()
        .view()
        .select_did_documents(Some(target_index as u32), Some(target_index as u32))
        .1
        .next()
        .ok_or_else(|| anyhow::anyhow!("baseline document is missing for {mutation}"))?;
    let mut raw = RawDidDocument::from_did_document(document)?;
    if mutation.apply(&mut raw, &params)? {
        raw.re_self_hash()?;
        // Root re-self-hash updates the DID suffix; keep TestVector.did aligned.
        if target_index == 0 {
            did = raw.did()?;
        }
    }
    line_v[target_index] = mutation.emit_line(&raw)?;

    let count = line_v.len() as u32;
    let error_code = RawDidDocument::predicted_error_code(mutation);
    let expected =
        Expected::reject_after(count, target_index as u32, error_code, target_index as u32);

    Ok(TestVector {
        name: name.to_owned(),
        category: "mutation-self-check".to_owned(),
        description: format!("Structured mutation self-check: {}.", mutation.as_str()),
        spec_ref_v: vec![],
        jsonl_line_v: line_v,
        did,
        expected,
        params,
    })
}

/// Fuzz-lite names are `fuzz-lite-<seed_hex>-{index:05}`; metadata keeps the original seed.
#[test]
fn fuzz_lite_names_and_generator_seed_round_trip() {
    let params = TestVectorParams::baseline("example.com");
    let expected_name_v = Catalog::fuzz_lite_vector_names(DEFAULT_SEED, FUZZ_LITE_COUNT);
    let vector_v = Catalog::generate_fuzz_lite(&params, DEFAULT_SEED, FUZZ_LITE_COUNT)
        .expect("fuzz-lite generation");
    assert_eq!(vector_v.len(), expected_name_v.len());
    for (vector, expected_name) in vector_v.iter().zip(expected_name_v.iter()) {
        assert_eq!(&vector.name, expected_name);
        assert_eq!(vector.category, "fuzz-lite");
        let metadata = TestVectorMetadata::from_test_vector(vector, DEFAULT_SEED);
        assert_eq!(metadata.generator.seed, DEFAULT_SEED);
        metadata
            .validate_fuzz_lite_seed()
            .expect("generator.seed must match seed hex embedded in the vector name");
    }
}
