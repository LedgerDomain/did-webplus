use did_webplus_mock::MicroledgerView;
use rand_core::Rng;

use crate::{
    DeterministicRng, Expected, MicroledgerBuilder, MutationTarget, RawDidDocument,
    StructuredMutation, TestVector, TestVectorParams,
};

const CATEGORY: &str = "fuzz-lite";
const NAME_PREFIX: &str = "fuzz-lite-";
const VALIDATION_REF: &str = "#validation-of-did-documents";

/// Derive seed-qualified vector names without generating cryptographic material.
///
/// Public surface: [`crate::Catalog::fuzz_lite_vector_names`]. Format
/// `fuzz-lite-<seed_hex>-{index:05}` with full lowercase hex of `seed` UTF-8.
pub(crate) fn vector_names(seed: &str, count: u32) -> Vec<String> {
    let seed_hex = encode_seed(seed);
    (0..count)
        .map(|index| format!("{NAME_PREFIX}{seed_hex}-{index:05}"))
        .collect()
}

fn encode_seed(seed: &str) -> String {
    seed.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn seed_from_vector_name(name: &str) -> anyhow::Result<String> {
    let qualified_name = name
        .strip_prefix(NAME_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("fuzz-lite name must start with {NAME_PREFIX}: {name}"))?;
    let (seed_hex, index) = qualified_name.rsplit_once('-').ok_or_else(|| {
        anyhow::anyhow!("fuzz-lite name must end with a five-digit index: {name}")
    })?;
    anyhow::ensure!(
        index.len() == 5 && index.bytes().all(|byte| byte.is_ascii_digit()),
        "fuzz-lite name must end with a five-digit index: {name}"
    );
    anyhow::ensure!(
        seed_hex.len() % 2 == 0
            && seed_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "fuzz-lite name seed must be full lowercase hex: {name}"
    );

    let seed_byte_v = seed_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("validated ASCII hex");
            u8::from_str_radix(pair, 16).expect("validated hex digits")
        })
        .collect();
    String::from_utf8(seed_byte_v)
        .map_err(|_| anyhow::anyhow!("fuzz-lite name seed is not valid UTF-8: {name}"))
}

/// Generate `count` fuzz-lite vector_v from `seed` alone (plus shared `params`).
///
/// Each vector starts from a seeded valid microledger, applies exactly one
/// [`StructuredMutation`] chosen deterministically from the per-vector RNG, and
/// records [`Expected`] via [`RawDidDocument::predicted_error_code`]. Names are
/// `fuzz-lite-<seed_hex>-{index:05}`; the RNG is
/// `DeterministicRng::for_vector("", name)` (seed already in the name — no
/// double-hashing). Re-running with the same `(seed, count, params)` yields
/// identical vectors.
pub(crate) fn generate(
    params: &TestVectorParams,
    seed: &str,
    count: u32,
) -> anyhow::Result<Vec<TestVector>> {
    anyhow::ensure!(
        !StructuredMutation::ALL.is_empty(),
        "structured mutation table must be non-empty"
    );
    let mut vector_v = Vec::with_capacity(count as usize);
    for name in vector_names(seed, count) {
        // The full UTF-8 seed is already encoded in `name`; bind the RNG only to
        // that final identity so the seed is not incorporated twice.
        let mut rng = DeterministicRng::for_vector("", &name);
        let mutation_index = (rng.rng_mut().next_u32() as usize) % StructuredMutation::ALL.len();
        let mutation = StructuredMutation::ALL[mutation_index];
        vector_v.push(generate_one(params.clone(), rng, name, mutation)?);
    }
    Ok(vector_v)
}

fn generate_one(
    params: TestVectorParams,
    rng: DeterministicRng,
    name: String,
    mutation: StructuredMutation,
) -> anyhow::Result<TestVector> {
    let update_count = mutation.update_count();
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
    let expected = Expected::reject_after(count, target_index as u32, error_code, update_count);

    debug_assert_eq!(
        mutation.target(),
        match update_count {
            0 => MutationTarget::Root,
            1 => MutationTarget::NonRoot,
            2 => MutationTarget::NonRootSecond,
            _ => unreachable!(),
        }
    );

    Ok(TestVector {
        name,
        category: CATEGORY.to_owned(),
        description: format!(
            "Fuzz-lite single-field structured mutation: {}.",
            mutation.as_str()
        ),
        spec_ref_v: vec![VALIDATION_REF.to_owned()],
        jsonl_line_v: line_v,
        did,
        expected,
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Catalog, TestVectorMetadata};

    #[test]
    fn generate_is_deterministic_from_seed_and_count() {
        let params = TestVectorParams::baseline("example.com");
        let first_v = Catalog::generate_fuzz_lite(&params, "fuzz-seed", 8).unwrap();
        let second_v = Catalog::generate_fuzz_lite(&params, "fuzz-seed", 8).unwrap();
        assert_eq!(first_v, second_v);
        assert_eq!(first_v.len(), 8);
        for (index, vector) in first_v.iter().enumerate() {
            assert_eq!(
                vector.name,
                format!("fuzz-lite-66757a7a2d73656564-{index:05}")
            );
            assert_eq!(vector.category, CATEGORY);
            assert!(!vector.expected.is_fully_valid());
            assert_eq!(
                vector.expected.did_document_count as usize,
                vector.jsonl_line_v.len()
            );
            assert!(vector.expected.error_code_o.is_some());
            let metadata = TestVectorMetadata::from_test_vector(vector, "fuzz-seed");
            assert_eq!(metadata.generator.seed, "fuzz-seed");
            metadata.validate_fuzz_lite_seed().unwrap();
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let params = TestVectorParams::baseline("example.com");
        let a_v = Catalog::generate_fuzz_lite(&params, "seed-a", 4).unwrap();
        let b_v = Catalog::generate_fuzz_lite(&params, "seed-b", 4).unwrap();
        assert_ne!(a_v, b_v);
        assert!(
            a_v.iter()
                .zip(&b_v)
                .all(|(left, right)| left.name != right.name)
        );
    }

    #[test]
    fn names_round_trip_full_utf8_seed() {
        let seed = "campaign-🌱-é";
        let name_v = vector_names(seed, 2);
        assert_eq!(
            name_v,
            [
                "fuzz-lite-63616d706169676e2df09f8cb12dc3a9-00000",
                "fuzz-lite-63616d706169676e2df09f8cb12dc3a9-00001",
            ]
        );
        for name in &name_v {
            assert_eq!(seed_from_vector_name(name).unwrap(), seed);
        }
    }

    #[test]
    fn seed_decoder_rejects_noncanonical_names() {
        for name in [
            "fuzz-lite-73656564-0000",
            "fuzz-lite-73656564-0000a",
            "fuzz-lite-7365656-00000",
            "fuzz-lite-7365656A-00000",
            "fuzz-lite-ff-00000",
        ] {
            assert!(seed_from_vector_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn every_structured_mutation_produces_computed_expected() {
        let params = TestVectorParams::baseline("example.com");
        for (index, &mutation) in StructuredMutation::ALL.iter().enumerate() {
            let name = format!("fuzz-lite-mutation-{index:04}");
            let rng = DeterministicRng::for_vector("mutation-coverage", &name);
            let vector = generate_one(params.clone(), rng, name, mutation).unwrap();
            assert_eq!(
                vector.expected.error_code_o,
                Some(RawDidDocument::predicted_error_code(mutation))
            );
            assert_eq!(
                vector.expected.error_version_id_o,
                Some(mutation.update_count())
            );
            assert_eq!(
                vector.expected.valid_did_document_count,
                mutation.update_count()
            );
            assert!(!vector.expected.is_fully_valid());
            assert_eq!(
                vector.expected.did_document_count as usize,
                vector.jsonl_line_v.len()
            );
        }
    }
}
