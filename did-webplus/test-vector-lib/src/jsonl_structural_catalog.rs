use did_webplus_mock::MicroledgerView;
use selfhash::HashFunctionT;

use crate::{
    DeterministicRng, ErrorCode, Expected, MicroledgerBuilder, RawDidDocument, TestVector,
    TestVectorParams, VectorDefinition,
};

const CATEGORY: &str = "jsonl-structural";
const VALIDATION_REF: &str = "#validation-of-did-documents";

fn positive_lines(
    params: TestVectorParams,
    rng: DeterministicRng,
    update_count: u32,
) -> anyhow::Result<(did_webplus_core::DID, Vec<String>, TestVectorParams)> {
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, update_count)?;
    Ok((
        builder.did().clone(),
        builder.canonical_jsonl_lines()?,
        params,
    ))
}

fn vector(
    name: &str,
    description: &str,
    params: TestVectorParams,
    did: did_webplus_core::DID,
    jsonl_line_v: Vec<String>,
    expected: Expected,
) -> TestVector {
    TestVector {
        name: name.to_owned(),
        category: CATEGORY.to_owned(),
        description: description.to_owned(),
        spec_ref_v: vec![VALIDATION_REF.to_owned()],
        jsonl_line_v,
        did,
        expected,
        params,
    }
}

/// Empty `did-documents.jsonl` body; DID identity still comes from a generated root.
fn empty_file(params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    let builder = MicroledgerBuilder::create(params.clone(), rng)?;
    Ok(vector(
        "jsonl-empty-file",
        "Empty did-documents.jsonl (zero lines) for a generated DID identity.",
        params,
        builder.did().clone(),
        Vec::new(),
        Expected::fully_valid(0),
    ))
}

/// Valid root then a blank line before the next document.
fn blank_lines(params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    let (did, mut line_v, params) = positive_lines(params, rng, 1)?;
    // Insert a blank line between root and update.
    line_v.insert(1, String::new());
    Ok(vector(
        "jsonl-blank-lines",
        "Valid root followed by a blank jsonl line before the next document.",
        params,
        did,
        line_v,
        Expected::reject_after(3, 1, ErrorCode::MalformedJsonlLine, 1),
    ))
}

/// Valid documents whose lines end with CR so `\n`-joined body is CRLF.
fn crlf_line_endings(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    let (did, line_v, params) = positive_lines(params, rng, 1)?;
    let line_v = line_v
        .into_iter()
        .map(|line| {
            let mut line = line;
            line.push('\r');
            line
        })
        .collect::<Vec<_>>();
    let count = line_v.len() as u32;
    Ok(vector(
        "jsonl-crlf-line-endings",
        "Valid DID documents emitted with CR so newline-joined body uses CRLF.",
        params,
        did,
        line_v,
        Expected::reject_after(count, 0, ErrorCode::MalformedJsonlLine, 0),
    ))
}

/// Valid root and update, then a duplicate of the update line.
fn duplicate_line(params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    let (did, mut line_v, params) = positive_lines(params, rng, 1)?;
    let duplicate = line_v
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("expected an update line to duplicate"))?;
    line_v.push(duplicate);
    Ok(vector(
        "jsonl-duplicate-line",
        "Valid root and update followed by a duplicate of the update line.",
        params,
        did,
        line_v,
        Expected::reject_after(3, 2, ErrorCode::VersionIdNotIncremented, 1),
    ))
}

/// Valid root and update followed by a non-JSON trailing line.
fn non_json_trailing_line(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    let (did, mut line_v, params) = positive_lines(params, rng, 1)?;
    line_v.push("this is not json".to_owned());
    Ok(vector(
        "jsonl-non-json-trailing-line",
        "Valid root and update followed by a non-JSON trailing line.",
        params,
        did,
        line_v,
        Expected::reject_after(3, 2, ErrorCode::MalformedJsonlLine, 2),
    ))
}

/// Two valid documents then an invalid third (self-hash mismatch).
fn valid_prefix_then_invalid_doc(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 2)?;
    let did = builder.did().clone();
    let mut line_v = builder.canonical_jsonl_lines()?;
    let document = builder
        .microledger()
        .view()
        .select_did_documents(Some(2), Some(2))
        .1
        .next()
        .ok_or_else(|| anyhow::anyhow!("third document is missing"))?;
    let mut raw = RawDidDocument::from_did_document(document)?;
    let wrong = params.mb_hash_function().placeholder_hash().to_string();
    raw.replace("/selfHash", serde_json::Value::String(wrong))?;
    line_v[2] = raw.to_jcs_line()?;
    Ok(vector(
        "jsonl-valid-prefix-then-invalid-doc",
        "Two valid documents followed by a third with a broken selfHash.",
        params,
        did,
        line_v,
        Expected::reject_after(3, 2, ErrorCode::SelfHashMismatch, 2),
    ))
}

pub(crate) fn definitions() -> &'static [VectorDefinition] {
    const DEFINITIONS: &[VectorDefinition] = &[
        VectorDefinition {
            name: "jsonl-empty-file",
            description: "Empty did-documents.jsonl (zero lines) for a generated DID identity.",
            positive: true,
            factory: empty_file,
        },
        VectorDefinition {
            name: "jsonl-blank-lines",
            description: "Valid root followed by a blank jsonl line before the next document.",
            positive: false,
            factory: blank_lines,
        },
        VectorDefinition {
            name: "jsonl-crlf-line-endings",
            description: "Valid DID documents emitted with CR so newline-joined body uses CRLF.",
            positive: false,
            factory: crlf_line_endings,
        },
        VectorDefinition {
            name: "jsonl-duplicate-line",
            description: "Valid root and update followed by a duplicate of the update line.",
            positive: false,
            factory: duplicate_line,
        },
        VectorDefinition {
            name: "jsonl-non-json-trailing-line",
            description: "Valid root and update followed by a non-JSON trailing line.",
            positive: false,
            factory: non_json_trailing_line,
        },
        VectorDefinition {
            name: "jsonl-valid-prefix-then-invalid-doc",
            description: "Two valid documents followed by a third with a broken selfHash.",
            positive: false,
            factory: valid_prefix_then_invalid_doc,
        },
    ];
    DEFINITIONS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    #[test]
    fn catalog_names_are_unique_and_every_vector_generates() {
        let definition_v = Catalog::jsonl_structural_definitions();
        let name_s = definition_v
            .iter()
            .map(|definition| definition.name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(name_s.len(), definition_v.len());

        let vector_v = Catalog::generate_jsonl_structural(
            &TestVectorParams::baseline("example.com"),
            "jsonl-structural-test",
        )
        .expect("all jsonl-structural vectors should generate");
        assert_eq!(vector_v.len(), definition_v.len());
        for (definition, vector) in definition_v.iter().zip(vector_v) {
            assert_eq!(vector.name, definition.name);
            assert_eq!(vector.category, CATEGORY);
            assert_eq!(
                vector.expected.did_document_count as usize,
                vector.jsonl_line_v.len()
            );
        }
    }
}
