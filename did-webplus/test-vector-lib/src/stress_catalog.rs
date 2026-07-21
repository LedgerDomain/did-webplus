use did_webplus_core::{
    All, Any, DIDDocument, PublicKeySet, RootLevelUpdateRules, UpdateKey, UpdateRules,
};
use signature_dyn::SignerT;

use crate::{
    CatalogDescriptor, DeterministicRng, Expected, MicroledgerBuilder, StressConfig, TestVector,
    TestVectorParams,
};

const CATEGORY: &str = "stress";
const VALIDATION_REF: &str = "#validation-of-did-documents";

fn positive_vector(
    name: String,
    description: String,
    params: TestVectorParams,
    did: did_webplus_core::DID,
    jsonl_line_v: Vec<String>,
) -> TestVector {
    let count = jsonl_line_v.len() as u32;
    TestVector {
        name,
        category: CATEGORY.to_owned(),
        description,
        spec_ref_v: vec![VALIDATION_REF.to_owned()],
        expected: Expected::fully_valid(count),
        jsonl_line_v,
        did,
        params,
    }
}

fn pub_key(signer: &dyn SignerT, params: &TestVectorParams) -> anyhow::Result<mbx::MBPubKey> {
    let verifier_bytes = signer
        .get_verifier_bytes()
        .map_err(|error| anyhow::anyhow!("failed to derive verifier bytes: {error}"))?;
    Ok(mbx::MBPubKey::try_from_verifier_bytes(
        mbx::Base::from(params.base),
        &verifier_bytes,
    )?)
}

fn borrowed_keys(keys: &PublicKeySet<mbx::MBPubKey>) -> PublicKeySet<&mbx::MBPubKey> {
    PublicKeySet {
        authentication_v: keys.authentication_v.iter().collect(),
        assertion_method_v: keys.assertion_method_v.iter().collect(),
        key_agreement_v: keys.key_agreement_v.iter().collect(),
        capability_invocation_v: keys.capability_invocation_v.iter().collect(),
        capability_delegation_v: keys.capability_delegation_v.iter().collect(),
    }
}

/// Stable catalog names produced for `config` (for listing / CLI filtering later).
pub(crate) fn vector_names(config: &StressConfig) -> Vec<String> {
    let mut name_v = config
        .version_count_v
        .iter()
        .map(|count| format!("stress-many-versions-{count}"))
        .collect::<Vec<_>>();
    name_v.push("stress-large-document".to_owned());
    name_v.push("stress-deeply-nested-update-rules".to_owned());
    name_v.push("stress-many-proofs".to_owned());
    name_v.push("stress-long-did-path".to_owned());
    name_v
}

/// Cheap listing descriptors produced from configurable stress bounds.
pub(crate) fn descriptors(config: &StressConfig) -> Vec<CatalogDescriptor> {
    let mut descriptor_v = config
        .version_count_v
        .iter()
        .map(|count| CatalogDescriptor {
            name: format!("stress-many-versions-{count}"),
            category: CATEGORY.to_owned(),
            description: format!("Valid microledger with {count} versions (bounded stress)."),
            positive: true,
        })
        .collect::<Vec<_>>();
    descriptor_v.extend([
        CatalogDescriptor {
            name: "stress-large-document".to_owned(),
            category: CATEGORY.to_owned(),
            description: format!(
                "Valid root with {} verification methods and ~{} bytes of extra updateRules keys.",
                config.verification_method_count, config.extra_field_byte_count
            ),
            positive: true,
        },
        CatalogDescriptor {
            name: "stress-deeply-nested-update-rules".to_owned(),
            category: CATEGORY.to_owned(),
            description: format!(
                "Valid history whose root updateRules nest `all` {} levels deep.",
                config.update_rules_nesting_depth
            ),
            positive: true,
        },
        CatalogDescriptor {
            name: "stress-many-proofs".to_owned(),
            category: CATEGORY.to_owned(),
            description: format!(
                "Valid update authorized by an `all` rule requiring {} proofs.",
                config.proof_count
            ),
            positive: true,
        },
        CatalogDescriptor {
            name: "stress-long-did-path".to_owned(),
            category: CATEGORY.to_owned(),
            description: format!(
                "Valid DID with {} additional method-specific path components under the base did-path.",
                config.did_path_component_count
            ),
            positive: true,
        },
    ]);
    descriptor_v
}

/// Generate every stress vector for the given configurable bounds.
pub(crate) fn generate(
    params: &TestVectorParams,
    global_seed: &str,
    config: &StressConfig,
) -> anyhow::Result<Vec<TestVector>> {
    generate_with_progress(params, global_seed, config, |_| {})
}

/// Generate every stress vector, reporting each name immediately before generation.
pub(crate) fn generate_with_progress(
    params: &TestVectorParams,
    global_seed: &str,
    config: &StressConfig,
    mut on_start: impl FnMut(&str),
) -> anyhow::Result<Vec<TestVector>> {
    let mut vector_v = Vec::with_capacity(vector_names(config).len());
    for &version_count in &config.version_count_v {
        anyhow::ensure!(
            version_count >= 1,
            "stress version count must be at least 1, got {version_count}"
        );
        let name = format!("stress-many-versions-{version_count}");
        on_start(&name);
        let rng = DeterministicRng::for_vector(global_seed, &name);
        vector_v.push(many_versions(params.clone(), rng, version_count)?);
    }
    on_start("stress-large-document");
    vector_v.push(large_document(
        params.clone(),
        DeterministicRng::for_vector(global_seed, "stress-large-document"),
        config,
    )?);
    on_start("stress-deeply-nested-update-rules");
    vector_v.push(deeply_nested_update_rules(
        params.clone(),
        DeterministicRng::for_vector(global_seed, "stress-deeply-nested-update-rules"),
        config.update_rules_nesting_depth,
    )?);
    on_start("stress-many-proofs");
    vector_v.push(many_proofs(
        params.clone(),
        DeterministicRng::for_vector(global_seed, "stress-many-proofs"),
        config.proof_count,
    )?);
    on_start("stress-long-did-path");
    vector_v.push(long_did_path(
        params.clone(),
        DeterministicRng::for_vector(global_seed, "stress-long-did-path"),
        config.did_path_component_count,
    )?);
    Ok(vector_v)
}

fn many_versions(
    params: TestVectorParams,
    rng: DeterministicRng,
    version_count: u32,
) -> anyhow::Result<TestVector> {
    let update_count = version_count - 1;
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, update_count)?;
    let did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;
    anyhow::ensure!(
        jsonl_line_v.len() as u32 == version_count,
        "expected {version_count} versions, got {}",
        jsonl_line_v.len()
    );
    Ok(positive_vector(
        format!("stress-many-versions-{version_count}"),
        format!("Valid microledger with {version_count} versions (bounded stress)."),
        params,
        did,
        jsonl_line_v,
    ))
}

fn large_document(
    params: TestVectorParams,
    mut rng: DeterministicRng,
    config: &StressConfig,
) -> anyhow::Result<TestVector> {
    anyhow::ensure!(
        config.verification_method_count >= 1,
        "verification_method_count must be at least 1"
    );

    let mut authentication_v = Vec::with_capacity(config.verification_method_count as usize);
    for _ in 0..config.verification_method_count {
        let signer = rng.generate_private_key(params.key_type);
        authentication_v.push(pub_key(&*signer, &params)?);
    }
    let public_key_set = PublicKeySet {
        authentication_v,
        assertion_method_v: Vec::new(),
        key_agreement_v: Vec::new(),
        capability_invocation_v: Vec::new(),
        capability_delegation_v: Vec::new(),
    };

    let update_signer = rng.generate_private_key(params.key_type);
    let update_pub_key = pub_key(&*update_signer, &params)?;
    let update_rules = padded_any_update_rules(
        UpdateKey {
            pub_key: update_pub_key,
        },
        &params,
        &mut rng,
        config.extra_field_byte_count,
    )?;

    let mut root = DIDDocument::create_unsigned_root(
        &params.host,
        params.port_o,
        params.path_o().as_deref(),
        update_rules,
        rng.next_timestamp(),
        borrowed_keys(&public_key_set),
        &params.mb_hash_function(),
    )?;
    root.finalize(None)?;

    let did = root.did.clone();
    let jsonl_line_v = vec![root.serialize_canonically()?];
    Ok(positive_vector(
        "stress-large-document".to_owned(),
        format!(
            "Valid root with {} verification methods and ~{} bytes of extra updateRules keys.",
            config.verification_method_count, config.extra_field_byte_count
        ),
        params,
        did,
        jsonl_line_v,
    ))
}

/// Build an `any` rule containing the real update key plus filler keys until the
/// serialized rule JSON is at least `target_bytes` long (known-field padding).
fn padded_any_update_rules(
    real: UpdateKey,
    params: &TestVectorParams,
    rng: &mut DeterministicRng,
    target_bytes: u32,
) -> anyhow::Result<RootLevelUpdateRules> {
    let mut update_rule_v = vec![UpdateRules::from(real)];
    loop {
        let candidate = RootLevelUpdateRules::from(Any {
            any: update_rule_v.clone(),
        });
        let encoded = serde_json::to_vec(&candidate)?;
        if encoded.len() as u32 >= target_bytes || target_bytes == 0 {
            return Ok(candidate);
        }
        let filler = rng.generate_private_key(params.key_type);
        update_rule_v.push(UpdateRules::from(UpdateKey {
            pub_key: pub_key(&*filler, params)?,
        }));
    }
}

fn deeply_nested_update_rules(
    params: TestVectorParams,
    mut rng: DeterministicRng,
    depth: u32,
) -> anyhow::Result<TestVector> {
    let update_signer = rng.generate_private_key(params.key_type);
    let update_pub_key = pub_key(&*update_signer, &params)?;
    let mut nested = UpdateRules::from(UpdateKey {
        pub_key: update_pub_key.clone(),
    });
    for _ in 0..depth {
        nested = UpdateRules::from(All::new(vec![nested]));
    }
    let root_rules = RootLevelUpdateRules::from(nested);

    let empty_keys = PublicKeySet::empty();
    let mut root = DIDDocument::create_unsigned_root(
        &params.host,
        params.port_o,
        params.path_o().as_deref(),
        root_rules,
        rng.next_timestamp(),
        borrowed_keys(&empty_keys),
        &params.mb_hash_function(),
    )?;
    root.finalize(None)?;

    let next_update_signer = rng.generate_private_key(params.key_type);
    let next_update_pub_key = pub_key(&*next_update_signer, &params)?;
    let mut update = DIDDocument::create_unsigned_non_root(
        &root,
        RootLevelUpdateRules::from(UpdateKey {
            pub_key: next_update_pub_key,
        }),
        rng.next_timestamp(),
        borrowed_keys(&empty_keys),
        &params.mb_hash_function(),
    )?;
    update.add_proof(
        update
            .sign(update_pub_key.to_string(), &*update_signer)?
            .into_string(),
    );
    update.finalize(Some(&root))?;

    let did = root.did.clone();
    let jsonl_line_v = vec![
        root.serialize_canonically()?,
        update.serialize_canonically()?,
    ];
    Ok(positive_vector(
        "stress-deeply-nested-update-rules".to_owned(),
        format!("Valid history whose root updateRules nest `all` {depth} levels deep."),
        params,
        did,
        jsonl_line_v,
    ))
}

fn many_proofs(
    params: TestVectorParams,
    mut rng: DeterministicRng,
    proof_count: u32,
) -> anyhow::Result<TestVector> {
    anyhow::ensure!(proof_count >= 1, "proof_count must be at least 1");

    let signer_v = (0..proof_count)
        .map(|_| rng.generate_private_key(params.key_type))
        .collect::<Vec<_>>();
    let pub_key_v = signer_v
        .iter()
        .map(|signer| pub_key(&**signer, &params))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let root_rules = RootLevelUpdateRules::from(All::new(
        pub_key_v
            .iter()
            .map(|pub_key| {
                UpdateRules::from(UpdateKey {
                    pub_key: pub_key.clone(),
                })
            })
            .collect(),
    ));

    let empty_keys = PublicKeySet::empty();
    let mut root = DIDDocument::create_unsigned_root(
        &params.host,
        params.port_o,
        params.path_o().as_deref(),
        root_rules,
        rng.next_timestamp(),
        borrowed_keys(&empty_keys),
        &params.mb_hash_function(),
    )?;
    root.finalize(None)?;

    let next_update_signer = rng.generate_private_key(params.key_type);
    let next_update_pub_key = pub_key(&*next_update_signer, &params)?;
    let mut update = DIDDocument::create_unsigned_non_root(
        &root,
        RootLevelUpdateRules::from(UpdateKey {
            pub_key: next_update_pub_key,
        }),
        rng.next_timestamp(),
        borrowed_keys(&empty_keys),
        &params.mb_hash_function(),
    )?;
    for (signer, pub_key) in signer_v.iter().zip(pub_key_v.iter()) {
        update.add_proof(update.sign(pub_key.to_string(), &**signer)?.into_string());
    }
    update.finalize(Some(&root))?;

    let did = root.did.clone();
    let jsonl_line_v = vec![
        root.serialize_canonically()?,
        update.serialize_canonically()?,
    ];
    Ok(positive_vector(
        "stress-many-proofs".to_owned(),
        format!("Valid update authorized by an `all` rule requiring {proof_count} proofs."),
        params,
        did,
        jsonl_line_v,
    ))
}

fn long_did_path(
    mut params: TestVectorParams,
    rng: DeterministicRng,
    component_count: u32,
) -> anyhow::Result<TestVector> {
    anyhow::ensure!(
        component_count >= 1,
        "did_path_component_count must be at least 1"
    );
    // Append under the caller-supplied `--did-path` prefix (do not replace it).
    params.path_component_v.extend(
        (0..component_count).map(|index| format!("path{index:04}")),
    );
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 1)?;
    let did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;
    Ok(positive_vector(
        "stress-long-did-path".to_owned(),
        format!(
            "Valid DID with {component_count} additional method-specific path components under the base did-path."
        ),
        params,
        did,
        jsonl_line_v,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    #[test]
    fn stress_catalog_generates_with_configurable_sizes() {
        let config = StressConfig::for_tests();
        let name_v = Catalog::stress_vector_names(&config);
        assert!(name_v.contains(&"stress-many-versions-3".to_owned()));
        assert!(name_v.contains(&"stress-many-versions-5".to_owned()));
        assert!(name_v.contains(&"stress-large-document".to_owned()));

        let vector_v = Catalog::generate_stress(
            &TestVectorParams::baseline("example.com"),
            "stress-catalog-test",
            &config,
        )
        .expect("stress vectors should generate");
        assert_eq!(vector_v.len(), name_v.len());
        for (name, vector) in name_v.iter().zip(&vector_v) {
            assert_eq!(&vector.name, name);
            assert_eq!(vector.category, CATEGORY);
            assert!(vector.expected.is_fully_valid());
            assert_eq!(
                vector.expected.did_document_count as usize,
                vector.jsonl_line_v.len()
            );
        }

        let many_3 = vector_v
            .iter()
            .find(|vector| vector.name == "stress-many-versions-3")
            .expect("many-versions-3");
        assert_eq!(many_3.jsonl_line_v.len(), 3);

        let large = vector_v
            .iter()
            .find(|vector| vector.name == "stress-large-document")
            .expect("large-document");
        let root: serde_json::Value = serde_json::from_str(&large.jsonl_line_v[0]).unwrap();
        assert_eq!(
            root["verificationMethod"].as_array().unwrap().len(),
            config.verification_method_count as usize
        );

        let nested = vector_v
            .iter()
            .find(|vector| vector.name == "stress-deeply-nested-update-rules")
            .expect("nested");
        assert_eq!(nested.jsonl_line_v.len(), 2);

        let proofs = vector_v
            .iter()
            .find(|vector| vector.name == "stress-many-proofs")
            .expect("many-proofs");
        let update: serde_json::Value = serde_json::from_str(&proofs.jsonl_line_v[1]).unwrap();
        assert_eq!(
            update["proofs"].as_array().unwrap().len(),
            config.proof_count as usize
        );

        let long_path = vector_v
            .iter()
            .find(|vector| vector.name == "stress-long-did-path")
            .expect("long-path");
        assert_eq!(
            long_path.params.path_component_v.len(),
            config.did_path_component_count as usize
        );

        // Extra path components are appended under a non-empty base `--did-path`.
        let mut with_base = TestVectorParams::baseline("example.com");
        with_base.path_component_v = vec!["tv".to_owned(), "demo".to_owned()];
        let with_base_v = Catalog::generate_stress(&with_base, "stress-catalog-test", &config)
            .expect("stress with base path");
        let long_with_base = with_base_v
            .iter()
            .find(|vector| vector.name == "stress-long-did-path")
            .expect("long-path with base");
        assert!(
            long_with_base
                .params
                .path_component_v
                .starts_with(&["tv".to_owned(), "demo".to_owned()])
        );
        assert_eq!(
            long_with_base.params.path_component_v.len(),
            2 + config.did_path_component_count as usize
        );
    }

    #[test]
    fn stress_generation_is_deterministic() {
        let config = StressConfig::for_tests();
        let params = TestVectorParams::baseline("example.com");
        let a = Catalog::generate_stress(&params, "det-stress", &config).unwrap();
        let b = Catalog::generate_stress(&params, "det-stress", &config).unwrap();
        assert_eq!(a, b);
    }
}
