use did_webplus_core::{
    All, Any, DIDDocument, HashedUpdateKey, PublicKeySet, RootLevelUpdateRules, Threshold,
    UpdateKey, UpdateRules, UpdatesDisallowed, WeightedUpdateRules,
};
use did_webplus_mock::MicroledgerView;
use signature_dyn::SignerT;

use crate::{
    DeterministicRng, ErrorCode, Expected, MicroledgerBuilder, RawDidDocument, StructuredMutation,
    TestVector, TestVectorParams, VectorDefinition,
};

const CATEGORY: &str = "conformance";
const VALIDATION_REF: &str = "#validation-of-did-documents";
const UPDATE_RULES_REF: &str = "#update-rules";

#[derive(Clone, Copy)]
enum Baseline {
    Root,
    Update,
    SecondUpdate,
}

/// Conformance-only mutations: no-op, positive twins, or a shared structured negative.
#[derive(Clone, Copy)]
enum Mutation {
    None,
    /// Accept `.1Z` timestamp spelling (positive twin).
    ValidFromTenth,
    /// Accept `.100Z` timestamp spelling (positive twin).
    ValidFromHundredMilliseconds,
    /// Accept no-fraction timestamp spelling (positive twin).
    ValidFromNoFraction,
    Structured(StructuredMutation),
}

fn baseline_vector(
    name: &str,
    description: &str,
    params: TestVectorParams,
    rng: DeterministicRng,
    baseline: Baseline,
    mutation: Mutation,
    error_code_o: Option<ErrorCode>,
) -> anyhow::Result<TestVector> {
    let update_count = match baseline {
        Baseline::Root => 0,
        Baseline::Update => 1,
        Baseline::SecondUpdate => 2,
    };
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, update_count)?;
    let mut did = builder.did().clone();
    let mut line_v = builder.canonical_jsonl_lines()?;
    let target_index = update_count as usize;

    if !matches!(mutation, Mutation::None) {
        let document = builder
            .microledger()
            .view()
            .select_did_documents(Some(target_index as u32), Some(target_index as u32))
            .1
            .next()
            .ok_or_else(|| anyhow::anyhow!("baseline document is missing"))?;
        let mut raw = RawDidDocument::from_did_document(document)?;
        let should_rehash = apply_mutation(&mut raw, mutation, &params)?;
        if should_rehash {
            raw.re_self_hash()?;
            // Root re-self-hash updates the DID suffix; keep TestVector.did aligned.
            if target_index == 0 {
                did = raw.did()?;
            }
        }
        line_v[target_index] = emit_mutated_line(&raw, mutation)?;
    }

    let count = line_v.len() as u32;
    let expected = match error_code_o {
        Some(error_code) => {
            Expected::reject_after(count, target_index as u32, error_code, target_index as u32)
        }
        None => Expected::fully_valid(count),
    };
    Ok(TestVector {
        name: name.to_owned(),
        category: CATEGORY.to_owned(),
        description: description.to_owned(),
        spec_ref_v: vec![VALIDATION_REF.to_owned()],
        jsonl_line_v: line_v,
        did,
        expected,
        params,
    })
}

fn apply_mutation(
    raw: &mut RawDidDocument,
    mutation: Mutation,
    params: &TestVectorParams,
) -> anyhow::Result<bool> {
    match mutation {
        Mutation::None => Ok(false),
        Mutation::ValidFromTenth => {
            raw.replace("/validFrom", serde_json::json!("2025-01-01T00:00:00.1Z"))?;
            Ok(true)
        }
        Mutation::ValidFromHundredMilliseconds => {
            raw.replace("/validFrom", serde_json::json!("2025-01-01T00:00:00.100Z"))?;
            Ok(true)
        }
        Mutation::ValidFromNoFraction => {
            raw.replace("/validFrom", serde_json::json!("2025-01-01T00:00:00Z"))?;
            Ok(true)
        }
        Mutation::Structured(structured) => structured.apply(raw, params),
    }
}

fn emit_mutated_line(raw: &RawDidDocument, mutation: Mutation) -> anyhow::Result<String> {
    match mutation {
        Mutation::Structured(structured) => structured.emit_line(raw),
        _ => raw.to_jcs_line(),
    }
}

#[derive(Clone, Copy)]
enum RuleCase {
    KeyValid,
    KeyUnauthorized,
    HashedKeyValid,
    HashedKeyUnauthorized,
    AnyValid,
    AnyUnauthorized,
    AllValid,
    AllMissingProof,
    ThresholdAt,
    ThresholdBelow,
    InvalidSignature,
    /// Single-key rule; one authorizing valid proof plus one cryptographically invalid proof.
    KeyWithMixedProofs,
    /// `any` with two keys; one authorizing valid proof plus one cryptographically invalid proof.
    AnyWithMixedProofs,
    MissingProofs,
    ExtraneousProofs,
    RootWithProof,
    /// Root with a single cryptographically invalid proof (roots need not carry proofs).
    RootWithInvalidProof,
    UpdateAfterTombstone,
}

fn rule_vector(
    name: &str,
    description: &str,
    params: TestVectorParams,
    mut rng: DeterministicRng,
    case: RuleCase,
) -> anyhow::Result<TestVector> {
    let signer_v = (0..3)
        .map(|_| rng.generate_private_key(params.key_type))
        .collect::<Vec<_>>();
    let pub_key_v = signer_v
        .iter()
        .map(|signer| pub_key(&**signer, &params))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let root_rules = match case {
        RuleCase::HashedKeyValid | RuleCase::HashedKeyUnauthorized => RootLevelUpdateRules::from(
            HashedUpdateKey::from_pub_key(&params.mb_hash_function(), pub_key_v[0].as_ref()),
        ),
        RuleCase::AnyValid
        | RuleCase::AnyUnauthorized
        | RuleCase::AnyWithMixedProofs => RootLevelUpdateRules::from(Any {
            any: vec![
                UpdateKey {
                    pub_key: pub_key_v[0].clone(),
                }
                .into(),
                UpdateKey {
                    pub_key: pub_key_v[1].clone(),
                }
                .into(),
            ],
        }),
        RuleCase::AllValid | RuleCase::AllMissingProof => {
            RootLevelUpdateRules::from(All::new(vec![
                UpdateKey {
                    pub_key: pub_key_v[0].clone(),
                }
                .into(),
                UpdateKey {
                    pub_key: pub_key_v[1].clone(),
                }
                .into(),
            ]))
        }
        RuleCase::ThresholdAt | RuleCase::ThresholdBelow => {
            RootLevelUpdateRules::from(Threshold::new(
                2,
                vec![
                    WeightedUpdateRules::new(
                        2,
                        UpdateRules::from(UpdateKey {
                            pub_key: pub_key_v[0].clone(),
                        }),
                    ),
                    WeightedUpdateRules::new(
                        1,
                        UpdateRules::from(UpdateKey {
                            pub_key: pub_key_v[1].clone(),
                        }),
                    ),
                ],
            ))
        }
        RuleCase::UpdateAfterTombstone => RootLevelUpdateRules::from(UpdatesDisallowed {}),
        _ => RootLevelUpdateRules::from(UpdateKey {
            pub_key: pub_key_v[0].clone(),
        }),
    };

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

    if matches!(
        case,
        RuleCase::RootWithProof | RuleCase::RootWithInvalidProof
    ) {
        root.add_proof(
            root.sign(pub_key_v[1].to_string(), &*signer_v[1])?
                .into_string(),
        );
    }
    root.finalize(None)?;
    let mut did = root.did.clone();
    let mut line_v = vec![root.serialize_canonically()?];

    if matches!(case, RuleCase::RootWithInvalidProof) {
        let mut raw = RawDidDocument::from_did_document(&root)?;
        corrupt_proof_signature(&mut raw, "/proofs/0")?;
        raw.re_self_hash()?;
        did = raw.did()?;
        line_v[0] = raw.to_jcs_line()?;
    } else if !matches!(case, RuleCase::RootWithProof) {
        let mut update = DIDDocument::create_unsigned_non_root(
            &root,
            RootLevelUpdateRules::from(UpdateKey {
                pub_key: pub_key_v[2].clone(),
            }),
            rng.next_timestamp(),
            borrowed_keys(&empty_keys),
            &params.mb_hash_function(),
        )?;
        let proof_index_v: &[usize] = match case {
            RuleCase::KeyValid
            | RuleCase::HashedKeyValid
            | RuleCase::ThresholdAt
            | RuleCase::InvalidSignature => &[0],
            RuleCase::AnyValid => &[1],
            // Authorizing proof first, then a second proof that will be corrupted.
            RuleCase::AnyWithMixedProofs => &[1, 0],
            RuleCase::AllValid
            | RuleCase::ExtraneousProofs
            | RuleCase::KeyWithMixedProofs => &[0, 1],
            RuleCase::KeyUnauthorized
            | RuleCase::HashedKeyUnauthorized
            | RuleCase::ThresholdBelow
            | RuleCase::UpdateAfterTombstone => &[1],
            RuleCase::AnyUnauthorized => &[2],
            RuleCase::AllMissingProof => &[0],
            RuleCase::MissingProofs => &[],
            RuleCase::RootWithProof | RuleCase::RootWithInvalidProof => unreachable!(),
        };
        for &index in proof_index_v {
            update.add_proof(
                update
                    .sign(pub_key_v[index].to_string(), &*signer_v[index])?
                    .into_string(),
            );
        }

        // Cases whose proofs (before optional corruption) satisfy updateRules can
        // go through typed finalize; others only re-self-hash.
        let rules_satisfied_before_corruption = matches!(
            case,
            RuleCase::KeyValid
                | RuleCase::HashedKeyValid
                | RuleCase::AnyValid
                | RuleCase::AllValid
                | RuleCase::ThresholdAt
                | RuleCase::ExtraneousProofs
                | RuleCase::InvalidSignature
                | RuleCase::KeyWithMixedProofs
                | RuleCase::AnyWithMixedProofs
        );
        let mut raw = if rules_satisfied_before_corruption {
            update.finalize(Some(&root))?;
            RawDidDocument::from_did_document(&update)?
        } else {
            let mut raw = RawDidDocument::from_did_document(&update)?;
            raw.re_self_hash()?;
            raw
        };
        let corrupt_pointer_o = match case {
            RuleCase::InvalidSignature => Some("/proofs/0"),
            RuleCase::KeyWithMixedProofs | RuleCase::AnyWithMixedProofs => Some("/proofs/1"),
            _ => None,
        };
        if let Some(pointer) = corrupt_pointer_o {
            corrupt_proof_signature(&mut raw, pointer)?;
            raw.re_self_hash()?;
        }
        line_v.push(raw.to_jcs_line()?);
    }

    let error_code = match case {
        RuleCase::KeyUnauthorized
        | RuleCase::HashedKeyUnauthorized
        | RuleCase::AnyUnauthorized
        | RuleCase::AllMissingProof
        | RuleCase::ThresholdBelow
        | RuleCase::MissingProofs => Some(ErrorCode::UpdateRulesNotSatisfied),
        RuleCase::InvalidSignature
        | RuleCase::KeyWithMixedProofs
        | RuleCase::AnyWithMixedProofs
        | RuleCase::RootWithInvalidProof => Some(ErrorCode::InvalidProofSignature),
        RuleCase::UpdateAfterTombstone => Some(ErrorCode::UpdateAfterDeactivation),
        _ => None,
    };
    let count = line_v.len() as u32;
    let expected = match error_code {
        Some(code) if matches!(case, RuleCase::RootWithInvalidProof) => {
            Expected::reject_after(count, 0, code, 0)
        }
        Some(code) => Expected::reject_after(count, 1, code, 1),
        None => Expected::fully_valid(count),
    };
    Ok(TestVector {
        name: name.to_owned(),
        category: CATEGORY.to_owned(),
        description: description.to_owned(),
        spec_ref_v: vec![VALIDATION_REF.to_owned(), UPDATE_RULES_REF.to_owned()],
        jsonl_line_v: line_v,
        did,
        expected,
        params,
    })
}

/// Flip the last character of a detached JWS so the signature fails verification
/// while remaining syntactically parseable.
fn corrupt_proof_signature(raw: &mut RawDidDocument, pointer: &str) -> anyhow::Result<()> {
    crate::structured_mutation::mutate_proof_string(raw, pointer, |proof| {
        let last = proof
            .pop()
            .ok_or_else(|| anyhow::anyhow!("proof is empty"))?;
        proof.push(if last == 'A' { 'B' } else { 'A' });
        Ok(())
    })
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

macro_rules! baseline_factory {
    ($function:ident, $name:literal, $description:literal, $baseline:expr, $mutation:expr, $error:expr) => {
        fn $function(
            params: TestVectorParams,
            rng: DeterministicRng,
        ) -> anyhow::Result<TestVector> {
            baseline_vector(
                $name,
                $description,
                params,
                rng,
                $baseline,
                $mutation,
                $error,
            )
        }
    };
}

macro_rules! rule_factory {
    ($function:ident, $name:literal, $description:literal, $case:expr) => {
        fn $function(
            params: TestVectorParams,
            rng: DeterministicRng,
        ) -> anyhow::Result<TestVector> {
            rule_vector($name, $description, params, rng, $case)
        }
    };
}

baseline_factory!(
    baseline_valid_root,
    "baseline-valid-root",
    "Valid canonical root baseline.",
    Baseline::Root,
    Mutation::None,
    None
);
baseline_factory!(
    baseline_valid_update,
    "baseline-valid-update",
    "Valid canonical root and update baseline.",
    Baseline::Update,
    Mutation::None,
    None
);
baseline_factory!(
    jcs_reordered,
    "jcs-reordered-fields",
    "Reject valid JSON with reversed object-member order.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::JcsReordered),
    Some(ErrorCode::NotJcsCanonical)
);
baseline_factory!(
    jcs_whitespace,
    "jcs-extra-whitespace",
    "Reject valid JSON containing non-canonical whitespace.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::JcsWhitespace),
    Some(ErrorCode::NotJcsCanonical)
);
baseline_factory!(
    jcs_number,
    "jcs-non-minimal-number",
    "Reject a non-minimal JSON number representation.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::JcsNonMinimalNumber),
    Some(ErrorCode::NotJcsCanonical)
);
baseline_factory!(
    version_string,
    "data-model-version-id-string",
    "Reject versionId encoded as a string.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VersionIdString),
    Some(ErrorCode::MalformedVersionId)
);
baseline_factory!(
    missing_field,
    "data-model-missing-required-field",
    "Reject a document missing updateRules.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::MissingRequiredField),
    Some(ErrorCode::MissingRequiredField)
);
baseline_factory!(
    malformed_id,
    "data-model-malformed-id",
    "Reject a malformed DID id.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::MalformedId),
    Some(ErrorCode::MalformedId)
);
baseline_factory!(
    valid_from_microseconds,
    "valid-from-microsecond-precision",
    "Reject validFrom precision finer than milliseconds.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::ValidFromMicroseconds),
    Some(ErrorCode::ValidFromPrecisionExceeded)
);
baseline_factory!(
    valid_from_pre_epoch,
    "valid-from-pre-epoch",
    "Reject validFrom before the Unix epoch.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::ValidFromPreEpoch),
    Some(ErrorCode::ValidFromPreEpoch)
);
baseline_factory!(
    valid_from_lowercase,
    "valid-from-lowercase-t-z",
    "Reject lowercase RFC 3339 t/z separators.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::ValidFromLowercase),
    Some(ErrorCode::ValidFromInvalidFormat)
);
baseline_factory!(
    valid_from_unparseable,
    "valid-from-unparseable-calendar",
    "Reject validFrom with an unparseable calendar date.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::ValidFromUnparseable),
    Some(ErrorCode::ValidFromInvalidFormat)
);
baseline_factory!(
    valid_from_tenth,
    "valid-from-equivalent-tenth",
    "Accept .1Z timestamp spelling.",
    Baseline::Root,
    Mutation::ValidFromTenth,
    None
);
baseline_factory!(
    valid_from_hundred,
    "valid-from-equivalent-hundred-milliseconds",
    "Accept equivalent .100Z timestamp spelling.",
    Baseline::Root,
    Mutation::ValidFromHundredMilliseconds,
    None
);
baseline_factory!(
    valid_from_none,
    "valid-from-equivalent-no-fraction",
    "Accept no-fraction timestamp spelling.",
    Baseline::Root,
    Mutation::ValidFromNoFraction,
    None
);
baseline_factory!(
    vm_missing_self_hash,
    "vm-id-missing-self-hash-param",
    "Reject a VM id missing selfHash.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmMissingSelfHash),
    Some(ErrorCode::VmIdMissingQueryParams)
);
baseline_factory!(
    vm_missing_version,
    "vm-id-missing-version-id-param",
    "Reject a VM id missing versionId.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmMissingVersionId),
    Some(ErrorCode::VmIdMissingQueryParams)
);
baseline_factory!(
    vm_wrong_order,
    "vm-id-query-param-order",
    "Reject VM id query parameters in the wrong order.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmWrongOrder),
    Some(ErrorCode::VmIdQueryParamOrder)
);
baseline_factory!(
    vm_hash_mismatch,
    "vm-id-self-hash-mismatch",
    "Reject a VM id with mismatched selfHash.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmSelfHashMismatch),
    Some(ErrorCode::VmIdSelfhashMismatch)
);
baseline_factory!(
    vm_version_mismatch,
    "vm-id-version-id-mismatch",
    "Reject a VM id with mismatched versionId.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmVersionIdMismatch),
    Some(ErrorCode::VmIdVersionIdMismatch)
);
baseline_factory!(
    vm_missing_fragment,
    "vm-id-missing-fragment",
    "Reject a VM id missing its fragment.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmMissingFragment),
    Some(ErrorCode::VmIdMissingFragment)
);
baseline_factory!(
    vm_id_controller_mismatch,
    "vm-id-controller-mismatch",
    "Reject a VM id whose DID host differs from the controller.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmIdControllerMismatch),
    Some(ErrorCode::VmIdControllerMismatch)
);
baseline_factory!(
    vm_missing_jwk_kid,
    "vm-missing-jwk-kid",
    "Reject a VM publicKeyJwk missing kid.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::VmMissingKid),
    Some(ErrorCode::VmMissingKid)
);
baseline_factory!(
    purpose_dangling_authentication_ref,
    "purpose-dangling-authentication-ref",
    "Reject an authentication purpose reference with no matching VM.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::DanglingPurposeRef),
    Some(ErrorCode::DanglingPurposeRef)
);
baseline_factory!(
    wrong_self_hash,
    "self-hash-wrong-field",
    "Reject an incorrect document selfHash.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::WrongSelfHash),
    Some(ErrorCode::SelfHashMismatch)
);
baseline_factory!(
    wrong_suffix,
    "self-hash-wrong-root-did-suffix",
    "Reject an incorrect root DID suffix.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::WrongRootDidSuffix),
    Some(ErrorCode::SelfHashMismatch)
);
baseline_factory!(
    inconsistent_slots,
    "self-hash-inconsistent-slots",
    "Reject inconsistent self-hash slots.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::InconsistentSelfHashSlots),
    Some(ErrorCode::SelfHashSlotMismatch)
);
baseline_factory!(
    root_version,
    "root-version-id-nonzero",
    "Reject a root with nonzero versionId.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::RootVersionNonzero),
    Some(ErrorCode::RootVersionIdNonzero)
);
baseline_factory!(
    root_prev,
    "root-prev-self-hash-present",
    "Reject a root containing prevDIDDocumentSelfHash.",
    Baseline::Root,
    Mutation::Structured(StructuredMutation::RootPrevHashPresent),
    Some(ErrorCode::RootPrevDidDocumentSelfHashPresent)
);
baseline_factory!(
    nonroot_id,
    "non-root-id-mismatch",
    "Reject a non-root id differing from the root.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::NonRootIdMismatch),
    Some(ErrorCode::NonRootIdMismatch)
);
baseline_factory!(
    nonroot_prev,
    "non-root-prev-self-hash-mismatch",
    "Reject an incorrect previous-document self-hash.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::NonRootPrevHashMismatch),
    Some(ErrorCode::PrevDidDocumentSelfHashMismatch)
);
baseline_factory!(
    nonroot_time_equal,
    "non-root-valid-from-equal",
    "Reject validFrom equal to the previous version.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::NonRootValidFromEqual),
    Some(ErrorCode::ValidFromNotStrictlyIncreasing)
);
baseline_factory!(
    nonroot_time_earlier,
    "non-root-valid-from-earlier",
    "Reject validFrom earlier than the previous version.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::NonRootValidFromEarlier),
    Some(ErrorCode::ValidFromNotStrictlyIncreasing)
);
baseline_factory!(
    nonroot_gap,
    "non-root-version-id-gap",
    "Reject a versionId gap.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::NonRootVersionGap),
    Some(ErrorCode::VersionIdNotIncremented)
);
baseline_factory!(
    nonroot_repeat,
    "non-root-version-id-repeat",
    "Reject a repeated versionId.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::NonRootVersionRepeat),
    Some(ErrorCode::VersionIdNotIncremented)
);
baseline_factory!(
    nonroot_decrease,
    "non-root-version-id-decrease",
    "Reject a decreasing versionId.",
    Baseline::SecondUpdate,
    Mutation::Structured(StructuredMutation::NonRootVersionDecrease),
    Some(ErrorCode::VersionIdNotIncremented)
);
baseline_factory!(
    proof_malformed_kid,
    "proof-malformed-kid",
    "Reject a proof whose kid is not a valid multicodec string.",
    Baseline::Update,
    Mutation::Structured(StructuredMutation::MalformedProofKid),
    Some(ErrorCode::MalformedProofKid)
);

rule_factory!(
    rule_key_valid,
    "update-rules-key-valid",
    "Accept a proof satisfying key.",
    RuleCase::KeyValid
);
rule_factory!(
    rule_key_bad,
    "update-rules-key-unauthorized",
    "Reject a valid proof from an unauthorized key.",
    RuleCase::KeyUnauthorized
);
rule_factory!(
    rule_hash_valid,
    "update-rules-hashed-key-valid",
    "Accept a proof satisfying hashedKey.",
    RuleCase::HashedKeyValid
);
rule_factory!(
    rule_hash_bad,
    "update-rules-hashed-key-unauthorized",
    "Reject a proof not satisfying hashedKey.",
    RuleCase::HashedKeyUnauthorized
);
rule_factory!(
    rule_any_valid,
    "update-rules-any-valid",
    "Accept when one any branch is satisfied.",
    RuleCase::AnyValid
);
rule_factory!(
    rule_any_bad,
    "update-rules-any-unsatisfied",
    "Reject when no any branch is satisfied.",
    RuleCase::AnyUnauthorized
);
rule_factory!(
    rule_all_valid,
    "update-rules-all-valid",
    "Accept when every all branch is satisfied.",
    RuleCase::AllValid
);
rule_factory!(
    rule_all_bad,
    "update-rules-all-missing-proof",
    "Reject when one all branch is unsatisfied.",
    RuleCase::AllMissingProof
);
rule_factory!(
    rule_threshold_valid,
    "update-rules-at-least-weighted-at-threshold",
    "Accept weighted proofs exactly at threshold.",
    RuleCase::ThresholdAt
);
rule_factory!(
    rule_threshold_bad,
    "update-rules-at-least-weighted-below-threshold",
    "Reject weighted proofs below threshold.",
    RuleCase::ThresholdBelow
);
rule_factory!(
    invalid_signature,
    "proof-invalid-signature",
    "Reject a cryptographically invalid proof.",
    RuleCase::InvalidSignature
);
rule_factory!(
    key_with_mixed_proofs,
    "proofs-mixed-valid-invalid-key",
    "Reject a key-authorized update that also includes a cryptographically invalid proof.",
    RuleCase::KeyWithMixedProofs
);
rule_factory!(
    any_with_mixed_proofs,
    "proofs-mixed-valid-invalid-any",
    "Reject an any-authorized update that also includes a cryptographically invalid proof.",
    RuleCase::AnyWithMixedProofs
);
rule_factory!(
    missing_proofs,
    "proofs-missing",
    "Reject an update with no proofs.",
    RuleCase::MissingProofs
);
rule_factory!(
    extraneous_proofs,
    "proofs-extraneous-ignored",
    "Accept extra valid proofs not needed by key rules.",
    RuleCase::ExtraneousProofs
);
rule_factory!(
    root_proof,
    "root-with-proofs",
    "Accept a root containing a valid proof.",
    RuleCase::RootWithProof
);
rule_factory!(
    root_invalid_proof,
    "root-with-invalid-proof",
    "Reject a root containing a cryptographically invalid proof.",
    RuleCase::RootWithInvalidProof
);
rule_factory!(
    after_tombstone,
    "update-after-tombstone",
    "Reject an update after updates are disallowed.",
    RuleCase::UpdateAfterTombstone
);

pub(crate) fn definitions() -> &'static [VectorDefinition] {
    const DEFINITIONS: &[VectorDefinition] = &[
        VectorDefinition {
            name: "baseline-valid-root",
            description: "Valid canonical root baseline.",
            positive: true,
            factory: baseline_valid_root,
        },
        VectorDefinition {
            name: "baseline-valid-update",
            description: "Valid canonical root and update baseline.",
            positive: true,
            factory: baseline_valid_update,
        },
        VectorDefinition {
            name: "jcs-reordered-fields",
            description: "Reject valid JSON with reversed object-member order.",
            positive: false,
            factory: jcs_reordered,
        },
        VectorDefinition {
            name: "jcs-extra-whitespace",
            description: "Reject valid JSON containing non-canonical whitespace.",
            positive: false,
            factory: jcs_whitespace,
        },
        VectorDefinition {
            name: "jcs-non-minimal-number",
            description: "Reject a non-minimal JSON number representation.",
            positive: false,
            factory: jcs_number,
        },
        VectorDefinition {
            name: "data-model-version-id-string",
            description: "Reject versionId encoded as a string.",
            positive: false,
            factory: version_string,
        },
        VectorDefinition {
            name: "data-model-missing-required-field",
            description: "Reject a document missing updateRules.",
            positive: false,
            factory: missing_field,
        },
        VectorDefinition {
            name: "data-model-malformed-id",
            description: "Reject a malformed DID id.",
            positive: false,
            factory: malformed_id,
        },
        VectorDefinition {
            name: "valid-from-microsecond-precision",
            description: "Reject validFrom precision finer than milliseconds.",
            positive: false,
            factory: valid_from_microseconds,
        },
        VectorDefinition {
            name: "valid-from-pre-epoch",
            description: "Reject validFrom before the Unix epoch.",
            positive: false,
            factory: valid_from_pre_epoch,
        },
        VectorDefinition {
            name: "valid-from-lowercase-t-z",
            description: "Reject lowercase RFC 3339 t/z separators.",
            positive: false,
            factory: valid_from_lowercase,
        },
        VectorDefinition {
            name: "valid-from-unparseable-calendar",
            description: "Reject validFrom with an unparseable calendar date.",
            positive: false,
            factory: valid_from_unparseable,
        },
        VectorDefinition {
            name: "valid-from-equivalent-tenth",
            description: "Accept .1Z timestamp spelling.",
            positive: true,
            factory: valid_from_tenth,
        },
        VectorDefinition {
            name: "valid-from-equivalent-hundred-milliseconds",
            description: "Accept equivalent .100Z timestamp spelling.",
            positive: true,
            factory: valid_from_hundred,
        },
        VectorDefinition {
            name: "valid-from-equivalent-no-fraction",
            description: "Accept no-fraction timestamp spelling.",
            positive: true,
            factory: valid_from_none,
        },
        VectorDefinition {
            name: "vm-id-missing-self-hash-param",
            description: "Reject a VM id missing selfHash.",
            positive: false,
            factory: vm_missing_self_hash,
        },
        VectorDefinition {
            name: "vm-id-missing-version-id-param",
            description: "Reject a VM id missing versionId.",
            positive: false,
            factory: vm_missing_version,
        },
        VectorDefinition {
            name: "vm-id-query-param-order",
            description: "Reject VM id query parameters in the wrong order.",
            positive: false,
            factory: vm_wrong_order,
        },
        VectorDefinition {
            name: "vm-id-self-hash-mismatch",
            description: "Reject a VM id with mismatched selfHash.",
            positive: false,
            factory: vm_hash_mismatch,
        },
        VectorDefinition {
            name: "vm-id-version-id-mismatch",
            description: "Reject a VM id with mismatched versionId.",
            positive: false,
            factory: vm_version_mismatch,
        },
        VectorDefinition {
            name: "vm-id-missing-fragment",
            description: "Reject a VM id missing its fragment.",
            positive: false,
            factory: vm_missing_fragment,
        },
        VectorDefinition {
            name: "vm-id-controller-mismatch",
            description: "Reject a VM id whose DID host differs from the controller.",
            positive: false,
            factory: vm_id_controller_mismatch,
        },
        VectorDefinition {
            name: "vm-missing-jwk-kid",
            description: "Reject a VM publicKeyJwk missing kid.",
            positive: false,
            factory: vm_missing_jwk_kid,
        },
        VectorDefinition {
            name: "purpose-dangling-authentication-ref",
            description: "Reject an authentication purpose reference with no matching VM.",
            positive: false,
            factory: purpose_dangling_authentication_ref,
        },
        VectorDefinition {
            name: "self-hash-wrong-field",
            description: "Reject an incorrect document selfHash.",
            positive: false,
            factory: wrong_self_hash,
        },
        VectorDefinition {
            name: "self-hash-wrong-root-did-suffix",
            description: "Reject an incorrect root DID suffix.",
            positive: false,
            factory: wrong_suffix,
        },
        VectorDefinition {
            name: "self-hash-inconsistent-slots",
            description: "Reject inconsistent self-hash slots.",
            positive: false,
            factory: inconsistent_slots,
        },
        VectorDefinition {
            name: "root-version-id-nonzero",
            description: "Reject a root with nonzero versionId.",
            positive: false,
            factory: root_version,
        },
        VectorDefinition {
            name: "root-prev-self-hash-present",
            description: "Reject a root containing prevDIDDocumentSelfHash.",
            positive: false,
            factory: root_prev,
        },
        VectorDefinition {
            name: "non-root-id-mismatch",
            description: "Reject a non-root id differing from the root.",
            positive: false,
            factory: nonroot_id,
        },
        VectorDefinition {
            name: "non-root-prev-self-hash-mismatch",
            description: "Reject an incorrect previous-document self-hash.",
            positive: false,
            factory: nonroot_prev,
        },
        VectorDefinition {
            name: "non-root-valid-from-equal",
            description: "Reject validFrom equal to the previous version.",
            positive: false,
            factory: nonroot_time_equal,
        },
        VectorDefinition {
            name: "non-root-valid-from-earlier",
            description: "Reject validFrom earlier than the previous version.",
            positive: false,
            factory: nonroot_time_earlier,
        },
        VectorDefinition {
            name: "non-root-version-id-gap",
            description: "Reject a versionId gap.",
            positive: false,
            factory: nonroot_gap,
        },
        VectorDefinition {
            name: "non-root-version-id-repeat",
            description: "Reject a repeated versionId.",
            positive: false,
            factory: nonroot_repeat,
        },
        VectorDefinition {
            name: "non-root-version-id-decrease",
            description: "Reject a decreasing versionId.",
            positive: false,
            factory: nonroot_decrease,
        },
        VectorDefinition {
            name: "proof-malformed-kid",
            description: "Reject a proof whose kid is not a valid multicodec string.",
            positive: false,
            factory: proof_malformed_kid,
        },
        VectorDefinition {
            name: "update-rules-key-valid",
            description: "Accept a proof satisfying key.",
            positive: true,
            factory: rule_key_valid,
        },
        VectorDefinition {
            name: "update-rules-key-unauthorized",
            description: "Reject a valid proof from an unauthorized key.",
            positive: false,
            factory: rule_key_bad,
        },
        VectorDefinition {
            name: "update-rules-hashed-key-valid",
            description: "Accept a proof satisfying hashedKey.",
            positive: true,
            factory: rule_hash_valid,
        },
        VectorDefinition {
            name: "update-rules-hashed-key-unauthorized",
            description: "Reject a proof not satisfying hashedKey.",
            positive: false,
            factory: rule_hash_bad,
        },
        VectorDefinition {
            name: "update-rules-any-valid",
            description: "Accept when one any branch is satisfied.",
            positive: true,
            factory: rule_any_valid,
        },
        VectorDefinition {
            name: "update-rules-any-unsatisfied",
            description: "Reject when no any branch is satisfied.",
            positive: false,
            factory: rule_any_bad,
        },
        VectorDefinition {
            name: "update-rules-all-valid",
            description: "Accept when every all branch is satisfied.",
            positive: true,
            factory: rule_all_valid,
        },
        VectorDefinition {
            name: "update-rules-all-missing-proof",
            description: "Reject when one all branch is unsatisfied.",
            positive: false,
            factory: rule_all_bad,
        },
        VectorDefinition {
            name: "update-rules-at-least-weighted-at-threshold",
            description: "Accept weighted proofs exactly at threshold.",
            positive: true,
            factory: rule_threshold_valid,
        },
        VectorDefinition {
            name: "update-rules-at-least-weighted-below-threshold",
            description: "Reject weighted proofs below threshold.",
            positive: false,
            factory: rule_threshold_bad,
        },
        VectorDefinition {
            name: "proof-invalid-signature",
            description: "Reject a cryptographically invalid proof.",
            positive: false,
            factory: invalid_signature,
        },
        VectorDefinition {
            name: "proofs-mixed-valid-invalid-key",
            description:
                "Reject a key-authorized update that also includes a cryptographically invalid proof.",
            positive: false,
            factory: key_with_mixed_proofs,
        },
        VectorDefinition {
            name: "proofs-mixed-valid-invalid-any",
            description:
                "Reject an any-authorized update that also includes a cryptographically invalid proof.",
            positive: false,
            factory: any_with_mixed_proofs,
        },
        VectorDefinition {
            name: "proofs-missing",
            description: "Reject an update with no proofs.",
            positive: false,
            factory: missing_proofs,
        },
        VectorDefinition {
            name: "proofs-extraneous-ignored",
            description: "Accept extra valid proofs not needed by key rules.",
            positive: true,
            factory: extraneous_proofs,
        },
        VectorDefinition {
            name: "root-with-proofs",
            description: "Accept a root containing a valid proof.",
            positive: true,
            factory: root_proof,
        },
        VectorDefinition {
            name: "root-with-invalid-proof",
            description: "Reject a root containing a cryptographically invalid proof.",
            positive: false,
            factory: root_invalid_proof,
        },
        VectorDefinition {
            name: "update-after-tombstone",
            description: "Reject an update after updates are disallowed.",
            positive: false,
            factory: after_tombstone,
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
        let definition_v = Catalog::conformance_definitions();
        let name_s = definition_v
            .iter()
            .map(|definition| definition.name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(name_s.len(), definition_v.len());

        let vector_v = Catalog::generate_conformance(
            &TestVectorParams::baseline("example.com"),
            "catalog-test",
        )
        .expect("all conformance vectors should generate");
        assert_eq!(vector_v.len(), definition_v.len());
        for (definition, vector) in definition_v.iter().zip(vector_v) {
            assert_eq!(vector.name, definition.name);
            assert_eq!(
                vector.expected.did_document_count as usize,
                vector.jsonl_line_v.len()
            );
        }
    }

    #[test]
    fn root_rehash_mutation_propagates_did_into_test_vector() {
        let params = TestVectorParams::baseline("example.com");
        let seed = "catalog-test";
        let name = "valid-from-tenth-second";
        let baseline = baseline_vector(
            "baseline-valid-root",
            "baseline",
            params.clone(),
            DeterministicRng::for_vector(seed, name),
            Baseline::Root,
            Mutation::None,
            None,
        )
        .unwrap();
        let mutated = baseline_vector(
            name,
            "rehashed root",
            params,
            DeterministicRng::for_vector(seed, name),
            Baseline::Root,
            Mutation::ValidFromTenth,
            None,
        )
        .unwrap();

        assert_ne!(mutated.did, baseline.did);
        let root: serde_json::Value = serde_json::from_str(&mutated.jsonl_line_v[0]).unwrap();
        assert_eq!(
            mutated.did.to_string(),
            root.get("id").and_then(|value| value.as_str()).unwrap()
        );
        assert_eq!(
            mutated.did.root_self_hash().as_str(),
            root.get("selfHash")
                .and_then(|value| value.as_str())
                .unwrap()
        );
    }
}
