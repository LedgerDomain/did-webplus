use selfhash::HashFunctionT;

use crate::{ErrorCode, RawDidDocument, TestVectorParams};

/// Which document in a minimal valid microledger a structured mutation targets.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MutationTarget {
    /// Mutate the root of a root-only microledger.
    Root,
    /// Mutate version 1 of a root+one-update microledger.
    NonRoot,
    /// Mutate version 2 of a root+two-updates microledger (e.g. version decrease).
    NonRootSecond,
}

/// Single-field structured mutation used by conformance negatives and fuzz-lite.
///
/// Each variant breaks exactly one validation rule. Expected outcomes come from
/// [`Self::error_code`], which is the rule table also exposed via
/// [`RawDidDocument::predicted_error_code`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StructuredMutation {
    /// Reversed JSON object-member order (non-JCS).
    JcsReordered,
    /// Extra whitespace after a colon (non-JCS).
    JcsWhitespace,
    /// Non-minimal number spelling for `versionId` (non-JCS).
    JcsNonMinimalNumber,
    /// `versionId` encoded as a JSON string.
    VersionIdString,
    /// Required `updateRules` field removed.
    MissingRequiredField,
    /// Document `id` replaced with a non-DID string.
    MalformedId,
    /// `validFrom` with microsecond precision.
    ValidFromMicroseconds,
    /// `validFrom` before the Unix epoch.
    ValidFromPreEpoch,
    /// `validFrom` with lowercase `t`/`z`.
    ValidFromLowercase,
    /// `validFrom` with valid `T`/`Z` shape but an unparseable calendar date.
    ValidFromUnparseable,
    /// Verification-method `id` missing `selfHash` query param.
    VmMissingSelfHash,
    /// Verification-method `id` missing `versionId` query param.
    VmMissingVersionId,
    /// Verification-method `id` query params in the wrong order.
    VmWrongOrder,
    /// Verification-method `id` `selfHash` does not match the document.
    VmSelfHashMismatch,
    /// Verification-method `id` `versionId` does not match the document.
    VmVersionIdMismatch,
    /// Verification-method `id` missing its fragment.
    VmMissingFragment,
    /// Verification-method `id` DID host differs from `controller` / document `id`.
    VmIdControllerMismatch,
    /// Verification-method `publicKeyJwk` is missing required `kid`.
    VmMissingKid,
    /// Purpose array references a verification-method fragment that does not exist.
    DanglingPurposeRef,
    /// Document `selfHash` replaced without updating slots.
    WrongSelfHash,
    /// Root DID suffix replaced without updating `selfHash`.
    WrongRootDidSuffix,
    /// One self-hash slot diverges from the others.
    InconsistentSelfHashSlots,
    /// Root `versionId` set nonzero.
    RootVersionNonzero,
    /// Root unexpectedly includes `prevDIDDocumentSelfHash`.
    RootPrevHashPresent,
    /// Non-root `id` differs from the root DID.
    NonRootIdMismatch,
    /// Non-root `prevDIDDocumentSelfHash` is wrong.
    NonRootPrevHashMismatch,
    /// Non-root `validFrom` equal to the previous document.
    NonRootValidFromEqual,
    /// Non-root `validFrom` earlier than the previous document.
    NonRootValidFromEarlier,
    /// Non-root `versionId` skips ahead.
    NonRootVersionGap,
    /// Non-root `versionId` repeats the previous value.
    NonRootVersionRepeat,
    /// Non-root `versionId` decreases relative to the previous value.
    NonRootVersionDecrease,
    /// Proof JWS header `kid` is not a multicodec public key.
    MalformedProofKid,
}

impl StructuredMutation {
    /// Stable table of every structured (negative) mutation, in catalog order.
    ///
    /// Fuzz-lite indexes into this table deterministically from the vector seed.
    pub const ALL: &'static [StructuredMutation] = &[
        StructuredMutation::JcsReordered,
        StructuredMutation::JcsWhitespace,
        StructuredMutation::JcsNonMinimalNumber,
        StructuredMutation::VersionIdString,
        StructuredMutation::MissingRequiredField,
        StructuredMutation::MalformedId,
        StructuredMutation::ValidFromMicroseconds,
        StructuredMutation::ValidFromPreEpoch,
        StructuredMutation::ValidFromLowercase,
        StructuredMutation::ValidFromUnparseable,
        StructuredMutation::VmMissingSelfHash,
        StructuredMutation::VmMissingVersionId,
        StructuredMutation::VmWrongOrder,
        StructuredMutation::VmSelfHashMismatch,
        StructuredMutation::VmVersionIdMismatch,
        StructuredMutation::VmMissingFragment,
        StructuredMutation::VmIdControllerMismatch,
        StructuredMutation::VmMissingKid,
        StructuredMutation::DanglingPurposeRef,
        StructuredMutation::WrongSelfHash,
        StructuredMutation::WrongRootDidSuffix,
        StructuredMutation::InconsistentSelfHashSlots,
        StructuredMutation::RootVersionNonzero,
        StructuredMutation::RootPrevHashPresent,
        StructuredMutation::NonRootIdMismatch,
        StructuredMutation::NonRootPrevHashMismatch,
        StructuredMutation::NonRootValidFromEqual,
        StructuredMutation::NonRootValidFromEarlier,
        StructuredMutation::NonRootVersionGap,
        StructuredMutation::NonRootVersionRepeat,
        StructuredMutation::NonRootVersionDecrease,
        StructuredMutation::MalformedProofKid,
    ];

    /// Short kebab-case name suitable for vector descriptions and logging.
    pub fn as_str(self) -> &'static str {
        match self {
            StructuredMutation::JcsReordered => "jcs-reordered-fields",
            StructuredMutation::JcsWhitespace => "jcs-extra-whitespace",
            StructuredMutation::JcsNonMinimalNumber => "jcs-non-minimal-number",
            StructuredMutation::VersionIdString => "version-id-string",
            StructuredMutation::MissingRequiredField => "missing-required-field",
            StructuredMutation::MalformedId => "malformed-id",
            StructuredMutation::ValidFromMicroseconds => "valid-from-microseconds",
            StructuredMutation::ValidFromPreEpoch => "valid-from-pre-epoch",
            StructuredMutation::ValidFromLowercase => "valid-from-lowercase-t-z",
            StructuredMutation::ValidFromUnparseable => "valid-from-unparseable-calendar",
            StructuredMutation::VmMissingSelfHash => "vm-id-missing-self-hash",
            StructuredMutation::VmMissingVersionId => "vm-id-missing-version-id",
            StructuredMutation::VmWrongOrder => "vm-id-query-param-order",
            StructuredMutation::VmSelfHashMismatch => "vm-id-self-hash-mismatch",
            StructuredMutation::VmVersionIdMismatch => "vm-id-version-id-mismatch",
            StructuredMutation::VmMissingFragment => "vm-id-missing-fragment",
            StructuredMutation::VmIdControllerMismatch => "vm-id-controller-mismatch",
            StructuredMutation::VmMissingKid => "vm-missing-jwk-kid",
            StructuredMutation::DanglingPurposeRef => "purpose-dangling-authentication-ref",
            StructuredMutation::WrongSelfHash => "wrong-self-hash",
            StructuredMutation::WrongRootDidSuffix => "wrong-root-did-suffix",
            StructuredMutation::InconsistentSelfHashSlots => "inconsistent-self-hash-slots",
            StructuredMutation::RootVersionNonzero => "root-version-id-nonzero",
            StructuredMutation::RootPrevHashPresent => "root-prev-self-hash-present",
            StructuredMutation::NonRootIdMismatch => "non-root-id-mismatch",
            StructuredMutation::NonRootPrevHashMismatch => "non-root-prev-self-hash-mismatch",
            StructuredMutation::NonRootValidFromEqual => "non-root-valid-from-equal",
            StructuredMutation::NonRootValidFromEarlier => "non-root-valid-from-earlier",
            StructuredMutation::NonRootVersionGap => "non-root-version-id-gap",
            StructuredMutation::NonRootVersionRepeat => "non-root-version-id-repeat",
            StructuredMutation::NonRootVersionDecrease => "non-root-version-id-decrease",
            StructuredMutation::MalformedProofKid => "proof-malformed-kid",
        }
    }

    /// Advisory [`ErrorCode`] predicted when this mutation is applied to a valid document.
    ///
    /// This is the shared rule table for conformance negatives and fuzz-lite expected outcomes.
    pub fn error_code(self) -> ErrorCode {
        match self {
            StructuredMutation::JcsReordered
            | StructuredMutation::JcsWhitespace
            | StructuredMutation::JcsNonMinimalNumber => ErrorCode::NotJcsCanonical,
            StructuredMutation::VersionIdString => ErrorCode::MalformedVersionId,
            StructuredMutation::MissingRequiredField => ErrorCode::MissingRequiredField,
            StructuredMutation::MalformedId => ErrorCode::MalformedId,
            StructuredMutation::ValidFromMicroseconds => ErrorCode::ValidFromPrecisionExceeded,
            StructuredMutation::ValidFromPreEpoch => ErrorCode::ValidFromPreEpoch,
            StructuredMutation::ValidFromLowercase
            | StructuredMutation::ValidFromUnparseable => ErrorCode::ValidFromInvalidFormat,
            StructuredMutation::VmMissingSelfHash | StructuredMutation::VmMissingVersionId => {
                ErrorCode::VmIdMissingQueryParams
            }
            StructuredMutation::VmWrongOrder => ErrorCode::VmIdQueryParamOrder,
            StructuredMutation::VmSelfHashMismatch => ErrorCode::VmIdSelfhashMismatch,
            StructuredMutation::VmVersionIdMismatch => ErrorCode::VmIdVersionIdMismatch,
            StructuredMutation::VmMissingFragment => ErrorCode::VmIdMissingFragment,
            StructuredMutation::VmIdControllerMismatch => ErrorCode::VmIdControllerMismatch,
            StructuredMutation::VmMissingKid => ErrorCode::VmMissingKid,
            StructuredMutation::DanglingPurposeRef => ErrorCode::DanglingPurposeRef,
            StructuredMutation::WrongSelfHash | StructuredMutation::WrongRootDidSuffix => {
                ErrorCode::SelfHashMismatch
            }
            StructuredMutation::InconsistentSelfHashSlots => ErrorCode::SelfHashSlotMismatch,
            StructuredMutation::RootVersionNonzero => ErrorCode::RootVersionIdNonzero,
            StructuredMutation::RootPrevHashPresent => {
                ErrorCode::RootPrevDidDocumentSelfHashPresent
            }
            StructuredMutation::NonRootIdMismatch => ErrorCode::NonRootIdMismatch,
            StructuredMutation::NonRootPrevHashMismatch => {
                ErrorCode::PrevDidDocumentSelfHashMismatch
            }
            StructuredMutation::NonRootValidFromEqual
            | StructuredMutation::NonRootValidFromEarlier => {
                ErrorCode::ValidFromNotStrictlyIncreasing
            }
            StructuredMutation::NonRootVersionGap
            | StructuredMutation::NonRootVersionRepeat
            | StructuredMutation::NonRootVersionDecrease => ErrorCode::VersionIdNotIncremented,
            StructuredMutation::MalformedProofKid => ErrorCode::MalformedProofKid,
        }
    }

    /// Which baseline document this mutation should be applied to.
    pub fn target(self) -> MutationTarget {
        match self {
            StructuredMutation::NonRootIdMismatch
            | StructuredMutation::NonRootPrevHashMismatch
            | StructuredMutation::NonRootValidFromEqual
            | StructuredMutation::NonRootValidFromEarlier
            | StructuredMutation::NonRootVersionGap
            | StructuredMutation::NonRootVersionRepeat
            | StructuredMutation::MalformedProofKid => MutationTarget::NonRoot,
            StructuredMutation::NonRootVersionDecrease => MutationTarget::NonRootSecond,
            _ => MutationTarget::Root,
        }
    }

    /// Number of successive updates needed before applying this mutation.
    pub fn update_count(self) -> u32 {
        match self.target() {
            MutationTarget::Root => 0,
            MutationTarget::NonRoot => 1,
            MutationTarget::NonRootSecond => 2,
        }
    }

    /// Apply this mutation to `raw`.
    ///
    /// Returns `true` when the caller should call [`RawDidDocument::re_self_hash`]
    /// afterwards so the break remains a single-rule failure.
    pub fn apply(
        self,
        raw: &mut RawDidDocument,
        params: &TestVectorParams,
    ) -> anyhow::Result<bool> {
        let placeholder = params.mb_hash_function().placeholder_hash().to_string();
        match self {
            StructuredMutation::JcsReordered
            | StructuredMutation::JcsWhitespace
            | StructuredMutation::JcsNonMinimalNumber => return Ok(false),
            StructuredMutation::VersionIdString => {
                raw.replace("/versionId", serde_json::json!("0"))?;
            }
            StructuredMutation::MissingRequiredField => {
                raw.remove("/updateRules")?;
            }
            StructuredMutation::MalformedId => {
                raw.replace("/id", serde_json::json!("not-a-did"))?;
                return Ok(false);
            }
            StructuredMutation::ValidFromMicroseconds => {
                raw.replace(
                    "/validFrom",
                    serde_json::json!("2025-01-01T00:00:00.000001Z"),
                )?;
            }
            StructuredMutation::ValidFromPreEpoch => {
                raw.replace("/validFrom", serde_json::json!("1969-12-31T23:59:59Z"))?;
            }
            StructuredMutation::ValidFromLowercase => {
                raw.replace("/validFrom", serde_json::json!("2025-01-01t00:00:00z"))?;
            }
            StructuredMutation::ValidFromUnparseable => {
                raw.replace("/validFrom", serde_json::json!("2025-02-30T00:00:00Z"))?;
            }
            StructuredMutation::VmMissingSelfHash => {
                mutate_vm_id(raw, |id| {
                    let query = id
                        .find('?')
                        .ok_or_else(|| anyhow::anyhow!("VM id lacks query"))?;
                    let version = id[query..]
                        .find("versionId=")
                        .ok_or_else(|| anyhow::anyhow!("VM id lacks versionId"))?
                        + query;
                    id.replace_range(query + 1..version, "");
                    Ok(())
                })?;
                return Ok(false);
            }
            StructuredMutation::VmMissingVersionId => {
                mutate_vm_id(raw, |id| {
                    let amp = id
                        .find("&versionId=")
                        .ok_or_else(|| anyhow::anyhow!("VM id lacks versionId"))?;
                    let fragment = id.find('#').unwrap_or(id.len());
                    id.replace_range(amp..fragment, "");
                    Ok(())
                })?;
                return Ok(false);
            }
            StructuredMutation::VmWrongOrder => {
                mutate_vm_id(raw, |id| {
                    let query = id
                        .find('?')
                        .ok_or_else(|| anyhow::anyhow!("VM id lacks query"))?;
                    let fragment = id.find('#').unwrap_or(id.len());
                    let self_hash = id[query + 1..fragment]
                        .split('&')
                        .find(|part| part.starts_with("selfHash="))
                        .ok_or_else(|| anyhow::anyhow!("VM id lacks selfHash"))?;
                    let version = id[query + 1..fragment]
                        .split('&')
                        .find(|part| part.starts_with("versionId="))
                        .ok_or_else(|| anyhow::anyhow!("VM id lacks versionId"))?;
                    id.replace_range(query + 1..fragment, &format!("{version}&{self_hash}"));
                    Ok(())
                })?;
                return Ok(false);
            }
            StructuredMutation::VmSelfHashMismatch => {
                mutate_vm_id(raw, |id| replace_query_value(id, "selfHash", &placeholder))?;
                return Ok(false);
            }
            StructuredMutation::VmVersionIdMismatch => {
                mutate_vm_id(raw, |id| replace_query_value(id, "versionId", "99"))?;
                return Ok(false);
            }
            StructuredMutation::VmMissingFragment => {
                mutate_vm_id(raw, |id| {
                    id.truncate(
                        id.find('#')
                            .ok_or_else(|| anyhow::anyhow!("VM id lacks fragment"))?,
                    );
                    Ok(())
                })?;
                return Ok(false);
            }
            StructuredMutation::VmIdControllerMismatch => {
                mutate_vm_id(raw, |id| {
                    let replacement = id.replacen("did:webplus:", "did:webplus:other.", 1);
                    *id = replacement;
                    Ok(())
                })?;
                return Ok(false);
            }
            StructuredMutation::VmMissingKid => {
                raw.remove("/verificationMethod/0/publicKeyJwk/kid")?;
                return Ok(false);
            }
            StructuredMutation::DanglingPurposeRef => {
                raw.replace("/authentication/0", serde_json::json!("#99999"))?;
                return Ok(false);
            }
            StructuredMutation::WrongSelfHash => {
                raw.replace("/selfHash", serde_json::json!(placeholder))?;
                return Ok(false);
            }
            StructuredMutation::WrongRootDidSuffix => {
                mutate_string(raw, "/id", |id| replace_did_suffix(id, &placeholder))?;
                return Ok(false);
            }
            StructuredMutation::InconsistentSelfHashSlots => {
                // Keep VM identity checks passing (kid == id, controller == doc id) while
                // making query selfHash slots disagree with document.selfHash / DID suffix.
                mutate_vm_id(raw, |id| replace_query_value(id, "selfHash", &placeholder))?;
                mutate_string(raw, "/verificationMethod/0/publicKeyJwk/kid", |kid| {
                    replace_query_value(kid, "selfHash", &placeholder)
                })?;
                return Ok(false);
            }
            StructuredMutation::RootVersionNonzero => {
                raw.replace("/versionId", serde_json::json!(1))?;
            }
            StructuredMutation::RootPrevHashPresent => {
                raw.mutate(|value| {
                    value.as_object_mut().unwrap().insert(
                        "prevDIDDocumentSelfHash".to_owned(),
                        serde_json::json!(placeholder),
                    );
                    Ok(())
                })?;
            }
            StructuredMutation::NonRootIdMismatch => {
                mutate_string(raw, "/id", |id| {
                    let replacement = id.replacen("did:webplus:", "did:webplus:other.", 1);
                    *id = replacement;
                    Ok(())
                })?;
            }
            StructuredMutation::NonRootPrevHashMismatch => {
                raw.replace("/prevDIDDocumentSelfHash", serde_json::json!(placeholder))?;
            }
            StructuredMutation::NonRootValidFromEqual => {
                raw.replace("/validFrom", serde_json::json!("2025-01-01T00:00:00Z"))?;
            }
            StructuredMutation::NonRootValidFromEarlier => {
                raw.replace("/validFrom", serde_json::json!("2024-12-31T23:59:59Z"))?;
            }
            StructuredMutation::NonRootVersionGap => {
                raw.replace("/versionId", serde_json::json!(2))?;
            }
            StructuredMutation::NonRootVersionRepeat
            | StructuredMutation::NonRootVersionDecrease => {
                raw.replace("/versionId", serde_json::json!(0))?;
            }
            StructuredMutation::MalformedProofKid => {
                mutate_proof_string(raw, "/proofs/0", |proof| {
                    rewrite_detached_jws_header_kid(proof, "not-a-multicodec-pub-key")
                })?;
            }
        }
        Ok(true)
    }

    /// Emit the mutated document as one jsonl line (canonical or deliberately non-JCS).
    pub fn emit_line(self, raw: &RawDidDocument) -> anyhow::Result<String> {
        match self {
            StructuredMutation::JcsReordered => reversed_object_line(raw.value()),
            StructuredMutation::JcsWhitespace => {
                let line = raw.to_jcs_line()?;
                Ok(line.replacen(':', ": ", 1))
            }
            StructuredMutation::JcsNonMinimalNumber => {
                let line = raw.to_jcs_line()?;
                Ok(line.replacen("\"versionId\":0", "\"versionId\":0.0", 1))
            }
            _ => raw.to_jcs_line(),
        }
    }
}

impl std::fmt::Display for StructuredMutation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn reversed_object_line(value: &serde_json::Value) -> anyhow::Result<String> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("document is not an object"))?;
    let member_v = object
        .iter()
        .rev()
        .map(|(key, value)| {
            Ok(format!(
                "{}:{}",
                serde_json::to_string(key)?,
                serde_json_canonicalizer::to_string(value)?
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(format!("{{{}}}", member_v.join(",")))
}

fn mutate_vm_id(
    raw: &mut RawDidDocument,
    mutation: impl FnOnce(&mut String) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    mutate_string(raw, "/verificationMethod/0/id", mutation)
}

fn mutate_string(
    raw: &mut RawDidDocument,
    pointer: &str,
    mutation: impl FnOnce(&mut String) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut string = raw
        .value()
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{pointer} is not a string"))?
        .to_owned();
    mutation(&mut string)?;
    raw.replace(pointer, serde_json::Value::String(string))?;
    Ok(())
}

fn replace_query_value(id: &mut String, name: &str, replacement: &str) -> anyhow::Result<()> {
    let marker = format!("{name}=");
    let start = id
        .find(&marker)
        .ok_or_else(|| anyhow::anyhow!("query value is missing"))?
        + marker.len();
    let end = id[start..]
        .find(['&', '#'])
        .map(|offset| start + offset)
        .unwrap_or(id.len());
    id.replace_range(start..end, replacement);
    Ok(())
}

fn replace_did_suffix(did_url: &mut String, replacement: &str) -> anyhow::Result<()> {
    let end = did_url.find(['?', '#']).unwrap_or(did_url.len());
    let start = did_url[..end]
        .rfind(':')
        .ok_or_else(|| anyhow::anyhow!("DID suffix is missing"))?
        + 1;
    did_url.replace_range(start..end, replacement);
    Ok(())
}

/// Rewrite the `kid` claim in a compact-form JWS header (typically detached `header..sig`).
fn rewrite_detached_jws_header_kid(jws: &mut String, new_kid: &str) -> anyhow::Result<()> {
    use base64::Engine;

    let mut part_i = jws.splitn(3, '.');
    let header_b64 = part_i
        .next()
        .ok_or_else(|| anyhow::anyhow!("JWS missing header"))?;
    let payload = part_i
        .next()
        .ok_or_else(|| anyhow::anyhow!("JWS missing payload segment"))?;
    let signature_b64 = part_i
        .next()
        .ok_or_else(|| anyhow::anyhow!("JWS missing signature"))?;

    let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_byte_v = engine
        .decode(header_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("JWS header is not base64url: {e}"))?;
    let mut header: serde_json::Value = serde_json::from_slice(&header_byte_v)?;
    header
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("JWS header is not a JSON object"))?
        .insert("kid".to_owned(), serde_json::Value::String(new_kid.to_owned()));
    let new_header_b64 = engine.encode(serde_json::to_vec(&header)?);
    *jws = format!("{new_header_b64}.{payload}.{signature_b64}");
    Ok(())
}

/// Helpers shared with conformance rule cases that mutate proof strings in place.
pub(crate) fn mutate_proof_string(
    raw: &mut RawDidDocument,
    pointer: &str,
    mutation: impl FnOnce(&mut String) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    mutate_string(raw, pointer, mutation)
}
