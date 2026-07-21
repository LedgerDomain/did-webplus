use did_webplus_core::DIDDocument;
use selfhash::{HashFunctionT, HashRefT};

use crate::{ErrorCode, StructuredMutation};

/// A DID document represented below the typed `did-webplus-core` API.
///
/// This representation is intended for constructing negative test vectors which
/// the typed API cannot emit. It supports JSON Pointer-targeted mutation,
/// did:webplus self-hash slot replacement, detached proof regeneration, and both
/// canonical and deliberately non-canonical JSON emission.
///
/// Structured mutations ([`StructuredMutation`]) share a rule table with this
/// type via [`Self::predicted_error_code`] so fuzz-lite and conformance negatives
/// compute the same expected outcomes.
#[derive(Clone, Debug, PartialEq)]
pub struct RawDidDocument {
    value: serde_json::Value,
}

impl RawDidDocument {
    /// Advisory [`ErrorCode`] predicted when `mutation` is applied to an otherwise-valid document.
    ///
    /// Fuzz-lite uses this rule knowledge (rather than hard-coding outcomes per vector)
    /// so expected metadata stays aligned with the structured mutation primitives.
    pub fn predicted_error_code(mutation: StructuredMutation) -> ErrorCode {
        mutation.error_code()
    }

    /// Convert a typed DID document to its raw JSON representation.
    pub fn from_did_document(did_document: &DIDDocument) -> anyhow::Result<Self> {
        Self::from_value(serde_json::to_value(did_document)?)
    }

    /// Wrap a raw JSON value after checking that it is a DID-document object.
    ///
    /// Individual fields are deliberately not validated, since malformed fields
    /// are the purpose of this type.
    pub fn from_value(value: serde_json::Value) -> anyhow::Result<Self> {
        anyhow::ensure!(value.is_object(), "raw DID document must be a JSON object");
        Ok(Self { value })
    }

    /// Borrow the underlying JSON value.
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    /// Consume this wrapper and return the underlying JSON value.
    pub fn into_value(self) -> serde_json::Value {
        self.value
    }

    /// Parse the document `id` field as a did:webplus [`DID`](did_webplus_core::DID).
    ///
    /// After [`Self::re_self_hash`] on a root document, this returns the updated DID
    /// whose suffix matches the recomputed self-hash.
    pub fn did(&self) -> anyhow::Result<did_webplus_core::DID> {
        let id = self
            .object()?
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("id must be a string"))?;
        did_webplus_core::DID::try_from(id.to_owned()).map_err(Into::into)
    }

    /// Apply an arbitrary targeted mutation to the underlying JSON value.
    pub fn mutate(
        &mut self,
        mutation: impl FnOnce(&mut serde_json::Value) -> anyhow::Result<()>,
    ) -> anyhow::Result<&mut Self> {
        mutation(&mut self.value)?;
        Ok(self)
    }

    /// Replace the value at an existing RFC 6901 JSON Pointer.
    pub fn replace(
        &mut self,
        json_pointer: &str,
        replacement: serde_json::Value,
    ) -> anyhow::Result<&mut Self> {
        let target = self
            .value
            .pointer_mut(json_pointer)
            .ok_or_else(|| anyhow::anyhow!("JSON Pointer does not exist: {json_pointer}"))?;
        *target = replacement;
        Ok(self)
    }

    /// Remove and return the value at an RFC 6901 JSON Pointer.
    pub fn remove(&mut self, json_pointer: &str) -> anyhow::Result<serde_json::Value> {
        let (parent_pointer, token) = json_pointer
            .rsplit_once('/')
            .ok_or_else(|| anyhow::anyhow!("JSON Pointer must identify a child value"))?;
        let token = token.replace("~1", "/").replace("~0", "~");
        let parent = self.value.pointer_mut(parent_pointer).ok_or_else(|| {
            anyhow::anyhow!("JSON Pointer parent does not exist: {parent_pointer}")
        })?;

        match parent {
            serde_json::Value::Object(object) => object.remove(&token).ok_or_else(|| {
                anyhow::anyhow!("JSON object member does not exist: {json_pointer}")
            }),
            serde_json::Value::Array(array) => {
                let index = token
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("invalid JSON array index: {token}"))?;
                anyhow::ensure!(index < array.len(), "JSON array index is out of bounds");
                Ok(array.remove(index))
            }
            _ => anyhow::bail!("JSON Pointer parent is not an object or array"),
        }
    }

    /// Recompute the document self-hash and populate every applicable slot.
    ///
    /// Root documents update the DID suffix, `selfHash`, and every verification
    /// method's `id`, `controller`, and JWK `kid` root/query slots. Non-root
    /// documents update `selfHash` and the query self-hash in verification-method
    /// `id` and JWK `kid` values.
    pub fn re_self_hash(&mut self) -> anyhow::Result<&mbx::MBHashStr> {
        let current_self_hash = self.self_hash()?.to_owned();
        let hash_function = current_self_hash.hash_function();
        let placeholder = hash_function.placeholder_hash();
        self.set_self_hash_slots_to(placeholder.as_ref())?;
        let digest_data = serde_json_canonicalizer::to_vec(&self.value)?;
        let self_hash = hash_function.hash(&digest_data);
        self.set_self_hash_slots_to(self_hash.as_ref())?;
        self.self_hash()
    }

    /// Replace `proofs` with one detached, unencoded-payload JWS.
    ///
    /// The signing payload follows the core implementation: proofs are omitted,
    /// all current-document self-hash slots are placeholders, and the result is
    /// JCS serialized. Call [`Self::re_self_hash`] afterwards because replacing
    /// the proof changes the document digest.
    pub fn re_sign(
        &mut self,
        kid: String,
        signer: &dyn signature_dyn::SignerT,
    ) -> anyhow::Result<&mut Self> {
        let mut signing_value = self.value.clone();
        let signing_object = signing_value
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("raw DID document must be a JSON object"))?;
        signing_object.remove("proofs");

        let mut signing_document = Self::from_value(signing_value)?;
        let placeholder = signing_document
            .self_hash()?
            .hash_function()
            .placeholder_hash();
        signing_document.set_self_hash_slots_to(placeholder.as_ref())?;
        let payload = serde_json_canonicalizer::to_vec(signing_document.value())?;
        let jws = did_webplus_jws::JWS::signed(
            kid,
            &mut payload.as_slice(),
            did_webplus_jws::JWSPayloadPresence::Detached,
            did_webplus_jws::JWSPayloadEncoding::None,
            signer,
        )?;

        self.object_mut()?.insert(
            "proofs".to_owned(),
            serde_json::Value::Array(vec![serde_json::Value::String(jws.into_string())]),
        );
        Ok(self)
    }

    /// Emit this document as one canonical JCS JSONL line (without a newline).
    pub fn to_jcs_line(&self) -> anyhow::Result<String> {
        Ok(serde_json_canonicalizer::to_string(&self.value)?)
    }

    /// Emit valid JSON that is deliberately not canonical JCS.
    ///
    /// A trailing space keeps the output on one JSONL line while guaranteeing it
    /// differs from its canonical serialization.
    pub fn to_non_jcs_line(&self) -> anyhow::Result<String> {
        let mut line = self.to_jcs_line()?;
        line.push(' ');
        Ok(line)
    }

    fn object(&self) -> anyhow::Result<&serde_json::Map<String, serde_json::Value>> {
        self.value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("raw DID document must be a JSON object"))
    }

    fn object_mut(&mut self) -> anyhow::Result<&mut serde_json::Map<String, serde_json::Value>> {
        self.value
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("raw DID document must be a JSON object"))
    }

    fn self_hash(&self) -> anyhow::Result<&mbx::MBHashStr> {
        let self_hash = self
            .object()?
            .get("selfHash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("selfHash must be a string"))?;
        mbx::MBHashStr::new_ref(self_hash).map_err(Into::into)
    }

    fn is_root(&self) -> anyhow::Result<bool> {
        Ok(!self.object()?.contains_key("prevDIDDocumentSelfHash"))
    }

    fn set_self_hash_slots_to(&mut self, hash: &mbx::MBHashStr) -> anyhow::Result<()> {
        let is_root = self.is_root()?;
        Self::set_string_field(self.object_mut()?, "selfHash", |value| {
            *value = hash.as_str().to_owned();
            Ok(())
        })?;

        if is_root {
            Self::set_string_field(self.object_mut()?, "id", |value| {
                Self::replace_did_root_hash(value, hash)
            })?;
        }

        let verification_method_v = self
            .object_mut()?
            .get_mut("verificationMethod")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| anyhow::anyhow!("verificationMethod must be an array"))?;
        for verification_method in verification_method_v {
            let verification_method = verification_method
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("verificationMethod entry must be an object"))?;
            Self::set_string_field(verification_method, "id", |value| {
                if is_root {
                    Self::replace_did_root_hash(value, hash)?;
                }
                Self::replace_query_self_hash(value, hash)
            })?;
            if is_root {
                Self::set_string_field(verification_method, "controller", |value| {
                    Self::replace_did_root_hash(value, hash)
                })?;
            }

            if let Some(public_key_jwk) = verification_method
                .get_mut("publicKeyJwk")
                .and_then(serde_json::Value::as_object_mut)
            {
                if public_key_jwk.contains_key("kid") {
                    Self::set_string_field(public_key_jwk, "kid", |value| {
                        if is_root {
                            Self::replace_did_root_hash(value, hash)?;
                        }
                        Self::replace_query_self_hash(value, hash)
                    })?;
                }
            }
        }
        Ok(())
    }

    fn set_string_field(
        object: &mut serde_json::Map<String, serde_json::Value>,
        field: &str,
        update: impl FnOnce(&mut String) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let value = object
            .get_mut(field)
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("{field} must be a string"))?
            .to_owned();
        let mut value = value;
        update(&mut value)?;
        object.insert(field.to_owned(), serde_json::Value::String(value));
        Ok(())
    }

    fn replace_did_root_hash(value: &mut String, hash: &mbx::MBHashStr) -> anyhow::Result<()> {
        let did_end = value
            .find('?')
            .or_else(|| value.find('#'))
            .unwrap_or(value.len());
        let hash_start = value[..did_end]
            .rfind(':')
            .map(|index| index + 1)
            .ok_or_else(|| anyhow::anyhow!("DID value has no root self-hash slot: {value}"))?;
        value.replace_range(hash_start..did_end, hash.as_str());
        Ok(())
    }

    fn replace_query_self_hash(value: &mut String, hash: &mbx::MBHashStr) -> anyhow::Result<()> {
        let value_start = value
            .find("?selfHash=")
            .map(|index| index + "?selfHash=".len())
            .ok_or_else(|| anyhow::anyhow!("DID URL has no selfHash query parameter: {value}"))?;
        let value_end = value[value_start..]
            .find('&')
            .map(|index| value_start + index)
            .unwrap_or(value.len());
        value.replace_range(value_start..value_end, hash.as_str());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BaseChoice, DeterministicRng, MicroledgerBuilder, TestVectorParams};
    use did_webplus_mock::MicroledgerView;

    #[test]
    fn mutation_and_re_self_hash_produce_a_valid_root() {
        let builder = MicroledgerBuilder::create(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("seed", "raw-root"),
        )
        .unwrap();
        let root = builder.microledger().view().root_did_document();
        let original_did = root.did.clone();
        let mut raw = RawDidDocument::from_did_document(root).unwrap();

        raw.replace(
            "/validFrom",
            serde_json::Value::String("2025-01-02T00:00:00Z".to_owned()),
        )
        .unwrap();
        raw.re_self_hash().unwrap();

        let updated_did = raw.did().unwrap();
        assert_ne!(updated_did, original_did);
        assert_eq!(updated_did.root_self_hash(), raw.self_hash().unwrap());

        let reparsed: DIDDocument = serde_json::from_value(raw.value().clone()).unwrap();
        reparsed.verify_root_nonrecursive().unwrap();
        assert_eq!(reparsed.did, updated_did);
    }

    #[test]
    fn emits_canonical_and_deliberately_noncanonical_lines() {
        let builder = MicroledgerBuilder::create(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("seed", "raw-emission"),
        )
        .unwrap();
        let raw =
            RawDidDocument::from_did_document(builder.microledger().view().root_did_document())
                .unwrap();

        let canonical = raw.to_jcs_line().unwrap();
        let noncanonical = raw.to_non_jcs_line().unwrap();
        assert_eq!(noncanonical, format!("{canonical} "));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&canonical).unwrap(),
            serde_json::from_str::<serde_json::Value>(&noncanonical).unwrap()
        );
    }

    #[test]
    fn re_sign_replaces_proofs_with_a_valid_detached_jws() {
        let params = TestVectorParams::baseline("example.com");
        let builder = MicroledgerBuilder::create(
            params.clone(),
            DeterministicRng::for_vector("seed", "raw-resign-document"),
        )
        .unwrap();
        let mut raw =
            RawDidDocument::from_did_document(builder.microledger().view().root_did_document())
                .unwrap();
        let mut signer_rng = DeterministicRng::for_vector("seed", "raw-resign-key");
        let signer = signer_rng.generate_private_key(params.key_type);
        let verifier_bytes = signer.get_verifier_bytes().unwrap();
        let kid = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::from(BaseChoice::Base64Url),
            &verifier_bytes,
        )
        .unwrap()
        .to_string();

        raw.re_sign(kid, &*signer).unwrap();
        raw.re_self_hash().unwrap();

        let reparsed: DIDDocument = serde_json::from_value(raw.value().clone()).unwrap();
        reparsed.verify_root_nonrecursive().unwrap();
        assert_eq!(reparsed.proof_v.len(), 1);
    }

    #[test]
    fn re_self_hash_preserves_valid_non_root_slot_semantics() {
        let builder = MicroledgerBuilder::create_with_updates(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("seed", "raw-non-root"),
            1,
        )
        .unwrap();
        let previous = builder.microledger().view().root_did_document();
        let latest = builder.microledger().view().latest_did_document();
        let expected_hash = latest.self_hash.clone();
        let mut raw = RawDidDocument::from_did_document(latest).unwrap();

        assert_eq!(raw.re_self_hash().unwrap(), expected_hash.as_ref());

        let reparsed: DIDDocument = serde_json::from_value(raw.value().clone()).unwrap();
        reparsed.verify_non_root_nonrecursive(previous).unwrap();
    }
}
