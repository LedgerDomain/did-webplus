use std::collections::HashMap;

use did_webplus_core::{
    DID, DIDDocument, PublicKeySet, RootLevelUpdateRules, UpdateKey, UpdatesDisallowed,
};
use did_webplus_mock::{Microledger, MicroledgerMutView, MicroledgerView};
use signature_dyn::SignerT;

use crate::{BaseChoice, DeterministicRng, HashFunctionChoice, KeyTypeChoice, TestVectorParams};

/// Builds valid did:webplus microledgers via [`DIDDocument`] create/sign/finalize APIs,
/// validated incrementally with [`did_webplus_mock::Microledger`].
///
/// Keys and `validFrom` timestamps come from a [`DeterministicRng`] so the same
/// `(params, rng seed)` always yields the same DID history. The happy path uses a
/// single [`UpdateKey`] in each document's `updateRules` (except after
/// [`Self::deactivate`]).
#[derive(Debug)]
pub struct MicroledgerBuilder {
    params: TestVectorParams,
    rng: DeterministicRng,
    microledger: Microledger,
    current_public_key_set: PublicKeySet<mbx::MBPubKey>,
    signer_bytes_m: HashMap<mbx::MBPubKey, signature_dyn::SignerBytes>,
    /// Private key authorized by the latest document's `updateRules`; `None` after deactivation.
    update_signer_bytes_o: Option<signature_dyn::SignerBytes>,
}

impl MicroledgerBuilder {
    /// Create a root DID document and wrap it in a verified [`Microledger`].
    ///
    /// Consumes `rng` so subsequent [`Self::update`] / [`Self::deactivate`] calls
    /// continue the same deterministic key and timestamp streams.
    pub fn create(params: TestVectorParams, mut rng: DeterministicRng) -> anyhow::Result<Self> {
        let (signer_bytes_m, current_public_key_set) = Self::generate_new_keys(&params, &mut rng)?;

        let update_signer = rng.generate_private_key(params.key_type);
        let update_signer_bytes = update_signer
            .extract_signer_bytes()
            .map_err(|e| anyhow::anyhow!("failed to extract update signer bytes: {}", e))?;
        let update_pub_key = Self::pub_key_from_signer(&*update_signer, params.base)?;

        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: update_pub_key,
        });
        let valid_from = rng.next_timestamp();
        let public_key_set = Self::borrowed_public_key_set(&current_public_key_set);
        let mb_hash_function = params.mb_hash_function();

        let mut root_did_document = DIDDocument::create_unsigned_root(
            &params.host,
            params.port_o,
            params.path_o().as_deref(),
            update_rules,
            valid_from,
            public_key_set,
            &mb_hash_function,
        )?;
        // Root needs no proof; finalize self-hashes and verifies the root.
        root_did_document.finalize(None)?;

        let microledger = Microledger::create(root_did_document)?;

        Ok(Self {
            params,
            rng,
            microledger,
            current_public_key_set,
            signer_bytes_m,
            update_signer_bytes_o: Some(update_signer_bytes),
        })
    }

    /// Create a root and then append `update_count` successive valid updates.
    ///
    /// `update_count == 0` yields a root-only microledger (same as [`Self::create`]).
    pub fn create_with_updates(
        params: TestVectorParams,
        rng: DeterministicRng,
        update_count: u32,
    ) -> anyhow::Result<Self> {
        let mut builder = Self::create(params, rng)?;
        for _ in 0..update_count {
            builder.update()?;
        }
        Ok(builder)
    }

    /// Append a non-root DID document that rotates verification-method and update keys.
    ///
    /// Signs with the update key from the previous document's `updateRules`, then
    /// validates via [`MicroledgerMutView::update`].
    pub fn update(&mut self) -> anyhow::Result<&DIDDocument> {
        self.update_with_choices(self.params.clone(), [self.params.key_type; 5])
    }

    /// Append an update using new key, hash-function, and multibase choices.
    ///
    /// The update is authorized by the previous document's update key while its
    /// new verification methods, update key, and self-hash use the supplied
    /// choices. Subsequent calls to [`Self::update`] continue with these choices.
    pub fn update_with_crypto(
        &mut self,
        key_type: KeyTypeChoice,
        hash_function: HashFunctionChoice,
        base: BaseChoice,
    ) -> anyhow::Result<&DIDDocument> {
        let mut next_params = self.params.clone();
        next_params.key_type = key_type;
        next_params.hash_function = hash_function;
        next_params.base = base;
        self.update_with_choices(next_params, [key_type; 5])
    }

    /// Append an update whose five verification-method purposes use distinct key types.
    ///
    /// Key types are ordered as authentication, assertion method, key agreement,
    /// capability invocation, and capability delegation. The next update key
    /// continues to use the primary key type in [`Self::params`].
    pub fn update_with_key_types(
        &mut self,
        key_type_v: [KeyTypeChoice; 5],
    ) -> anyhow::Result<&DIDDocument> {
        self.update_with_choices(self.params.clone(), key_type_v)
    }

    fn update_with_choices(
        &mut self,
        next_params: TestVectorParams,
        key_type_v: [KeyTypeChoice; 5],
    ) -> anyhow::Result<&DIDDocument> {
        let update_signer_bytes = self
            .update_signer_bytes_o
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cannot update a deactivated DID microledger"))?;

        let (new_signer_bytes_m, new_public_key_set) =
            Self::generate_keys(next_params.base, key_type_v, &mut self.rng)?;

        let next_update_signer = self.rng.generate_private_key(next_params.key_type);
        let next_update_signer_bytes = next_update_signer
            .extract_signer_bytes()
            .map_err(|e| anyhow::anyhow!("failed to extract next update signer bytes: {}", e))?;
        let next_update_pub_key =
            Self::pub_key_from_signer(&*next_update_signer, next_params.base)?;

        let next_update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: next_update_pub_key,
        });
        let valid_from = self.rng.next_timestamp();
        let public_key_set = Self::borrowed_public_key_set(&new_public_key_set);
        let mb_hash_function = next_params.mb_hash_function();

        let prev_did_document = self.microledger.view().latest_did_document().clone();
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            &prev_did_document,
            next_update_rules,
            valid_from,
            public_key_set,
            &mb_hash_function,
        )?;

        let jws = {
            let update_pub_key = Self::pub_key_from_signer(update_signer_bytes, self.params.base)?;
            new_did_document.sign(update_pub_key.to_string(), update_signer_bytes)?
        };
        new_did_document.add_proof(jws.into_string());
        new_did_document.finalize(Some(&prev_did_document))?;

        self.microledger.mut_view().update(new_did_document)?;
        self.params = next_params;
        self.current_public_key_set = new_public_key_set;
        self.signer_bytes_m = new_signer_bytes_m;
        self.update_signer_bytes_o = Some(next_update_signer_bytes);

        Ok(self.microledger.view().latest_did_document())
    }

    /// Append a deactivation document: `updateRules` = updates-disallowed, empty VMs.
    ///
    /// After this succeeds, further [`Self::update`] / [`Self::deactivate`] calls fail.
    pub fn deactivate(&mut self) -> anyhow::Result<&DIDDocument> {
        let update_signer_bytes = self.update_signer_bytes_o.as_ref().ok_or_else(|| {
            anyhow::anyhow!("cannot deactivate an already-deactivated DID microledger")
        })?;

        let new_public_key_set = PublicKeySet::empty();
        let next_update_rules = RootLevelUpdateRules::from(UpdatesDisallowed {});
        let valid_from = self.rng.next_timestamp();
        let public_key_set = Self::borrowed_public_key_set(&new_public_key_set);
        let mb_hash_function = self.params.mb_hash_function();

        let prev_did_document = self.microledger.view().latest_did_document().clone();
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            &prev_did_document,
            next_update_rules,
            valid_from,
            public_key_set,
            &mb_hash_function,
        )?;

        let jws = {
            let update_pub_key = Self::pub_key_from_signer(update_signer_bytes, self.params.base)?;
            new_did_document.sign(update_pub_key.to_string(), update_signer_bytes)?
        };
        new_did_document.add_proof(jws.into_string());
        new_did_document.finalize(Some(&prev_did_document))?;

        self.microledger.mut_view().update(new_did_document)?;
        self.current_public_key_set = new_public_key_set;
        self.signer_bytes_m.clear();
        self.update_signer_bytes_o = None;

        Ok(self.microledger.view().latest_did_document())
    }

    /// Generation parameters used for this microledger.
    pub fn params(&self) -> &TestVectorParams {
        &self.params
    }

    /// The DID identity (includes root self-hash).
    pub fn did(&self) -> &DID {
        self.microledger.view().did()
    }

    /// Borrow the in-memory verified microledger.
    pub fn microledger(&self) -> &Microledger {
        &self.microledger
    }

    /// Consume the builder and return the verified microledger.
    pub fn into_microledger(self) -> Microledger {
        self.microledger
    }

    /// Number of DID documents currently in the microledger (`versionId` of latest + 1).
    pub fn version_count(&self) -> u32 {
        self.microledger.view().latest_did_document().version_id + 1
    }

    /// Whether the latest document has `updateRules` set to updates-disallowed.
    pub fn is_deactivated(&self) -> bool {
        self.update_signer_bytes_o.is_none()
    }

    /// Public keys listed in the latest DID document.
    pub fn current_public_key_set(&self) -> &PublicKeySet<mbx::MBPubKey> {
        &self.current_public_key_set
    }

    /// Canonical JCS jsonl lines for every DID document in order (root first).
    pub fn canonical_jsonl_lines(&self) -> anyhow::Result<Vec<String>> {
        let (count, iter) = self.microledger.view().select_did_documents(None, None);
        let mut line_v = Vec::with_capacity(count as usize);
        for did_document in iter {
            line_v.push(did_document.serialize_canonically()?);
        }
        Ok(line_v)
    }

    fn pub_key_from_signer(
        signer: &dyn SignerT,
        base: crate::BaseChoice,
    ) -> anyhow::Result<mbx::MBPubKey> {
        let verifier_bytes = signer
            .get_verifier_bytes()
            .map_err(|e| anyhow::anyhow!("failed to get verifier bytes from signer: {}", e))?;
        mbx::MBPubKey::try_from_verifier_bytes(mbx::Base::from(base), &verifier_bytes)
            .map_err(|e| anyhow::anyhow!("failed to encode public key as multibase: {}", e))
    }

    fn borrowed_public_key_set(
        owned: &PublicKeySet<mbx::MBPubKey>,
    ) -> PublicKeySet<&mbx::MBPubKey> {
        PublicKeySet {
            authentication_v: owned.authentication_v.iter().collect(),
            assertion_method_v: owned.assertion_method_v.iter().collect(),
            key_agreement_v: owned.key_agreement_v.iter().collect(),
            capability_invocation_v: owned.capability_invocation_v.iter().collect(),
            capability_delegation_v: owned.capability_delegation_v.iter().collect(),
        }
    }

    /// One private/public key per verification-method purpose, using `params.key_type` / `params.base`.
    fn generate_new_keys(
        params: &TestVectorParams,
        rng: &mut DeterministicRng,
    ) -> anyhow::Result<(
        HashMap<mbx::MBPubKey, signature_dyn::SignerBytes>,
        PublicKeySet<mbx::MBPubKey>,
    )> {
        Self::generate_keys(params.base, [params.key_type; 5], rng)
    }

    fn generate_keys(
        base: BaseChoice,
        key_type_v: [KeyTypeChoice; 5],
        rng: &mut DeterministicRng,
    ) -> anyhow::Result<(
        HashMap<mbx::MBPubKey, signature_dyn::SignerBytes>,
        PublicKeySet<mbx::MBPubKey>,
    )> {
        let signing_key_authentication = rng.generate_private_key(key_type_v[0]);
        let signing_key_assertion_method = rng.generate_private_key(key_type_v[1]);
        let signing_key_key_agreement = rng.generate_private_key(key_type_v[2]);
        let signing_key_capability_invocation = rng.generate_private_key(key_type_v[3]);
        let signing_key_capability_delegation = rng.generate_private_key(key_type_v[4]);

        let pub_key_authentication = Self::pub_key_from_signer(&*signing_key_authentication, base)?;
        let pub_key_assertion_method =
            Self::pub_key_from_signer(&*signing_key_assertion_method, base)?;
        let pub_key_key_agreement = Self::pub_key_from_signer(&*signing_key_key_agreement, base)?;
        let pub_key_capability_invocation =
            Self::pub_key_from_signer(&*signing_key_capability_invocation, base)?;
        let pub_key_capability_delegation =
            Self::pub_key_from_signer(&*signing_key_capability_delegation, base)?;

        let current_public_key_set = PublicKeySet {
            authentication_v: vec![pub_key_authentication.clone()],
            assertion_method_v: vec![pub_key_assertion_method.clone()],
            key_agreement_v: vec![pub_key_key_agreement.clone()],
            capability_invocation_v: vec![pub_key_capability_invocation.clone()],
            capability_delegation_v: vec![pub_key_capability_delegation.clone()],
        };

        let mut signer_bytes_m = HashMap::new();
        signer_bytes_m.insert(
            pub_key_authentication,
            signing_key_authentication
                .extract_signer_bytes()
                .map_err(|e| anyhow::anyhow!("extract auth signer: {}", e))?,
        );
        signer_bytes_m.insert(
            pub_key_assertion_method,
            signing_key_assertion_method
                .extract_signer_bytes()
                .map_err(|e| anyhow::anyhow!("extract assertion signer: {}", e))?,
        );
        signer_bytes_m.insert(
            pub_key_key_agreement,
            signing_key_key_agreement
                .extract_signer_bytes()
                .map_err(|e| anyhow::anyhow!("extract keyAgreement signer: {}", e))?,
        );
        signer_bytes_m.insert(
            pub_key_capability_invocation,
            signing_key_capability_invocation
                .extract_signer_bytes()
                .map_err(|e| anyhow::anyhow!("extract capabilityInvocation signer: {}", e))?,
        );
        signer_bytes_m.insert(
            pub_key_capability_delegation,
            signing_key_capability_delegation
                .extract_signer_bytes()
                .map_err(|e| anyhow::anyhow!("extract capabilityDelegation signer: {}", e))?,
        );

        Ok((signer_bytes_m, current_public_key_set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeterministicRng, TIMESTAMP_BASE, TestVectorParams};

    #[test]
    fn create_update_deactivate_happy_path() {
        let params = TestVectorParams::baseline("example.com");
        let rng = DeterministicRng::for_vector("seed", "builder-happy-path");
        let mut builder = MicroledgerBuilder::create(params, rng).expect("create");
        assert_eq!(builder.version_count(), 1);
        assert!(!builder.is_deactivated());
        assert_eq!(
            builder
                .microledger()
                .view()
                .root_did_document()
                .valid_from()
                .unwrap(),
            TIMESTAMP_BASE
        );

        builder.update().expect("update");
        assert_eq!(builder.version_count(), 2);

        builder.deactivate().expect("deactivate");
        assert_eq!(builder.version_count(), 3);
        assert!(builder.is_deactivated());
        assert!(builder.update().is_err());

        let line_v = builder.canonical_jsonl_lines().expect("jsonl");
        assert_eq!(line_v.len(), 3);
    }

    #[test]
    fn create_with_updates_and_determinism() {
        let params = TestVectorParams::baseline("example.com");
        let a = MicroledgerBuilder::create_with_updates(
            params.clone(),
            DeterministicRng::for_vector("seed", "det"),
            2,
        )
        .expect("a");
        let b = MicroledgerBuilder::create_with_updates(
            params,
            DeterministicRng::for_vector("seed", "det"),
            2,
        )
        .expect("b");

        assert_eq!(a.did(), b.did());
        assert_eq!(
            a.canonical_jsonl_lines().unwrap(),
            b.canonical_jsonl_lines().unwrap()
        );
        assert_eq!(a.version_count(), 3);
    }
}
