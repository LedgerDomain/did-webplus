use std::{collections::HashMap, ops::Deref};

use did_webplus_core::{
    DID, DIDDocument, DIDKeyResourceFullyQualified, KeyPurpose, PublicKeySet, RootLevelUpdateRules,
    UpdateKey, UpdatesDisallowed, now_utc_milliseconds,
};
use selfhash::HashRefT;
use signature_dyn::SignerT;

use crate::{Microledger, MicroledgerMutView, MicroledgerView, VDRClient};

pub struct ControlledDID {
    pub current_public_key_set: PublicKeySet<mbx::MBPubKey>,
    signer_bytes_m: HashMap<mbx::MBPubKey, signature_dyn::SignerBytes>,
    update_signing_key_o: Option<signature_dyn::SignerBytes>,
    microledger: Microledger,
}

impl ControlledDID {
    pub fn create(
        did_hostname: String,
        did_port_o: Option<u16>,
        did_path_o: Option<String>,
        hash_function: &selfhash::MBHashFunction,
        key_type: signature_dyn::KeyType,
        vdr_client: &dyn VDRClient,
    ) -> did_webplus_core::Result<Self> {
        // Generate the key set for use in the root DID document.
        let (signer_bytes_m, current_public_key_set) = Self::generate_new_keys(key_type);

        // Generate the update signing key (for when the this root DID document is updated later).
        let update_signing_key_b = key_type.generate_random_private_key();
        let update_verifying_key_b = update_signing_key_b.get_verifier()?;
        let update_pub_key = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &update_verifying_key_b.to_verifier_bytes(),
        )?;

        // Set the update rules.  In this case, just a single key.
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: update_pub_key.clone(),
        });
        let valid_from = now_utc_milliseconds();
        let public_key_set = PublicKeySet {
            authentication_v: current_public_key_set.authentication_v.iter().collect(),
            assertion_method_v: current_public_key_set.assertion_method_v.iter().collect(),
            key_agreement_v: current_public_key_set.key_agreement_v.iter().collect(),
            capability_invocation_v: current_public_key_set
                .capability_invocation_v
                .iter()
                .collect(),
            capability_delegation_v: current_public_key_set
                .capability_delegation_v
                .iter()
                .collect(),
        };
        let mut root_did_document = DIDDocument::create_unsigned_root(
            &did_hostname,
            did_port_o,
            did_path_o.as_deref(),
            update_rules,
            valid_from,
            public_key_set,
            hash_function,
        )?;
        // NOTE: There's no need to sign the root DID document, but it is allowed.
        // Finalize the root DID document.  In particular, this will self-hash the DID document.
        root_did_document.finalize(None)?;

        // Sanity check.
        root_did_document
            .verify_root_nonrecursive()
            .expect("programmer error");

        // Register the DID with the appropriate VDR.  The VDR mostly only has authority over if creation of a DID
        // is allowed.  Once the DID is being hosted by the VDR, all valid updates should be accepted by it.
        vdr_client.create_did(root_did_document.clone())?;
        // Create the Microledger.  This is the local copy of the DID document history, and in a way
        // is authoritative, so long as the updates are valid and can get to the VDR.
        let microledger = Microledger::create(root_did_document)?;
        Ok(Self {
            current_public_key_set,
            signer_bytes_m,
            update_signing_key_o: Some(update_signing_key_b.extract_signer_bytes()?),
            microledger,
        })
    }
    pub fn update(
        &mut self,
        key_type: signature_dyn::KeyType,
        vdr_client: &dyn VDRClient,
    ) -> did_webplus_core::Result<()> {
        // TODO: Factor this with deactivate and potentially create

        if self.update_signing_key_o.is_none() {
            return Err(did_webplus_core::Error::InvalidDIDUpdateOperation(
                "Can't update a deactivated DID".into(),
            ));
        }
        let update_signing_key = self.update_signing_key_o.as_ref().unwrap();

        // Generate the new key set to rotate in during the DID update.
        let (new_signer_bytes_m, new_public_key_set) = Self::generate_new_keys(key_type);

        // Generate the next update signing key (for when the this new DID document is updated later).
        // use signature_dyn::GenerateRandom;
        let next_update_signing_key_b = key_type.generate_random_private_key();
        let next_update_verifying_key_b = next_update_signing_key_b.get_verifier()?;
        let next_update_pub_key = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &next_update_verifying_key_b.to_verifier_bytes(),
        )?;

        let mb_hash_function = self.did().root_self_hash().hash_function();

        // Set the update rules for this new DID document.  In this case, just a single key.
        let next_update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: next_update_pub_key.clone(),
        });
        let valid_from = now_utc_milliseconds();
        let public_key_set = PublicKeySet {
            authentication_v: new_public_key_set.authentication_v.iter().collect(),
            assertion_method_v: new_public_key_set.assertion_method_v.iter().collect(),
            key_agreement_v: new_public_key_set.key_agreement_v.iter().collect(),
            capability_invocation_v: new_public_key_set.capability_invocation_v.iter().collect(),
            capability_delegation_v: new_public_key_set.capability_delegation_v.iter().collect(),
        };
        let prev_did_document = self.microledger.view().latest_did_document();
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            prev_did_document,
            next_update_rules,
            valid_from,
            public_key_set,
            &mb_hash_function,
        )?;

        // Sign the new DID document using the existing update_signing_key (the one referenced in the
        // previous DID document), and add the proof.
        let jws = {
            let update_verifying_key_b = update_signing_key.get_verifier()?;
            let update_pub_key = mbx::MBPubKey::try_from_verifier_bytes(
                mbx::Base::Base64Url,
                &update_verifying_key_b.to_verifier_bytes(),
            )?;
            use signature_dyn::SignerT;
            new_did_document.sign(update_pub_key.to_string(), update_signing_key)?
        };
        new_did_document.add_proof(jws.into_string());
        // Finalize the new DID document.  In particular, this will self-hash the DID document.
        new_did_document.finalize(Some(prev_did_document))?;

        // Sanity check.
        new_did_document.verify_non_root_nonrecursive(prev_did_document)?;

        vdr_client.update_did(new_did_document.clone())?;
        // If the VDR update succeeded, then update the local Microledger.
        self.microledger.mut_view().update(new_did_document)?;
        // Now update the local signer and public key set.
        self.current_public_key_set = new_public_key_set;
        self.signer_bytes_m = new_signer_bytes_m;
        self.update_signing_key_o = Some(next_update_signing_key_b.extract_signer_bytes()?);
        Ok(())
    }
    pub fn deactivate(&mut self, vdr_client: &dyn VDRClient) -> did_webplus_core::Result<()> {
        // TODO: Factor this with update and potentially create

        if self.update_signing_key_o.is_none() {
            return Err(did_webplus_core::Error::InvalidDIDUpdateOperation(
                "Can't update/deactivate a deactivated DID".into(),
            ));
        }
        let update_signing_key = self.update_signing_key_o.as_ref().unwrap();

        // Rotate out all pub keys and leave verification methods empty.
        let new_public_key_set = PublicKeySet::empty();

        let mb_hash_function = self.did().root_self_hash().hash_function();

        // Set the update rules for this new DID document.  In this case, just a single key.
        let next_update_rules = RootLevelUpdateRules::from(UpdatesDisallowed {});
        let valid_from = now_utc_milliseconds();
        let public_key_set = PublicKeySet {
            authentication_v: new_public_key_set.authentication_v.iter().collect(),
            assertion_method_v: new_public_key_set.assertion_method_v.iter().collect(),
            key_agreement_v: new_public_key_set.key_agreement_v.iter().collect(),
            capability_invocation_v: new_public_key_set.capability_invocation_v.iter().collect(),
            capability_delegation_v: new_public_key_set.capability_delegation_v.iter().collect(),
        };
        let prev_did_document = self.microledger.view().latest_did_document();
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            prev_did_document,
            next_update_rules,
            valid_from,
            public_key_set,
            &mb_hash_function,
        )?;

        // Sign the new DID document using the existing update_signing_key (the one referenced in the
        // previous DID document), and add the proof.
        let jws = {
            let update_verifying_key_b = update_signing_key.get_verifier()?;
            let update_pub_key = mbx::MBPubKey::try_from_verifier_bytes(
                mbx::Base::Base64Url,
                &update_verifying_key_b.to_verifier_bytes(),
            )?;
            new_did_document.sign(update_pub_key.to_string(), update_signing_key)?
        };
        new_did_document.add_proof(jws.into_string());
        // Finalize the new DID document.  In particular, this will self-hash the DID document.
        new_did_document.finalize(Some(prev_did_document))?;

        // Sanity check.
        new_did_document.verify_non_root_nonrecursive(prev_did_document)?;

        vdr_client.update_did(new_did_document.clone())?;
        // If the VDR update succeeded, then update the local Microledger.
        self.microledger.mut_view().update(new_did_document)?;
        // Now update the local signer and public key set.
        self.current_public_key_set = new_public_key_set;
        self.signer_bytes_m.clear();
        self.update_signing_key_o = None;
        Ok(())
    }
    pub fn did(&self) -> &DID {
        self.microledger.view().did()
    }
    pub fn microledger(&self) -> &Microledger {
        &self.microledger
    }
    /// Returns the signer (i.e. private key) and key id for the given key purpose.  The signer is
    /// the private key corresponding to a public key in the latest DID document.  The key id
    /// is the DID with query params for "versionId" and "selfHash" set to those of the latest
    /// DID document.  This causes signatures to be a limited form of witnessing.  This method
    /// assumes that there's exactly one key per KeyPurpose, and returns that one.
    pub fn signer_and_key_id_for_key_purpose(
        &self,
        key_purpose: KeyPurpose,
    ) -> (&signature_dyn::SignerBytes, DIDKeyResourceFullyQualified) {
        let public_key_v = self
            .current_public_key_set
            .public_keys_for_purpose(key_purpose);
        assert_eq!(public_key_v.len(), 1);
        let public_key = public_key_v.first().unwrap();
        let signer_bytes = self
            .signer_bytes_m
            .get(public_key)
            .expect("programmer error");
        let did = self.microledger.view().did();
        let version_id = self.microledger.view().latest_did_document().version_id;
        let self_hash = self
            .microledger
            .view()
            .latest_did_document()
            .self_hash
            .deref();
        // NOTE: The use of key_purpose.integer_value() to determine the key id fragment depends
        // on the fact that there is exactly 1 key per KeyPurpose (see assertion above).
        let key_id = did
            .with_queries(&self_hash, version_id)
            .with_fragment(format!("{}", key_purpose.integer_value()).as_str());
        (signer_bytes, key_id)
    }
    fn generate_new_keys(
        key_type: signature_dyn::KeyType,
    ) -> (
        HashMap<mbx::MBPubKey, signature_dyn::SignerBytes>,
        PublicKeySet<mbx::MBPubKey>,
    ) {
        // Generate a full set of private keys.

        let signing_key_authentication_b = key_type.generate_random_private_key();
        let verifying_key_authentication_b = signing_key_authentication_b.get_verifier().unwrap();

        let signing_key_assertion_method_b = key_type.generate_random_private_key();
        let verifying_key_assertion_method_b =
            signing_key_assertion_method_b.get_verifier().unwrap();

        let signing_key_key_agreement_b = key_type.generate_random_private_key();
        let verifying_key_key_agreement_b = signing_key_key_agreement_b.get_verifier().unwrap();

        // This will be used exclusively for signing DID documents.
        let signing_key_capability_invocation_b = key_type.generate_random_private_key();
        let verifying_key_capability_invocation_b =
            signing_key_capability_invocation_b.get_verifier().unwrap();

        let signing_key_capability_delegation_b = key_type.generate_random_private_key();
        let verifying_key_capability_delegation_b =
            signing_key_capability_delegation_b.get_verifier().unwrap();

        let pub_key_authentication = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &verifying_key_authentication_b.to_verifier_bytes(),
        )
        .unwrap();
        let pub_key_assertion_method = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &verifying_key_assertion_method_b.to_verifier_bytes(),
        )
        .unwrap();
        let pub_key_key_agreement = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &verifying_key_key_agreement_b.to_verifier_bytes(),
        )
        .unwrap();
        let pub_key_capability_invocation = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &verifying_key_capability_invocation_b.to_verifier_bytes(),
        )
        .unwrap();
        let pub_key_capability_delegation = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &verifying_key_capability_delegation_b.to_verifier_bytes(),
        )
        .unwrap();

        let current_public_key_set = PublicKeySet {
            authentication_v: vec![pub_key_authentication.clone()],
            assertion_method_v: vec![pub_key_assertion_method.clone()],
            key_agreement_v: vec![pub_key_key_agreement.clone()],
            capability_invocation_v: vec![pub_key_capability_invocation.clone()],
            capability_delegation_v: vec![pub_key_capability_delegation.clone()],
        };
        let signer_bytes_m = {
            let mut signer_bytes_m: HashMap<mbx::MBPubKey, signature_dyn::SignerBytes> =
                HashMap::new();
            signer_bytes_m.insert(
                pub_key_authentication,
                signing_key_authentication_b.extract_signer_bytes().unwrap(),
            );
            signer_bytes_m.insert(
                pub_key_assertion_method,
                signing_key_assertion_method_b
                    .extract_signer_bytes()
                    .unwrap(),
            );
            signer_bytes_m.insert(
                pub_key_key_agreement,
                signing_key_key_agreement_b.extract_signer_bytes().unwrap(),
            );
            signer_bytes_m.insert(
                pub_key_capability_invocation,
                signing_key_capability_invocation_b
                    .extract_signer_bytes()
                    .unwrap(),
            );
            signer_bytes_m.insert(
                pub_key_capability_delegation,
                signing_key_capability_delegation_b
                    .extract_signer_bytes()
                    .unwrap(),
            );
            signer_bytes_m
        };

        (signer_bytes_m, current_public_key_set)
    }
}
