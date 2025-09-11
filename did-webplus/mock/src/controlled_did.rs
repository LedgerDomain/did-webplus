use std::{collections::HashMap, ops::Deref};

use did_webplus_core::{
    DIDDocument, DIDKeyResourceFullyQualified, Error, KeyPurpose, MicroledgerView, PublicKeySet,
    RootLevelUpdateRules, UpdateKey, DID,
};

use crate::{Microledger, VDRClient};

pub struct ControlledDID {
    pub current_public_key_set: PublicKeySet<selfsign::KERIVerifier>,
    signer_m: HashMap<selfsign::KERIVerifier, Box<dyn selfsign::Signer>>,
    update_signing_key: ed25519_dalek::SigningKey,
    microledger: Microledger,
}

impl ControlledDID {
    pub fn create(
        did_hostname: String,
        did_port_o: Option<u16>,
        did_path_o: Option<String>,
        vdr_client: &dyn VDRClient,
    ) -> Result<Self, Error> {
        // Generate the key set for use in the root DID document.
        let (signer_m, current_public_key_set) = Self::generate_new_keys();

        // Generate the update signing key (for when the this root DID document is updated later).
        let update_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let update_verifying_key = update_signing_key.verifying_key();
        let update_pub_key = mbc::B64UPubKey::try_from(&update_verifying_key).expect("pass");

        // Set the update rules.  In this case, just a single key.
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            key: update_pub_key.clone(),
        });
        let valid_from = time::OffsetDateTime::now_utc();
        let public_key_set = PublicKeySet {
            authentication_v: current_public_key_set
                .authentication_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            assertion_method_v: current_public_key_set
                .assertion_method_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            key_agreement_v: current_public_key_set
                .key_agreement_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            capability_invocation_v: current_public_key_set
                .capability_invocation_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            capability_delegation_v: current_public_key_set
                .capability_delegation_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
        };
        let mut root_did_document = DIDDocument::create_unsigned_root(
            &did_hostname,
            did_port_o,
            did_path_o.as_deref(),
            update_rules,
            valid_from,
            public_key_set,
            &selfhash::Blake3,
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
            signer_m,
            update_signing_key,
            microledger,
        })
    }
    pub fn update(&mut self, vdr_client: &dyn VDRClient) -> Result<(), Error> {
        // Generate the new key set to rotate in during the DID update.
        let (new_signer_m, new_public_key_set) = Self::generate_new_keys();

        // Generate the next update signing key (for when the this new DID document is updated later).
        let next_update_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let next_update_verifying_key = next_update_signing_key.verifying_key();
        let next_update_pub_key =
            mbc::B64UPubKey::try_from(&next_update_verifying_key).expect("pass");

        // Set the update rules for this new DID document.  In this case, just a single key.
        let next_update_rules = RootLevelUpdateRules::from(UpdateKey {
            key: next_update_pub_key.clone(),
        });
        let valid_from = time::OffsetDateTime::now_utc();
        let public_key_set = PublicKeySet {
            authentication_v: new_public_key_set
                .authentication_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            assertion_method_v: new_public_key_set
                .assertion_method_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            key_agreement_v: new_public_key_set
                .key_agreement_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            capability_invocation_v: new_public_key_set
                .capability_invocation_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
            capability_delegation_v: new_public_key_set
                .capability_delegation_v
                .iter()
                .map(|v| v as &dyn selfsign::Verifier)
                .collect(),
        };
        let prev_did_document = self.microledger.view().latest_did_document();
        let mut new_did_document = DIDDocument::create_unsigned_non_root(
            prev_did_document,
            next_update_rules,
            valid_from,
            public_key_set,
            &selfhash::Blake3,
        )?;

        // Sign the new DID document using the existing update_signing_key (the one referenced in the
        // previous DID document), and add the proof.
        let jws = {
            let update_verifying_key = self.update_signing_key.verifying_key();
            let update_pub_key = mbc::B64UPubKey::try_from(&update_verifying_key).expect("pass");
            new_did_document.sign(update_pub_key.to_string(), &self.update_signing_key)?
        };
        new_did_document.add_proof(jws.into_string());
        // Finalize the new DID document.  In particular, this will self-hash the DID document.
        new_did_document.finalize(Some(prev_did_document))?;

        // Sanity check.
        new_did_document.verify_non_root_nonrecursive(prev_did_document)?;

        vdr_client.update_did(new_did_document.clone())?;
        // If the VDR update succeeded, then update the local Microledger.
        use did_webplus_core::MicroledgerMutView;
        self.microledger.mut_view().update(new_did_document)?;
        // Now update the local signer and public key set.
        self.current_public_key_set = new_public_key_set;
        self.signer_m = new_signer_m;
        self.update_signing_key = next_update_signing_key;
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
    ) -> (&dyn selfsign::Signer, DIDKeyResourceFullyQualified) {
        let public_key_v = self
            .current_public_key_set
            .public_keys_for_purpose(key_purpose);
        assert_eq!(public_key_v.len(), 1);
        let public_key = public_key_v.first().unwrap();
        let signer = self
            .signer_m
            .get(public_key)
            .expect("programmer error")
            .as_ref();
        let did = self.microledger.view().did();
        let version_id = self.microledger.view().latest_did_document().version_id();
        let self_hash = self
            .microledger
            .view()
            .latest_did_document()
            .self_hash
            .deref();
        let key_id = did
            .with_queries(&self_hash, version_id)
            .with_fragment(public_key.as_keri_verifier_str());
        (signer, key_id)
    }
    fn generate_new_keys() -> (
        HashMap<selfsign::KERIVerifier, Box<dyn selfsign::Signer>>,
        PublicKeySet<selfsign::KERIVerifier>,
    ) {
        // Generate a full set of private keys.

        let ed25519_signing_key_authentication =
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_verifying_key_authentication =
            ed25519_signing_key_authentication.verifying_key();

        let ed25519_signing_key_assertion_method =
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_verifying_key_assertion_method =
            ed25519_signing_key_assertion_method.verifying_key();

        let ed25519_signing_key_key_agreement =
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_verifying_key_key_agreement = ed25519_signing_key_key_agreement.verifying_key();

        // This will be used exclusively for signing DID documents.
        let ed25519_signing_key_capability_invocation =
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_verifying_key_capability_invocation =
            ed25519_signing_key_capability_invocation.verifying_key();

        let ed25519_signing_key_capability_delegation =
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_verifying_key_capability_delegation =
            ed25519_signing_key_capability_delegation.verifying_key();

        use selfsign::Verifier;
        let current_public_key_set = PublicKeySet {
            authentication_v: vec![ed25519_verifying_key_authentication
                .to_keri_verifier()
                .into_owned()],
            assertion_method_v: vec![ed25519_verifying_key_assertion_method
                .to_keri_verifier()
                .into_owned()],
            key_agreement_v: vec![ed25519_verifying_key_key_agreement
                .to_keri_verifier()
                .into_owned()],
            capability_invocation_v: vec![ed25519_verifying_key_capability_invocation
                .to_keri_verifier()
                .into_owned()],
            capability_delegation_v: vec![ed25519_verifying_key_capability_delegation
                .to_keri_verifier()
                .into_owned()],
        };
        let signer_m = {
            let mut signer_m: HashMap<selfsign::KERIVerifier, Box<dyn selfsign::Signer>> =
                HashMap::new();
            signer_m.insert(
                ed25519_verifying_key_authentication
                    .to_keri_verifier()
                    .into_owned(),
                Box::new(ed25519_signing_key_authentication),
            );
            signer_m.insert(
                ed25519_verifying_key_assertion_method
                    .to_keri_verifier()
                    .into_owned(),
                Box::new(ed25519_signing_key_assertion_method),
            );
            signer_m.insert(
                ed25519_verifying_key_key_agreement
                    .to_keri_verifier()
                    .into_owned(),
                Box::new(ed25519_signing_key_key_agreement),
            );
            signer_m.insert(
                ed25519_verifying_key_capability_invocation
                    .to_keri_verifier()
                    .into_owned(),
                Box::new(ed25519_signing_key_capability_invocation),
            );
            signer_m.insert(
                ed25519_verifying_key_capability_delegation
                    .to_keri_verifier()
                    .into_owned(),
                Box::new(ed25519_signing_key_capability_delegation),
            );
            signer_m
        };

        (signer_m, current_public_key_set)
    }
}
