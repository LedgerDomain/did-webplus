use std::collections::HashMap;

use did_webplus::{
    DIDDocument, DIDDocumentCreateParams, DIDDocumentUpdateParams, DIDWithQueryAndKeyIdFragment,
    Error, KeyPurpose, MicroledgerView, PublicKeySet, DID,
};

use crate::{Microledger, VDRClient};

pub struct ControlledDID {
    pub current_public_key_set: PublicKeySet<selfsign::KERIVerifier>,
    signer_m: HashMap<selfsign::KERIVerifier, Box<dyn selfsign::Signer>>,
    microledger: Microledger,
}

impl ControlledDID {
    pub fn create(
        did_host: String,
        did_path_o: Option<String>,
        vdr_client: &dyn VDRClient,
    ) -> Result<Self, Error> {
        let (signer_m, current_public_key_set) = Self::generate_new_keys();
        // Assume there's only one capability_invocation_v key, and use that to sign.
        assert_eq!(current_public_key_set.capability_invocation_v.len(), 1);
        let did_document_signer = signer_m
            .get(
                current_public_key_set
                    .capability_invocation_v
                    .first()
                    .unwrap(),
            )
            .unwrap()
            .as_ref();

        let root_did_document = DIDDocument::create_root(
            DIDDocumentCreateParams {
                did_host: did_host.into(),
                did_path_o: did_path_o.map(|did_path| did_path.into()),
                valid_from: time::OffsetDateTime::now_utc(),
                public_key_set: PublicKeySet {
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
                },
            },
            &selfhash::Blake3,
            did_document_signer,
        )?;
        // Register the DID with the appropriate VDR.  The VDR mostly only has authority over if creation of a DID
        // is allowed.  Once the DID is being hosted by the VDR, all valid updates should be accepted by it.
        vdr_client.create_did(root_did_document.clone())?;
        // Create the Microledger.  This is the local copy of the DID document history, and in a way
        // is authoritative, so long as the updates are valid and can get to the VDR.
        let microledger = Microledger::create(root_did_document)?;
        Ok(Self {
            current_public_key_set,
            signer_m,
            microledger,
        })
    }
    pub fn update(&mut self, vdr_client: &dyn VDRClient) -> Result<(), Error> {
        let (new_signer_m, new_public_key_set) = Self::generate_new_keys();

        let new_did_document = DIDDocument::update_from_previous(
            self.microledger.view().latest_did_document(),
            DIDDocumentUpdateParams {
                valid_from: time::OffsetDateTime::now_utc(),
                public_key_set: PublicKeySet {
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
                },
            },
            &selfhash::Blake3,
            self.signer_and_key_id_for_key_purpose(KeyPurpose::CapabilityInvocation)
                .0,
        )?;
        vdr_client.update_did(new_did_document.clone())?;
        // If the VDR update succeeded, then update the local Microledger.
        use did_webplus::MicroledgerMutView;
        self.microledger.mut_view().update(new_did_document)?;
        // Now update the local signer and public key set.
        self.signer_m = new_signer_m;
        self.current_public_key_set = new_public_key_set;
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
    ) -> (&dyn selfsign::Signer, DIDWithQueryAndKeyIdFragment) {
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
        let self_hash = self.microledger.view().latest_did_document().self_hash();
        let key_id = did
            .with_queries(self_hash.clone(), version_id)
            .with_fragment(public_key.to_owned());
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
            authentication_v: vec![ed25519_verifying_key_authentication.to_keri_verifier()],
            assertion_method_v: vec![ed25519_verifying_key_assertion_method.to_keri_verifier()],
            key_agreement_v: vec![ed25519_verifying_key_key_agreement.to_keri_verifier()],
            capability_invocation_v: vec![
                ed25519_verifying_key_capability_invocation.to_keri_verifier()
            ],
            capability_delegation_v: vec![
                ed25519_verifying_key_capability_delegation.to_keri_verifier()
            ],
        };
        let signer_m = {
            let mut signer_m: HashMap<selfsign::KERIVerifier, Box<dyn selfsign::Signer>> =
                HashMap::new();
            signer_m.insert(
                ed25519_verifying_key_authentication.to_keri_verifier(),
                Box::new(ed25519_signing_key_authentication),
            );
            signer_m.insert(
                ed25519_verifying_key_assertion_method.to_keri_verifier(),
                Box::new(ed25519_signing_key_assertion_method),
            );
            signer_m.insert(
                ed25519_verifying_key_key_agreement.to_keri_verifier(),
                Box::new(ed25519_signing_key_key_agreement),
            );
            signer_m.insert(
                ed25519_verifying_key_capability_invocation.to_keri_verifier(),
                Box::new(ed25519_signing_key_capability_invocation),
            );
            signer_m.insert(
                ed25519_verifying_key_capability_delegation.to_keri_verifier(),
                Box::new(ed25519_signing_key_capability_delegation),
            );
            signer_m
        };

        (signer_m, current_public_key_set)
    }
}
