use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus::{
    DIDDocument, DIDDocumentCreateParams, DIDDocumentUpdateParams, DIDWebplus, Error, KeyPurpose,
    MicroledgerViewTrait, PublicKeySet,
};

use crate::{Microledger, MockVDR};

// Owns private keys and controls a single DID which is hosted by a single VDR.
pub struct MockWallet {
    pub user_agent: String,
    pub current_public_key_set: PublicKeySet<selfsign::KERIVerifier<'static>>,
    signer_m: HashMap<selfsign::KERIVerifier<'static>, Box<dyn selfsign::Signer>>,
    microledger: Microledger,
    mock_vdr_la: Arc<RwLock<MockVDR>>,
    // TODO: Mock connection to VDGs.
}

impl std::fmt::Debug for MockWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockWallet")
            // .field("signer_m (showing pub keys only)", self.signer_m.keys())
            .field("current_public_key_set", &self.current_public_key_set)
            .field("microledger", &self.microledger)
            .field(
                "mock_vdr_la (showing host only)",
                &self.mock_vdr_la.read().unwrap().host,
            )
            .finish()
    }
}

impl MockWallet {
    pub fn new_with_vdr(
        user_agent: String,
        mock_vdr_la: Arc<RwLock<MockVDR>>,
    ) -> Result<Self, Error> {
        println!(
            "MockWallet::new_with_vdr;\n    user_agent: {:?}",
            user_agent
        );
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

        let did_webplus_host = mock_vdr_la.read().unwrap().host.clone();
        let root_did_document = DIDDocument::create_root(
            DIDDocumentCreateParams {
                did_webplus_host: did_webplus_host.into(),
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
        // Register the DID with the VDR.  The VDR mostly only has authority over if creation of a DID
        // is allowed.  Once the DID is being hosted by the VDR, all valid updates should be accepted by it.
        mock_vdr_la
            .write()
            .unwrap()
            .create(user_agent.as_str(), root_did_document.clone())?;
        // Create the Microledger.  This is the local copy of the DID document history, and in a way
        // is authoritative, so long as the updates are valid and can get to the VDR.
        let microledger = Microledger::create(root_did_document)?;
        Ok(Self {
            user_agent,
            current_public_key_set,
            signer_m,
            microledger,
            mock_vdr_la,
        })
    }
    pub fn did(&self) -> &DIDWebplus {
        self.microledger.view().did()
    }
    /// Get a read-only view of this wallet's Microledger.
    pub fn microledger_view(&self) -> impl MicroledgerViewTrait<'_> {
        self.microledger.view()
    }
    // For now, just do a full rotation of all keys.
    pub fn update(&mut self) -> Result<(), Error> {
        println!(
            "MockWallet::update;\n    user_agent: {:?}\n    DID: {}",
            self.user_agent,
            self.did()
        );
        let (new_signer_m, new_public_key_set) = Self::generate_new_keys();

        use selfhash::HashFunction;
        let non_root_did_document = DIDDocument::update_from_previous(
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
            selfhash::Blake3.new_hasher(),
            self.signer_for_key_purpose(KeyPurpose::CapabilityInvocation),
        )?;
        self.mock_vdr_la
            .write()
            .unwrap()
            .update(self.user_agent.as_str(), non_root_did_document.clone())?;
        // If the VDR update succeeded, then update the local Microledger.
        use did_webplus::MicroledgerMutViewTrait;
        self.microledger.mut_view().update(non_root_did_document)?;
        // Now update the local signer and public key set.
        self.signer_m = new_signer_m;
        self.current_public_key_set = new_public_key_set;
        Ok(())
    }
    // This assumes that there's exactly one key per KeyPurpose, and returns that.
    pub fn signer_for_key_purpose(&self, key_purpose: KeyPurpose) -> &dyn selfsign::Signer {
        let public_key_v = self
            .current_public_key_set
            .public_keys_for_purpose(key_purpose);
        assert_eq!(public_key_v.len(), 1);
        let public_key = public_key_v.first().unwrap();
        self.signer_m
            .get(public_key)
            .expect("programmer error")
            .as_ref()
    }
    // // This assumes that there's exactly one capability_invocation key, and returns that.
    // fn capability_invocation_signer(&self) -> &dyn selfsign::Signer {
    //     assert_eq!(self.current_public_key_set.capability_invocation_v.len(), 1);
    //     self.signer_m
    //         .get(
    //             self.current_public_key_set
    //                 .capability_invocation_v
    //                 .first()
    //                 .unwrap(),
    //         )
    //         .expect("programmer error")
    //         .as_ref()
    // }
    fn generate_new_keys() -> (
        HashMap<selfsign::KERIVerifier<'static>, Box<dyn selfsign::Signer>>,
        PublicKeySet<selfsign::KERIVerifier<'static>>,
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
            let mut signer_m: HashMap<selfsign::KERIVerifier<'static>, Box<dyn selfsign::Signer>> =
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
    /// Produce a JWS with the given bytes as a payload (payload_byte_v will be base64-encoded)
    pub fn sign_jws(
        &self,
        public_key: selfsign::KERIVerifier<'_>,
        payload_byte_v: &[u8],
    ) -> Result<String, Error> {
        let signer = self
            .signer_m
            .get(&public_key)
            .ok_or(Error::NotFound("No private key found for given public key"))?;

        let alg = match signer.signature_algorithm().named_signature_algorithm() {
            selfsign::NamedSignatureAlgorithm::ED25519_SHA_512 => "EdDSA".to_string(),
            selfsign::NamedSignatureAlgorithm::SECP256K1_SHA_256 => "ES256K".to_string(),
            _ => return Err(Error::Malformed("Unsupported signature algorithm for JWS")),
        };
        // TODO: More systematic way of getting the key id.
        let did = self.microledger.view().did();
        let latest_did_document = self.microledger.view().latest_did_document();
        let version_id = latest_did_document.version_id();
        let self_hash = latest_did_document.self_hash();
        let did_with_query_params_and_key_id_fragment = did
            .with_query(format!("versionId={}&selfHash={}", version_id, self_hash))
            .with_fragment(public_key);

        #[derive(serde::Serialize)]
        struct JWSHeader {
            alg: String,
            kid: String,
        }
        let jws_header = JWSHeader {
            alg,
            kid: did_with_query_params_and_key_id_fragment.to_string(),
        };

        // Produce the message to be signed: base64url(header) || '.' || base64url(payload)
        let mut message = String::new();
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(
            serde_json::to_string(&jws_header).expect("pass").as_bytes(),
            &mut message,
        );
        message.push('.');
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode_string(payload_byte_v, &mut message);

        // Sign the message, base64url-encode the signature, and add to the message.
        message.push('.');
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(
            signer
                .sign_message(message.as_bytes())?
                .to_signature_bytes()
                .as_ref(),
            &mut message,
        );

        // The message is now base64url(header) || '.' || base64url(payload) || '.' || base64url(signature)
        // which is a fully-formed JWS.
        Ok(message)
    }
}
