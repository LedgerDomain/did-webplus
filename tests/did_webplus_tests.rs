use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus::{
    DIDDocument, DIDDocumentCreateParams, DIDDocumentMetadata, DIDDocumentUpdateParams, DIDWebplus,
    Error, Microledger, NonRootDIDDocument, PublicKeySet, RootDIDDocument,
};
use selfhash::HashFunction;
use selfsign::SelfSignAndHashable;

#[test]
#[serial_test::serial]
fn test_root_did_document_self_sign() {
    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();
    // To create a RootDIDDocument from the controller side, we only supply:
    // - The did:webplus value with a placeholder self-signature
    // - The valid_from timestamp at which the DID document becomes valid.
    // - The public keys for each key purpose
    let root_did_document = RootDIDDocument::create(
        DIDDocumentCreateParams {
            did_webplus_host: "example.com".into(),
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                // Note that this is the one being used to self-sign the RootDIDDocument.
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_0],
            },
        },
        &selfhash::Blake3,
        &ed25519_signing_key_1,
    )
    .expect("pass");
    root_did_document
        .verify_self_signatures_and_hashes()
        .expect("pass");

    println!(
        "root did_document:\n{}",
        serde_json::to_string_pretty(&root_did_document).unwrap()
    );
}

#[test]
#[serial_test::serial]
fn test_did_document_verification() {
    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();
    // To create a RootDIDDocument from the controller side, we only supply:
    // - The did:webplus value with a placeholder self-signature
    // - The valid_from timestamp at which the DID document becomes valid.
    // - The public keys for each key purpose
    let did_document_0 = RootDIDDocument::create(
        DIDDocumentCreateParams {
            did_webplus_host: "example.com".into(),
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                // Note that this is the one being used to self-sign the RootDIDDocument.
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_0],
            },
        },
        &selfhash::Blake3,
        &ed25519_signing_key_1,
    )
    .expect("pass");
    println!(
        "did_document_0:\n{}",
        serde_json::to_string_pretty(&did_document_0).unwrap()
    );
    did_document_0
        .verify_self_signatures_and_hashes()
        .expect("pass");
    did_document_0.verify_nonrecursive().expect("pass");

    // Now create a second DID document, which is a non-root DID document.  Create another key to be rotated in.
    let ed25519_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_2 = ed25519_signing_key_2.verifying_key();
    let did_document_1 = NonRootDIDDocument::update_from_previous(
        DIDDocument::from(&did_document_0),
        DIDDocumentUpdateParams {
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0, &ed25519_verifying_key_2],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_2],
            },
        },
        selfhash::Blake3.new_hasher(),
        &ed25519_signing_key_1,
    )
    .expect("pass");
    println!(
        "did_document_1:\n{}",
        serde_json::to_string_pretty(&did_document_1).unwrap()
    );
    did_document_1
        .verify_self_signatures_and_hashes()
        .expect("pass");
    did_document_1
        .verify_nonrecursive(DIDDocument::from(&did_document_0))
        .expect("pass");

    // Attempt to make an update using a key not listed in capability_invocation_v, and see that it fails.
    let ed25519_signing_key_attacker = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_attacker = ed25519_signing_key_attacker.verifying_key();
    NonRootDIDDocument::update_from_previous(
        DIDDocument::from(&did_document_1),
        DIDDocumentUpdateParams {
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![
                    &ed25519_verifying_key_0,
                    &ed25519_verifying_key_2,
                    &ed25519_verifying_key_attacker,
                ],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_2],
            },
        },
        selfhash::Blake3.new_hasher(),
        &ed25519_signing_key_attacker,
    )
    .expect_err("pass");
}

fn priv_jwk_from_ed25519_signing_key(
    ed25519_signing_key: &ed25519_dalek::SigningKey,
) -> ssi_jwk::JWK {
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    ssi_jwk::JWK::from(ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
        curve: "Ed25519".to_string(),
        public_key: ssi_jwk::Base64urlUInt(ed25519_verifying_key.to_bytes().to_vec()),
        private_key: Some(ssi_jwk::Base64urlUInt(
            ed25519_signing_key.to_bytes().to_vec(),
        )),
    }))
}

#[test]
#[serial_test::serial]
fn test_signature_generation() {
    let ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    let mut ed25519_priv_jwk = priv_jwk_from_ed25519_signing_key(&ed25519_signing_key);

    // TODO: Other key types
    {
        let did_document_0 = RootDIDDocument::create(
            DIDDocumentCreateParams {
                did_webplus_host: "example.com".into(),
                valid_from: time::OffsetDateTime::now_utc(),
                public_key_set: PublicKeySet {
                    authentication_v: vec![&ed25519_verifying_key],
                    assertion_method_v: vec![&ed25519_verifying_key],
                    key_agreement_v: vec![&ed25519_verifying_key],
                    // Note that this is the one being used to self-sign the RootDIDDocument.
                    capability_invocation_v: vec![&ed25519_verifying_key],
                    capability_delegation_v: vec![&ed25519_verifying_key],
                },
            },
            &selfhash::Blake3,
            &ed25519_signing_key,
        )
        .expect("pass");
        did_document_0
            .verify_self_signatures_and_hashes()
            .expect("pass");
        let did = did_document_0.id.clone();
        println!(
            "root did_document:\n{}",
            serde_json::to_string_pretty(&did_document_0).unwrap()
        );
        did_document_0.verify_nonrecursive().expect("pass");
        use selfsign::Verifier;
        let did_webplus_with_key_id_fragment =
            did.with_fragment(ed25519_verifying_key.to_keri_verifier().into_owned());

        // Add query params for versionId and hl (which is set to the current DID document's self-signature),
        // so that the signature produced with this key commits the DID document with the given versionId to have
        // the given self-signature.
        let did_webplus_with_query_and_key_id_fragment = did_webplus_with_key_id_fragment
            .with_query(format!(
                "versionId={}&hl={}",
                did_document_0.version_id,
                did_document_0.self_hash_o.as_ref().unwrap()
            ));
        ed25519_priv_jwk.key_id = Some(did_webplus_with_query_and_key_id_fragment.to_string());
        // Sign stuff.
        let message = b"HIPPOS are much better than OSTRICHES";
        let jws = ssi_jws::detached_sign_unencoded_payload(
            ed25519_priv_jwk.get_algorithm().expect("pass"),
            message,
            &ed25519_priv_jwk,
        )
        .expect("pass");
        println!("jws: {}", jws);
        // Verify signature.
        let ed25519_pub_jwk = ed25519_priv_jwk.to_public();
        let jws_header = ssi_jws::detached_verify(&jws, message, &ed25519_pub_jwk).expect("pass");
        println!(
            "jws header:\n{}",
            serde_json::to_string_pretty(&jws_header).unwrap()
        );
        ssi_jws::detached_verify(&jws, b"fake payload, this should fail", &ed25519_pub_jwk)
            .expect_err("pass");
    }
}

#[test]
#[serial_test::serial]
fn test_microledger() {
    println!("-- TESTING MICROLEDGER ---------------------------------\n");

    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();

    // Create a DID and its associated Microledger
    let (mut microledger, _ed25519_priv_jwk_0) = {
        let microledger = Microledger::create(
            RootDIDDocument::create(
                DIDDocumentCreateParams {
                    did_webplus_host: "example.com".into(),
                    valid_from: time::OffsetDateTime::now_utc(),
                    public_key_set: PublicKeySet {
                        authentication_v: vec![&ed25519_verifying_key_0],
                        assertion_method_v: vec![&ed25519_verifying_key_0],
                        key_agreement_v: vec![&ed25519_verifying_key_0],
                        // Note that this is the one being used to self-sign the RootDIDDocument.
                        capability_invocation_v: vec![&ed25519_verifying_key_0],
                        capability_delegation_v: vec![&ed25519_verifying_key_0],
                    },
                },
                &selfhash::Blake3,
                &ed25519_signing_key_0,
            )
            .expect("pass"),
        )
        .expect("pass");
        let did = microledger.did().clone();
        println!("did: {}", did);
        use selfsign::Verifier;
        let did_webplus_with_key_id_fragment =
            did.with_fragment(ed25519_verifying_key_0.to_keri_verifier().into_owned());
        let mut ed25519_priv_jwk_0 = priv_jwk_from_ed25519_signing_key(&ed25519_signing_key_0);
        ed25519_priv_jwk_0.key_id = Some(did_webplus_with_key_id_fragment.to_string());
        println!(
            "ed25519_priv_jwk: {}",
            serde_json::to_string(&ed25519_priv_jwk_0).expect("pass")
        );
        let latest_did_document = microledger.latest_did_document();
        println!(
            "latest DID document (which by construction is the root):\n{}",
            latest_did_document.to_json_pretty(),
        );
        println!(
            "latest DID document metadata:\n{:#?}",
            microledger.did_document_metadata_for(&latest_did_document)
        );
        (microledger, ed25519_priv_jwk_0)
    };

    println!("\n-- updating microledger -----------------------------------------------\n");
    // Update the Microledger.
    let _ed25519_priv_jwk_1 = {
        microledger
            .update_as_controller(
                DIDDocumentUpdateParams {
                    valid_from: time::OffsetDateTime::now_utc(),
                    public_key_set: PublicKeySet {
                        authentication_v: vec![&ed25519_verifying_key_0, &ed25519_verifying_key_1],
                        assertion_method_v: vec![&ed25519_verifying_key_0],
                        key_agreement_v: vec![&ed25519_verifying_key_1],
                        capability_invocation_v: vec![&ed25519_verifying_key_0],
                        capability_delegation_v: vec![&ed25519_verifying_key_0],
                    },
                },
                selfhash::Blake3.new_hasher(),
                &ed25519_signing_key_0,
            )
            .expect("pass");
        let did = microledger.did().clone();
        println!("did: {}", did);
        use selfsign::Verifier;
        let did_webplus_with_key_id_fragment =
            did.with_fragment(ed25519_verifying_key_0.to_keri_verifier().into_owned());
        let mut ed25519_priv_jwk_1 = priv_jwk_from_ed25519_signing_key(&ed25519_signing_key_0);
        ed25519_priv_jwk_1.key_id = Some(did_webplus_with_key_id_fragment.to_string());
        println!(
            "ed25519_priv_jwk: {}",
            serde_json::to_string(&ed25519_priv_jwk_1).expect("pass")
        );
        println!(
            "root DID document metadata:\n{:#?}",
            microledger
                .did_document_metadata_for(&DIDDocument::from(microledger.root_did_document()))
        );
        let latest_did_document = microledger.latest_did_document();
        println!(
            "latest DID document (which by construction is the second):\n{}",
            latest_did_document.to_json_pretty(),
        );
        println!(
            "latest DID document metadata:\n{:#?}",
            microledger.did_document_metadata_for(&latest_did_document)
        );
        ed25519_priv_jwk_1
    };

    println!("\n-- results -----------------------------------------------\n");

    println!(
        "root DID document:\n{}",
        serde_json::to_string_pretty(microledger.root_did_document()).expect("pass")
    );
    println!(
        "root DID document metadata:\n{}",
        serde_json::to_string_pretty(
            &microledger
                .did_document_metadata_for(&DIDDocument::from(microledger.root_did_document()))
        )
        .expect("pass")
    );
    for non_root_microledger_node in microledger.non_root_did_document_v() {
        println!(
            "non-root DID document:\n{}",
            serde_json::to_string_pretty(&non_root_microledger_node).expect("pass")
        );
        println!(
            "non-root DID document metadata:\n{}",
            serde_json::to_string_pretty(
                &microledger
                    .did_document_metadata_for(&DIDDocument::from(non_root_microledger_node))
            )
            .expect("pass")
        );
    }

    // TODO:
    // // Now have an "external" party pull the Microledger one node at a time, verifying it as it goes.
    // let mut external_microledger = Microledger::create()
}

// Mock VDR -- Purely in-memory, intra-process VDR.
#[derive(Debug)]
pub struct MockDIDWebplusVDR {
    host: String,
    microledger_m: std::collections::HashMap<DIDWebplus, Microledger>,
    simulated_latency_o: Option<std::time::Duration>,
}

impl MockDIDWebplusVDR {
    pub fn new_with_host(host: String, simulated_latency_o: Option<std::time::Duration>) -> Self {
        Self {
            host,
            microledger_m: std::collections::HashMap::new(),
            simulated_latency_o,
        }
    }
    pub fn create(
        &mut self,
        agent_name: &str,
        root_did_document: RootDIDDocument,
    ) -> Result<DIDWebplus, Error> {
        println!(
            "VDR (host: {:?}) servicing CREATE request from {:?} for\n    DID: {}",
            self.host, agent_name, root_did_document.id
        );
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }

        if root_did_document.id.host != self.host {
            return Err(Error::Malformed("DID host doesn't match that of VDR"));
        }
        // This construction will fail if the root_did_document isn't valid.
        let microledger = Microledger::create(root_did_document)?;
        if self.microledger_m.contains_key(&microledger.did()) {
            return Err(Error::AlreadyExists("DID already exists"));
        }
        let did = microledger.did().clone();
        self.microledger_m.insert(did.clone(), microledger);
        Ok(did)
    }
    pub fn update(
        &mut self,
        agent_name: &str,
        non_root_did_document: NonRootDIDDocument,
    ) -> Result<(), Error> {
        println!(
            "VDR (host: {:?}) servicing UPDATE request from {:?} for\n    DID: {}",
            self.host, agent_name, non_root_did_document.id
        );
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }

        if non_root_did_document.id.host != self.host {
            return Err(Error::Malformed("DID host doesn't match that of VDR"));
        }
        let microledger = self
            .microledger_m
            .get_mut(&non_root_did_document.id)
            .ok_or_else(|| Error::NotFound("DID not found"))?;
        microledger.update_from_non_root_did_document(non_root_did_document)?;
        Ok(())
    }
    pub fn select_did_documents(
        &self,
        agent_name: &str,
        did: &DIDWebplus,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Vec<DIDDocument>, Error> {
        println!(
            "VDR (host: {:?}) servicing SELECT request from {:?} for\n    DID: {}\n    version_id_begin_o: {:?}\n    version_id_end_o: {:?}",
            self.host, agent_name, did, version_id_begin_o, version_id_end_o
        );
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }

        let microledger = self.microledger(did)?;
        let did_document_v = microledger.select_did_documents(version_id_begin_o, version_id_end_o);
        Ok(did_document_v)
    }
    // // You could call resolve directly on a VDR if you trust that VDR.  But if you don't, then you
    // // should use a local cache to retrieve and verify the DID's microledger, and potentially reduce
    // // the number of times you need to hit the VDR.
    // pub fn resolve<'a>(
    //     &self,
    //     did: &DIDWebplus,
    //     version_id_o: Option<u32>,
    //     self_signature_o: Option<&selfsign::KERISignature<'a>>,
    // ) -> Result<(DIDDocument, DIDDocumentMetadata), Error> {
    //     if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
    //         std::thread::sleep(*simulated_latency);
    //     }

    //     let microledger = self.microledger(did)?;
    //     let (did_document, did_document_metadata) =
    //         microledger.resolve(version_id_o, self_signature_o)?;
    //     Ok((did_document, did_document_metadata))
    // }
    fn microledger(&self, did: &DIDWebplus) -> Result<&Microledger, Error> {
        self.microledger_m
            .get(did)
            .ok_or_else(|| Error::NotFound("DID not found"))
    }
}

pub struct MicroledgerCache {
    pub agent_name: String,
    /// The cached microledger itself.
    pub microledger: Microledger,
    /// The timestamp of the most recent caching action (i.e. checking against the host VDR), needed
    /// to judge the freshness of the cached microledger.
    pub current_as_of: time::OffsetDateTime,
}

impl MicroledgerCache {
    pub fn new_from_vdr(
        agent_name: String,
        did: &DIDWebplus,
        mock_vdr: &MockDIDWebplusVDR,
    ) -> Result<Self, Error> {
        println!(
            "MicroledgerCache::new_from_vdr;\n    agent_name: {:?}\n    DID: {}",
            agent_name, did
        );
        // Retrieve all DID documents from the VDR.
        let did_document_v = mock_vdr.select_did_documents(agent_name.as_str(), did, None, None)?;
        let current_as_of = time::OffsetDateTime::now_utc();
        let microledger = Microledger::new_from_did_documents(did_document_v)?;
        Ok(Self {
            agent_name,
            microledger,
            current_as_of,
        })
    }
    /// Pulls the latest DID document(s) from the VDR and updates the cache.  Returns the number
    /// of previously-uncached DID documents that were returned in the operation.  In particular,
    /// if the returned value is 0, then the local cache was already up to date.
    pub fn update_cache(&mut self, mock_vdr: &MockDIDWebplusVDR) -> Result<u32, Error> {
        println!(
            "MicroledgerCache::update_cache;\n    DID: {}",
            self.microledger.did()
        );
        let latest_cached_version_id = self.microledger.latest_did_document().version_id();
        // Retrieve the next through the latest DID documents from the VDR.
        let new_did_document_v = mock_vdr.select_did_documents(
            self.agent_name.as_str(),
            self.microledger.did(),
            Some(latest_cached_version_id + 1),
            None,
        )?;
        // Update the cache's timestamp.
        self.current_as_of = time::OffsetDateTime::now_utc();
        let new_did_document_count = new_did_document_v.len() as u32;
        if new_did_document_count > 0 {
            // There are DID documents that are more recent than what we have cached, so
            // verify and add them to the cache.
            for did_document in new_did_document_v.into_iter() {
                // All updates should be non-root DID documents.  This Microledger should already have a root.
                assert!(did_document.is_non_root_did_document());
                let non_root_did_document = did_document
                    .into_non_root_did_document()
                    .unwrap()
                    .into_owned();
                self.microledger
                    .update_from_non_root_did_document(non_root_did_document)?;
            }
        }
        Ok(new_did_document_count)
    }
    // TODO: Make a resolve_without_metadata version of this that can operate local-only in more cases.
    pub fn resolve<'a>(
        &mut self,
        version_id_o: Option<u32>,
        self_signature_o: Option<&selfsign::KERISignature<'a>>,
        mock_vdr_la: Arc<RwLock<MockDIDWebplusVDR>>,
    ) -> Result<(DIDDocument<'static>, DIDDocumentMetadata), Error> {
        println!("MicroledgerCache::resolve;\n    DID: {}\n    version_id_o: {:?}\n    self_signature_o: {:?}", self.microledger.did(), version_id_o, self_signature_o);

        use std::ops::Deref;

        if let Ok((did_document, did_document_metadata)) =
            self.microledger.resolve(version_id_o, self_signature_o)
        {
            // If the resolved, cached DID document is not the latest DID document in the local cache,
            // then it can't be the latest in the VDR (which is the authority on latest-ness), so there's
            // no reason to hit the VDR.
            if did_document_metadata.next_version_id_o.is_some() {
                return Ok((did_document, did_document_metadata));
            }
            // Otherwise, we have the DID document, but we don't know that it's the latest, so we'll
            // need to hit the VDR to check if there are any previously-uncached DID documents.
            let new_did_document_count = self.update_cache(mock_vdr_la.read().unwrap().deref())?;
            if new_did_document_count == 0 {
                // If the update_cache call returned 0, then the local cache was already up to date,
                // so we can just return.
                return Ok((did_document, did_document_metadata));
            } else {
                // Otherwise, we need to re-resolve using the recent updates.
                return self.microledger.resolve(version_id_o, self_signature_o);
            }
        }

        // The requested DID document was not found in the local cache, so hit the VDR to get the latest
        // and then re-resolve.
        self.update_cache(mock_vdr_la.read().unwrap().deref())?;
        self.microledger.resolve(version_id_o, self_signature_o)
    }
}

/// Handles retrieval, caching, and verification of did:webplus microledgers.  This could be in the
/// end-use resolver, or in a gateway service that handles this on behalf of a "dumb" client which
/// basically gets to pretend that it's resolving using did:web.
pub struct MockDIDWebplusCache {
    pub agent_name: String,
    /// Mock mechanism for connecting to VDRs based on their host names.  The key of this map is the
    /// host of the VDR.
    pub mock_vdr_lam: HashMap<String, Arc<RwLock<MockDIDWebplusVDR>>>,
    /// This is the cache of all did:webplus microledgers this cache knows about.
    pub microledger_cache_lam: HashMap<DIDWebplus, Arc<RwLock<MicroledgerCache>>>,
}

impl MockDIDWebplusCache {
    pub fn new(
        agent_name: String,
        mock_vdr_lam: HashMap<String, Arc<RwLock<MockDIDWebplusVDR>>>,
    ) -> Self {
        println!("MockDIDWebplusCache::new; agent_name: {:?}", agent_name);
        Self {
            agent_name,
            mock_vdr_lam,
            microledger_cache_lam: HashMap::new(),
        }
    }
    // TODO: Make a resolve_without_metadata version of this that can operate local-only in more cases.
    // This will be useful if you don't care to know if the resolved DID document is the latest.  And
    // then perhaps make a separate resolve_did_document_metadata which only returns the metadata for
    // a given DID document, which could operate asynchronously, so that e.g. signature verification
    // can proceed in parallel with determining currentness of the DID doc.
    pub fn resolve<'a>(
        &mut self,
        did: &DIDWebplus,
        version_id_o: Option<u32>,
        self_signature_o: Option<&selfsign::KERISignature<'a>>,
    ) -> Result<(DIDDocument<'static>, DIDDocumentMetadata), Error> {
        println!(
            "MockDIDWebplusCache::resolve;\n    did: {}\n    version_id_o: {:?}\n    self_signature_o: {:?}",
            did, version_id_o, self_signature_o
        );
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(did.host.as_str())
            .ok_or_else(|| Error::NotFound("Unknown VDR host"))?;

        if !self.microledger_cache_lam.contains_key(did) {
            // If we have no cache for the given DID, we have to fetch it from the VDR.
            use std::ops::Deref;
            let microledger_cache = MicroledgerCache::new_from_vdr(
                format!("MicroledgerCache under {}", self.agent_name),
                did,
                mock_vdr_la.read().unwrap().deref(),
            )?;
            let microledger_cache_la = Arc::new(RwLock::new(microledger_cache));
            self.microledger_cache_lam
                .insert(did.clone(), microledger_cache_la);
            // Because we just hit the VDR, we can resolve against the locally cached microledger directly.
            let microledger_cache_la = self.microledger_cache_lam.get(did).unwrap();
            let microledger_cache_g = microledger_cache_la.read().unwrap();
            microledger_cache_g
                .microledger
                .resolve(version_id_o, self_signature_o)
        } else {
            let microledger_cache_la = self.microledger_cache_lam.get(did).unwrap();
            let mut microledger_cache_g = microledger_cache_la.write().unwrap();
            microledger_cache_g.resolve(version_id_o, self_signature_o, mock_vdr_la.clone())
        }
    }
}

// Owns private keys and controls a single DID which is hosted by a single VDR.
pub struct MockWallet {
    agent_name: String,
    signer_m: HashMap<selfsign::KERIVerifier<'static>, Box<dyn selfsign::Signer>>,
    current_public_key_set: PublicKeySet<selfsign::KERIVerifier<'static>>,
    microledger: Microledger,
    mock_vdr_la: Arc<RwLock<MockDIDWebplusVDR>>,
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
        agent_name: String,
        mock_vdr_la: Arc<RwLock<MockDIDWebplusVDR>>,
    ) -> Result<Self, Error> {
        println!(
            "MockWallet::new_with_vdr;\n    agent_name: {:?}",
            agent_name
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
        let root_did_document = RootDIDDocument::create(
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
            .create(agent_name.as_str(), root_did_document.clone())?;
        // Create the Microledger.  This is the local copy of the DID document history, and in a way
        // is authoritative, so long as the updates are valid and can get to the VDR.
        let microledger = Microledger::create(root_did_document)?;
        Ok(Self {
            agent_name,
            signer_m,
            current_public_key_set,
            microledger,
            mock_vdr_la,
        })
    }
    pub fn did(&self) -> &DIDWebplus {
        self.microledger.did()
    }
    // For now, just do a full rotation of all keys.
    pub fn update(&mut self) -> Result<(), Error> {
        println!(
            "MockWallet::update;\n    agent_name: {:?}\n    DID: {}",
            self.agent_name,
            self.did()
        );
        let (new_signer_m, new_public_key_set) = Self::generate_new_keys();

        let non_root_did_document = NonRootDIDDocument::update_from_previous(
            self.microledger.latest_did_document(),
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
            self.capability_invocation_signer(),
        )?;
        self.mock_vdr_la
            .write()
            .unwrap()
            .update(self.agent_name.as_str(), non_root_did_document.clone())?;
        // If the VDR update succeeded, then update the local Microledger.
        self.microledger
            .update_from_non_root_did_document(non_root_did_document)?;
        // Now update the local signer and public key set.
        self.signer_m = new_signer_m;
        self.current_public_key_set = new_public_key_set;
        Ok(())
    }
    // This assumes that there's exactly one capability_invocation key, and returns that.
    fn capability_invocation_signer(&self) -> &dyn selfsign::Signer {
        assert_eq!(self.current_public_key_set.capability_invocation_v.len(), 1);
        self.signer_m
            .get(
                self.current_public_key_set
                    .capability_invocation_v
                    .first()
                    .unwrap(),
            )
            .expect("programmer error")
            .as_ref()
    }
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
}

#[test]
#[serial_test::serial]
fn test_did_operations() {
    let mock_vdr_la = Arc::new(RwLock::new(MockDIDWebplusVDR::new_with_host(
        "example.com".into(),
        None,
    )));
    let mut mock_cache = MockDIDWebplusCache::new("MockDIDWebplusCache".to_string(), {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert("example.com".into(), mock_vdr_la.clone());
        mock_vdr_lam
    });
    println!("----------------------------------------------------");
    println!("-- Wallet creation ---------------------------------");
    println!("----------------------------------------------------");
    let mut mock_wallet =
        MockWallet::new_with_vdr("Alice's Wallet".to_string(), mock_vdr_la.clone()).expect("pass");

    // Do some resolutions.
    println!("-- Let's do some DID resolutions ---------------------------------");
    {
        let (did_document, did_document_metadata) = mock_cache
            .resolve(mock_wallet.did(), None, None)
            .expect("pass");
        println!(
            "LATEST (which is root) did_document: {}",
            did_document.to_json_pretty()
        );
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        // Do a resolution against specific query params
        if false {
            {
                let (did_document_query, did_document_metadata_query) = mock_cache
                    .resolve(mock_wallet.did(), Some(0), None)
                    .expect("pass");
                assert_eq!(did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) = mock_cache
                    .resolve(mock_wallet.did(), None, Some(did_document.self_signature()))
                    .expect("pass");
                assert_eq!(did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) =
            // Both query params
            mock_cache
                .resolve(mock_wallet.did(), Some(0), Some(did_document.self_signature()))
                .expect("pass");
                assert_eq!(did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
        }
    }

    println!("----------------------------------------------------");
    println!("-- Wallet updates its DID (first update) -----------");
    println!("----------------------------------------------------");
    mock_wallet.update().expect("pass");

    // Do some resolutions.
    println!("-- Let's do some more resolutions ---------------------------------");
    {
        println!("-- First, we'll resolve the root DID document -----------------");
        let (did_document, did_document_metadata) = mock_cache
            .resolve(mock_wallet.did(), Some(0), None)
            .expect("pass");
        println!("ROOT did_document: {}", did_document.to_json_pretty());
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        println!("-- Now, we'll resolve the latest DID document -----------------");
        let (did_document, did_document_metadata) = mock_cache
            .resolve(mock_wallet.did(), None, None)
            .expect("pass");
        println!("LATEST did_document: {}", did_document.to_json_pretty());
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        println!("-- Finally, we'll resolve the latest DID document again -------");
        let (did_document, did_document_metadata) = mock_cache
            .resolve(mock_wallet.did(), None, None)
            .expect("pass");
        println!("LATEST did_document: {}", did_document.to_json_pretty());
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        // Do a resolution against specific query params
        if false {
            {
                let (did_document_query, did_document_metadata_query) = mock_cache
                    .resolve(mock_wallet.did(), Some(did_document.version_id()), None)
                    .expect("pass");
                assert_eq!(did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) = mock_cache
                    .resolve(mock_wallet.did(), None, Some(did_document.self_signature()))
                    .expect("pass");
                assert_eq!(did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) =
            // Both query params
            mock_cache
                .resolve(mock_wallet.did(), Some(did_document.version_id()), Some(did_document.self_signature()))
                .expect("pass");
                assert_eq!(did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
        }
    }
}
