use crate::Result;
use anyhow::Context;
use did_webplus_core::{
    DIDDocument, DIDDocumentCreateParams, DIDFullyQualified, DIDStr, KeyPurpose, KeyPurposeFlags,
};
use did_webplus_doc_store::DIDDocRecord;
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyUsage, PrivKeyUsageRecord,
    VerificationMethodRecord, WalletRecord, WalletStorageCtx,
};
use selfsign::{Signer, Verifier};
use std::borrow::Cow;
use wasm_bindgen_futures::JsFuture;
use web_sys::wasm_bindgen::JsValue;

#[derive(Debug)]
pub struct Error(anyhow::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}

impl From<indexed_db::Error<Error>> for Error {
    fn from(e: indexed_db::Error<Error>) -> Self {
        match e {
            indexed_db::Error::User(err) => err,
            _ => Self(anyhow::anyhow!("{}", e)),
        }
    }
}

fn into_wallet_error<E: std::fmt::Display>(e: E) -> did_webplus_wallet::Error {
    did_webplus_wallet::Error::WalletStorageError(did_webplus_wallet_store::Error::StorageError(
        e.to_string().into(),
    ))
}

#[derive(Clone, Debug)]
pub struct SoftwareWalletIndexedDB {
    db_name: String,
    #[allow(unused)]
    db_version: u32,
    ctx: WalletStorageCtx,
}

impl SoftwareWalletIndexedDB {
    pub async fn create(
        db_name: String,
        db_version: u32,
        wallet_name_o: Option<String>,
    ) -> Result<Self> {
        tracing::debug!(
            db_name,
            db_version,
            wallet_name_o,
            "SoftwareWalletIndexedDB::create"
        );
        let factory = indexed_db::Factory::<Error>::get().context("opening IndexedDB")?;
        tracing::debug!("created factory");
        let db = factory
            .open(&db_name, db_version, Self::version_change_callback)
            .await
            .context("opening the database")?;
        tracing::debug!("opened database");

        // Create a wallet.
        let ctx = db.transaction(&["wallets"]).rw().run(async move |transaction| {
            tracing::debug!("started transaction for creating a wallet");
            let wallets_object_store = transaction.object_store("wallets")?;
            tracing::debug!("got wallets_object_store");
            // Create a random UUID for the wallet.  The chance of collision is so low that
            // it's more likely a programmer error if it happens.
            let now_utc = time::OffsetDateTime::now_utc();
            for i in 0..5 {
                let wallet_uuid = uuid::Uuid::new_v4();
                tracing::debug!("attempt #{} to create wallet; wallet_uuid: {:?}", i, wallet_uuid);
                let wallet_already_exists = wallets_object_store.contains(&serde_wasm_bindgen::to_value(&wallet_uuid).unwrap()).await?;
                tracing::debug!("wallet_already_exists: {:?}", wallet_already_exists);
                if !wallet_already_exists {
                    let wallet_record = WalletRecord {
                        wallet_uuid,
                        created_at: now_utc,
                        updated_at: now_utc,
                        deleted_at_o: None,
                        wallet_name_o,
                    };
                    tracing::debug!("adding wallet_record: {:?}", wallet_record);
                    let wallets_rowid_jsvalue = wallets_object_store.add(&serde_wasm_bindgen::to_value(&wallet_record).unwrap()).await?;
                    tracing::debug!("wallets_rowid_jsvalue: {:?}", wallets_rowid_jsvalue);
                    let wallets_rowid = wallets_rowid_jsvalue.as_f64().unwrap() as i64;
                    tracing::debug!("wallets_rowid: {:?}", wallets_rowid);
                    return Ok(WalletStorageCtx { wallets_rowid });
                }
            }
            panic!("Failed to create a unique wallet UUID after 5 attempts; this is so unlikely that it's almost certainly a programmer error");
        }).await?;

        tracing::debug!(
            db_name,
            db_version,
            ctx.wallets_rowid,
            "successfully created wallet"
        );
        Ok(Self {
            db_name,
            db_version,
            ctx,
        })
    }
    pub async fn open(db_name: String, db_version: u32, wallet_uuid: uuid::Uuid) -> Result<Self> {
        tracing::debug!(
            db_name,
            db_version,
            "SoftwareWalletIndexedDB::open; wallet_uuid: {:?}",
            wallet_uuid
        );

        // Obtain the database builder
        let factory = indexed_db::Factory::<Error>::get().context("opening IndexedDB")?;
        tracing::debug!("created factory");

        // Open the database, creating it and/or applying migrations if needed
        let db = factory
            .open(&db_name, db_version, Self::version_change_callback)
            .await
            .context("opening the database")?;
        tracing::debug!("opened database");

        let ctx = db
            .transaction(&["wallets"])
            .run(async move |transaction| {
                tracing::debug!("started transaction for opening a wallet");
                let wallets_rowid_jsvalue_o = transaction
                    .object_store("wallets")?
                    .index("wallet_uuid index")?
                    .get(&serde_wasm_bindgen::to_value(&wallet_uuid).unwrap())
                    .await?;
                if wallets_rowid_jsvalue_o.is_none() {
                    return Err(Error::from(anyhow::anyhow!(
                        "Wallet with UUID {:?} not found",
                        wallet_uuid
                    ))
                    .into());
                }
                let wallets_rowid_jsvalue = wallets_rowid_jsvalue_o.unwrap();
                let wallets_rowid = wallets_rowid_jsvalue.as_f64().unwrap() as i64;
                tracing::debug!(wallets_rowid, "successfully opened wallet");
                return Ok(WalletStorageCtx { wallets_rowid });
            })
            .await?;

        Ok(Self {
            db_name,
            db_version,
            ctx,
        })
    }
    /// Retrieves the database for this wallet.
    ///
    /// Because we can't store a indexed_db::Database in SoftwareWalletIndexedDB (since indexed_db::Database
    /// doesn't implement Send or Sync), we need to retrieve the database each time we need it.
    async fn db(&self) -> Result<indexed_db::Database<Error>> {
        let factory = indexed_db::Factory::<Error>::get().context("opening IndexedDB")?;
        let db = factory
            .open_latest_version(&self.db_name)
            .await
            .context("opening the database at the latest version")?;
        Ok(db)
    }
    /// This is where database migrations are implemented.
    async fn version_change_callback(
        version_change_event: indexed_db::VersionChangeEvent<Error>,
    ) -> Result<(), indexed_db::Error<Error>> {
        tracing::debug!("version_change_callback");

        let db = version_change_event.database();

        let old_version = version_change_event.old_version();
        let new_version = version_change_event.new_version();

        tracing::info!(
            "Attempting IndexedDB database upgrade: {:?} -> {:?}",
            old_version,
            new_version
        );

        // TODO: Probably need to process the upgrade as a sequence of migrations.

        match (old_version, new_version) {
            (0, 1) => Self::migration_0_to_1(db),
            // Catch-all for unknown migrations.
            (old_version, new_version) => {
                let err = Error::from(anyhow::anyhow!(
                    "Unsupported database version upgrade: {} -> {}",
                    old_version,
                    new_version
                ));
                tracing::error!("{}", err);
                Err(err.into())
            }
        }
    }
    fn migration_0_to_1(db: &indexed_db::Database<Error>) -> Result<(), indexed_db::Error<Error>> {
        tracing::info!("Applying database migration 0 -> 1: Adding initial object stores",);
        let wallets_object_store = db.build_object_store("wallets").auto_increment().create()?;
        wallets_object_store
            .build_index("wallet_uuid index", "wallet_uuid")
            .create()?;

        db.build_object_store("priv_keys")
            .auto_increment()
            .create()?;
        db.build_object_store("priv_keys_provisional")
            .auto_increment()
            .create()?;
        db.build_object_store("priv_key_usages")
            .auto_increment()
            .create()?;
        db.build_object_store("priv_key_usages_provisional")
            .auto_increment()
            .create()?;
        db.build_object_store("did_documents")
            .auto_increment()
            .create()?;
        db.build_object_store("did_documents_provisional")
            .auto_increment()
            .create()?;
        Ok(())
    }
}

// TODO: Move these somewhere appropriate.

/// This is the blob that gets stored in the IndexedDB database for each DID document.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct DIDDocumentBlob {
    pub did_doc_record: DIDDocRecord,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PrivKeyBlob {
    pub wallets_rowid: i64,
    pub priv_key_record: PrivKeyRecord,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PrivKeyUsageBlob {
    pub wallets_rowid: i64,
    pub priv_key_usage_record: PrivKeyUsageRecord,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_wallet::Wallet for SoftwareWalletIndexedDB {
    async fn create_did(
        &self,
        vdr_did_create_endpoint: &str,
    ) -> did_webplus_wallet::Result<DIDFullyQualified> {
        tracing::debug!(
            vdr_did_create_endpoint,
            "SoftwareWalletIndexedDB::create_did"
        );
        // TODO: Factor this code with that in SoftwareWallet::create_did.

        // Parse the vdr_did_create_endpoint as a URL.
        let vdr_did_create_endpoint_url =
            url::Url::parse(vdr_did_create_endpoint).map_err(|e| {
                did_webplus_wallet::Error::InvalidVDRDIDCreateURL(
                    format!(
                        "Parse error in VDR DID Create endpoint URL {:?} -- error was: {}",
                        vdr_did_create_endpoint, e
                    )
                    .into(),
                )
            })?;
        let scheme: &'static str = match vdr_did_create_endpoint_url.scheme() {
            "http" => "http",
            "https" => "https",
            _ => {
                return Err(did_webplus_wallet::Error::InvalidVDRDIDCreateURL(
                    format!(
                        "VDR DID Create endpoint URL {:?} expected scheme \"http\" or \"https\"",
                        vdr_did_create_endpoint
                    )
                    .into(),
                ));
            }
        };
        if vdr_did_create_endpoint_url.host_str().is_none() {
            return Err(did_webplus_wallet::Error::InvalidVDRDIDCreateURL(
                format!(
                    "VDR DID Create endpoint URL {:?} has no host",
                    vdr_did_create_endpoint
                )
                .into(),
            ));
        }
        let did_path_o = {
            let path = vdr_did_create_endpoint_url
                .path()
                .strip_prefix('/')
                .expect("programmer error");
            let path = if let Some(path) = path.strip_suffix('/') {
                path
            } else {
                path
            };
            if path.is_empty() {
                None
            } else if path.contains('/') {
                Some(Cow::Owned(path.replace("/", ":")))
            } else {
                Some(Cow::Borrowed(path))
            }
        };

        // Generate an appropriate set of keys.  Record the creation timestamp.
        let created_at = time::OffsetDateTime::now_utc();

        // TODO: This should use SubtleCrypto, not ed25519-dalek.
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => priv_key_m[KeyPurpose::Authentication].verifying_key(),
            KeyPurpose::AssertionMethod => priv_key_m[KeyPurpose::AssertionMethod].verifying_key(),
            KeyPurpose::KeyAgreement => priv_key_m[KeyPurpose::KeyAgreement].verifying_key(),
            KeyPurpose::CapabilityInvocation => priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key(),
            KeyPurpose::CapabilityDelegation => priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key(),
        };

        // Form the self-signed-and-hashed root DID document.
        let did_document = DIDDocument::create_root(
            DIDDocumentCreateParams {
                did_host: vdr_did_create_endpoint_url.host_str().unwrap().into(),
                did_port_o: vdr_did_create_endpoint_url.port(),
                did_path_o,
                valid_from: time::OffsetDateTime::now_utc(),
                public_key_set: did_webplus_core::PublicKeySet {
                    authentication_v: vec![&pub_key_m[KeyPurpose::Authentication]],
                    assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod]],
                    key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement]],
                    // Note that this is the one being used to self-sign the root DIDDocument.
                    capability_invocation_v: vec![&pub_key_m[KeyPurpose::CapabilityInvocation]],
                    capability_delegation_v: vec![&pub_key_m[KeyPurpose::CapabilityDelegation]],
                },
            },
            &selfhash::Blake3,
            &priv_key_m[KeyPurpose::CapabilityInvocation],
        )
        .expect("pass");
        assert!(did_document.self_signature_verifier_o.is_some());
        let did = did_document.did.clone();
        let controlled_did = did.with_queries(did_document.self_hash(), 0);
        let controlled_did_with_key_id = controlled_did
            .with_fragment(did_document.self_signature_verifier_o.as_deref().unwrap());

        // Serialize DID doc as JCS (JSON Canonicalization Scheme).  This is what gets POST'ed to the VDR.
        let did_document_jcs = did_document
            .serialize_canonically()
            .expect("this shouldn't happen");

        tracing::trace!(
            "formed DID document (not yet stored anywhere); did: {}; controlled_did: {}; did_document_jcs: {}",
            did,
            controlled_did,
            did_document_jcs
        );

        // First, add the DID document, priv keys, and priv key usages to the database, but under
        // the "provisional" versions of those object stores.  Then the HTTP POST to the VDR will
        // happen, and then only if it succeeds will move the records to the non-provisional
        // versions of those object stores.
        // let db = self.db().await.map_err(into_wallet_error)?;

        let ctx_clone = self.ctx.clone();
        let did_clone = did.clone();
        let did_document_jcs_clone = did_document_jcs.clone();
        let (did_document_blob_key, priv_key_blob_key_v, priv_key_usage_blob_key) = self
            .db()
            .await
            .map_err(into_wallet_error)?
            .transaction(&[
                "did_documents_provisional",
                "priv_keys_provisional",
                "priv_key_usages_provisional",
            ])
            .rw()
            .run(async move |transaction| {
                tracing::trace!("started transaction #1; adding provisional records for DID document, priv keys, and priv key usages");
                // Add the DID document.
                let did_document_blob = DIDDocumentBlob {
                    did_doc_record: DIDDocRecord {
                        self_hash: did_document.self_hash().to_string(),
                        did: did_document.did.to_string(),
                        version_id: did_document.version_id.try_into().unwrap(),
                        valid_from: did_document.valid_from,
                        did_document_jcs: did_document_jcs_clone,
                    },
                };
                tracing::trace!("adding did_document_blob: {:?}", did_document_blob);
                let did_document_blob_key = transaction
                    .object_store("did_documents_provisional")?
                    .put(&serde_wasm_bindgen::to_value(&did_document_blob).unwrap())
                    .await?;
                tracing::trace!("added did_document_blob; did_document_blob_key: {:?}", did_document_blob_key);

                // Add the priv keys.
                let mut priv_key_blob_key_v = Vec::with_capacity(KeyPurpose::VARIANTS.len());
                for key_purpose in KeyPurpose::VARIANTS {
                    tracing::trace!("adding priv key for key_purpose: {:?}", key_purpose);
                    let priv_key_blob = PrivKeyBlob {
                        wallets_rowid: ctx_clone.wallets_rowid,
                        priv_key_record: PrivKeyRecord {
                            pub_key: pub_key_m[key_purpose].to_keri_verifier().into_owned(),
                            key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                            created_at,
                            last_used_at_o: Some(created_at),
                            usage_count: 1,
                            deleted_at_o: None,
                            private_key_bytes_o: Some(
                                priv_key_m[key_purpose].to_private_key_bytes().to_owned(),
                            ),
                        },
                    };
                    let priv_key_blob_key = transaction
                        .object_store("priv_keys_provisional")?
                        .put(&serde_wasm_bindgen::to_value(&priv_key_blob).unwrap())
                        .await?;
                    tracing::trace!("added priv key; key_purpose: {:?}; priv_key_blob_key.priv_key_record.pub_key: {:?}", key_purpose, priv_key_blob.priv_key_record.pub_key);
                    priv_key_blob_key_v.push(priv_key_blob_key);
                }

                // Add the priv key usage for the DIDCreate.
                tracing::trace!("adding priv key usage for DIDCreate");
                let priv_key_usage_blob = PrivKeyUsageBlob {
                    wallets_rowid: ctx_clone.wallets_rowid,
                    priv_key_usage_record: PrivKeyUsageRecord {
                        pub_key: did_document
                            .self_signature_verifier_o
                            .as_ref()
                            .unwrap()
                            .clone(),
                        used_at: created_at,
                        usage: PrivKeyUsage::DIDCreate {
                            created_did_o: Some(did.to_owned()),
                        },
                        verification_method_and_purpose_o: Some((
                            controlled_did_with_key_id,
                            KeyPurpose::CapabilityInvocation,
                        )),
                    },
                };
                let priv_key_usage_blob_key = transaction
                    .object_store("priv_key_usages_provisional")?
                    .put(&serde_wasm_bindgen::to_value(&priv_key_usage_blob).unwrap())
                    .await?;
                tracing::trace!("added priv key usage; priv_key_usage_blob_key: {:?}", priv_key_usage_blob_key);

                tracing::trace!("transaction #1 succeeded");
                Ok((
                    did_document_blob_key,
                    priv_key_blob_key_v,
                    priv_key_usage_blob_key,
                ))
            })
            .await
            .map_err(into_wallet_error)?;

        // POST the DID document to the VDR to create the DID.
        // TODO: Handle errors -- if the POST fails, then we need to delete the provisional records.
        {
            tracing::trace!("POST'ing DID document to VDR");
            let request_init = web_sys::RequestInit::new();
            request_init.set_method("POST");
            request_init.set_body(&JsValue::from_str(did_document_jcs.as_str()));

            let request = web_sys::Request::new_with_str_and_init(
                &did_clone.resolution_url(scheme),
                &request_init,
            )
            .map_err(|_| {
                did_webplus_wallet::Error::HTTPRequestError("Failed to create a request".into())
            })?;
            tracing::trace!("created HTTP request: {:?}", request);
            request
                .headers()
                .set("Content-Type", "application/json")
                .unwrap();
            use wasm_bindgen_futures::wasm_bindgen::JsCast;
            let response: web_sys::Response =
                JsFuture::from(web_sys::window().unwrap().fetch_with_request(&request))
                    .await
                    .map_err(|_| {
                        did_webplus_wallet::Error::HTTPRequestError(
                            "Failed to fetch response".into(),
                        )
                    })?
                    .dyn_into()
                    .map_err(|_| {
                        did_webplus_wallet::Error::HTTPRequestError(
                            "Failed to convert response to web_sys::Response".into(),
                        )
                    })?;
            tracing::trace!("got HTTP response: {:?}", response);

            if !response.ok() {
                tracing::error!("HTTP POST to DID create endpoint failed: {:?}", response);
                return Err(did_webplus_wallet::Error::HTTPOperationStatus(
                    format!("HTTP POST to DID create endpoint failed: {:?}", response).into(),
                ));
            }
            tracing::trace!("HTTP POST to DID create endpoint succeeded");
        }

        // Now that the HTTP POST is successful, move the provisional records to the non-provisional
        // versions of those object stores.
        self.db()
            .await
            .map_err(into_wallet_error)?
            .transaction(&[
                "did_documents",
                "did_documents_provisional",
                "priv_keys",
                "priv_keys_provisional",
                "priv_key_usages",
                "priv_key_usages_provisional",
            ])
            .rw()
            .run(async move |transaction| {
                tracing::trace!("started transaction #2; moving provisional records to non-provisional versions of those object stores");
                let did_document_blob_jsvalue = transaction
                    .object_store("did_documents_provisional")?
                    .get(&did_document_blob_key)
                    .await?
                    .unwrap();
                transaction
                    .object_store("did_documents_provisional")?
                    .delete(&did_document_blob_key)
                    .await?;
                transaction
                    .object_store("did_documents")?
                    .put(&did_document_blob_jsvalue)
                    .await?;

                for priv_key_blob_key in priv_key_blob_key_v {
                    let priv_key_blob_jsvalue = transaction
                        .object_store("priv_keys_provisional")?
                        .get(&priv_key_blob_key)
                        .await?
                        .unwrap();
                    transaction
                        .object_store("priv_keys_provisional")?
                        .delete(&priv_key_blob_key)
                        .await?;
                    transaction
                        .object_store("priv_keys")?
                        .put(&priv_key_blob_jsvalue)
                        .await?;
                }

                let priv_key_usage_blob_jsvalue = transaction
                    .object_store("priv_key_usages_provisional")?
                    .get(&priv_key_usage_blob_key)
                    .await?
                    .unwrap();
                transaction
                    .object_store("priv_key_usages_provisional")?
                    .delete(&priv_key_usage_blob_key)
                    .await?;
                transaction
                    .object_store("priv_key_usages")?
                    .put(&priv_key_usage_blob_jsvalue)
                    .await?;

                tracing::trace!("transaction #2 succeeded");
                Ok(())
            })
            .await
            .map_err(into_wallet_error)?;

        Ok(controlled_did)
    }
    async fn fetch_did(
        &self,
        _did: &DIDStr,
        _vdr_scheme: &'static str,
    ) -> did_webplus_wallet::Result<()> {
        todo!()
    }
    async fn update_did(
        &self,
        _did: &DIDStr,
        _vdr_scheme: &'static str,
    ) -> did_webplus_wallet::Result<DIDFullyQualified> {
        todo!()
    }
    async fn get_locally_controlled_verification_methods(
        &self,
        _locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> did_webplus_wallet::Result<Vec<(VerificationMethodRecord, Box<dyn selfsign::Signer>)>>
    {
        todo!()
    }
}
