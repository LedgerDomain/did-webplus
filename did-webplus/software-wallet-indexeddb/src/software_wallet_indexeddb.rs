use crate::Result;
use anyhow::Context;
use did_webplus_core::{
    now_utc_milliseconds, DIDDocument, DIDFullyQualified, DIDStr, HashedUpdateKey, KeyPurpose,
    KeyPurposeFlags, RootLevelUpdateRules, UpdateKey,
};
use did_webplus_doc_store::DIDDocRecord;
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyUsage, PrivKeyUsageRecord,
    VerificationMethodRecord, WalletRecord, WalletStorageCtx,
};
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

fn into_doc_store_error<E: std::fmt::Display>(e: E) -> did_webplus_doc_store::Error {
    did_webplus_doc_store::Error::StorageError(e.to_string().into())
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
    /// Optionally specifies the host (i.e. hostname and optional port number) of a VDG to use in the
    /// DIDResolverFull for fetching DID documents.  This is used so that this resolver can take part
    /// in the scope of agreement defined by the VDG.  Without using a VDG, a DIDResolverFull has a
    /// scope of agreement that only contains itself.
    vdg_host_o: Option<String>,
}

impl SoftwareWalletIndexedDB {
    pub const CURRENT_DB_VERSION: u32 = 1;
    pub async fn create(
        db_name: String,
        db_version: u32,
        wallet_name_o: Option<String>,
        vdg_host_o: Option<String>,
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
        let ctx = db.transaction(&[Self::WALLETS_OBJECT_STORE]).rw().run(async move |transaction| {
            tracing::debug!("started transaction for creating a wallet");
            let wallets_object_store = transaction.object_store(Self::WALLETS_OBJECT_STORE)?;
            tracing::debug!("got wallets_object_store");
            // Create a random UUID for the wallet.  The chance of collision is so low that
            // it's more likely a programmer error if it happens.
            let now_utc = time::OffsetDateTime::now_utc();
            tracing::debug!("now_utc: {:?}", now_utc);
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
            vdg_host_o,
        })
    }
    pub async fn open(
        db_name: String,
        db_version: u32,
        wallet_uuid: uuid::Uuid,
        vdg_host_o: Option<String>,
    ) -> Result<Self> {
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
            .transaction(&[Self::WALLETS_OBJECT_STORE])
            .run(async move |transaction| {
                tracing::debug!("started transaction for opening a wallet");
                let wallets_rowid_jsvalue_o = transaction
                    .object_store(Self::WALLETS_OBJECT_STORE)?
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
            vdg_host_o,
        })
    }
    async fn get_locally_controlled_verification_methods_internal(
        &self,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, PrivKeyRecord)>> {
        let filter = locally_controlled_verification_method_filter.clone();
        let ctx = self.ctx.clone();
        self.db()
            .await?
            .transaction(&[
                Self::DID_DOCUMENTS_OBJECT_STORE,
                Self::PRIV_KEYS_OBJECT_STORE,
            ])
            .run(async move |transaction| {
                let did_documents_object_store =
                    transaction.object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?;
                let priv_keys_object_store =
                    transaction.object_store(Self::PRIV_KEYS_OBJECT_STORE)?;
                let wallets_rowid_as_f64_jsvalue =
                    Self::wallets_rowid_as_f64_jsvalue(ctx.wallets_rowid);

                let did_document_blob_jsvalue_v = if let Some(did) = filter.did_o.as_ref() {
                    let did_as_jsvalue = JsValue::from(did.as_str());
                    let range_begin = if let Some(version_id) = filter.version_id_o {
                        JsValue::from(vec![did_as_jsvalue.clone(), JsValue::from(version_id)])
                    } else {
                        JsValue::from(vec![did_as_jsvalue.clone(), JsValue::from(0)])
                    };
                    let range_end = if let Some(version_id) = filter.version_id_o {
                        JsValue::from(vec![did_as_jsvalue.clone(), JsValue::from(version_id)])
                    } else {
                        JsValue::from(vec![did_as_jsvalue.clone(), JsValue::from(i32::MAX)])
                    };
                    let range = range_begin.clone()..=range_end;
                    did_documents_object_store
                        .index(Self::DID_DOCUMENTS_INDEX_DID_AND_VERSION_ID)?
                        .get_all_in(range, None)
                        .await?
                } else {
                    did_documents_object_store.get_all(None).await?
                };

                let mut locally_controlled_verification_method_v = Vec::new();
                for did_document_blob_jsvalue in did_document_blob_jsvalue_v {
                    let did_document_blob = serde_wasm_bindgen::from_value::<DIDDocumentBlob>(
                        did_document_blob_jsvalue,
                    )
                    .map_err(|e| {
                        Error::from(anyhow::anyhow!(
                            "Database corruption in DID document; error was: {}",
                            e
                        ))
                    })?;
                    let did_doc_record = &did_document_blob.did_doc_record;

                    if let Some(filter_did) = filter.did_o.as_ref() {
                        if did_doc_record.did.as_str() != filter_did.as_str() {
                            continue;
                        }
                    }
                    if let Some(filter_version_id) = filter.version_id_o {
                        if did_doc_record.version_id != filter_version_id as i64 {
                            continue;
                        }
                    }

                    let did_document: DIDDocument =
                        serde_json::from_str(&did_doc_record.did_document_jcs).map_err(|e| {
                            Error::from(anyhow::anyhow!(
                                "Database corruption in DID document; parse error was: {}",
                                e
                            ))
                        })?;

                    for verification_method in did_document
                        .public_key_material
                        .verification_method_v
                        .iter()
                    {
                        if let Some(filter_key_id) = filter.key_id_o.as_deref() {
                            if verification_method.id.fragment() != filter_key_id {
                                continue;
                            }
                        }

                        let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk)
                            .map_err(|e| {
                                Error::from(anyhow::anyhow!(
                                    "error converting public key JWK to MBPubKey; error was: {}",
                                    e
                                ))
                            })?;

                        if let Some(filter_key_purpose) = filter.key_purpose_o {
                            let key_purpose_flags = did_document
                                .public_key_material
                                .key_purpose_flags_for_key_id_fragment(&pub_key);
                            if !key_purpose_flags.contains(filter_key_purpose) {
                                continue;
                            }
                        }

                        let compound_key = JsValue::from(vec![
                            wallets_rowid_as_f64_jsvalue.clone(),
                            JsValue::from(pub_key.to_string()),
                        ]);
                        let priv_key_blob_jsvalue_o = priv_keys_object_store
                            .index(Self::PRIV_KEYS_INDEX_WALLETS_ROWID_AND_PUB_KEY)?
                            .get(&compound_key)
                            .await?;

                        if let Some(priv_key_blob_jsvalue) = priv_key_blob_jsvalue_o {
                            let priv_key_blob = serde_wasm_bindgen::from_value::<PrivKeyBlob>(
                                priv_key_blob_jsvalue,
                            )
                            .map_err(|e| {
                                Error::from(anyhow::anyhow!(
                                    "Database corruption in priv key; error was: {}",
                                    e
                                ))
                            })?;
                            let priv_key_record = &priv_key_blob.priv_key_record;
                            if priv_key_record.deleted_at_o.is_some() {
                                continue;
                            }
                            priv_key_record.private_key_bytes_o.clone().ok_or_else(|| {
                                Error::from(anyhow::anyhow!(
                                    "priv key has no private_key_bytes_o (deleted or corrupted)"
                                ))
                            })?;

                            let key_purpose_flags = did_document
                                .public_key_material
                                .key_purpose_flags_for_key_id_fragment(&pub_key);
                            let verification_method_record = VerificationMethodRecord {
                                did_key_resource_fully_qualified: verification_method.id.clone(),
                                key_purpose_flags,
                                pub_key,
                            };
                            locally_controlled_verification_method_v
                                .push((verification_method_record, priv_key_record.clone()));

                            if let Some(limit) = filter.result_limit_o {
                                if locally_controlled_verification_method_v.len() >= limit as usize
                                {
                                    return Ok(locally_controlled_verification_method_v);
                                }
                            }
                        }
                    }
                }
                Ok(locally_controlled_verification_method_v)
            })
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
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

    // Names for object stores and indexes, so they don't need to be repeated in multiple places.

    const WALLETS_OBJECT_STORE: &str = "wallets";
    const WALLETS_INDEX_WALLET_UUID: &str = "wallets index: wallet_uuid";

    const PRIV_KEYS_OBJECT_STORE: &str = "priv_keys";
    const PRIV_KEYS_PROVISIONAL_OBJECT_STORE: &str = "priv_keys_provisional";
    const PRIV_KEYS_INDEX_WALLETS_ROWID_AND_PUB_KEY: &str =
        "priv_keys index: wallets_rowid_and_pub_key";

    const PRIV_KEY_USAGES_OBJECT_STORE: &str = "priv_key_usages";

    const PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE: &str = "priv_key_usages_provisional";

    const DID_DOCUMENTS_OBJECT_STORE: &str = "did_documents";
    const DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE: &str = "did_documents_provisional";
    const DID_DOCUMENTS_INDEX_DID_AND_SELF_HASH: &str = "did_documents index: did_and_self_hash";
    const DID_DOCUMENTS_INDEX_DID_AND_VERSION_ID: &str = "did_documents index: did_and_version_id";
    const DID_DOCUMENTS_INDEX_SELF_HASH_AND_VERSION_ID: &str =
        "did_documents index: self_hash_and_version_id";
    const DID_DOCUMENTS_INDEX_SELF_HASH_AND_VALID_FROM: &str =
        "did_documents index: self_hash_and_valid_from";

    fn migration_0_to_1(db: &indexed_db::Database<Error>) -> Result<(), indexed_db::Error<Error>> {
        tracing::info!("Applying database migration 0 -> 1: Adding initial object stores",);
        let wallets_object_store = db
            .build_object_store(Self::WALLETS_OBJECT_STORE)
            .auto_increment()
            .create()?;
        wallets_object_store
            .build_index(Self::WALLETS_INDEX_WALLET_UUID, "wallet_uuid")
            .create()?;

        let priv_keys_object_store = db
            .build_object_store(Self::PRIV_KEYS_OBJECT_STORE)
            .auto_increment()
            .create()?;
        let priv_keys_provisional_object_store = db
            .build_object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)
            .auto_increment()
            .create()?;
        for object_store in [&priv_keys_object_store, &priv_keys_provisional_object_store] {
            object_store
                .build_compound_index(
                    Self::PRIV_KEYS_INDEX_WALLETS_ROWID_AND_PUB_KEY,
                    &["wallets_rowid", "priv_key_record.pub_key"],
                )
                .create()?;
        }

        db.build_object_store(Self::PRIV_KEY_USAGES_OBJECT_STORE)
            .auto_increment()
            .create()?;

        db.build_object_store(Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE)
            .auto_increment()
            .create()?;

        let did_documents_object_store = db
            .build_object_store(Self::DID_DOCUMENTS_OBJECT_STORE)
            .auto_increment()
            .create()?;
        let did_documents_provisional_object_store = db
            .build_object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)
            .auto_increment()
            .create()?;
        for object_store in [
            &did_documents_object_store,
            &did_documents_provisional_object_store,
        ] {
            object_store
                .build_compound_index(
                    Self::DID_DOCUMENTS_INDEX_DID_AND_SELF_HASH,
                    &["did_doc_record.did", "did_doc_record.self_hash"],
                )
                .create()?;
            object_store
                .build_compound_index(
                    Self::DID_DOCUMENTS_INDEX_DID_AND_VERSION_ID,
                    &["did_doc_record.did", "did_doc_record.version_id"],
                )
                .create()?;
            object_store
                .build_compound_index(
                    Self::DID_DOCUMENTS_INDEX_SELF_HASH_AND_VERSION_ID,
                    &["did_doc_record.self_hash", "did_doc_record.version_id"],
                )
                .create()?;
            object_store
                .build_compound_index(
                    Self::DID_DOCUMENTS_INDEX_SELF_HASH_AND_VALID_FROM,
                    &["did_doc_record.self_hash", "did_doc_record.valid_from"],
                )
                .create()?;
        }

        Ok(())
    }
    async fn fetch_did_internal(
        &self,
        did: &DIDStr,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<did_webplus_core::DIDDocument> {
        // Note the version of the known latest DID document.  This will only differ from the actual latest
        // version if more than one wallet controls the DID.

        // Retrieve any unfetched updates to the DID.
        let did_doc_storage = self.clone();
        let did_doc_storage_a = std::sync::Arc::new(did_doc_storage);
        let did_doc_store = did_webplus_doc_store::DIDDocStore::new(did_doc_storage_a);
        let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
            did_doc_store,
            self.vdg_host_o.as_deref(),
            http_options_o.cloned(),
        )
        .unwrap();
        use did_webplus_resolver::DIDResolver;
        let (did_document, _did_document_metadata, _did_resolution_metadata) = did_resolver_full
            .resolve_did_document(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::no_metadata(false),
            )
            .await
            .map_err(|e| {
                did_webplus_wallet::Error::DIDFetchError(
                    format!("DID: {}, error was: {}", did, e).into(),
                )
            })?;

        Ok(did_document)
    }
    async fn post_or_put_did_document(
        &self,
        operation: &'static str,
        did_document_jcs: &str,
        did: &DIDStr,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<()> {
        if operation != "create" && operation != "update" {
            return Err(did_webplus_wallet::Error::Malformed(
                format!("Invalid operation: {}", operation).into(),
            ));
        }
        let http_method = match operation {
            "create" => "POST",
            "update" => "PUT",
            _ => unreachable!(),
        };

        tracing::trace!(
            "DID {}; {}'ing DID document to VDR for DID: {}",
            operation,
            http_method,
            did,
        );
        let request_init = web_sys::RequestInit::new();
        request_init.set_method(http_method);
        request_init.set_body(&JsValue::from_str(did_document_jcs));

        let request = web_sys::Request::new_with_str_and_init(
            &did.resolution_url_for_did_documents_jsonl(
                http_options_o.as_ref().map(|o| &o.http_scheme_override),
            ),
            &request_init,
        )
        .map_err(|_| {
            did_webplus_wallet::Error::HTTPRequestError("Failed to create a request".into())
        })?;

        request
            .headers()
            .set("Content-Type", "application/json")
            .unwrap();
        if let Some(http_headers_for) = http_options_o.map(|o| &o.http_headers_for) {
            let http_header_v = http_headers_for
                .http_headers_for_hostname(did.hostname())
                .unwrap_or_default();
            for http_header in http_header_v {
                request
                    .headers()
                    .set(&http_header.name, &http_header.value)
                    .unwrap();
            }
        }
        tracing::trace!("created HTTP request: {:?}", request);

        use wasm_bindgen_futures::wasm_bindgen::JsCast;
        let response: web_sys::Response =
            JsFuture::from(web_sys::window().unwrap().fetch_with_request(&request))
                .await
                .map_err(|_| {
                    did_webplus_wallet::Error::HTTPRequestError("Failed to fetch response".into())
                })?
                .dyn_into()
                .map_err(|_| {
                    did_webplus_wallet::Error::HTTPRequestError(
                        "Failed to convert response to web_sys::Response".into(),
                    )
                })?;
        tracing::trace!("got HTTP response: {:?}", response);

        if !response.ok() {
            tracing::error!(
                "DID {}; {}'ing DID document to VDR failed (DID: {}): {:?}",
                operation,
                http_method,
                did,
                response
            );
            return Err(did_webplus_wallet::Error::HTTPOperationStatus(
                format!(
                    "DID {}; {}'ing DID document to VDR failed (DID: {}): {:?}",
                    operation, http_method, did, response
                )
                .into(),
            ));
        }
        tracing::trace!(
            "DID {}; {}'ing DID document to VDR succeeded; DID: {}",
            operation,
            http_method,
            did
        );

        Ok(())
    }
    fn wallets_rowid_as_f64_jsvalue(wallets_rowid: i64) -> JsValue {
        let wallets_rowid_as_i32 = i32::try_from(wallets_rowid).expect("programmer error: overflow in wallets_rowid; this is so unlikely that it's almost certainly a programmer error");
        let wallets_rowid_as_f64 = f64::from(wallets_rowid_as_i32);
        assert!(
            wallets_rowid_as_f64.fract() == 0.0,
            "programmer error: wallets_rowid is not an integer"
        );
        JsValue::from(wallets_rowid_as_f64)
    }
}

/// This is the blob that gets stored in the IndexedDB database for each DID document.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct DIDDocumentBlob {
    pub did_doc_record: DIDDocRecord,
}

/// This is the blob that gets stored in the IndexedDB database for each private key.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct PrivKeyBlob {
    pub wallets_rowid: i64,
    pub priv_key_record: PrivKeyRecord,
}

/// This is the blob that gets stored in the IndexedDB database for each private key usage.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct PrivKeyUsageBlob {
    pub wallets_rowid: i64,
    pub priv_key_usage_record: PrivKeyUsageRecord,
}

/// NOTE: This is a hack that doesn't follow the semantics of storage_traits::TransactionDynT
/// and storage_traits::StorageDynT, and is only used to allow the SoftwareWalletIndexedDB to
/// implement the DIDDocStorage trait.  SoftwareWalletIndexedDB can't directly support the
/// TransactionDynT pattern because the indexed_db crate transaction pattern involves async
/// closures passed to a particular async executor, instead of passing around a transaction
/// object.  This means that each DIDDocStorage operation on SoftwareWalletIndexedDB is
/// effectively in its own transaction, and not part of a larger transaction.
#[derive(Clone, Debug)]
pub struct NotATransaction;

impl std::ops::Drop for NotATransaction {
    fn drop(&mut self) {
        // Nothing to do.
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::TransactionDynT for NotATransaction {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn commit(self: Box<Self>) -> storage_traits::Result<()> {
        Ok(())
    }
    async fn rollback(self: Box<Self>) -> storage_traits::Result<()> {
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for SoftwareWalletIndexedDB {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(NotATransaction))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_doc_store::DIDDocStorage for SoftwareWalletIndexedDB {
    async fn add_did_document(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> did_webplus_doc_store::Result<()> {
        let self_hash = did_document.self_hash.to_string();
        let did = did_document.did.to_string();
        let version_id = did_document.version_id.try_into().unwrap();
        let valid_from = did_document.valid_from;
        let did_document_jcs = did_document_jcs.to_string();
        self.db()
            .await
            .map_err(into_doc_store_error)?
            .transaction(&[Self::DID_DOCUMENTS_OBJECT_STORE])
            .rw()
            .run(async move |transaction| {
                // Retrieve the latest DIDDocRecord to get the did_documents_jsonl_octet_length.
                let latest_did_doc_record_cursor = transaction
                    .object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?
                    .index(Self::DID_DOCUMENTS_INDEX_DID_AND_VERSION_ID)?
                    .cursor()
                    .direction(indexed_db::CursorDirection::Prev)
                    .open()
                    .await?;
                let did_documents_jsonl_octet_length = latest_did_doc_record_cursor
                    .value()
                    .map(|jsvalue| {
                        serde_wasm_bindgen::from_value::<DIDDocumentBlob>(jsvalue)
                            .map_err(into_doc_store_error)
                            .map(|blob| blob.did_doc_record.did_documents_jsonl_octet_length)
                    })
                    .transpose()
                    .map_err(|e| indexed_db::Error::User(Error::from(anyhow::anyhow!(e))))?
                    .unwrap_or(0)
                    + did_document_jcs.len() as i64
                    + 1;

                let did_document_blob = DIDDocumentBlob {
                    did_doc_record: DIDDocRecord {
                        self_hash,
                        did,
                        version_id,
                        valid_from,
                        did_documents_jsonl_octet_length,
                        did_document_jcs,
                    },
                };
                transaction
                    .object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?
                    .put(&serde_wasm_bindgen::to_value(&did_document_blob).unwrap())
                    .await?;
                Ok(())
            })
            .await
            .map_err(into_doc_store_error)?;
        Ok(())
    }
    async fn add_did_documents(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did_document_jcs_v: &[&str],
        _did_document_v: &[DIDDocument],
    ) -> did_webplus_doc_store::Result<()> {
        unimplemented!("SoftwareWalletIndexedDB::add_did_documents");
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did: &DIDStr,
        _self_hash: &mbx::MBHashStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        unimplemented!("SoftwareWalletIndexedDB::get_did_doc_record_with_self_hash");
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did: &DIDStr,
        _version_id: u32,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        unimplemented!("SoftwareWalletIndexedDB::get_did_doc_record_with_version_id");
    }
    async fn get_latest_known_did_doc_record(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did = did.to_owned();
        let did_as_jsvalue = JsValue::from(did.as_str());
        let range_begin = JsValue::from(vec![did_as_jsvalue.clone(), JsValue::from(0)]);
        let range_end = JsValue::from(vec![did_as_jsvalue.clone(), JsValue::from(i32::MAX)]);
        let did_doc_record_o = self
            .db()
            .await
            .map_err(into_doc_store_error)?
            .transaction(&[Self::DID_DOCUMENTS_OBJECT_STORE])
            .run(async move |transaction| {
                tracing::debug!("starting transaction for fetch_did_internal");
                let did_document_blob_cursor = transaction
                    .object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?
                    .index(Self::DID_DOCUMENTS_INDEX_DID_AND_VERSION_ID)?
                    .cursor()
                    // TODO: Is this range necessary?
                    .range(range_begin..range_end)?
                    // DID documents are stored in chronological order, so we need to go backwards.
                    .direction(indexed_db::CursorDirection::Prev)
                    .open()
                    .await?;
                tracing::trace!("got did_document_blob_cursor");
                let did_document_blob_jsvalue_o = did_document_blob_cursor.value();
                if let Some(did_document_blob_jsvalue) = did_document_blob_jsvalue_o {
                    tracing::trace!(
                        "got did_document_blob_jsvalue: {:?}",
                        did_document_blob_jsvalue
                    );
                    let did_document_blob = serde_wasm_bindgen::from_value::<DIDDocumentBlob>(
                        did_document_blob_jsvalue,
                    )
                    .map_err(|e| {
                        Error::from(anyhow::anyhow!(
                            "Database corruption in DID document; error was: {}",
                            e
                        ))
                    })?;
                    Ok(Some(did_document_blob.did_doc_record))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(into_doc_store_error)?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_records(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did_doc_record_filter: &did_webplus_doc_store::DIDDocRecordFilter,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        unimplemented!("SoftwareWalletIndexedDB::get_did_doc_records");
    }
    async fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did: &DIDStr,
        _range_begin_inclusive_o: Option<u64>,
        _range_end_exclusive_o: Option<u64>,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        unimplemented!(
            "SoftwareWalletIndexedDB::get_did_doc_records_for_did_documents_jsonl_range"
        );
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_wallet::Wallet for SoftwareWalletIndexedDB {
    async fn create_did(
        &self,
        create_did_parameters: did_webplus_wallet::CreateDIDParameters<'_>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<DIDFullyQualified> {
        tracing::debug!(
            ?create_did_parameters,
            "SoftwareWalletIndexedDB::create_did"
        );
        // TODO: Factor this code with that in SoftwareWallet::create_did.

        // Have to created owned versions of each of these because of the async closures below.
        let vdr_did_create_endpoint = create_did_parameters.vdr_did_create_endpoint.to_owned();
        let mb_hash_function_for_did = create_did_parameters.mb_hash_function_for_did.to_owned();
        let mb_hash_function_for_update_key_o = create_did_parameters
            .mb_hash_function_for_update_key_o
            .map(|o| o.to_owned());

        // Parse the vdr_did_create_endpoint as a URL.
        let vdr_did_create_endpoint_url =
            url::Url::parse(&vdr_did_create_endpoint).map_err(|e| {
                did_webplus_wallet::Error::InvalidVDRDIDCreateURL(
                    format!(
                        "Parse error in VDR DID Create endpoint URL {:?} -- error was: {}",
                        vdr_did_create_endpoint, e
                    )
                    .into(),
                )
            })?;
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
        let now_utc = now_utc_milliseconds();
        // TODO: This should use SubtleCrypto, not ed25519-dalek.
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::UpdateDIDDocument => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::Authentication].verifying_key()),
            KeyPurpose::AssertionMethod => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::AssertionMethod].verifying_key()),
            KeyPurpose::KeyAgreement => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::KeyAgreement].verifying_key()),
            KeyPurpose::CapabilityInvocation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key()),
            KeyPurpose::CapabilityDelegation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key()),
            KeyPurpose::UpdateDIDDocument => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::UpdateDIDDocument].verifying_key()),
        };

        // Define the update rules.  For now, just a single key.
        let update_rules = if let Some(mb_hash_function_for_update_key) =
            mb_hash_function_for_update_key_o.as_ref()
        {
            RootLevelUpdateRules::from(HashedUpdateKey::from_pub_key(
                mb_hash_function_for_update_key,
                &pub_key_m[KeyPurpose::UpdateDIDDocument],
            ))
        } else {
            RootLevelUpdateRules::from(UpdateKey {
                pub_key: pub_key_m[KeyPurpose::UpdateDIDDocument].clone(),
            })
        };

        // Form the unsigned root DID document.
        let mut did_document = DIDDocument::create_unsigned_root(
            vdr_did_create_endpoint_url.host_str().unwrap(),
            vdr_did_create_endpoint_url.port(),
            did_path_o.as_deref(),
            update_rules,
            now_utc,
            did_webplus_core::PublicKeySet {
                authentication_v: vec![&pub_key_m[KeyPurpose::Authentication]],
                assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod]],
                key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement]],
                capability_invocation_v: vec![&pub_key_m[KeyPurpose::CapabilityInvocation]],
                capability_delegation_v: vec![&pub_key_m[KeyPurpose::CapabilityDelegation]],
            },
            &mb_hash_function_for_did,
        )
        .expect("programmer error");

        // There's no need to sign the root DID document, but it is allowed.  There could be
        // reasons outside of the did:webplus specification for doing so.

        // Finalize the root DID document.
        did_document.finalize(None).expect("programmer error");

        // Sanity check.
        did_document
            .verify_root_nonrecursive()
            .expect("programmer error");

        // Now that the DID document is finalized, we can get the DID.
        let did = did_document.did.clone();

        tracing::trace!(?did, "created root DID document");

        let did_document_jcs = did_document
            .serialize_canonically()
            .expect("this shouldn't happen");
        tracing::trace!("serialized root DID document: {}", did_document_jcs);

        // First, add the DID document, priv keys, and priv key usages to the database, but under
        // the "provisional" versions of those object stores.  Then the HTTP POST to the VDR will
        // happen, and then only if it succeeds will move the records to the non-provisional
        // versions of those object stores.

        let ctx_clone = self.ctx.clone();
        let did_clone = did.clone();
        let did_document_clone = did_document.clone();
        let did_document_jcs_clone = did_document_jcs.clone();
        let (did_document_blob_key, priv_key_blob_key_v) = self
            .db()
            .await
            .map_err(into_wallet_error)?
            .transaction(&[
                Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE,
                Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE,
            ])
            .rw()
            .run(async move |transaction| {
                tracing::trace!("started transaction #1; adding provisional records for DID document, priv keys, and priv key usages");
                // Store the DID document.
                let did_document_blob = DIDDocumentBlob {
                    did_doc_record: DIDDocRecord {
                        self_hash: did_document_clone.self_hash.to_string(),
                        did: did_document_clone.did.to_string(),
                        version_id: did_document_clone.version_id.try_into().unwrap(),
                        valid_from: did_document_clone.valid_from,
                        did_documents_jsonl_octet_length: did_document_jcs_clone.len() as i64 + 1,
                        did_document_jcs: did_document_jcs_clone,
                    },
                };
                tracing::trace!("adding did_document_blob: {:?}", did_document_blob);
                let did_document_blob_key = transaction
                    .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                    .put(&serde_wasm_bindgen::to_value(&did_document_blob).unwrap())
                    .await?;
                tracing::trace!("added did_document_blob; did_document_blob_key: {:?}", did_document_blob_key);

                // Store the priv keys.
                let mut priv_key_blob_key_v = Vec::with_capacity(KeyPurpose::VARIANTS.len());
                for key_purpose in KeyPurpose::VARIANTS {
                    tracing::trace!("adding priv key for key_purpose: {:?}", key_purpose);
                    let pub_key = pub_key_m[key_purpose].clone();
                    let hashed_pub_key_string = if let Some(mb_hash_function_for_update_key) =
                        mb_hash_function_for_update_key_o.as_ref()
                    {
                        mb_hash_function_for_update_key
                            .hash(pub_key.as_bytes())
                            .to_string()
                    } else {
                        "<not-hashed>".to_string()
                    };
                    let max_usage_count_o = if key_purpose == KeyPurpose::UpdateDIDDocument {
                        Some(1)
                    } else {
                        None
                    };
                    let comment_o = Some("generated during DID create".to_string());
                    use signature_dyn::SignerDynT;
                    let priv_key_blob = PrivKeyBlob {
                        wallets_rowid: ctx_clone.wallets_rowid,
                        priv_key_record: PrivKeyRecord {
                            pub_key,
                            hashed_pub_key: hashed_pub_key_string,
                            did_restriction_o: Some(did_clone.to_string()),
                            key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                            created_at: now_utc,
                            last_used_at_o: None,
                            max_usage_count_o,
                            usage_count: 0,
                            deleted_at_o: None,
                            private_key_bytes_o: Some(
                                priv_key_m[key_purpose].to_signer_bytes().to_owned(),
                            ),
                            comment_o,
                        },
                    };
                    let priv_key_blob_key = transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .put(&serde_wasm_bindgen::to_value(&priv_key_blob).unwrap())
                        .await?;
                    tracing::trace!("added priv key; key_purpose: {:?}; priv_key_blob_key.priv_key_record.pub_key: {:?}", key_purpose, priv_key_blob.priv_key_record.pub_key);
                    priv_key_blob_key_v.push(priv_key_blob_key);
                }

                tracing::trace!("transaction #1 succeeded");
                Ok((
                    did_document_blob_key,
                    priv_key_blob_key_v,
                ))
            })
            .await
            .map_err(into_wallet_error)?;

        // POST the DID document to the VDR to create the DID.  If an error occurs, then delete the
        // provisional records.
        match self
            .post_or_put_did_document("create", &did_document_jcs, &did, http_options_o)
            .await
        {
            Ok(()) => (),
            Err(e) => {
                tracing::error!("error POST'ing DID document to VDR: {:?}", e);
                // Delete the provisional records.
                // TODO: Figure out how to handle errors here.  Maybe do some sort of cleanup of provisional records
                // that are older than some threshold.
                self.db()
                    .await
                    .map_err(into_wallet_error)?
                    .transaction(&[
                        Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE,
                        Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE,
                    ])
                    .rw()
                    .run(async move |transaction| {
                        tracing::trace!("undoing transaction #1 because HTTP POST for DID {} failed; deleting provisional records", did);
                        transaction
                            .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                            .delete(&did_document_blob_key)
                            .await?;

                        for priv_key_blob_key in priv_key_blob_key_v {
                            transaction
                                .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                                .delete(&priv_key_blob_key)
                                .await?;
                        }

                        tracing::trace!("undo of transaction #1 succeeded");
                        Ok(())
                    })
                    .await
                    .map_err(into_wallet_error)?;
                // Finally, abort this operation.
                return Err(e);
            }
        }

        // Now that the HTTP POST is successful, move the provisional records to the non-provisional
        // versions of those object stores.
        self.db()
            .await
            .map_err(into_wallet_error)?
            .transaction(&[
                Self::DID_DOCUMENTS_OBJECT_STORE,
                Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE,
                Self::PRIV_KEYS_OBJECT_STORE,
                Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE,
            ])
            .rw()
            .run(async move |transaction| {
                tracing::trace!("started transaction #2; moving provisional records to non-provisional versions of those object stores");
                let did_document_blob_jsvalue = transaction
                    .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                    .get(&did_document_blob_key)
                    .await?
                    .unwrap();
                transaction
                    .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                    .delete(&did_document_blob_key)
                    .await?;
                transaction
                    .object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?
                    .put(&did_document_blob_jsvalue)
                    .await?;

                for priv_key_blob_key in priv_key_blob_key_v {
                    let priv_key_blob_jsvalue = transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .get(&priv_key_blob_key)
                        .await?
                        .unwrap();
                    transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .delete(&priv_key_blob_key)
                        .await?;
                    transaction
                        .object_store(Self::PRIV_KEYS_OBJECT_STORE)?
                        .put(&priv_key_blob_jsvalue)
                        .await?;
                }

                tracing::trace!("transaction #2 succeeded");
                Ok(())
            })
            .await
            .map_err(into_wallet_error)?;

        // Derive the controlled DID.
        let controlled_did = did.with_queries(&did_document.self_hash, 0);

        Ok(controlled_did)
    }
    async fn fetch_did(
        &self,
        _did: &DIDStr,
        _http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<()> {
        todo!()
    }
    async fn update_did(
        &self,
        update_did_parameters: did_webplus_wallet::UpdateDIDParameters<'_>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<DIDFullyQualified> {
        tracing::debug!(
            "SoftwareWalletIndexedDB::update_did; did: {}; http_options_o: {:?}",
            update_did_parameters.did,
            http_options_o
        );

        // Have to created owned versions of each of these because of the async closures below.
        let did = update_did_parameters.did.to_owned();
        let change_mb_hash_function_for_self_hash_o = update_did_parameters
            .change_mb_hash_function_for_self_hash_o
            .map(|o| o.to_owned());
        let mb_hash_function_for_update_key_o = update_did_parameters
            .mb_hash_function_for_update_key_o
            .map(|o| o.to_owned());

        // Fetch external updates to the DID before updating it.  This is only relevant if more than one wallet
        // controls the DID.
        let latest_did_document = self.fetch_did_internal(&did, http_options_o).await?;
        let did_fully_qualified = did.with_queries(
            &latest_did_document.self_hash,
            latest_did_document.version_id,
        );

        // Rotate the appropriate set of keys.  Record the creation timestamp.
        let now_utc = time::OffsetDateTime::now_utc();
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::UpdateDIDDocument => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::Authentication].verifying_key()),
            KeyPurpose::AssertionMethod => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::AssertionMethod].verifying_key()),
            KeyPurpose::KeyAgreement => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::KeyAgreement].verifying_key()),
            KeyPurpose::CapabilityInvocation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key()),
            KeyPurpose::CapabilityDelegation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key()),
            KeyPurpose::UpdateDIDDocument => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::UpdateDIDDocument].verifying_key()),
        };

        // First, add the DID document, priv keys, and priv key usages to the database, but under
        // the "provisional" versions of those object stores.  Then the HTTP PUT to the VDR will
        // happen, and then only if it succeeds will move the records to the non-provisional
        // versions of those object stores.
        let ctx_clone = self.ctx.clone();
        let did_clone = did.clone();
        // let updated_did_document_clone = updated_did_document.clone();
        // let updated_did_document_jcs_clone = updated_did_document_jcs.clone();
        let (updated_did_document, updated_did_document_jcs, did_document_blob_key, priv_key_blob_key_v, priv_key_usage_blob_key, priv_key_blob_keys_to_retire_v) = self
            .db()
            .await
            .map_err(into_wallet_error)?
            .transaction(&[
                Self::DID_DOCUMENTS_OBJECT_STORE,
                Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE,
                Self::PRIV_KEYS_OBJECT_STORE,
                Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE,
                Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE,
            ])
            .rw()
            .run(async move |transaction| -> std::result::Result<_, indexed_db::Error<Error>> {
                tracing::trace!("started transaction #1; retrieving appropriate signing key, updating DID document, adding provisional records for updated DID document, priv keys, and priv key usages");

                // Get locally controlled verification methods for the latest DID document
                let priv_keys_object_store = transaction.object_store(Self::PRIV_KEYS_OBJECT_STORE)?;
                let locally_controlled_verification_method_v = {
                    tracing::trace!("getting locally controlled verification methods for latest DID document");
                    let mut locally_controlled_verification_method_v = Vec::new();
                    // Go through latest_did_document and find the verification methods that are locally controlled,
                    // i.e. whose public keys match those in the priv_keys object store.
                    for verification_method in latest_did_document.public_key_material.verification_method_v.iter() {
                        let wallets_rowid_as_f64_jsvalue = Self::wallets_rowid_as_f64_jsvalue(ctx_clone.wallets_rowid);

                        let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk).map_err(|e| Error::from(anyhow::anyhow!("error converting public key JWK to MBPubKey; error was: {}", e)))?;
                        let pub_key_str_jsvalue = JsValue::from(pub_key.to_string());

                        let compound_key = JsValue::from(vec![
                            wallets_rowid_as_f64_jsvalue.clone(),
                            pub_key_str_jsvalue.clone(),
                        ]);
                        let priv_key_blob_jsvalue_o = priv_keys_object_store
                            .index(Self::PRIV_KEYS_INDEX_WALLETS_ROWID_AND_PUB_KEY)?
                            .get(&compound_key)
                            .await?;
                        if let Some(priv_key_blob_jsvalue) = priv_key_blob_jsvalue_o {
                            let primary_keys = priv_keys_object_store
                                .index(Self::PRIV_KEYS_INDEX_WALLETS_ROWID_AND_PUB_KEY)?
                                .get_all_keys_in(compound_key.clone()..=compound_key, Some(1))
                                .await?;
                            if let Some(primary_key) = primary_keys.into_iter().next() {
                                let key_purpose_flags =
                                    latest_did_document.public_key_material.key_purpose_flags_for_key_id_fragment(&pub_key);
                                let verification_method_record =
                                    did_webplus_wallet_store::VerificationMethodRecord {
                                        did_key_resource_fully_qualified: did_fully_qualified
                                            .with_fragment(&verification_method.id.fragment()),
                                        key_purpose_flags,
                                        pub_key,
                                    };
                                let priv_key_blob =
                                    serde_wasm_bindgen::from_value::<PrivKeyBlob>(priv_key_blob_jsvalue)
                                        .map_err(|e| {
                                            Error::from(anyhow::anyhow!(
                                                "Database corruption in DID document; error was: {}",
                                                e
                                            ))
                                        })?;
                                locally_controlled_verification_method_v
                                    .push((verification_method_record, priv_key_blob, primary_key));
                            }
                        }
                    }
                    tracing::trace!(
                        "found {} locally controlled verification methods for latest DID document",
                        locally_controlled_verification_method_v.len()
                    );
                    locally_controlled_verification_method_v
                };

                // Query all update keys.
                let update_key_v = {
                    tracing::trace!("getting update keys for latest DID document");
                    let priv_key_record_filter = did_webplus_wallet_store::PrivKeyRecordFilter {
                        pub_key_o: None,
                        hashed_pub_key_o: None,
                        did_o: Some(did_clone.to_string()),
                        key_purpose_flags_o: Some(KeyPurposeFlags::from(KeyPurpose::UpdateDIDDocument)),
                        is_not_deleted_o: Some(true),
                    };
                    let mut update_key_v = Vec::new();
                    let priv_key_blob_jsvalue_v = priv_keys_object_store.get_all(None).await?;
                    for priv_key_blob_jsvalue in priv_key_blob_jsvalue_v {
                        let priv_key_blob = serde_wasm_bindgen::from_value::<PrivKeyBlob>(priv_key_blob_jsvalue).map_err(|e| {
                            Error::from(anyhow::anyhow!(
                                "Database corruption in DID document; error was: {}",
                                e
                            ))
                        })?;
                        if priv_key_blob.wallets_rowid != ctx_clone.wallets_rowid {
                            continue;
                        }
                        if !priv_key_record_filter.matches(&priv_key_blob.priv_key_record) {
                            continue;
                        }
                        update_key_v.push(priv_key_blob.priv_key_record);
                    }
                    tracing::trace!("found {} update keys for latest DID document", update_key_v.len());
                    update_key_v
                };

                // Check if there are any matching update keys.
                let matching_update_key_v = {
                    let mut matching_update_key_v: Vec<&PrivKeyRecord> = Vec::new();
                    let update_pub_key_v = update_key_v
                        .iter()
                        .map(|priv_key_record| &priv_key_record.pub_key)
                        .collect::<Vec<_>>();
                    let mut matching_update_key_index_v = Vec::new();
                    use did_webplus_core::VerifyRulesT;
                    latest_did_document.update_rules.find_matching_update_keys(
                        update_pub_key_v.as_slice(),
                        &mut matching_update_key_index_v,
                    );
                    matching_update_key_index_v.sort();
                    matching_update_key_index_v.dedup();
                    for matching_update_key_index in matching_update_key_index_v.iter() {
                        matching_update_key_v.push(&update_key_v[*matching_update_key_index]);
                    }
                    matching_update_key_v
                };
                // If there are no matching update keys, then this means that this wallet doesn't have
                // the authority to update the DID.  This could happen if another wallet updated the DID
                // and removed this wallet's update key.
                if matching_update_key_v.is_empty() {
                    return Err(indexed_db::Error::from(Error::from(anyhow::anyhow!("this wallet has no update key for {}, so DID cannot be updated by this wallet; latest DID doc has selfHash {} and versionId {}", did_clone, latest_did_document.self_hash, latest_did_document.version_id))));
                }
                // Temporary assumption: There will only be one update key per wallet.
                assert_eq!(
                    matching_update_key_v.len(),
                    1,
                    "programmer error: assumption is that there should only be one update key per wallet"
                );

                // Select the appropriate key to sign the update.
                let priv_key_record_for_update = &matching_update_key_v[0];
                let priv_key_for_update = priv_key_record_for_update
                    .private_key_bytes_o
                    .as_ref()
                    .expect(
                        "programmer error: priv_key_bytes_o was expected to be Some(_); i.e. not deleted",
                    );

                // Define the update rules.  Temporary limitation: Just specify a single key.
                // TODO: Support multiple update keys.
                let update_rules = if let Some(mb_hash_function_for_update_key) =
                    mb_hash_function_for_update_key_o.as_ref()
                {
                    RootLevelUpdateRules::from(HashedUpdateKey::from_pub_key(
                        mb_hash_function_for_update_key,
                        &pub_key_m[KeyPurpose::UpdateDIDDocument],
                    ))
                } else {
                    RootLevelUpdateRules::from(UpdateKey {
                        pub_key: pub_key_m[KeyPurpose::UpdateDIDDocument].clone(),
                    })
                };

                // Form the unsigned non-root DID document.
                let latest_did_document_mb_hash_function_o = if change_mb_hash_function_for_self_hash_o.is_none() {
                    let mb_hash_function = selfhash::MBHashFunction::new(
                            latest_did_document.self_hash.base(),
                            latest_did_document.self_hash.decoded::<64>().expect("programmer error: all hash functions expected to be no larger than 64 bytes").code(),
                        ).map_err(|e| indexed_db::Error::from(Error::from(anyhow::anyhow!("failed to create MBHashFunction from latest_did_document.self_hash; error was: {}", e))))?;
                    Some(mb_hash_function)
                } else {
                    None
                };
                let mb_hash_function_for_self_hash = if let Some(mb_hash_function_for_self_hash) =
                    change_mb_hash_function_for_self_hash_o.as_ref()
                {
                    mb_hash_function_for_self_hash
                } else {
                    latest_did_document_mb_hash_function_o.as_ref().unwrap()
                };
                let mut updated_did_document = DIDDocument::create_unsigned_non_root(
                    &latest_did_document,
                    update_rules,
                    now_utc,
                    did_webplus_core::PublicKeySet {
                        authentication_v: vec![&pub_key_m[KeyPurpose::Authentication]],
                        assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod]],
                        key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement]],
                        capability_invocation_v: vec![&pub_key_m[KeyPurpose::CapabilityInvocation]],
                        capability_delegation_v: vec![&pub_key_m[KeyPurpose::CapabilityDelegation]],
                    },
                    mb_hash_function_for_self_hash,
                )
                .expect("programmer error");

                use signature_dyn::SignerDynT;
                let signing_kid = mbx::MBPubKey::try_from_verifier_bytes(
                    mbx::Base::Base64Url,
                    &priv_key_for_update.verifier_bytes().map_err(|e| indexed_db::Error::from(Error::from(anyhow::anyhow!("error converting verifier bytes to MBPubKey; error was: {}", e))))?//.map_err(into_wallet_error)?,
                    // &priv_key_for_update.verifier_bytes().expect("TEMP HACK")//.map_err(|e| indexed_db::Error::from(Error::from(anyhow::anyhow!("error converting verifier bytes to MBPubKey; error was: {}", e))))?//.map_err(into_wallet_error)?,
                )
                .expect("programmer error")
                .to_string();

                // The updated DID document must be signed by the UpdateDIDDocument key specified in the latest DID document.
                let jws = updated_did_document
                    .sign(signing_kid, priv_key_for_update)
                    .expect("programmer error");

                // Add the proof to the DID document.
                updated_did_document.add_proof(jws.into_string());

                // Finalize the DID document.
                updated_did_document
                    .finalize(Some(&latest_did_document))
                    .expect("programmer error");

                // Sanity check.
                updated_did_document
                    .verify_non_root_nonrecursive(&latest_did_document)
                    .expect("programmer error");

                let updated_did_document_jcs = updated_did_document
                    .serialize_canonically()
                    .expect("this shouldn't happen");
                tracing::debug!("updated_did_document_jcs: {}", updated_did_document_jcs);

                // Retrieve the latest DIDDocRecord to get the did_documents_jsonl_octet_length.
                let latest_did_doc_record_cursor = transaction
                    .object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?
                    .index(Self::DID_DOCUMENTS_INDEX_DID_AND_VERSION_ID)?
                    .cursor()
                    .direction(indexed_db::CursorDirection::Prev)
                    .open()
                    .await?;
                let did_documents_jsonl_octet_length = latest_did_doc_record_cursor
                    .value()
                    .map(|jsvalue| {
                        serde_wasm_bindgen::from_value::<DIDDocumentBlob>(jsvalue)
                            .map_err(into_doc_store_error)
                            .map(|blob| blob.did_doc_record.did_documents_jsonl_octet_length)
                    })
                    .transpose()
                    .map_err(|e| indexed_db::Error::from(Error::from(anyhow::anyhow!("Error while deserializing DIDDocumentBlob, this likely indicates database corruption; error was: {}", e))))?
                    .unwrap_or(0)
                    + updated_did_document_jcs.len() as i64
                    + 1;

                // Add the updated DID document.
                let did_document_blob = DIDDocumentBlob {
                    did_doc_record: DIDDocRecord {
                        self_hash: updated_did_document.self_hash.to_string(),
                        did: updated_did_document.did.to_string(),
                        version_id: updated_did_document.version_id.try_into().unwrap(),
                        valid_from: updated_did_document.valid_from,
                        did_documents_jsonl_octet_length,
                        did_document_jcs: updated_did_document_jcs.clone(),
                    },
                };
                tracing::trace!("adding did_document_blob: {:?}", did_document_blob);
                let did_document_blob_key = transaction
                    .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                    .put(&serde_wasm_bindgen::to_value(&did_document_blob).unwrap())
                    .await?;
                tracing::trace!("added did_document_blob; did_document_blob_key: {:?}", did_document_blob_key);

                // Store the priv keys.
                let mut priv_key_blob_key_v = Vec::with_capacity(KeyPurpose::VARIANTS.len());
                for key_purpose in KeyPurpose::VARIANTS {
                    tracing::trace!("adding priv key for key_purpose: {:?}", key_purpose);
                    let pub_key = pub_key_m[key_purpose].clone();
                    let hashed_pub_key_string = if let Some(mb_hash_function_for_update_key) =
                        mb_hash_function_for_update_key_o.as_ref()
                    {
                        mb_hash_function_for_update_key
                            .hash(pub_key.as_bytes())
                            .to_string()
                    } else {
                        "<not-hashed>".to_string()
                    };
                    let max_usage_count_o = if key_purpose == KeyPurpose::UpdateDIDDocument {
                        Some(1)
                    } else {
                        None
                    };
                    let comment_o = Some(format!(
                        "generated during DID update versionId {} -> {}",
                        latest_did_document.version_id, updated_did_document.version_id
                    ));
                    let priv_key_blob = PrivKeyBlob {
                        wallets_rowid: ctx_clone.wallets_rowid,
                        priv_key_record: PrivKeyRecord {
                            pub_key,
                            hashed_pub_key: hashed_pub_key_string,
                            did_restriction_o: Some(did_clone.to_string()),
                            key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                            created_at: now_utc,
                            last_used_at_o: None,
                            max_usage_count_o,
                            usage_count: 0,
                            deleted_at_o: None,
                            private_key_bytes_o: Some(
                                priv_key_m[key_purpose].to_signer_bytes().to_owned(),
                            ),
                            comment_o,
                        },
                    };
                    let priv_key_blob_key = transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .put(&serde_wasm_bindgen::to_value(&priv_key_blob).unwrap())
                        .await?;
                    tracing::trace!("added priv key; key_purpose: {:?}; priv_key_blob_key.priv_key_record.pub_key: {:?}", key_purpose, priv_key_blob.priv_key_record.pub_key);
                    priv_key_blob_key_v.push(priv_key_blob_key);
                }

                let controlled_did = did_clone.with_queries(
                    &updated_did_document.self_hash,
                    updated_did_document.version_id,
                );

                // Store the priv key usage for the UpdateDIDDocument.
                tracing::trace!("adding priv key usage for UpdateDIDDocument");
                let priv_key_usage_blob = PrivKeyUsageBlob {
                    wallets_rowid: ctx_clone.wallets_rowid,
                    priv_key_usage_record: PrivKeyUsageRecord {
                        pub_key: priv_key_record_for_update.pub_key.clone(),
                        hashed_pub_key: priv_key_record_for_update.hashed_pub_key.clone(),
                        used_at: now_utc,
                        usage: PrivKeyUsage::DIDUpdate {
                            updated_did_fully_qualified_o: Some(controlled_did.clone()),
                        },
                        verification_method_o: None,
                        key_purpose_o: Some(KeyPurpose::UpdateDIDDocument),
                    }
                };
                let priv_key_usage_blob_key = transaction
                    .object_store(Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE)?
                    .put(&serde_wasm_bindgen::to_value(&priv_key_usage_blob).unwrap())
                    .await?;
                tracing::trace!("added priv key usage; priv_key_usage_blob_key: {:?}", priv_key_usage_blob_key);

                // Retire the priv keys for the old locally-controlled verification methods and the old update key.
                let mut priv_key_blob_keys_to_retire_v = Vec::new();
                let priv_keys_provisional_object_store =
                    transaction.object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?;

                for (_verification_method_record, priv_key_blob, primary_key) in
                    locally_controlled_verification_method_v
                {
                    let mut soft_deleted_record = priv_key_blob.priv_key_record.clone();
                    soft_deleted_record.deleted_at_o = Some(now_utc);
                    soft_deleted_record.private_key_bytes_o = None;
                    let soft_deleted_blob = PrivKeyBlob {
                        priv_key_record: soft_deleted_record,
                        ..priv_key_blob.clone()
                    };
                    priv_keys_provisional_object_store
                        .put_kv(
                            &primary_key,
                            &serde_wasm_bindgen::to_value(&soft_deleted_blob).unwrap(),
                        )
                        .await?;
                    priv_key_blob_keys_to_retire_v.push(primary_key);
                }

                // Retire the old update key.
                let update_key_compound_key = JsValue::from(vec![
                    Self::wallets_rowid_as_f64_jsvalue(ctx_clone.wallets_rowid),
                    JsValue::from(priv_key_record_for_update.pub_key.to_string()),
                ]);
                let update_key_primary_keys = priv_keys_object_store
                    .index(Self::PRIV_KEYS_INDEX_WALLETS_ROWID_AND_PUB_KEY)?
                    .get_all_keys_in(
                        update_key_compound_key.clone()..=update_key_compound_key,
                        Some(1),
                    )
                    .await?;
                if let Some(update_key_primary_key) = update_key_primary_keys.into_iter().next() {
                    let mut soft_deleted_record = (*priv_key_record_for_update).clone();
                    soft_deleted_record.deleted_at_o = Some(now_utc);
                    soft_deleted_record.private_key_bytes_o = None;
                    let soft_deleted_blob = PrivKeyBlob {
                        wallets_rowid: ctx_clone.wallets_rowid,
                        priv_key_record: soft_deleted_record,
                    };
                    priv_keys_provisional_object_store
                        .put_kv(
                            &update_key_primary_key,
                            &serde_wasm_bindgen::to_value(&soft_deleted_blob).unwrap(),
                        )
                        .await?;
                    priv_key_blob_keys_to_retire_v.push(update_key_primary_key);
                }

                tracing::trace!("transaction #1 succeeded");
                Ok((
                    updated_did_document,
                    updated_did_document_jcs,
                    did_document_blob_key,
                    priv_key_blob_key_v,
                    priv_key_usage_blob_key,
                    priv_key_blob_keys_to_retire_v,
                ))
            })
            .await
            .map_err(into_wallet_error)?;

        // PUT the DID document to the VDR to update the DID.  If an error occurs, then delete the
        // provisional records.
        match self
            .post_or_put_did_document(
                "update",
                updated_did_document_jcs.as_str(),
                &did,
                http_options_o,
            )
            .await
        {
            Ok(()) => (),
            Err(e) => {
                tracing::error!("error PUT'ing DID document to VDR: {:?}", e);
                // Delete the provisional records.
                // TODO: Figure out how to handle errors here.  Maybe do some sort of cleanup of provisional records
                // that are older than some threshold.
                self.db()
                    .await
                    .map_err(into_wallet_error)?
                    .transaction(&[
                        Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE,
                        Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE,
                        Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE,
                    ])
                    .rw()
                    .run(async move |transaction| {
                        tracing::trace!("undoing transaction #1 because HTTP PUT for DID {} failed; deleting provisional records", did);
                        transaction
                            .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                            .delete(&did_document_blob_key)
                            .await?;

                        for priv_key_blob_key in priv_key_blob_key_v {
                            transaction
                                .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                                .delete(&priv_key_blob_key)
                                .await?;
                        }

                        for priv_key_blob_key_to_retire in priv_key_blob_keys_to_retire_v {
                            transaction
                                .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                                .delete(&priv_key_blob_key_to_retire)
                                .await?;
                        }

                        transaction
                            .object_store(Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE)?
                            .delete(&priv_key_usage_blob_key)
                            .await?;

                        tracing::trace!("undo of transaction #1 succeeded");
                        Ok(())
                    })
                    .await
                    .map_err(into_wallet_error)?;
                // Finally, abort this operation.
                return Err(e);
            }
        }

        // Now that the HTTP PUT is successful, move the provisional records to the non-provisional
        // versions of those object stores.
        self.db()
            .await
            .map_err(into_wallet_error)?
            .transaction(&[
                Self::DID_DOCUMENTS_OBJECT_STORE,
                Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE,
                Self::PRIV_KEYS_OBJECT_STORE,
                Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE,
                Self::PRIV_KEY_USAGES_OBJECT_STORE,
                Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE,
            ])
            .rw()
            .run(async move |transaction| {
                tracing::trace!("started transaction #2; moving provisional records to non-provisional versions of those object stores");
                let did_document_blob_jsvalue = transaction
                    .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                    .get(&did_document_blob_key)
                    .await?
                    .unwrap();
                transaction
                    .object_store(Self::DID_DOCUMENTS_PROVISIONAL_OBJECT_STORE)?
                    .delete(&did_document_blob_key)
                    .await?;
                transaction
                    .object_store(Self::DID_DOCUMENTS_OBJECT_STORE)?
                    .put(&did_document_blob_jsvalue)
                    .await?;

                for priv_key_blob_key in priv_key_blob_key_v {
                    let priv_key_blob_jsvalue = transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .get(&priv_key_blob_key)
                        .await?
                        .unwrap();
                    transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .delete(&priv_key_blob_key)
                        .await?;
                    transaction
                        .object_store(Self::PRIV_KEYS_OBJECT_STORE)?
                        .put(&priv_key_blob_jsvalue)
                        .await?;
                }

                for priv_key_blob_key_to_retire in priv_key_blob_keys_to_retire_v {
                    let priv_key_blob_jsvalue = transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .get(&priv_key_blob_key_to_retire)
                        .await?
                        .unwrap();
                    transaction
                        .object_store(Self::PRIV_KEYS_PROVISIONAL_OBJECT_STORE)?
                        .delete(&priv_key_blob_key_to_retire)
                        .await?;
                    transaction
                        .object_store(Self::PRIV_KEYS_OBJECT_STORE)?
                        .put_kv(&priv_key_blob_key_to_retire, &priv_key_blob_jsvalue)
                        .await?;
                }

                let priv_key_usage_blob_jsvalue = transaction
                    .object_store(Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE)?
                    .get(&priv_key_usage_blob_key)
                    .await?
                    .unwrap();
                transaction
                    .object_store(Self::PRIV_KEY_USAGES_PROVISIONAL_OBJECT_STORE)?
                    .delete(&priv_key_usage_blob_key)
                    .await?;
                transaction
                    .object_store(Self::PRIV_KEY_USAGES_OBJECT_STORE)?
                    .put(&priv_key_usage_blob_jsvalue)
                    .await?;

                tracing::trace!("transaction #2 succeeded");
                Ok(())
            })
            .await
            .map_err(into_wallet_error)?;

        let controlled_did = did.with_queries(
            &updated_did_document.self_hash,
            updated_did_document.version_id,
        );
        Ok(controlled_did)
    }
    async fn deactivate_did(
        &self,
        _deactivate_did_parameters: did_webplus_wallet::DeactivateDIDParameters<'_>,
        _http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> did_webplus_wallet::Result<DIDFullyQualified> {
        // Wait until this is factored with update_did and create_did (in SoftwareWallet and Self)
        todo!()
    }
    async fn get_locally_controlled_verification_methods(
        &self,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> did_webplus_wallet::Result<
        Vec<(
            VerificationMethodRecord,
            signature_dyn::SignerBytes<'static>,
        )>,
    > {
        let results = self
            .get_locally_controlled_verification_methods_internal(
                locally_controlled_verification_method_filter,
            )
            .await
            .map_err(into_wallet_error)?;

        Ok(results
            .into_iter()
            .map(|(verification_method_record, priv_key_record)| {
                let signer_bytes = priv_key_record
                    .private_key_bytes_o
                    .expect("programmer error: priv_key_bytes_o was verified Some(_) in the loop");
                (verification_method_record, signer_bytes)
            })
            .collect())
    }
}
