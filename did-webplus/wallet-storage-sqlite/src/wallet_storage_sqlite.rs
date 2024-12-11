use crate::{DIDDocumentRowSQLite, PrivKeyRow, PrivKeyUsageRow};
use did_webplus_core::{DIDDocument, DIDKeyResourceFullyQualifiedStr, DIDStr, KeyPurposeFlags};
use did_webplus_doc_store::{DIDDocRecord, DIDDocRecordFilter, DIDDocStorage};
use did_webplus_wallet_store::{
    Error, LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter,
    PrivKeyUsageRecord, PrivKeyUsageRecordFilter, Result, VerificationMethodRecord, WalletRecord,
    WalletRecordFilter, WalletStorage, WalletStorageCtx,
};
use selfsign::KERIVerifierStr;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct WalletStorageSQLite {
    sqlite_pool: SqlitePool,
}

impl WalletStorageSQLite {
    pub async fn open_and_run_migrations(sqlite_pool: SqlitePool) -> Result<Self> {
        sqlx::migrate!().run(&sqlite_pool).await.map_err(|err| {
            Error::StorageError(
                format!(
                    "Failed to run SQLite database migrations; error was: {}",
                    err
                )
                .into(),
            )
        })?;
        Ok(Self { sqlite_pool })
    }
}

#[async_trait::async_trait]
impl DIDDocStorage for WalletStorageSQLite {
    type Transaction<'t> = sqlx::Transaction<'t, sqlx::Sqlite>;
    async fn begin_transaction<'s, 't: 's, 'u: 't>(
        &self,
        existing_transaction_o: Option<&'u mut Self::Transaction<'t>>,
    ) -> did_webplus_doc_store::Result<Self::Transaction<'s>> {
        if let Some(existing_transaction) = existing_transaction_o {
            use sqlx::Acquire;
            Ok(existing_transaction.begin().await?)
        } else {
            Ok(self.sqlite_pool.begin().await?)
        }
    }
    async fn commit_transaction(
        &self,
        transaction: Self::Transaction<'_>,
    ) -> did_webplus_doc_store::Result<()> {
        transaction.commit().await?;
        Ok(())
    }
    async fn rollback_transaction(
        &self,
        transaction: Self::Transaction<'_>,
    ) -> did_webplus_doc_store::Result<()> {
        transaction.rollback().await?;
        Ok(())
    }
    async fn add_did_document(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> did_webplus_doc_store::Result<()> {
        assert!(
            did_document.self_hash_o.is_some(),
            "programmer error: self_hash is expected to be present on a valid DID document"
        );
        let did_str = did_document.did.as_str();
        let version_id = did_document.version_id() as i64;
        let valid_from = did_document.valid_from();
        let self_hash_str = did_document.self_hash().as_str();
        let did_documents_rowid = sqlx::query!(
            r#"
                INSERT INTO did_documents(did, version_id, valid_from, self_hash, did_document_jcs)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING rowid
            "#,
            did_str,
            version_id,
            valid_from,
            self_hash_str,
            did_document_jcs,
        )
        .fetch_one(transaction.as_mut())
        .await?
        .rowid;

        // Also ingest the verification methods into the verification_methods table
        for verification_method in did_document
            .public_key_material
            .verification_method_v
            .iter()
        {
            let key_id_fragment_str = verification_method.id.fragment().as_str();
            let controller = verification_method.controller.as_str();
            let pub_key =
                selfsign::KERIVerifier::try_from(&verification_method.public_key_jwk)?.to_string();
            let key_purpose_flags = did_document
                .public_key_material
                .key_purpose_flags_for_key_id_fragment(verification_method.id.fragment());
            let key_purpose_flags_integer = key_purpose_flags.integer_value() as i32;
            sqlx::query!(
                r#"
                    INSERT INTO verification_methods(did_documents_rowid, key_id_fragment, controller, pub_key, key_purpose_flags)
                    VALUES ($1, $2, $3, $4, $5)
                "#,
                did_documents_rowid,
                key_id_fragment_str,
                controller,
                pub_key,
                key_purpose_flags_integer,
            )
            .execute(transaction.as_mut())
            .await?;
        }
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let self_hash_str = self_hash.as_str();
        let did_doc_record_o = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_document_jcs
                FROM did_documents
                WHERE did = $1 AND self_hash = $2
            "#,
            did_str,
            self_hash_str,
        )
        .fetch_optional(transaction.as_mut())
        .await?
        .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        version_id: u32,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let version_id = version_id as i64;
        let did_doc_record_o = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_document_jcs
                FROM did_documents
                WHERE did = $1 AND version_id = $2
            "#,
            did_str,
            version_id,
        )
        .fetch_optional(transaction.as_mut())
        .await?
        .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_latest_did_doc_record(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let did_doc_record_o = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_document_jcs
                FROM did_documents
                WHERE did = $1
                ORDER BY version_id desc
                LIMIT 1
            "#,
            did_str,
        )
        .fetch_optional(transaction.as_mut())
        .await?
        .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_records(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        let filter_on_did = did_doc_record_filter.did_o.is_some();
        let filter_on_self_hash = did_doc_record_filter.self_hash_o.is_some();
        let filter_on_version_id = did_doc_record_filter.version_id_o.is_some();
        // TODO: SQL-based filtering on valid_at
        // let filter_on_valid_at = did_doc_record_filter.valid_at_o.is_some();
        let did_doc_record_v = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                select did, version_id, valid_from, self_hash, did_document_jcs
                from did_documents
                where (NOT $1 OR did = $2) AND
                      (NOT $3 OR self_hash = $4) AND
                      (NOT $5 OR version_id = $6)
            "#,
            filter_on_did,
            did_doc_record_filter.did_o,
            filter_on_self_hash,
            did_doc_record_filter.self_hash_o,
            filter_on_version_id,
            did_doc_record_filter.version_id_o,
        )
        .fetch_all(transaction.as_mut())
        .await?
        .into_iter()
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .collect::<did_webplus_doc_store::Result<Vec<_>>>()?;
        Ok(did_doc_record_v)
    }
}

#[async_trait::async_trait]
impl WalletStorage for WalletStorageSQLite {
    async fn add_wallet(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_record: WalletRecord,
    ) -> Result<WalletStorageCtx> {
        let wallet_uuid_string = wallet_record.wallet_uuid.as_hyphenated();
        let query_result = sqlx::query!(
            r#"
                INSERT INTO wallets(wallet_uuid, created_at, updated_at, deleted_at_o, wallet_name_o)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING rowid
            "#,
            wallet_uuid_string,
            wallet_record.created_at,
            wallet_record.updated_at,
            wallet_record.deleted_at_o,
            wallet_record.wallet_name_o,
        )
        .fetch_one(transaction.as_mut())
        .await?;
        Ok(WalletStorageCtx {
            wallets_rowid: query_result.rowid,
        })
    }
    async fn get_wallet(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_uuid: &uuid::Uuid,
    ) -> Result<Option<(WalletStorageCtx, WalletRecord)>> {
        let wallet_uuid_string = wallet_uuid.as_hyphenated();
        let query_result_o = sqlx::query!(
            r#"
                SELECT rowid, wallet_uuid, created_at, updated_at, deleted_at_o, wallet_name_o
                FROM wallets
                WHERE wallet_uuid = $1
            "#,
            wallet_uuid_string,
        )
        .fetch_optional(transaction.as_mut())
        .await?;
        if let Some(query_result) = query_result_o {
            let wallet_storage_ctx = WalletStorageCtx {
                wallets_rowid: query_result.rowid,
            };
            let wallet_record = WalletRecord {
                wallet_uuid: uuid::Uuid::parse_str(query_result.wallet_uuid.as_str()).map_err(
                    |e| {
                        Error::RecordCorruption(
                            format!(
                                "invalid wallet_uuid {}; error was: {}",
                                query_result.wallet_uuid, e
                            )
                            .into(),
                        )
                    },
                )?,
                created_at: query_result.created_at,
                updated_at: query_result.updated_at,
                deleted_at_o: query_result.deleted_at_o,
                wallet_name_o: query_result.wallet_name_o,
            };
            Ok(Some((wallet_storage_ctx, wallet_record)))
        } else {
            Ok(None)
        }
    }
    async fn get_wallets(
        &self,
        transaction: &mut <Self as did_webplus_doc_store::DIDDocStorage>::Transaction<'_>,
        wallet_record_filter: &WalletRecordFilter,
    ) -> Result<Vec<(WalletStorageCtx, WalletRecord)>> {
        let filter_on_wallet_uuid = wallet_record_filter.wallet_uuid_o.is_some();
        let wallet_uuid_string_o = wallet_record_filter
            .wallet_uuid_o
            .as_ref()
            .map(|wallet_uuid| wallet_uuid.as_hyphenated());
        let filter_on_wallet_name = wallet_record_filter.wallet_name_o.is_some();
        sqlx::query!(
            r#"
                SELECT rowid, wallet_uuid, created_at, updated_at, deleted_at_o, wallet_name_o
                FROM wallets
                WHERE 
                    (NOT $1 OR wallet_uuid = $2) AND
                    (NOT $3 OR wallet_name_o = $4)
            "#,
            filter_on_wallet_uuid,
            wallet_uuid_string_o,
            filter_on_wallet_name,
            wallet_record_filter.wallet_name_o,
        )
        .fetch_all(transaction.as_mut())
        .await?
        .into_iter()
        .map(|query_result| -> Result<(WalletStorageCtx, WalletRecord)> {
            let wallet_storage_ctx = WalletStorageCtx {
                wallets_rowid: query_result.rowid,
            };
            let wallet_record = WalletRecord {
                wallet_uuid: uuid::Uuid::try_parse(query_result.wallet_uuid.as_str()).map_err(
                    |e| {
                        Error::RecordCorruption(
                            format!(
                                "Invalid UUID in database: {}; error was: {}",
                                query_result.wallet_uuid, e
                            )
                            .into(),
                        )
                    },
                )?,
                created_at: query_result.created_at,
                updated_at: query_result.updated_at,
                deleted_at_o: query_result.deleted_at_o,
                wallet_name_o: query_result.wallet_name_o,
            };
            Ok((wallet_storage_ctx, wallet_record))
        })
        .collect::<Result<Vec<_>>>()
    }

    async fn add_priv_key(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> Result<()> {
        let priv_key_row = PrivKeyRow::try_from_priv_key_record(ctx, priv_key_record)?;
        sqlx::query!(
            r#"
                INSERT INTO priv_keys(wallets_rowid, pub_key, key_type, key_purpose_restriction_o, created_at, last_used_at_o, usage_count, deleted_at_o, priv_key_format_o, priv_key_bytes_o)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            priv_key_row.wallets_rowid,
            priv_key_row.pub_key,
            priv_key_row.key_type,
            priv_key_row.key_purpose_restriction_o,
            priv_key_row.created_at,
            priv_key_row.last_used_at_o,
            priv_key_row.usage_count,
            priv_key_row.deleted_at_o,
            priv_key_row.priv_key_format_o,
            priv_key_row.priv_key_bytes_o,
        ).execute(transaction.as_mut()).await?;
        Ok(())
    }
    async fn delete_priv_key(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        pub_key: &selfsign::KERIVerifierStr,
    ) -> Result<()> {
        // This will only update if the priv key is not already deleted.
        let deleted_at_o = Some(time::OffsetDateTime::now_utc());
        let pub_key_str = pub_key.as_str();
        sqlx::query!(
            r#"
                UPDATE priv_keys
                SET deleted_at_o = $1, priv_key_format_o = NULL, priv_key_bytes_o = NULL
                WHERE wallets_rowid = $2 AND pub_key = $3 AND deleted_at_o IS NULL
            "#,
            deleted_at_o,
            ctx.wallets_rowid,
            pub_key_str,
        )
        .execute(transaction.as_mut())
        .await?;
        Ok(())
    }
    async fn get_priv_key(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        pub_key: &selfsign::KERIVerifierStr,
    ) -> Result<Option<PrivKeyRecord>> {
        let pub_key_str = pub_key.as_str();
        sqlx::query_as!(
            PrivKeyRow,
            r#"
                SELECT wallets_rowid, pub_key, key_type, key_purpose_restriction_o, created_at, last_used_at_o, usage_count, deleted_at_o, priv_key_format_o, priv_key_bytes_o
                FROM priv_keys
                WHERE wallets_rowid = $1 AND pub_key = $2
            "#,
            ctx.wallets_rowid,
            pub_key_str,
        ).fetch_optional(transaction.as_mut()).await?
        .map(PrivKeyRow::try_into_priv_key_record)
        .transpose()
    }
    async fn get_priv_keys(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_record_filter: &PrivKeyRecordFilter,
    ) -> Result<Vec<PrivKeyRecord>> {
        let filter_on_pub_key = priv_key_record_filter.pub_key_o.is_some();
        let pub_key_str_o = priv_key_record_filter
            .pub_key_o
            .as_ref()
            .map(|pub_key| pub_key.as_str());
        let filter_on_key_purpose = priv_key_record_filter.key_purpose_o.is_some();
        let key_purpose_str_o = priv_key_record_filter
            .key_purpose_o
            .as_ref()
            .map(|key_purpose| key_purpose.as_str());
        let filter_on_is_not_deleted = priv_key_record_filter.is_not_deleted_o.is_some();
        let priv_key_row_v = sqlx::query_as!(
            PrivKeyRow,
            r#"
                SELECT wallets_rowid, pub_key, key_type, key_purpose_restriction_o, created_at, last_used_at_o, usage_count, deleted_at_o, priv_key_format_o, priv_key_bytes_o
                FROM priv_keys
                WHERE wallets_rowid = $1
                    AND (NOT $2 OR pub_key = $3)
                    AND (NOT $4 OR key_purpose_restriction_o IS NULL OR key_purpose_restriction_o = $5)
                    AND (NOT $6 OR deleted_at_o = $7)
            "#,
            ctx.wallets_rowid,
            filter_on_pub_key,
            pub_key_str_o,
            filter_on_key_purpose,
            key_purpose_str_o,
            filter_on_is_not_deleted,
            priv_key_record_filter.is_not_deleted_o,
        ).fetch_all(transaction.as_mut()).await?;
        let priv_key_record_v = priv_key_row_v
            .into_iter()
            .map(|row| row.try_into_priv_key_record())
            .collect::<Result<Vec<_>>>()?;
        Ok(priv_key_record_v)
    }

    async fn add_priv_key_usage(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record: &PrivKeyUsageRecord,
    ) -> Result<()> {
        let priv_key_usage_row =
            PrivKeyUsageRow::try_from_priv_key_usage_record(ctx, priv_key_usage_record)?;
        sqlx::query!(
            r#"
                INSERT INTO priv_key_usages(wallets_rowid, pub_key, used_at, usage_type, usage_spec_o, did_resource_fully_qualified_o, key_purpose_o)
                VALUES ($1, $2, $3, $4, $5, $6, $7);

                UPDATE priv_keys
                SET last_used_at_o = $8, usage_count = usage_count+1
                WHERE wallets_rowid = $9 AND pub_key = $10
            "#,
            priv_key_usage_row.wallets_rowid,
            priv_key_usage_row.pub_key,
            priv_key_usage_row.used_at,
            priv_key_usage_row.usage_type,
            priv_key_usage_row.usage_spec_o,
            priv_key_usage_row.did_resource_fully_qualified_o,
            priv_key_usage_row.key_purpose_o,
            priv_key_usage_row.used_at,
            priv_key_usage_row.wallets_rowid,
            priv_key_usage_row.pub_key,
        )
        .execute(transaction.as_mut())
        .await?;
        Ok(())
    }
    async fn get_priv_key_usages(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record_filter: &PrivKeyUsageRecordFilter,
    ) -> Result<Vec<PrivKeyUsageRecord>> {
        let filter_on_pub_key = priv_key_usage_record_filter.pub_key_o.is_some();
        let pub_key_str_o = priv_key_usage_record_filter
            .pub_key_o
            .as_ref()
            .map(|pub_key| pub_key.as_str());
        let filter_on_usage_type = priv_key_usage_record_filter.usage_type_o.is_some();
        let usage_type_str_o = priv_key_usage_record_filter
            .usage_type_o
            .as_ref()
            .map(|usage_type| usage_type.as_str());
        let filter_on_used_at_or_after = priv_key_usage_record_filter.used_at_or_after_o.is_some();
        let filter_on_used_at_or_before =
            priv_key_usage_record_filter.used_at_or_before_o.is_some();
        let priv_key_usage_row_v = sqlx::query_as!(
            PrivKeyUsageRow,
            r#"
                SELECT wallets_rowid, pub_key, used_at, usage_type, usage_spec_o, did_resource_fully_qualified_o, key_purpose_o
                FROM priv_key_usages
                WHERE wallets_rowid = $1
                    AND (NOT $2 OR pub_key = $3)
                    AND (NOT $4 OR usage_type = $5)
                    AND (NOT $6 OR used_at >= $7)
                    AND (NOT $8 OR used_at <= $9)
            "#,
            ctx.wallets_rowid,
            filter_on_pub_key,
            pub_key_str_o,
            filter_on_usage_type,
            usage_type_str_o,
            filter_on_used_at_or_after,
            priv_key_usage_record_filter.used_at_or_after_o,
            filter_on_used_at_or_before,
            priv_key_usage_record_filter.used_at_or_before_o,
        ).fetch_all(transaction.as_mut()).await?;
        let mut priv_key_usage_record_v = Vec::with_capacity(priv_key_usage_row_v.len());
        for priv_key_usage_row in priv_key_usage_row_v.into_iter() {
            let priv_key_usage_record = priv_key_usage_row.try_into_priv_key_usage_record(ctx)?;
            priv_key_usage_record_v.push(priv_key_usage_record);
        }
        Ok(priv_key_usage_record_v)
    }

    async fn get_verification_method(
        &self,
        _transaction: &mut Self::Transaction<'_>,
        _ctx: &WalletStorageCtx,
        _did_key_resource_fully_qualified: &DIDKeyResourceFullyQualifiedStr,
    ) -> Result<VerificationMethodRecord> {
        unimplemented!();
    }

    async fn get_locally_controlled_verification_methods(
        &self,
        transaction: &mut Self::Transaction<'_>,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, PrivKeyRecord)>> {
        let filter_on_did = locally_controlled_verification_method_filter
            .did_o
            .is_some();
        let did_o = locally_controlled_verification_method_filter
            .did_o
            .as_ref()
            .map(|did| did.as_str());
        let filter_on_version_id = locally_controlled_verification_method_filter
            .version_id_o
            .is_some();
        let filter_on_key_purpose = locally_controlled_verification_method_filter
            .key_purpose_o
            .is_some();
        let key_purpose_integer_o = locally_controlled_verification_method_filter
            .key_purpose_o
            .map(|key_purpose| key_purpose.as_key_purpose_flags().integer_value() as i64);

        let query_result_v = sqlx::query!(
            r#"
                SELECT
                    verification_methods.did_documents_rowid,
                    verification_methods.key_id_fragment,
                    verification_methods.controller,
                    verification_methods.pub_key,
                    verification_methods.key_purpose_flags,
                    did_documents.did,
                    did_documents.self_hash,
                    did_documents.version_id,
                    priv_keys.key_type,
                    priv_keys.key_purpose_restriction_o,
                    priv_keys.created_at,
                    priv_keys.last_used_at_o,
                    priv_keys.usage_count,
                    priv_keys.deleted_at_o,
                    priv_keys.priv_key_format_o,
                    priv_keys.priv_key_bytes_o
                FROM verification_methods
                INNER JOIN did_documents
                    ON verification_methods.did_documents_rowid = did_documents.rowid
                INNER JOIN priv_keys
                    ON verification_methods.pub_key = priv_keys.pub_key
                WHERE
                    priv_keys.wallets_rowid = $1
                    AND priv_keys.deleted_at_o IS NULL
                    AND (NOT $2 OR did_documents.did = $3)
                    AND (NOT $4 OR did_documents.version_id = $5)
                    AND (NOT $6 OR (verification_methods.key_purpose_flags & $7 != 0))
            "#,
            ctx.wallets_rowid,
            filter_on_did,
            did_o,
            filter_on_version_id,
            locally_controlled_verification_method_filter.version_id_o,
            filter_on_key_purpose,
            key_purpose_integer_o,
        )
        .fetch_all(transaction.as_mut())
        .await?;

        let mut locally_controlled_verification_method_v = Vec::with_capacity(query_result_v.len());
        for query_result in query_result_v.into_iter() {
            let did = DIDStr::new_ref(query_result.did.as_str()).map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid did_documents.did value {}; error was: {}",
                        query_result.did, e
                    )
                    .into(),
                )
            })?;
            let self_hash = selfhash::KERIHashStr::new_ref(query_result.self_hash.as_str())
                .map_err(|e| {
                    Error::RecordCorruption(
                        format!(
                            "invalid did_documents.self_hash value {}; error was: {}",
                            query_result.self_hash, e
                        )
                        .into(),
                    )
                })?;
            let version_id = u32::try_from(query_result.version_id).map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid did_documents.version_id value {}; error was: {}",
                        query_result.version_id, e
                    )
                    .into(),
                )
            })?;
            let key_id_fragment = KERIVerifierStr::new_ref(query_result.key_id_fragment.as_str())
                .map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid verification_methods.key_id_fragment value {:?}; error was: {}",
                        query_result.key_id_fragment, e
                    )
                    .into(),
                )
            })?;
            let did_key_resource_fully_qualified = did
                .with_queries(self_hash, version_id)
                .with_fragment(key_id_fragment);

            let key_purpose_flags = KeyPurposeFlags::try_from(
                u8::try_from(query_result.key_purpose_flags).map_err(|e| {
                    Error::RecordCorruption(
                        format!(
                            "invalid verification_methods.key_purpose_flags value {}; error was: {}",
                            query_result.key_purpose_flags, e,
                        )
                        .into(),
                    )
                })?,
            )
            .map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid verification_methods.key_purpose_flags value {}; error was: {}",
                        query_result.key_purpose_flags, e,
                    )
                    .into(),
                )
            })?;

            let priv_key_row = PrivKeyRow {
                wallets_rowid: ctx.wallets_rowid,
                pub_key: query_result.pub_key,
                key_type: query_result.key_type,
                key_purpose_restriction_o: query_result.key_purpose_restriction_o,
                created_at: query_result.created_at,
                last_used_at_o: query_result.last_used_at_o,
                usage_count: query_result.usage_count,
                deleted_at_o: query_result.deleted_at_o,
                priv_key_format_o: query_result.priv_key_format_o,
                priv_key_bytes_o: query_result.priv_key_bytes_o,
            };
            let priv_key_record = priv_key_row.try_into_priv_key_record()?;

            let verification_method_record = VerificationMethodRecord {
                did_key_resource_fully_qualified,
                key_purpose_flags,
                pub_key: priv_key_record.pub_key.clone(),
            };
            locally_controlled_verification_method_v
                .push((verification_method_record, priv_key_record));
        }
        Ok(locally_controlled_verification_method_v)
    }
}
