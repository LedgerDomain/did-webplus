use did_webplus_wallet_store::{PrivKeyUsageRecord, Result, WalletStorageCtx};

pub(crate) struct PrivKeyUsageInsert {
    pub(crate) wallets_rowid: i64,
    // pub(crate) priv_keys_rowid: i64,
    pub(crate) pub_key: String,
    pub(crate) used_at: time::OffsetDateTime,
    pub(crate) usage_type: String,
    pub(crate) usage_spec_o: Option<Vec<u8>>,
    pub(crate) verification_method_o: Option<String>,
    pub(crate) key_purpose_o: Option<i64>,
}

impl PrivKeyUsageInsert {
    pub fn try_from_priv_key_usage_record(
        ctx: &WalletStorageCtx,
        priv_key_usage_record: &PrivKeyUsageRecord,
    ) -> Result<Self> {
        Ok(Self {
            wallets_rowid: ctx.wallets_rowid,
            pub_key: priv_key_usage_record.pub_key.to_string(),
            used_at: priv_key_usage_record.used_at,
            usage_type: priv_key_usage_record
                .usage
                .priv_key_usage_type()
                .to_string(),
            usage_spec_o: priv_key_usage_record.usage.priv_key_usage_spec(),
            verification_method_o: priv_key_usage_record
                .verification_method_o
                .as_ref()
                .map(|verification_method| verification_method.to_string()),
            key_purpose_o: priv_key_usage_record
                .key_purpose_o
                .map(|key_purpose| key_purpose.integer_value() as i64),
        })
    }
}
