use std::str::FromStr;

use did_webplus::{DIDKeyResourceFullyQualified, KeyPurpose};
use did_webplus_wallet_storage::{
    Error, PrivKeyUsage, PrivKeyUsageRecord, PrivKeyUsageType, Result, WalletStorageCtx,
};

pub(crate) struct PrivKeyUsageRow {
    pub(crate) wallets_rowid: i64,
    pub(crate) pub_key: String,
    pub(crate) used_at: time::OffsetDateTime,
    pub(crate) usage_type: String,
    pub(crate) usage_spec_o: Option<Vec<u8>>,
    pub(crate) did_resource_fully_qualified_o: Option<String>,
    pub(crate) key_purpose_o: Option<i64>,
}

impl PrivKeyUsageRow {
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
            did_resource_fully_qualified_o: priv_key_usage_record
                .verification_method_and_purpose_o
                .as_ref()
                .map(|(did_resource_fully_qualified, _key_purpose)| {
                    did_resource_fully_qualified.to_string()
                }),
            key_purpose_o: priv_key_usage_record
                .verification_method_and_purpose_o
                .as_ref()
                .map(|(_did_resource_fully_qualified, key_purpose)| {
                    key_purpose.integer_value() as i64
                }),
        })
    }
    pub fn try_into_priv_key_usage_record(
        self,
        ctx: &WalletStorageCtx,
    ) -> Result<PrivKeyUsageRecord> {
        if self.wallets_rowid != ctx.wallets_rowid {
            panic!("ctx.wallets_rowid {} doesn't match priv_key_usages.wallets_rowid {}; this is a programmer error", ctx.wallets_rowid, self.wallets_rowid);
        }
        let verification_method_and_purpose_o = match (
            self.did_resource_fully_qualified_o,
            self.key_purpose_o,
        ) {
            (Some(did_key_resource_fully_qualified_string), Some(key_purpose_integer)) => {
                let did_key_resource_fully_qualified = DIDKeyResourceFullyQualified::try_from(did_key_resource_fully_qualified_string).map_err(|e| Error::RecordCorruption(format!("priv_key_usages.did_resource_fully_qualified_o contained invalid DIDKeyResourceFullyQualified value; error was: {}", e).into()))?;
                let key_purpose = KeyPurpose::try_from(u8::try_from(key_purpose_integer).map_err(|e| Error::RecordCorruption(format!("priv_key_usages.key_purpose_o contained invalid KeyPurpose value {}; error was: {}", key_purpose_integer, e).into()))?).map_err(|e| Error::RecordCorruption(format!("priv_key_usages.key_purpose_o contained invalid KeyPurpose value {}; error was: {}", key_purpose_integer, e).into()))?;
                Some((did_key_resource_fully_qualified, key_purpose))
            }
            (None, None) => None,
            _ => {
                return Err(Error::RecordCorruption("priv_key_usages.did_resource_fully_qualified_o and priv_key_usages.key_purpose_o must both be NULL or not NULL".into()));
            }
        };
        Ok(PrivKeyUsageRecord {
            pub_key: selfsign::KERIVerifier::try_from(self.pub_key.as_str()).map_err(|e| Error::RecordCorruption(format!("priv_key_usages.pub_key column contains invalid KERIVerifier {:?}; error was: {}", self.pub_key, e).into()))?,
            used_at: self.used_at,
            usage: PrivKeyUsage::try_from_priv_key_usage_type_and_spec(
                PrivKeyUsageType::from_str(self.usage_type.as_str())?,
                self.usage_spec_o.as_deref(),
            ).map_err(|e| Error::RecordCorruption(format!("priv_key_usages.usage_type and priv_key_usages.usage_spec_o column values could not be parsed into a well-formed PrivKeyUsage; error was: {}", e).into()))?,
            verification_method_and_purpose_o,
        })
    }
}
