use std::str::FromStr;

use did_webplus_core::{DIDKeyResourceFullyQualified, KeyPurpose};
use did_webplus_wallet_store::{
    Error, PrivKeyUsage, PrivKeyUsageRecord, PrivKeyUsageType, Result, WalletStorageCtx,
};

pub(crate) struct PrivKeyUsageSelect {
    // TODO: Hook this up to PrivKeyUsageRecord appropriately.
    #[allow(dead_code)]
    pub(crate) rowid: i64,
    // TODO: Is this needed/desired?
    pub(crate) wallets_rowid: i64,
    pub(crate) pub_key: String,
    pub(crate) hashed_pub_key: String,
    pub(crate) used_at: time::OffsetDateTime,
    pub(crate) usage_type: String,
    pub(crate) usage_spec_o: Option<Vec<u8>>,
    pub(crate) verification_method_o: Option<String>,
    pub(crate) key_purpose_o: Option<i64>,
}

impl PrivKeyUsageSelect {
    pub fn try_into_priv_key_usage_record(
        self,
        ctx: &WalletStorageCtx,
    ) -> Result<PrivKeyUsageRecord> {
        if self.wallets_rowid != ctx.wallets_rowid {
            panic!("ctx.wallets_rowid {} doesn't match priv_key_usages.wallets_rowid {}; this is a programmer error", ctx.wallets_rowid, self.wallets_rowid);
        }

        let pub_key = selfsign::KERIVerifier::try_from(
            self.pub_key.as_str()
        ).map_err(|e| {
            Error::RecordCorruption(
                format!(
                    "priv_key_usages.pub_key column contains invalid KERIVerifier {:?}; error was: {}",
                    self.pub_key,
                    e).into()
                )
        })?;

        let usage = PrivKeyUsage::try_from_priv_key_usage_type_and_spec(
            PrivKeyUsageType::from_str(self.usage_type.as_str())?,
            self.usage_spec_o.as_deref(),
        ).map_err(|e| {
            Error::RecordCorruption(
                format!(
                    "priv_key_usages.usage_type and priv_key_usages.usage_spec_o column values could not be parsed into a well-formed PrivKeyUsage; error was: {}", 
                    e
                ).into()
            )
        })?;

        let verification_method_o = 
            self.verification_method_o
                .map(|verification_method| {
                    DIDKeyResourceFullyQualified::try_from(verification_method).map_err(|e| {
                        Error::RecordCorruption(
                            format!(
                                "priv_key_usages.verification_method_o contained invalid DIDKeyResourceFullyQualified value; error was: {}", 
                                e
                            ).into()
                        )
                    })
                }).transpose()?;

        let key_purpose_u8_o = self.key_purpose_o.map(|key_purpose| {
            u8::try_from(key_purpose).map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "priv_key_usages.key_purpose_o column contains invalid KeyPurpose value {}; error was: {}", 
                        key_purpose, 
                        e
                    ).into()
                )
            })
        }).transpose()?;
        let key_purpose_o = key_purpose_u8_o.map(|key_purpose_u8| {
            KeyPurpose::try_from(key_purpose_u8).map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "priv_key_usages.key_purpose_o column contains invalid KeyPurpose value {}; error was: {}", 
                        key_purpose_u8, 
                        e
                    ).into()
                )
            })
        }).transpose()?;

        Ok(PrivKeyUsageRecord {
            pub_key,
            hashed_pub_key: self.hashed_pub_key,
            used_at: self.used_at,
            usage,
            verification_method_o,
            key_purpose_o,
        })
    }
}
