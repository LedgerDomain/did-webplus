use std::str::FromStr;

use did_webplus_core::KeyPurposeFlags;
use did_webplus_wallet_store::{Error, PrivKeyRecord, Result, WalletStorageCtx};
use selfsign::Verifier;

pub struct PrivKeyRow {
    pub wallets_rowid: i64,
    pub pub_key: String,
    pub hashed_pub_key: String,
    pub key_type: String,
    pub did_restriction_o: Option<String>,
    pub key_purpose_restriction_o: Option<i64>,
    pub created_at: time::OffsetDateTime,
    pub last_used_at_o: Option<time::OffsetDateTime>,
    pub max_usage_count_o: Option<i64>,
    pub usage_count: i64,
    pub deleted_at_o: Option<time::OffsetDateTime>,
    pub priv_key_format_o: Option<String>,
    pub priv_key_bytes_o: Option<Vec<u8>>,
    pub comment_o: Option<String>,
}

impl PrivKeyRow {
    /// Validate constraints on this priv key row.  Mostly regarding deletion.
    pub fn validate(&self) -> Result<()> {
        selfsign::KeyType::from_str(self.key_type.as_str())
            .map_err(|e| Error::RecordCorruption(e.to_string().into()))?;
        // TODO: Validate hashed_pub_key and did_restriction_o, and maybe max_usage_count_o.
        if let Some(key_purpose_restriction) = self.key_purpose_restriction_o {
            KeyPurposeFlags::try_from(key_purpose_restriction as u8)
                .map_err(|e| Error::RecordCorruption(e.to_string().into()))?;
        }
        if let Some(last_used_at) = self.last_used_at_o {
            if last_used_at < self.created_at {
                return Err(Error::RecordCorruption(
                    "last_used_at_o must be no earlier than created_at".into(),
                ));
            }
            if let Some(deleted_at) = self.deleted_at_o {
                if last_used_at > deleted_at {
                    return Err(Error::RecordCorruption(
                        "last_used_at_o must be no earlier than deleted_at_o (if deleted_at_o is not null)".into(),
                    ));
                }
            }
        }
        if self.deleted_at_o.is_some() {
            if self.priv_key_format_o.is_some() {
                return Err(Error::RecordCorruption(
                    "priv_key_format_o is present in deleted priv key (deleted_at_o is not null)"
                        .into(),
                ));
            }
            if self.priv_key_bytes_o.is_some() {
                return Err(Error::RecordCorruption(
                    "priv_key_bytes_o is present in deleted priv key (deleted_at_o is not null)"
                        .into(),
                ));
            }
        } else {
            if self.priv_key_format_o.is_none() {
                return Err(Error::RecordCorruption("priv_key_format_o is not present in non-deleted priv key (deleted_at_o is null)".into()));
            }
            if self.priv_key_bytes_o.is_none() {
                return Err(Error::RecordCorruption("priv_key_bytes_o is not present in non-deleted priv key (deleted_at_o is null)".into()));
            }
        }
        Ok(())
    }
    pub fn try_from_priv_key_record(
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> Result<Self> {
        if priv_key_record.deleted_at_o.is_some() {
            if priv_key_record.private_key_bytes_o.is_some() {
                return Err(Error::Malformed(
                    "priv_key_o must be None if deleted_at_o is Some".into(),
                ));
            }
        } else {
            if priv_key_record.private_key_bytes_o.is_none() {
                return Err(Error::Malformed(
                    "priv_key_o must be Some if deleted_at_o is None".into(),
                ));
            }
        }
        let (priv_key_format_o, priv_key_bytes_o) = match priv_key_record.private_key_bytes_o {
            Some(private_key_bytes) => {
                let priv_key_format = "selfsign::PrivateKeyBytes".to_string();
                let priv_key_bytes = private_key_bytes.into_private_key_byte_v().to_vec();
                (Some(priv_key_format), Some(priv_key_bytes))
            }
            None => (None, None),
        };
        let retval = Self {
            wallets_rowid: ctx.wallets_rowid,
            pub_key: priv_key_record.pub_key.to_string(),
            hashed_pub_key: priv_key_record.hashed_pub_key,
            key_type: priv_key_record.pub_key.key_type().to_string(),
            did_restriction_o: priv_key_record.did_restriction_o,
            key_purpose_restriction_o: priv_key_record
                .key_purpose_restriction_o
                .map(|key_purpose_restriction| key_purpose_restriction.integer_value() as i64),
            created_at: priv_key_record.created_at,
            last_used_at_o: priv_key_record.last_used_at_o,
            max_usage_count_o: priv_key_record
                .max_usage_count_o
                .map(|max_usage_count| max_usage_count as i64),
            usage_count: priv_key_record.usage_count as i64,
            deleted_at_o: priv_key_record.deleted_at_o,
            priv_key_format_o,
            priv_key_bytes_o,
            comment_o: priv_key_record.comment_o,
        };
        retval.validate()?;
        Ok(retval)
    }
    pub fn try_into_priv_key_record(self) -> Result<PrivKeyRecord> {
        self.validate()?;

        let key_type = selfsign::KeyType::from_str(self.key_type.as_str()).unwrap();

        let priv_key_bytes_o = match (self.priv_key_format_o, self.priv_key_bytes_o) {
            (Some(priv_key_format), Some(priv_key_bytes)) => match priv_key_format.as_str() {
                "selfsign::PrivateKeyBytes" => Some(
                    selfsign::PrivateKeyBytes::new(key_type, priv_key_bytes.into())
                        .map_err(|e| Error::RecordCorruption(e.to_string().into()))?,
                ),
                _ => {
                    return Err(Error::RecordCorruption(
                        format!("unsupported priv_key_format_o value: {}", priv_key_format).into(),
                    ));
                }
            },
            (None, None) => None,
            _ => {
                return Err(Error::RecordCorruption(
                    "priv_key_format and priv_key_bytes must both be present or both be absent"
                        .into(),
                ));
            }
        };

        Ok(PrivKeyRecord {
            pub_key: selfsign::KERIVerifier::try_from(self.pub_key)
                .map_err(|e| Error::RecordCorruption(e.to_string().into()))?,
            hashed_pub_key: self.hashed_pub_key,
            did_restriction_o: self.did_restriction_o,
            key_purpose_restriction_o: self
                .key_purpose_restriction_o
                .map(|key_purpose_restriction| {
                    KeyPurposeFlags::try_from(
                        u8::try_from(key_purpose_restriction)
                            .map_err(|e| Error::RecordCorruption(e.to_string().into()))?,
                    )
                    .map_err(|e| Error::RecordCorruption(e.to_string().into()))
                })
                .transpose()?,
            created_at: self.created_at,
            last_used_at_o: self.last_used_at_o,
            max_usage_count_o: self
                .max_usage_count_o
                .map(|max_usage_count| u32::try_from(max_usage_count))
                .transpose()
                .map_err(|e| Error::RecordCorruption(e.to_string().into()))?,
            usage_count: self.usage_count.try_into().expect("overflow"),
            deleted_at_o: self.deleted_at_o,
            private_key_bytes_o: priv_key_bytes_o,
            comment_o: self.comment_o,
        })
    }
}
