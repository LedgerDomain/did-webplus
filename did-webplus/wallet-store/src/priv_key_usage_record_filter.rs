use crate::{PrivKeyUsageRecord, PrivKeyUsageType};

#[derive(Default)]
pub struct PrivKeyUsageRecordFilter {
    pub pub_key_o: Option<selfsign::KERIVerifier>,
    // TODO: Add more filters (did, key purpose, etc., maybe hashed_pub_key)
    pub usage_type_o: Option<PrivKeyUsageType>,
    pub used_at_or_after_o: Option<time::OffsetDateTime>,
    pub used_at_or_before_o: Option<time::OffsetDateTime>,
}

impl PrivKeyUsageRecordFilter {
    pub fn matches(&self, priv_key_usage_record: &PrivKeyUsageRecord) -> bool {
        if let Some(pub_key) = self.pub_key_o.as_deref() {
            if priv_key_usage_record.pub_key.as_keri_verifier_str() != pub_key {
                return false;
            }
        }
        if let Some(usage_type) = self.usage_type_o {
            if priv_key_usage_record.usage.priv_key_usage_type() != usage_type {
                return false;
            }
        }
        if let Some(used_at_or_after) = self.used_at_or_after_o {
            if priv_key_usage_record.used_at < used_at_or_after {
                return false;
            }
        }
        if let Some(used_at_or_before) = self.used_at_or_before_o {
            if priv_key_usage_record.used_at > used_at_or_before {
                return false;
            }
        }
        true
    }
}
