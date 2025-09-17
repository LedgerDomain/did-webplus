use std::ops::Deref;

use did_webplus_core::KeyPurposeFlags;

use crate::PrivKeyRecord;

#[derive(Debug, Default)]
pub struct PrivKeyRecordFilter {
    /// If this is Some(pub_key), then only the priv key for that pub key will be returned.  Because priv keys
    /// are indexed by pub key, this is a way to select a single priv key.  If this is None, then priv keys
    /// will not be filtered by pub key.
    pub pub_key_o: Option<mbc::MBPubKey>,
    /// If this is Some(hashed_pub_key), then only the priv key for that hashed pub key will be returned.
    /// Because priv keys are indexed by hashed pub key, this is a way to select a single priv key.
    /// If this is None, then priv keys will not be filtered by hashed pub key.
    pub hashed_pub_key_o: Option<String>,
    /// If this is Some(did), then only priv keys that are usable for that DID will be returned.
    /// In particular, this means keys that have a did_restriction_o field that is Some(did) or None.
    /// If this is None, then priv keys will not be filtered by DID restriction.
    pub did_o: Option<String>,
    /// If this is Some(key_purpose_flags), then only priv keys that are usable for those purposes will be returned.
    /// In particular, this means keys that have a key_purpose_restriction_o field that is None or is Some(_) and
    /// have having a nonzero intersection with key_purpose_flags.  If this is None, then priv keys will not be
    /// filtered by key purpose.
    pub key_purpose_flags_o: Option<KeyPurposeFlags>,
    /// If this is Some(is_not_deleted), then only priv keys with matching deletion status will be returned.
    pub is_not_deleted_o: Option<bool>,
    // /// If this is Some(time), then only priv keys created after that time will be returned.
    // pub created_after_o: Option<time::OffsetDateTime>,
    // /// If this is Some(time), then only priv keys created before that time will be returned.
    // pub created_before_o: Option<time::OffsetDateTime>,
    // /// If this is Some(time), then only priv keys last used after that time will be returned.
    // pub last_used_after_o: Option<time::OffsetDateTime>,
    // /// If this is Some(time), then only priv keys last used before that time will be returned.
    // pub last_used_before_o: Option<time::OffsetDateTime>,
    // /// If this is Some(count), then only priv keys used at least that many times will be returned.
    // pub usage_count_at_least: Option<u32>,
    // /// If this is Some(count), then only priv keys used no more than that many times will be returned.
    // pub usage_count_at_most: Option<u32>,
    // /// If this is Some(time), then only priv keys deleted after that time will be returned.
    // pub deleted_after_o: Option<time::OffsetDateTime>,
    // /// If this is Some(time), then only priv keys deleted before that time will be returned.
    // pub deleted_before_o: Option<time::OffsetDateTime>,
}

impl PrivKeyRecordFilter {
    pub fn matches(&self, priv_key_record: &PrivKeyRecord) -> bool {
        if let Some(pub_key) = self.pub_key_o.as_deref() {
            if priv_key_record.pub_key.deref() != pub_key {
                return false;
            }
        }
        if let Some(key_purpose_flags) = self.key_purpose_flags_o {
            if let Some(key_purpose_restriction) = priv_key_record.key_purpose_restriction_o {
                if !key_purpose_restriction.intersects(key_purpose_flags) {
                    return false;
                }
            }
        }
        if let Some(is_not_deleted) = self.is_not_deleted_o {
            let priv_key_record_is_not_deleted = priv_key_record.deleted_at_o.is_none();
            if priv_key_record_is_not_deleted != is_not_deleted {
                return false;
            }
        }
        true
    }
}
