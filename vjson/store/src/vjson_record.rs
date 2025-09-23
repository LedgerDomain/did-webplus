use std::ops::Deref;

use crate::{error_invalid_vjson, Error, Result};
use selfhash::SelfHashableT;

#[derive(Clone, Debug)]
pub struct VJSONRecord {
    pub self_hash: mbx::MBHash,
    pub added_at: time::OffsetDateTime,
    // TODO
    // pub schema_self_hash_o: Option<mbx::MBHash>,
    pub vjson_jcs: String,
}

impl VJSONRecord {
    /// This is rather pedantic, but it's important to guarantee the consistency of VJSONRecords-s
    /// because the whole validation scheme of VJSON depends on it.  This only checks that the
    /// self_hash field matches the self-hash of the vjson_jcs field.
    pub fn validate_consistency(&self) -> Result<()> {
        // Ensure that the vjson_jcs field is valid JSON.
        let vjson_value = serde_json::from_str::<serde_json::Value>(self.vjson_jcs.as_str())
            .map_err(error_invalid_vjson)?;

        // Ensure that the vjson_jcs field is properly JCS-serialized.
        let vjson_jcs =
            serde_json_canonicalizer::to_string(&vjson_value).map_err(error_invalid_vjson)?;
        if vjson_jcs != self.vjson_jcs {
            return Err(Error::InvalidVJSON(
                "VJSONRecord vjson_jcs field doesn't match its JCS-serialized value".into(),
            ));
        }

        // TODO: use schema to determine self-hash slots and self-hash URL slots.  For now, assume it's "selfHash".
        let self_hash = vjson_value
            .verify_self_hashes()
            .map_err(error_invalid_vjson)?
            .to_owned();
        if self_hash.deref() != self.self_hash.deref() {
            return Err(Error::InvalidVJSON(
                "VJSONRecord self_hash field doesn't match that of vjson_jcs field".into(),
            ));
        }

        Ok(())
    }
}
