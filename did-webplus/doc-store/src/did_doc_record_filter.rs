use crate::DIDDocRecord;

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocRecordFilter {
    #[serde(rename = "did")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_o: Option<String>,
    #[serde(rename = "selfHash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_hash_o: Option<String>,
    #[serde(rename = "versionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id_o: Option<u32>,
    // TODO
    // #[serde(with = "time::serde::rfc3339::option")]
    // #[serde(rename = "validAt")]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub valid_at_o: Option<time::OffsetDateTime>,
}

impl DIDDocRecordFilter {
    pub fn matches(&self, did_doc_record: &DIDDocRecord) -> bool {
        if let Some(did) = self.did_o.as_deref() {
            if did_doc_record.did.as_str() != did {
                return false;
            }
        }
        if let Some(self_hash) = self.self_hash_o.as_deref() {
            if did_doc_record.self_hash.as_str() != self_hash {
                return false;
            }
        }
        if let Some(version_id) = self.version_id_o {
            if did_doc_record.version_id != version_id as i64 {
                return false;
            }
        }
        true
    }
}
