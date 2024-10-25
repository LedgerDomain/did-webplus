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
