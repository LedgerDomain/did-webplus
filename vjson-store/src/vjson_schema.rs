use crate::VJSONProperties;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VJSONSchema {
    #[serde(rename = "$id")]
    pub id: selfhash::SelfHashURL,
    #[serde(rename = "$schema")]
    pub schema: selfhash::SelfHashURL,
    #[serde(rename = "type")]
    pub r#type: String,
    pub title: String,
    #[serde(rename = "properties")]
    pub property_m: serde_json::Map<String, serde_json::Value>,
    #[serde(rename = "required")]
    pub required_v: Vec<String>,
    pub additional_properties: bool,
    pub vjson_properties: VJSONProperties,
}
