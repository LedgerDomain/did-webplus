#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VJSONProperties {
    #[serde(rename = "directDependencies")]
    pub direct_dependency_v: Vec<String>,
    pub must_be_signed: bool,
    #[serde(rename = "selfHashPaths")]
    pub self_hash_path_v: Vec<String>,
    #[serde(rename = "selfHashURLPaths")]
    pub self_hash_url_path_v: Vec<String>,
}
