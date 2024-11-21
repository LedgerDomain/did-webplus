use selfhash::{HashFunction, SelfHashable};
use std::{borrow::Cow, collections::HashSet};

lazy_static::lazy_static! {
    pub static ref DEFAULT_SCHEMA: DefaultSchema = DefaultSchema::compute();
}

pub struct DefaultSchema {
    pub value: serde_json::Value,
    pub jcs: String,
    pub self_hash: selfhash::KERIHash,
    // TODO: Make this VJSONURL.
    pub vjson_url: String,
}

impl DefaultSchema {
    pub fn compute() -> Self {
        let self_hash_path_s = {
            let mut self_hash_path_s = HashSet::new();
            self_hash_path_s.insert(Cow::Borrowed("$.selfHash"));
            self_hash_path_s
        };
        let self_hash_url_path_s = {
            let mut self_hash_url_path_s = HashSet::new();
            self_hash_url_path_s.insert(Cow::Borrowed("$.$id"));
            self_hash_url_path_s.insert(Cow::Borrowed("$.$schema"));
            self_hash_url_path_s
        };

        let mut self_hashable_json = selfhash::SelfHashableJSON::new(
            serde_json::from_str(include_str!("schema/Default.schema-source.json")).unwrap(),
            Cow::Owned(self_hash_path_s),
            Cow::Owned(self_hash_url_path_s),
        )
        .unwrap();

        let self_hash = self_hashable_json
            .self_hash(selfhash::Blake3.new_hasher())
            .unwrap()
            .to_keri_hash()
            .unwrap()
            .into_owned();
        let vjson_url = format!("vjson:///{}", self_hash);
        let value = self_hashable_json.into_value();
        let jcs = serde_json_canonicalizer::to_string(&value).unwrap();

        Self {
            value,
            jcs,
            self_hash,
            vjson_url,
        }
    }
}
