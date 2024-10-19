use std::{borrow::Cow, collections::HashSet};

#[derive(clap::Args)]
pub struct SelfHashArgs {
    /// Optionally specify a comma-delimited list of JSONPath queries that are considered self-hash slots.
    /// Note that while each self-hash field (i.e. self-hash path query result) doesn't have to exist already,
    /// its parent must exist.  Each self-hash path must end with a plain field name (not a wildcard and not
    /// a bracket-enclosed field name).  See https://en.wikipedia.org/wiki/JSONPath for details on JSONPath.
    #[arg(short, long, default_value = "$.selfHash", value_name = "PATHS")]
    self_hash_paths: String,
    /// Optionally specify a comma-delimited list of JSONPath queries that are considered self-hash URL slots.
    /// Note that each self-hash URL field (i.e. self-hash URL path query result) must already exist and be a
    /// valid self-hash URL (a valid default is "selfhash:///").  Each self-hash URL path must end with a
    /// plain field name (not a wildcard and not a bracket-enclosed field name).  See
    /// https://en.wikipedia.org/wiki/JSONPath for details on JSONPath.
    #[arg(short = 'U', long, default_value = "", value_name = "PATHS")]
    self_hash_url_paths: String,
}

impl SelfHashArgs {
    pub fn parse_self_hash_paths(&self) -> HashSet<Cow<'_, str>> {
        let self_hash_paths = self.self_hash_paths.trim();
        if self_hash_paths.is_empty() {
            HashSet::new()
        } else {
            self_hash_paths
                .split(',')
                .map(|s| Cow::Borrowed(s))
                .collect::<HashSet<_>>()
        }
    }
    pub fn parse_self_hash_url_paths(&self) -> HashSet<Cow<'_, str>> {
        let self_hash_url_paths = self.self_hash_url_paths.trim();
        if self_hash_url_paths.is_empty() {
            HashSet::new()
        } else {
            self_hash_url_paths
                .split(',')
                .map(|s| Cow::Borrowed(s))
                .collect::<HashSet<_>>()
        }
    }
}
