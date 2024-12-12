use crate::Result;
use std::{borrow::Cow, collections::HashSet};

#[derive(clap::Args)]
pub struct SelfHashArgs {
    /// Optionally specify a comma-delimited list of JSONPath queries that are considered self-hash slots.
    /// Note that while each self-hash field (i.e. self-hash path query result) doesn't have to exist already,
    /// its parent must exist.  Each self-hash path must end with a plain field name (not a wildcard and not
    /// a bracket-enclosed field name).  See https://en.wikipedia.org/wiki/JSONPath for details on JSONPath.
    #[arg(name = "self-hash-paths", short, long, default_value = "$.selfHash", value_name = "PATHS", value_parser = parse_comma_separated_json_paths)]
    self_hash_path_s: HashSet<Cow<'static, str>>,
    /// Optionally specify a comma-delimited list of JSONPath queries that are considered self-hash VJSON URL slots.
    /// Note that each self-hash URL field (i.e. self-hash VJSON URL path query result) must already exist and be a
    /// valid self-hash VJSON URL (a valid default is "vjson:///").  Each self-hash VJSON URL path must end with a
    /// plain field name (not a wildcard and not a bracket-enclosed field name).  See
    /// https://en.wikipedia.org/wiki/JSONPath for details on JSONPath.
    #[arg(name = "self-hash-url-paths", short = 'U', long, default_value = "", value_name = "PATHS", value_parser = parse_comma_separated_json_paths)]
    self_hash_url_path_s: HashSet<Cow<'static, str>>,
}

fn parse_comma_separated_json_paths(s: &str) -> Result<HashSet<Cow<'static, str>>> {
    if s.is_empty() {
        Ok(HashSet::new())
    } else {
        Ok(s.trim()
            .split(',')
            .map(|s| Cow::Owned(s.to_string()))
            .collect::<HashSet<_>>())
    }
}
