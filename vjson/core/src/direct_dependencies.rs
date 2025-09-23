use crate::{Error, Result, VJSONResolver, VJSONSchema};

/// A type implementing DirectDependencies has a set of direct dependencies that can be enumerated via iterator.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait DirectDependencies {
    /// Produce an iterator of the direct dependencies of self.
    // TODO: Need this to return Result, since it could incur errors during resolution.
    // TODO: Should this actually produce &selfhash::SelfHashURLStr?
    // TODO: I had simplified the types here to quickly get things to compile, but it added allocations,
    // so try to improve it again later.
    async fn direct_dependency_iter(
        &self,
        vjson_resolver: &dyn VJSONResolver,
    ) -> Result<Vec<mbx::MBHash>>;
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DirectDependencies for serde_json::Value {
    // TODO: Maybe also return the JSONPath that produced each direct dependency.
    async fn direct_dependency_iter(
        &self,
        vjson_resolver: &dyn VJSONResolver,
    ) -> Result<Vec<mbx::MBHash>> {
        // log::trace!("serde_json::Value::direct_dependency_iter; self: {:?}", self);

        if self.get("$schema").is_none() {
            // If there's no schema, then this is assumed to be "dumb" JSON, having no self-hash links,
            // and therefore no direct dependencies.
            return Ok(vec![]);
        }
        // If the "$schema" and "$id" fields are present and are equal, then this is the Default
        // schema, and by definition has no direct dependencies.
        if self.get("$schema").is_some()
            && self.get("$id").is_some()
            && self.get("$id") == self.get("$schema")
        {
            return Ok(vec![]);
        }

        let schema_self_hash_url_str = self.get("$schema").unwrap().as_str().ok_or_else(|| {
            Error::Malformed("JSON's \"$schema\" field is expected to be a string".into())
        })?;
        let schema_self_hash_url = selfhash::SelfHashURLStr::new_ref(schema_self_hash_url_str)
            .map_err(|e| {
                Error::Malformed(
                    format!(
                        "Malformed schema self-hash URL {:?}; error was: {}",
                        schema_self_hash_url_str, e
                    )
                    .into(),
                )
            })?;
        // log::debug!("serde_json::Value::direct_dependency_iter; schema_self_hash_url: {:?}", schema_self_hash_url);
        if schema_self_hash_url.mb_hash_o().is_none() {
            return Err(Error::Malformed(
                "VJSON \"$schema\" URL must be a valid VJSONURL".into(),
            ));
        }
        let schema_value = vjson_resolver
            .resolve_vjson_value(schema_self_hash_url.mb_hash_o().unwrap())
            .await?;
        // log::debug!("serde_json::Value::direct_dependency_iter; schema_json:\n{}", serde_json::to_string_pretty(&schema_json).unwrap());
        // Validate this JSON against its schema just to be safe.
        {
            let json_schema = jsonschema::JSONSchema::compile(&schema_value).map_err(|e| {
                Error::Malformed(
                    format!(
                        "VJSON schema {} failed to compile as a JSON schema; error was: {}",
                        schema_self_hash_url, e
                    )
                    .into(),
                )
            })?;
            // log::debug!("serde_json::Value::direct_dependency_iter; json_schema: {:?}", json_schema);
            if let Err(error_iterator) = json_schema.validate(self) {
                let mut error_string = String::new();
                error_string.push_str("VJSON failed validation against its schema ");
                error_string.push_str(schema_self_hash_url.as_str());
                error_string.push_str("; errors were:\n");
                for error in error_iterator {
                    error_string.push_str(format!("    {:?}\n", error).as_str());
                }
                return Err(Error::InvalidVJSON(error_string.into()));
            };
            // log::debug!("serde_json::Value::direct_dependency_iter; after json_schema.validate(self)");
        }

        // The schema defines the JSONPath queries that give the direct dependencies.  Assuming
        let vjson_schema: VJSONSchema = serde_json::from_value(schema_value).map_err(|e| {
            Error::InvalidVJSON(format!("VJSON schema was invalid JSON; error was: {}", e).into())
        })?;
        // log::debug!("serde_json::Value::direct_dependency_iter; schema: {:?}", schema);
        let mut selector = jsonpath_lib::selector(self);
        let mut direct_dependency_v = Vec::new();
        for schema_direct_dependency in vjson_schema.vjson_properties.direct_dependency_v.iter() {
            let query_result_v = selector(schema_direct_dependency).map_err(|_| Error::Malformed(format!("VJSON schema (\"title\": {:?}) \"directDependencies\" field is expected to be an array of valid JSONPath queries", vjson_schema.title).into()))?;
            for (query_result_index, query_result) in query_result_v.into_iter().enumerate() {
                // A query value is allowed to be null, in which case it gets ignored as a direct dependency.
                // Validation as to if a field is not null should be handled by the "properties" section
                // of the schema.
                if query_result.is_null() {
                    continue;
                }

                // Otherwise it should be a string.
                let query_result_str = query_result.as_str().ok_or_else(
                    || Error::Malformed(format!("JSON schema (\"title\": {:?}) \"directDependencies\" field is expected to be an array of valid JSONPath queries that each return a string, but the {}th result was {:?}", vjson_schema.title, query_result_index, query_result).into()),
                )?;
                let self_hash_url = selfhash::SelfHashURLStr::new_ref(query_result_str)
                    .map_err(|_| Error::Malformed(format!("JSON schema (\"title\": {:?}) \"directDependencies\" field is expected to be an array of valid JSONPath queries that each return a valid VJSONURL, but the {}th value was {}", vjson_schema.title, query_result_index, query_result_str).into()))?;
                if self_hash_url.mb_hash_o().is_none() {
                    return Err(Error::Malformed(format!("JSON schema (\"title\": {:?}) \"directDependencies\" field is expected to be an array of valid JSONPath queries that each return a valid, fully-specified VJSONURL",
                    vjson_schema.title).into())
                );
                }
                direct_dependency_v.push(self_hash_url.mb_hash_o().unwrap().to_owned());
            }
        }
        Ok(direct_dependency_v)
    }
}
