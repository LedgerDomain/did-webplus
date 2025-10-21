use std::collections::HashMap;

use vjson_core::Validate;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    env_logger::init();
}

struct TestVJSONResolver {
    vjson_m: HashMap<mbx::MBHash, String>,
}

impl TestVJSONResolver {
    pub fn new() -> Self {
        Self {
            vjson_m: HashMap::new(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl vjson_core::VJSONResolver for TestVJSONResolver {
    async fn resolve_vjson_string(&self, self_hash: &mbx::MBHashStr) -> vjson_core::Result<String> {
        Ok(self
            .vjson_m
            .get(self_hash)
            .ok_or_else(|| vjson_core::Error::NotFound(self_hash.to_string().into()))?
            .clone())
    }
}

#[tokio::test]
async fn test_vjson_core_0() {
    let mut vjson_resolver = TestVJSONResolver::new();
    // Empty resolvers map.  But we don't need any for this test.
    let verifier_resolver = verifier_resolver::VerifierResolverMap::new();

    vjson_resolver.vjson_m.insert(
        vjson_core::DEFAULT_SCHEMA.self_hash.clone(),
        vjson_core::DEFAULT_SCHEMA.jcs.clone(),
    );

    // Add the default schema
    {
        use vjson_core::VJSONResolver;
        let default_schema_string = vjson_resolver
            .resolve_vjson_string(&vjson_core::DEFAULT_SCHEMA.self_hash)
            .await
            .expect("pass");
        assert_eq!(default_schema_string, vjson_core::DEFAULT_SCHEMA.jcs);
    }

    // Create an arbitrary VJSON doc, implicitly using the Default schema.
    {
        use rand::Rng;
        let value =
            serde_json::json!({ "blah": rand::thread_rng().r#gen::<f64>(), "$id": "vjson:///" });

        let (mut self_hashable_json, _schema_value) =
            vjson_core::self_hashable_json_from(value, &vjson_resolver)
                .await
                .expect("pass");
        use selfhash::{HashFunctionT, SelfHashableT};
        let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
        let self_hash = self_hashable_json
            .self_hash(mb_hash_function.new_hasher())
            .expect("pass")
            .to_owned();

        // Verify the newly created VJSON.
        let validated_self_hash = self_hashable_json
            .value()
            .validate_and_return_self_hash(&vjson_resolver, &verifier_resolver)
            .await
            .expect("pass");
        assert_eq!(validated_self_hash, self_hash);

        // Store it in the resolver (NOTE: This does no validation (TEMP HACK)).
        vjson_resolver
            .vjson_m
            .insert(self_hash.clone(), self_hashable_json.value().to_string());
    }

    // TODO: Create a schema
    // TODO: Create a VJSON using that schema
}
