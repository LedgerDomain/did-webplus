mod default_schema;
mod direct_dependencies;
mod error;
mod validate;
mod vjson_properties;
mod vjson_resolver;
mod vjson_schema;

pub use crate::{
    default_schema::{DefaultSchema, DEFAULT_SCHEMA},
    direct_dependencies::DirectDependencies,
    error::{
        error_already_exists, error_internal_error, error_invalid_vjson, error_malformed,
        error_not_found, error_storage_error, Error,
    },
    validate::Validate,
    vjson_properties::VJSONProperties,
    vjson_resolver::VJSONResolver,
    vjson_schema::VJSONSchema,
};
pub type Result<T> = std::result::Result<T, Error>;

/// Returns the SelfHashableJSON (which defines the self-hash and self-hash URL paths) and the schema
/// corresponding to this SelfHashableJSON (specified by "$schema" if present, otherwise a default schema).
/// Note that this does not do full validation, only enough to determine the schema and the self-hash and
/// self-hash URL paths.
pub async fn self_hashable_json_from(
    mut value: serde_json::Value,
    vjson_resolver: &dyn VJSONResolver,
) -> Result<(
    selfhash::SelfHashableJSON<'static, 'static>,
    serde_json::Value,
)> {
    use std::{borrow::Cow, collections::HashSet};

    if !value.is_object() {
        return Err(Error::InvalidVJSON("VJSON must be a JSON object".into()));
    }

    // This should be true only of the Default schema (which is its own schema).
    let is_self_schema = value.get("$schema").is_some()
        && value.get("$id").is_some()
        && value.get("$schema") == value.get("$id");
    tracing::trace!(
        "self_hashable_json_from; is_self_schema = {:?}",
        is_self_schema
    );

    // If there is no "$schema" field, then set it to the default schema URL.
    if value.get("$schema").is_none() {
        tracing::trace!(
            "self_hashable_json_from; no \"$schema\" field found; setting to Default schema {}",
            DEFAULT_SCHEMA.vjson_url
        );
        value.as_object_mut().unwrap().insert(
            "$schema".to_string(),
            serde_json::Value::String(DEFAULT_SCHEMA.vjson_url.clone()),
        );
    }

    let schema_self_hash_url_value = value.get("$schema").unwrap();

    // Resolve the schema and validate the JSON against it.  The schema can optionally specify the name of
    // the field that contains the self-hash.  This field is used to verify the self-hash of the JSON.

    tracing::trace!("self_hashable_json_from; has schema");

    let schema_self_hash_url_str = schema_self_hash_url_value.as_str().ok_or_else(|| {
        Error::Malformed("VJSON \"$schema\" field is expected to be a string".into())
    })?;
    tracing::trace!(
        "self_hashable_json_from; schema_self_hash_url_str: {:?}",
        schema_self_hash_url_str
    );
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
    tracing::trace!(
        "self_hashable_json_from; schema_self_hash_url: {}",
        schema_self_hash_url
    );

    if schema_self_hash_url.mb_hash_o().is_none() {
        return Err(Error::Malformed(
            "VJSON \"$schema\" URL must be a valid and complete VJSONURL".into(),
        ));
    }
    let schema_value = vjson_resolver
        .resolve_vjson_value(schema_self_hash_url.mb_hash_o().unwrap())
        .await?;

    tracing::trace!(
        "self_hashable_json_from; schema: {}",
        schema_value.to_string()
    );

    // The schema defines the JSONPath queries that define the self-hash [URL] slots, as well as
    // if this JSON blob is expected to be self-signed.
    let vjson_schema: VJSONSchema = serde_json::from_value(schema_value.clone()).map_err(|e| {
        Error::InvalidVJSON(format!("VJSON schema was invalid JSON; error was: {}", e).into())
    })?;
    tracing::trace!("self_hashable_json_from; vjson_schema: {:?}", vjson_schema);

    let self_hash_path_s = vjson_schema
        .vjson_properties
        .self_hash_path_v
        .into_iter()
        .map(Cow::Owned)
        .collect::<HashSet<_>>();
    let mut self_hash_url_path_s = vjson_schema
        .vjson_properties
        .self_hash_url_path_v
        .into_iter()
        .map(Cow::Owned)
        .collect::<HashSet<_>>();
    if is_self_schema {
        self_hash_url_path_s.insert(Cow::Borrowed("$.$schema"));
    }

    let self_hashable_json = selfhash::SelfHashableJSON::new(
        value,
        Cow::Owned(self_hash_path_s),
        Cow::Owned(self_hash_url_path_s),
    )
    .unwrap();

    Ok((self_hashable_json, schema_value))
}

pub fn validate_against_json_schema(
    schema_value: &serde_json::Value,
    json_value: &serde_json::Value,
) -> Result<()> {
    tracing::trace!("validate_against_json_schema; attempting to compile schema");
    let json_schema = jsonschema::JSONSchema::compile(schema_value).map_err(|e| {
        Error::Malformed(
            format!(
                "VJSON schema failed to compile as a JSON schema; error was: {}",
                e
            )
            .into(),
        )
    })?;
    tracing::trace!("validate_against_json_schema; schema compiled successfully");
    tracing::trace!("validate_against_json_schema; attempting to validate against schema");
    if let Err(error_iterator) = json_schema.validate(&json_value) {
        tracing::trace!("validate_against_json_schema; schema validation failed; errors follow:");
        let mut error_string = String::new();
        error_string.push_str("VJSON failed validation against its schema; errors were:\n");
        for error in error_iterator {
            tracing::trace!(
                "validate_against_json_schema; schema validation error: {}",
                error
            );
            error_string.push_str(format!("    {:?}\n", error).as_str());
        }
        return Err(Error::InvalidVJSON(error_string.into()));
    };
    Ok(())
}

/// The kid field should give the fully-qualified DID resource of the signer.  For did:key this would look like
/// "did:key:<base58enc-key>#<base58enc-key>" (see did_key::DIDResource).  For did:webplus this would look like
/// "did:webplus:<hostname>:<path>:<root-self-hash>?selfHash=<query-self-hash>&versionId=<version-id>#<key-id>"
/// (see did_webplus::DIDKeyResourceFullyQualified).  If verifier_resolver_o is Some(_), then the
/// signed-and-self-hashed VJSON will be verified before returning.  This is not strictly necessary,
/// but will be done as a sanity check for now.
pub async fn sign_and_self_hash_vjson(
    value: &mut serde_json::Value,
    kid: String,
    signer: &dyn signature_dyn::SignerDynT,
    vjson_resolver: &dyn VJSONResolver,
    verifier_resolver_o: Option<&dyn verifier_resolver::VerifierResolver>,
) -> Result<mbx::MBHash> {
    if !kid.starts_with("did:") {
        return Err(Error::Malformed("kid must start with \"did:\"".into()));
    }
    // TODO (maybe): Could resolve the DID here to ensure it's valid as a sanity check, but it's not strictly necessary.

    use selfhash::{HashFunctionT, SelfHashableT};

    // Swap out the value with a null value, so that we can take ownership for use in SelfHashableJSON.
    let mut owned_value = serde_json::Value::Null;
    std::mem::swap(value, &mut owned_value);

    let mut proofs = {
        if !owned_value.is_object() {
            return Err(Error::Malformed("JSON must be an object".into()));
        }
        let value_object = owned_value.as_object_mut().unwrap();
        // Extract the "proofs" field, if it exists, and if so, ensure that it's an array.  We will
        // add the proof to it, and re-add it after signing.
        match value_object.remove("proofs") {
            None => {
                // No existing "proofs" field, this is fine.  Create an empty array to be populated later.
                Vec::new()
            }
            Some(serde_json::Value::Array(proofs)) => {
                // Existing "proofs" field that is an array, as expected.  Use it.
                proofs
            }
            Some(_) => {
                return Err(Error::Malformed(
                    "\"proofs\" field, if it exists, must be an array".into(),
                ));
            }
        }
    };

    let (mut self_hashable_json, schema_value) =
        self_hashable_json_from(owned_value, vjson_resolver).await?;

    let jws = {
        let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
        self_hashable_json
            .set_self_hash_slots_to(&mb_hash_function.placeholder_hash())
            .map_err(error_internal_error)?;
        tracing::debug!(
            "JSON that will be signed: {}",
            self_hashable_json.value().to_string()
        );
        let payload_bytes = serde_json_canonicalizer::to_vec(self_hashable_json.value()).unwrap();
        did_webplus_jws::JWS::signed(
            kid,
            &mut payload_bytes.as_slice(),
            did_webplus_jws::JWSPayloadPresence::Detached,
            did_webplus_jws::JWSPayloadEncoding::Base64,
            signer,
        )
        .map_err(|e| Error::InternalError(format!("Failed to sign JWS; error was: {}", e).into()))?
    };

    // Attach the JWS to the "proofs" array.
    proofs.push(serde_json::Value::String(jws.into_string()));

    // Re-add the "proofs" field to the json.
    let value_object = self_hashable_json.value_mut().as_object_mut().unwrap();
    value_object.insert("proofs".to_owned(), serde_json::Value::Array(proofs));

    // Self-hash the JSON with the "proofs" field populated.
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
    let self_hash = self_hashable_json
        .self_hash(mb_hash_function.new_hasher())
        .map_err(error_internal_error)?
        .to_owned();

    owned_value = self_hashable_json.into_value();

    // Validate it to ensure it's completely valid, including against its schema.
    validate_against_json_schema(&schema_value, &owned_value)?;

    // Swap the value back in.
    std::mem::swap(value, &mut owned_value);

    // If a verifier_resolver was provided, then verify the signed-and-self-hashed VJSON.
    if let Some(verifier_resolver) = verifier_resolver_o {
        value
            .validate_and_return_self_hash(vjson_resolver, verifier_resolver)
            .await?;
    }

    Ok(self_hash)
}
