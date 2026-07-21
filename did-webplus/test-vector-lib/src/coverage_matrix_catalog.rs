use crate::{
    BaseChoice, DeterministicRng, Expected, HashFunctionChoice, KeyTypeChoice, MicroledgerBuilder,
    TestVector, TestVectorParams, VectorDefinition,
};

const CATEGORY: &str = "coverage-matrix";
const VALIDATION_REF: &str = "#validation-of-did-documents";

fn positive_vector(
    name: &str,
    description: &str,
    params: TestVectorParams,
    builder: MicroledgerBuilder,
) -> anyhow::Result<TestVector> {
    let did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;
    Ok(TestVector {
        name: name.to_owned(),
        category: CATEGORY.to_owned(),
        description: description.to_owned(),
        spec_ref_v: vec![VALIDATION_REF.to_owned()],
        expected: Expected::fully_valid(jsonl_line_v.len() as u32),
        jsonl_line_v,
        did,
        params,
    })
}

fn matrix_vector(
    name: &str,
    key_type: KeyTypeChoice,
    hash_function: HashFunctionChoice,
    mut params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    params.key_type = key_type;
    params.hash_function = hash_function;
    params.base = BaseChoice::Base64Url;
    let description = format!(
        "Valid root and update using {} keys and {} self-hashes.",
        key_type, hash_function
    );
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 1)?;
    positive_vector(name, &description, params, builder)
}

macro_rules! matrix_factory {
    ($function:ident, $name:literal, $key_type:expr, $hash_function:expr) => {
        fn $function(
            params: TestVectorParams,
            rng: DeterministicRng,
        ) -> anyhow::Result<TestVector> {
            matrix_vector($name, $key_type, $hash_function, params, rng)
        }
    };
}

matrix_factory!(
    ed25519_blake3,
    "matrix-ed25519-blake3",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Blake3
);
matrix_factory!(
    ed25519_sha224,
    "matrix-ed25519-sha224",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha224
);
matrix_factory!(
    ed25519_sha256,
    "matrix-ed25519-sha256",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha256
);
matrix_factory!(
    ed25519_sha384,
    "matrix-ed25519-sha384",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha384
);
matrix_factory!(
    ed25519_sha512,
    "matrix-ed25519-sha512",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha512
);
matrix_factory!(
    ed25519_sha3_224,
    "matrix-ed25519-sha3-224",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha3_224
);
matrix_factory!(
    ed25519_sha3_256,
    "matrix-ed25519-sha3-256",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha3_256
);
matrix_factory!(
    ed25519_sha3_384,
    "matrix-ed25519-sha3-384",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha3_384
);
matrix_factory!(
    ed25519_sha3_512,
    "matrix-ed25519-sha3-512",
    KeyTypeChoice::Ed25519,
    HashFunctionChoice::Sha3_512
);
matrix_factory!(
    ed448_blake3,
    "matrix-ed448-blake3",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Blake3
);
matrix_factory!(
    ed448_sha224,
    "matrix-ed448-sha224",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha224
);
matrix_factory!(
    ed448_sha256,
    "matrix-ed448-sha256",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha256
);
matrix_factory!(
    ed448_sha384,
    "matrix-ed448-sha384",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha384
);
matrix_factory!(
    ed448_sha512,
    "matrix-ed448-sha512",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha512
);
matrix_factory!(
    ed448_sha3_224,
    "matrix-ed448-sha3-224",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha3_224
);
matrix_factory!(
    ed448_sha3_256,
    "matrix-ed448-sha3-256",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha3_256
);
matrix_factory!(
    ed448_sha3_384,
    "matrix-ed448-sha3-384",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha3_384
);
matrix_factory!(
    ed448_sha3_512,
    "matrix-ed448-sha3-512",
    KeyTypeChoice::Ed448,
    HashFunctionChoice::Sha3_512
);
matrix_factory!(
    p256_blake3,
    "matrix-p256-blake3",
    KeyTypeChoice::P256,
    HashFunctionChoice::Blake3
);
matrix_factory!(
    p256_sha224,
    "matrix-p256-sha224",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha224
);
matrix_factory!(
    p256_sha256,
    "matrix-p256-sha256",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha256
);
matrix_factory!(
    p256_sha384,
    "matrix-p256-sha384",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha384
);
matrix_factory!(
    p256_sha512,
    "matrix-p256-sha512",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha512
);
matrix_factory!(
    p256_sha3_224,
    "matrix-p256-sha3-224",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha3_224
);
matrix_factory!(
    p256_sha3_256,
    "matrix-p256-sha3-256",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha3_256
);
matrix_factory!(
    p256_sha3_384,
    "matrix-p256-sha3-384",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha3_384
);
matrix_factory!(
    p256_sha3_512,
    "matrix-p256-sha3-512",
    KeyTypeChoice::P256,
    HashFunctionChoice::Sha3_512
);
matrix_factory!(
    p384_blake3,
    "matrix-p384-blake3",
    KeyTypeChoice::P384,
    HashFunctionChoice::Blake3
);
matrix_factory!(
    p384_sha224,
    "matrix-p384-sha224",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha224
);
matrix_factory!(
    p384_sha256,
    "matrix-p384-sha256",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha256
);
matrix_factory!(
    p384_sha384,
    "matrix-p384-sha384",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha384
);
matrix_factory!(
    p384_sha512,
    "matrix-p384-sha512",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha512
);
matrix_factory!(
    p384_sha3_224,
    "matrix-p384-sha3-224",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha3_224
);
matrix_factory!(
    p384_sha3_256,
    "matrix-p384-sha3-256",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha3_256
);
matrix_factory!(
    p384_sha3_384,
    "matrix-p384-sha3-384",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha3_384
);
matrix_factory!(
    p384_sha3_512,
    "matrix-p384-sha3-512",
    KeyTypeChoice::P384,
    HashFunctionChoice::Sha3_512
);
matrix_factory!(
    p521_blake3,
    "matrix-p521-blake3",
    KeyTypeChoice::P521,
    HashFunctionChoice::Blake3
);
matrix_factory!(
    p521_sha224,
    "matrix-p521-sha224",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha224
);
matrix_factory!(
    p521_sha256,
    "matrix-p521-sha256",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha256
);
matrix_factory!(
    p521_sha384,
    "matrix-p521-sha384",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha384
);
matrix_factory!(
    p521_sha512,
    "matrix-p521-sha512",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha512
);
matrix_factory!(
    p521_sha3_224,
    "matrix-p521-sha3-224",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha3_224
);
matrix_factory!(
    p521_sha3_256,
    "matrix-p521-sha3-256",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha3_256
);
matrix_factory!(
    p521_sha3_384,
    "matrix-p521-sha3-384",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha3_384
);
matrix_factory!(
    p521_sha3_512,
    "matrix-p521-sha3-512",
    KeyTypeChoice::P521,
    HashFunctionChoice::Sha3_512
);
matrix_factory!(
    secp256k1_blake3,
    "matrix-secp256k1-blake3",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Blake3
);
matrix_factory!(
    secp256k1_sha224,
    "matrix-secp256k1-sha224",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha224
);
matrix_factory!(
    secp256k1_sha256,
    "matrix-secp256k1-sha256",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha256
);
matrix_factory!(
    secp256k1_sha384,
    "matrix-secp256k1-sha384",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha384
);
matrix_factory!(
    secp256k1_sha512,
    "matrix-secp256k1-sha512",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha512
);
matrix_factory!(
    secp256k1_sha3_224,
    "matrix-secp256k1-sha3-224",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha3_224
);
matrix_factory!(
    secp256k1_sha3_256,
    "matrix-secp256k1-sha3-256",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha3_256
);
matrix_factory!(
    secp256k1_sha3_384,
    "matrix-secp256k1-sha3-384",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha3_384
);
matrix_factory!(
    secp256k1_sha3_512,
    "matrix-secp256k1-sha3-512",
    KeyTypeChoice::Secp256k1,
    HashFunctionChoice::Sha3_512
);

fn base58btc_spot(
    mut params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    params.base = BaseChoice::Base58Btc;
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 1)?;
    positive_vector(
        "base-base58btc",
        "Valid root and update with base58btc self-hashes and public keys.",
        params,
        builder,
    )
}

fn mixed_hash_history(
    mut params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    params.hash_function = HashFunctionChoice::Blake3;
    params.base = BaseChoice::Base64Url;
    let mut builder = MicroledgerBuilder::create(params.clone(), rng)?;
    builder.update_with_crypto(
        params.key_type,
        HashFunctionChoice::Sha256,
        BaseChoice::Base64Url,
    )?;
    builder.update_with_crypto(
        params.key_type,
        HashFunctionChoice::Sha3_512,
        BaseChoice::Base64Url,
    )?;
    positive_vector(
        "mixed-hash-history",
        "Valid history changing self-hash functions from BLAKE3 to SHA-256 to SHA3-512.",
        params,
        builder,
    )
}

fn mixed_key_types(
    mut params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    params.key_type = KeyTypeChoice::Ed25519;
    let mut builder = MicroledgerBuilder::create(params.clone(), rng)?;
    builder.update_with_key_types([
        KeyTypeChoice::Ed448,
        KeyTypeChoice::P256,
        KeyTypeChoice::P384,
        KeyTypeChoice::P521,
        KeyTypeChoice::Secp256k1,
    ])?;
    positive_vector(
        "mixed-key-types-one-document",
        "Valid update using a different supported key type for each verification-method purpose.",
        params,
        builder,
    )
}

fn mixed_base_history(
    mut params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    params.base = BaseChoice::Base64Url;
    let mut builder = MicroledgerBuilder::create(params.clone(), rng)?;
    builder.update_with_crypto(params.key_type, params.hash_function, BaseChoice::Base58Btc)?;
    builder.update_with_crypto(params.key_type, params.hash_function, BaseChoice::Base64Url)?;
    positive_vector(
        "mixed-base-history",
        "Valid history changing from base64url to base58btc and back.",
        params,
        builder,
    )
}

fn multi_path(mut params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    // Append under the caller-supplied `--did-path` prefix (do not replace it).
    params.path_component_v.extend([
        "teams".to_owned(),
        "identity".to_owned(),
        "alice".to_owned(),
    ]);
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 1)?;
    positive_vector(
        "did-multi-path-components",
        "Valid DID with three additional method-specific path components under the base did-path.",
        params,
        builder,
    )
}

pub(crate) fn definitions() -> &'static [VectorDefinition] {
    const DEFINITIONS: &[VectorDefinition] = &[
        VectorDefinition {
            name: "matrix-ed25519-blake3",
            description: "Valid root and update using Ed25519 keys and BLAKE3 self-hashes.",
            positive: true,
            factory: ed25519_blake3,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha224",
            description: "Valid root and update using Ed25519 keys and SHA-224 self-hashes.",
            positive: true,
            factory: ed25519_sha224,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha256",
            description: "Valid root and update using Ed25519 keys and SHA-256 self-hashes.",
            positive: true,
            factory: ed25519_sha256,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha384",
            description: "Valid root and update using Ed25519 keys and SHA-384 self-hashes.",
            positive: true,
            factory: ed25519_sha384,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha512",
            description: "Valid root and update using Ed25519 keys and SHA-512 self-hashes.",
            positive: true,
            factory: ed25519_sha512,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha3-224",
            description: "Valid root and update using Ed25519 keys and SHA3-224 self-hashes.",
            positive: true,
            factory: ed25519_sha3_224,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha3-256",
            description: "Valid root and update using Ed25519 keys and SHA3-256 self-hashes.",
            positive: true,
            factory: ed25519_sha3_256,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha3-384",
            description: "Valid root and update using Ed25519 keys and SHA3-384 self-hashes.",
            positive: true,
            factory: ed25519_sha3_384,
        },
        VectorDefinition {
            name: "matrix-ed25519-sha3-512",
            description: "Valid root and update using Ed25519 keys and SHA3-512 self-hashes.",
            positive: true,
            factory: ed25519_sha3_512,
        },
        VectorDefinition {
            name: "matrix-ed448-blake3",
            description: "Valid root and update using Ed448 keys and BLAKE3 self-hashes.",
            positive: true,
            factory: ed448_blake3,
        },
        VectorDefinition {
            name: "matrix-ed448-sha224",
            description: "Valid root and update using Ed448 keys and SHA-224 self-hashes.",
            positive: true,
            factory: ed448_sha224,
        },
        VectorDefinition {
            name: "matrix-ed448-sha256",
            description: "Valid root and update using Ed448 keys and SHA-256 self-hashes.",
            positive: true,
            factory: ed448_sha256,
        },
        VectorDefinition {
            name: "matrix-ed448-sha384",
            description: "Valid root and update using Ed448 keys and SHA-384 self-hashes.",
            positive: true,
            factory: ed448_sha384,
        },
        VectorDefinition {
            name: "matrix-ed448-sha512",
            description: "Valid root and update using Ed448 keys and SHA-512 self-hashes.",
            positive: true,
            factory: ed448_sha512,
        },
        VectorDefinition {
            name: "matrix-ed448-sha3-224",
            description: "Valid root and update using Ed448 keys and SHA3-224 self-hashes.",
            positive: true,
            factory: ed448_sha3_224,
        },
        VectorDefinition {
            name: "matrix-ed448-sha3-256",
            description: "Valid root and update using Ed448 keys and SHA3-256 self-hashes.",
            positive: true,
            factory: ed448_sha3_256,
        },
        VectorDefinition {
            name: "matrix-ed448-sha3-384",
            description: "Valid root and update using Ed448 keys and SHA3-384 self-hashes.",
            positive: true,
            factory: ed448_sha3_384,
        },
        VectorDefinition {
            name: "matrix-ed448-sha3-512",
            description: "Valid root and update using Ed448 keys and SHA3-512 self-hashes.",
            positive: true,
            factory: ed448_sha3_512,
        },
        VectorDefinition {
            name: "matrix-p256-blake3",
            description: "Valid root and update using P-256 keys and BLAKE3 self-hashes.",
            positive: true,
            factory: p256_blake3,
        },
        VectorDefinition {
            name: "matrix-p256-sha224",
            description: "Valid root and update using P-256 keys and SHA-224 self-hashes.",
            positive: true,
            factory: p256_sha224,
        },
        VectorDefinition {
            name: "matrix-p256-sha256",
            description: "Valid root and update using P-256 keys and SHA-256 self-hashes.",
            positive: true,
            factory: p256_sha256,
        },
        VectorDefinition {
            name: "matrix-p256-sha384",
            description: "Valid root and update using P-256 keys and SHA-384 self-hashes.",
            positive: true,
            factory: p256_sha384,
        },
        VectorDefinition {
            name: "matrix-p256-sha512",
            description: "Valid root and update using P-256 keys and SHA-512 self-hashes.",
            positive: true,
            factory: p256_sha512,
        },
        VectorDefinition {
            name: "matrix-p256-sha3-224",
            description: "Valid root and update using P-256 keys and SHA3-224 self-hashes.",
            positive: true,
            factory: p256_sha3_224,
        },
        VectorDefinition {
            name: "matrix-p256-sha3-256",
            description: "Valid root and update using P-256 keys and SHA3-256 self-hashes.",
            positive: true,
            factory: p256_sha3_256,
        },
        VectorDefinition {
            name: "matrix-p256-sha3-384",
            description: "Valid root and update using P-256 keys and SHA3-384 self-hashes.",
            positive: true,
            factory: p256_sha3_384,
        },
        VectorDefinition {
            name: "matrix-p256-sha3-512",
            description: "Valid root and update using P-256 keys and SHA3-512 self-hashes.",
            positive: true,
            factory: p256_sha3_512,
        },
        VectorDefinition {
            name: "matrix-p384-blake3",
            description: "Valid root and update using P-384 keys and BLAKE3 self-hashes.",
            positive: true,
            factory: p384_blake3,
        },
        VectorDefinition {
            name: "matrix-p384-sha224",
            description: "Valid root and update using P-384 keys and SHA-224 self-hashes.",
            positive: true,
            factory: p384_sha224,
        },
        VectorDefinition {
            name: "matrix-p384-sha256",
            description: "Valid root and update using P-384 keys and SHA-256 self-hashes.",
            positive: true,
            factory: p384_sha256,
        },
        VectorDefinition {
            name: "matrix-p384-sha384",
            description: "Valid root and update using P-384 keys and SHA-384 self-hashes.",
            positive: true,
            factory: p384_sha384,
        },
        VectorDefinition {
            name: "matrix-p384-sha512",
            description: "Valid root and update using P-384 keys and SHA-512 self-hashes.",
            positive: true,
            factory: p384_sha512,
        },
        VectorDefinition {
            name: "matrix-p384-sha3-224",
            description: "Valid root and update using P-384 keys and SHA3-224 self-hashes.",
            positive: true,
            factory: p384_sha3_224,
        },
        VectorDefinition {
            name: "matrix-p384-sha3-256",
            description: "Valid root and update using P-384 keys and SHA3-256 self-hashes.",
            positive: true,
            factory: p384_sha3_256,
        },
        VectorDefinition {
            name: "matrix-p384-sha3-384",
            description: "Valid root and update using P-384 keys and SHA3-384 self-hashes.",
            positive: true,
            factory: p384_sha3_384,
        },
        VectorDefinition {
            name: "matrix-p384-sha3-512",
            description: "Valid root and update using P-384 keys and SHA3-512 self-hashes.",
            positive: true,
            factory: p384_sha3_512,
        },
        VectorDefinition {
            name: "matrix-p521-blake3",
            description: "Valid root and update using P-521 keys and BLAKE3 self-hashes.",
            positive: true,
            factory: p521_blake3,
        },
        VectorDefinition {
            name: "matrix-p521-sha224",
            description: "Valid root and update using P-521 keys and SHA-224 self-hashes.",
            positive: true,
            factory: p521_sha224,
        },
        VectorDefinition {
            name: "matrix-p521-sha256",
            description: "Valid root and update using P-521 keys and SHA-256 self-hashes.",
            positive: true,
            factory: p521_sha256,
        },
        VectorDefinition {
            name: "matrix-p521-sha384",
            description: "Valid root and update using P-521 keys and SHA-384 self-hashes.",
            positive: true,
            factory: p521_sha384,
        },
        VectorDefinition {
            name: "matrix-p521-sha512",
            description: "Valid root and update using P-521 keys and SHA-512 self-hashes.",
            positive: true,
            factory: p521_sha512,
        },
        VectorDefinition {
            name: "matrix-p521-sha3-224",
            description: "Valid root and update using P-521 keys and SHA3-224 self-hashes.",
            positive: true,
            factory: p521_sha3_224,
        },
        VectorDefinition {
            name: "matrix-p521-sha3-256",
            description: "Valid root and update using P-521 keys and SHA3-256 self-hashes.",
            positive: true,
            factory: p521_sha3_256,
        },
        VectorDefinition {
            name: "matrix-p521-sha3-384",
            description: "Valid root and update using P-521 keys and SHA3-384 self-hashes.",
            positive: true,
            factory: p521_sha3_384,
        },
        VectorDefinition {
            name: "matrix-p521-sha3-512",
            description: "Valid root and update using P-521 keys and SHA3-512 self-hashes.",
            positive: true,
            factory: p521_sha3_512,
        },
        VectorDefinition {
            name: "matrix-secp256k1-blake3",
            description: "Valid root and update using secp256k1 keys and BLAKE3 self-hashes.",
            positive: true,
            factory: secp256k1_blake3,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha224",
            description: "Valid root and update using secp256k1 keys and SHA-224 self-hashes.",
            positive: true,
            factory: secp256k1_sha224,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha256",
            description: "Valid root and update using secp256k1 keys and SHA-256 self-hashes.",
            positive: true,
            factory: secp256k1_sha256,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha384",
            description: "Valid root and update using secp256k1 keys and SHA-384 self-hashes.",
            positive: true,
            factory: secp256k1_sha384,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha512",
            description: "Valid root and update using secp256k1 keys and SHA-512 self-hashes.",
            positive: true,
            factory: secp256k1_sha512,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha3-224",
            description: "Valid root and update using secp256k1 keys and SHA3-224 self-hashes.",
            positive: true,
            factory: secp256k1_sha3_224,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha3-256",
            description: "Valid root and update using secp256k1 keys and SHA3-256 self-hashes.",
            positive: true,
            factory: secp256k1_sha3_256,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha3-384",
            description: "Valid root and update using secp256k1 keys and SHA3-384 self-hashes.",
            positive: true,
            factory: secp256k1_sha3_384,
        },
        VectorDefinition {
            name: "matrix-secp256k1-sha3-512",
            description: "Valid root and update using secp256k1 keys and SHA3-512 self-hashes.",
            positive: true,
            factory: secp256k1_sha3_512,
        },
        VectorDefinition {
            name: "base-base58btc",
            description: "Valid root and update with base58btc self-hashes and public keys.",
            positive: true,
            factory: base58btc_spot,
        },
        VectorDefinition {
            name: "mixed-hash-history",
            description: "Valid history changing self-hash functions from BLAKE3 to SHA-256 to SHA3-512.",
            positive: true,
            factory: mixed_hash_history,
        },
        VectorDefinition {
            name: "mixed-key-types-one-document",
            description: "Valid update using a different supported key type for each verification-method purpose.",
            positive: true,
            factory: mixed_key_types,
        },
        VectorDefinition {
            name: "mixed-base-history",
            description: "Valid history changing from base64url to base58btc and back.",
            positive: true,
            factory: mixed_base_history,
        },
        VectorDefinition {
            name: "did-multi-path-components",
            description: "Valid DID with three additional method-specific path components under the base did-path.",
            positive: true,
            factory: multi_path,
        },
    ];
    DEFINITIONS
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::Catalog;

    #[test]
    fn catalog_covers_crypto_cross_product_and_special_cases() {
        let definition_v = Catalog::coverage_matrix_definitions();
        let name_s = definition_v
            .iter()
            .map(|definition| definition.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(name_s.len(), definition_v.len());

        let vector_v = Catalog::generate_coverage_matrix(
            &TestVectorParams::baseline("example.com"),
            "coverage-matrix-test",
        )
        .expect("all coverage-matrix vectors should generate");
        assert_eq!(vector_v.len(), definition_v.len());

        let combination_s = vector_v
            .iter()
            .filter(|vector| vector.name.starts_with("matrix-"))
            .map(|vector| (vector.params.key_type, vector.params.hash_function))
            .collect::<BTreeSet<_>>();
        let expected_combination_s = KeyTypeChoice::VARIANTS
            .into_iter()
            .flat_map(|key_type| {
                HashFunctionChoice::VARIANTS
                    .into_iter()
                    .map(move |hash_function| (key_type, hash_function))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(combination_s, expected_combination_s);

        for (definition, vector) in definition_v.iter().zip(vector_v) {
            assert_eq!(vector.name, definition.name);
            assert!(vector.expected.is_fully_valid());
            assert_eq!(
                vector.expected.did_document_count as usize,
                vector.jsonl_line_v.len()
            );
        }
    }

    #[test]
    fn multi_path_appends_under_base_did_path() {
        let mut params = TestVectorParams::baseline("example.com");
        params.path_component_v = vec!["tv".to_owned(), "demo".to_owned()];
        let vector = multi_path(
            params,
            DeterministicRng::for_vector("coverage-matrix-test", "did-multi-path-components"),
        )
        .expect("multi_path");
        assert_eq!(
            vector.params.path_component_v,
            [
                "tv".to_owned(),
                "demo".to_owned(),
                "teams".to_owned(),
                "identity".to_owned(),
                "alice".to_owned(),
            ]
        );
        assert!(
            vector
                .did
                .to_string()
                .contains(":tv:demo:teams:identity:alice:")
        );
    }
}
