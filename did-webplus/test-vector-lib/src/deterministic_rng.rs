use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use time::{Duration, OffsetDateTime};

use crate::KeyTypeChoice;

/// Fixed base instant for deterministic `validFrom` timestamps.
///
/// All timestamps produced by [`DeterministicRng::next_timestamp`] are this
/// instant plus a deterministic increment per call.
pub const TIMESTAMP_BASE: OffsetDateTime = time::macros::datetime!(2025-01-01 00:00:00 UTC);

/// Increment applied between successive [`DeterministicRng::next_timestamp`] calls.
pub const TIMESTAMP_INCREMENT: Duration = Duration::seconds(1);

/// Per-vector deterministic RNG and timestamp source.
///
/// Seeded as `BLAKE3(global_seed || vector_name)` so each vector's keys and
/// timestamps are stable and independent of catalog ordering: adding vectors
/// later never changes existing DIDs.
///
/// For ordinary catalog vectors, pass the CLI seed as `global_seed`. For
/// fuzz-lite, the final name already embeds that seed
/// (`fuzz-lite-<seed_hex>-…`); call [`Self::for_vector`] with an empty
/// `global_seed` and the full name so the seed is not incorporated twice.
///
/// Keys should be generated via each key type's `random`/`generate` method
/// taking `&mut` this RNG (see [`Self::generate_private_key`]). Timestamps
/// start at [`TIMESTAMP_BASE`] and advance by [`TIMESTAMP_INCREMENT`].
#[derive(Debug)]
pub struct DeterministicRng {
    rng: ChaCha20Rng,
    next_timestamp_index: u32,
}

impl DeterministicRng {
    /// Derive a per-vector RNG from the global generator seed and vector name.
    ///
    /// The seed bytes are `BLAKE3(global_seed || vector_name)` (raw 32-byte digest).
    /// Pass `global_seed = ""` when `vector_name` already embeds the campaign seed
    /// (fuzz-lite), so the seed is not double-hashed.
    pub fn for_vector(global_seed: &str, vector_name: &str) -> Self {
        let seed_byte_v = Self::seed_bytes(global_seed, vector_name);
        Self {
            rng: ChaCha20Rng::from_seed(seed_byte_v),
            next_timestamp_index: 0,
        }
    }

    /// Compute the ChaCha20 seed bytes for a (global_seed, vector_name) pair.
    pub fn seed_bytes(global_seed: &str, vector_name: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(global_seed.as_bytes());
        hasher.update(vector_name.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Mutable access to the underlying ChaCha20 CSPRNG for key generation etc.
    pub fn rng_mut(&mut self) -> &mut ChaCha20Rng {
        &mut self.rng
    }

    /// Next deterministic timestamp for a DID document `validFrom` field.
    ///
    /// The first call returns [`TIMESTAMP_BASE`]; each subsequent call adds
    /// [`TIMESTAMP_INCREMENT`].
    pub fn next_timestamp(&mut self) -> OffsetDateTime {
        let offset = TIMESTAMP_INCREMENT * self.next_timestamp_index;
        self.next_timestamp_index = self.next_timestamp_index.saturating_add(1);
        TIMESTAMP_BASE + offset
    }

    /// Generate a private key of the given type from this RNG.
    ///
    /// Uses each key type's RNG-consuming constructor (`generate` / `random` /
    /// `generate_from_rng`) so keys are reproducible from the vector seed.
    pub fn generate_private_key(
        &mut self,
        key_type: KeyTypeChoice,
    ) -> Box<dyn signature_dyn::ExtractableSignerT + Send + Sync> {
        match key_type {
            KeyTypeChoice::Ed25519 => Box::new(ed25519_dalek::SigningKey::generate(&mut self.rng)),
            KeyTypeChoice::Ed448 => {
                use ed448_goldilocks::elliptic_curve::Generate;
                Box::new(ed448_goldilocks::SigningKey::generate_from_rng(
                    &mut self.rng,
                ))
            }
            KeyTypeChoice::P256 => {
                use p256::elliptic_curve::Generate;
                Box::new(p256::ecdsa::SigningKey::generate_from_rng(&mut self.rng))
            }
            KeyTypeChoice::P384 => {
                use p384::elliptic_curve::Generate;
                Box::new(p384::ecdsa::SigningKey::generate_from_rng(&mut self.rng))
            }
            KeyTypeChoice::P521 => {
                use p521::elliptic_curve::Generate;
                Box::new(p521::ecdsa::SigningKey::generate_from_rng(&mut self.rng))
            }
            KeyTypeChoice::Secp256k1 => {
                use k256::elliptic_curve::Generate;
                Box::new(k256::ecdsa::SigningKey::generate_from_rng(&mut self.rng))
            }
        }
    }
}
