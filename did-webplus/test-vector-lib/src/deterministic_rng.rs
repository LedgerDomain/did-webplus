use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use time::{Duration, OffsetDateTime};

use crate::KeyTypeChoice;

/// Fixed base instant for deterministic `validFrom` timestamps.
///
/// All timestamps produced by [`DeterministicRng::next_timestamp`] are this
/// instant plus a deterministic increment per call (and, when fractional
/// timestamps are enabled, a deterministic millisecond offset).
pub const TIMESTAMP_BASE: OffsetDateTime = time::macros::datetime!(2025-01-01 00:00:00 UTC);

/// Whole-seconds increment applied between successive
/// [`DeterministicRng::next_timestamp`] calls.
///
/// The floor-to-seconds value of each successive `validFrom` advances by this
/// amount. When fractional milliseconds are enabled, the full timestamps remain
/// strictly increasing (DID rule) but may be less than one second apart when a
/// later millisecond component is smaller than the previous one.
pub const TIMESTAMP_INCREMENT: Duration = Duration::seconds(1);

/// Multiplicative hash constant (Knuth) used to spread timestamp-index values
/// across the millisecond range without consuming the key-generation RNG.
const FRACTIONAL_MS_GOLDEN: u32 = 2654435761;

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
/// start at [`TIMESTAMP_BASE`] and advance by [`TIMESTAMP_INCREMENT`]. When
/// [`Self::with_fractional_timestamps`] is enabled, each timestamp also gets a
/// deterministic millisecond component in `1..=999` derived from the timestamp
/// index (key RNG stream untouched), so DID document metadata can exercise the
/// floor-to-seconds truncation from `*Milliseconds` fields to their DID-spec
/// counterparts.
#[derive(Debug)]
pub struct DeterministicRng {
    rng: ChaCha20Rng,
    next_timestamp_index: u32,
    fractional_timestamps: bool,
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
            fractional_timestamps: false,
        }
    }

    /// Enable deterministic fractional-second `validFrom` timestamps.
    ///
    /// Each [`Self::next_timestamp`] call advances the whole-seconds floor by
    /// [`TIMESTAMP_INCREMENT`], then adds `1..=999` milliseconds derived from the
    /// timestamp index (independent of the key-generation RNG). Full timestamps
    /// remain strictly increasing; resolution-scenario microledgers use this so
    /// expected DID document metadata can assert that whole-seconds fields are
    /// the floor of their `*Milliseconds` counterparts.
    pub fn with_fractional_timestamps(mut self) -> Self {
        self.fractional_timestamps = true;
        self
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

    /// Millisecond offset (`1..=999`) for timestamp index `i` when fractional
    /// timestamps are enabled. Always non-zero so `*Milliseconds` metadata fields
    /// differ from their whole-seconds counterparts.
    pub fn fractional_millisecond_for_index(index: u32) -> u32 {
        // Map index -> 0..=998 via multiplicative hash, then shift to 1..=999.
        ((index.wrapping_mul(FRACTIONAL_MS_GOLDEN)) >> 22) % 999 + 1
    }

    /// Next deterministic timestamp for a DID document `validFrom` field.
    ///
    /// The first call returns [`TIMESTAMP_BASE`] (plus an optional millisecond
    /// component when fractional timestamps are enabled); each subsequent call
    /// adds [`TIMESTAMP_INCREMENT`].
    pub fn next_timestamp(&mut self) -> OffsetDateTime {
        let index = self.next_timestamp_index;
        let offset = TIMESTAMP_INCREMENT * index;
        self.next_timestamp_index = self.next_timestamp_index.saturating_add(1);
        let mut timestamp = TIMESTAMP_BASE + offset;
        if self.fractional_timestamps {
            timestamp += Duration::milliseconds(
                Self::fractional_millisecond_for_index(index) as i64,
            );
        }
        timestamp
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

#[cfg(test)]
mod tests {
    use super::*;
    use did_webplus_core::truncated_to_seconds;
    use std::collections::BTreeSet;

    #[test]
    fn default_timestamps_are_whole_seconds() {
        let mut rng = DeterministicRng::for_vector("seed", "whole");
        let t0 = rng.next_timestamp();
        let t1 = rng.next_timestamp();
        assert_eq!(t0, TIMESTAMP_BASE);
        assert_eq!(t1, TIMESTAMP_BASE + TIMESTAMP_INCREMENT);
        assert_eq!(t0.nanosecond(), 0);
        assert_eq!(t1.nanosecond(), 0);
    }

    #[test]
    fn fractional_timestamps_vary_and_strictly_increase() {
        let mut rng = DeterministicRng::for_vector("seed", "frac").with_fractional_timestamps();
        let mut prev_o = None;
        let mut millisecond_s = BTreeSet::new();
        for index in 0u32..16 {
            let timestamp = rng.next_timestamp();
            let millisecond = timestamp.millisecond() as u32;
            assert_eq!(
                millisecond,
                DeterministicRng::fractional_millisecond_for_index(index)
            );
            assert!((1..=999).contains(&millisecond));
            millisecond_s.insert(millisecond);
            assert_eq!(
                truncated_to_seconds(timestamp),
                TIMESTAMP_BASE + TIMESTAMP_INCREMENT * index
            );
            if let Some(prev) = prev_o {
                // DID rule: strictly increasing. Whole-second floors advance by
                // TIMESTAMP_INCREMENT; full values may be <1s apart when ms dips.
                assert!(timestamp > prev);
                assert_eq!(
                    truncated_to_seconds(timestamp) - truncated_to_seconds(prev),
                    TIMESTAMP_INCREMENT
                );
            }
            prev_o = Some(timestamp);
        }
        assert!(
            millisecond_s.len() >= 8,
            "expected variety of fractional milliseconds, got {millisecond_s:?}"
        );
    }

    #[test]
    fn fractional_millisecond_for_index_is_stable() {
        assert_eq!(DeterministicRng::fractional_millisecond_for_index(0), 1);
        assert_eq!(DeterministicRng::fractional_millisecond_for_index(1), 633);
        assert_eq!(
            DeterministicRng::fractional_millisecond_for_index(0),
            DeterministicRng::fractional_millisecond_for_index(0)
        );
    }
}
