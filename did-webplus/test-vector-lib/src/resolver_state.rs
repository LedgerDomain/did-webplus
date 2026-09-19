/// Local knowledge of a full resolver for one DID: a contiguous microledger prefix.
///
/// Because updates are append-only and fetches are Range GETs from the known
/// octet offset, known documents are always versions `0..known_version_count`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolverState {
    /// Number of leading versions present in the local DID document store.
    pub known_version_count: u32,
}

impl ResolverState {
    /// Empty store (fresh resolver at the start of a scenario).
    pub fn empty() -> Self {
        Self {
            known_version_count: 0,
        }
    }
}
