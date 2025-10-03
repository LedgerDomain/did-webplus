use crate::Resolver;
use did_webplus_core::{
    now_utc_milliseconds, DIDDocument, DIDDocumentMetadata, DIDStr, Error,
    RequestedDIDDocumentMetadata, DID,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

/// Semantic subtype denoting that a u32 is the primary key for the DID table.
#[derive(
    Clone,
    Copy,
    Debug,
    derive_more::Deref,
    derive_more::Display,
    Eq,
    derive_more::From,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
)]
struct DIDPrimaryKey(u32);

/// Semantic subtype denoting that a u32 is the primary key for the DID document table.
#[derive(
    Clone,
    Copy,
    Debug,
    derive_more::Deref,
    derive_more::Display,
    Eq,
    derive_more::From,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
)]
struct DIDDocumentPrimaryKey(u32);

/// Semantic subtype denoting that a u32 is the primary key for the self-hash table.
#[derive(
    Clone,
    Copy,
    Debug,
    derive_more::Deref,
    derive_more::Display,
    Eq,
    derive_more::From,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
)]
struct SelfHashPrimaryKey(u32);

struct MockVerifiedCacheMicroledgerView<'a> {
    mock_verified_cache: &'a MockVerifiedCache,
    /// Cached DID primary key, since it's used in basically every method.
    did_primary_key: DIDPrimaryKey,
}

impl<'v> MockVerifiedCacheMicroledgerView<'v> {
    fn new_with_did_primary_key(
        mock_verified_cache: &'v MockVerifiedCache,
        did_primary_key: DIDPrimaryKey,
    ) -> Self {
        if mock_verified_cache.did_v.len() <= *did_primary_key as usize {
            panic!("programmer error: DID primary key should be valid");
        }
        Self {
            mock_verified_cache,
            did_primary_key,
        }
    }
}

impl<'v> did_webplus_core::MicroledgerView<'v> for MockVerifiedCacheMicroledgerView<'v> {
    fn did(&self) -> &'v DID {
        self.mock_verified_cache.did(self.did_primary_key)
    }
    fn root_did_document(&self) -> &'v DIDDocument {
        let root_did_document_primary_key = *self
            .mock_verified_cache
            .did_version_id_m
            .get(&(self.did_primary_key, 0))
            .expect("programmer error: root DID document for DID should exist");
        self.mock_verified_cache
            .did_document(root_did_document_primary_key)
    }
    fn latest_did_document(&self) -> &'v DIDDocument {
        let latest_did_document_primary_key = *self
            .mock_verified_cache
            .did_version_id_m
            .range((self.did_primary_key, 0)..=(self.did_primary_key, u32::MAX))
            .nth_back(0)
            .expect("programmer error: root DID document for DID should exist")
            .1;
        self.mock_verified_cache
            .did_document(latest_did_document_primary_key)
    }
    /// This is a pure select operation on the DID document data store, returning the number of selected
    /// DID documents and an iterator of those DID documents.  The range is inclusive on both
    /// ends.  If version_id_begin_o is None, then it is treated as 0.  If version_id_end_o is None,
    /// then it is treated as u32::MAX.
    fn select_did_documents<'s>(
        &'s self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> (
        u32,
        Box<dyn std::iter::Iterator<Item = &'v DIDDocument> + 'v>,
    ) {
        let version_id_begin = version_id_begin_o.unwrap_or(0);
        let version_id_end = version_id_end_o.unwrap_or(u32::MAX);
        let did_document_count = self
            .mock_verified_cache
            .did_version_id_m
            .range(
                (self.did_primary_key, version_id_begin)..=(self.did_primary_key, version_id_end),
            )
            .count() as u32;
        let did_document_ib = Box::new(
            self.mock_verified_cache
                .did_version_id_m
                .range(
                    (self.did_primary_key, version_id_begin)
                        ..=(self.did_primary_key, version_id_end),
                )
                .map(|(_, &did_document_primary_key)| {
                    self.mock_verified_cache
                        .did_document(did_document_primary_key)
                }),
        );
        (did_document_count, did_document_ib)
    }
    fn did_document_for_version_id(&self, version_id: u32) -> Result<&'v DIDDocument, Error> {
        let did_document_primary_key = *self
            .mock_verified_cache
            .did_version_id_m
            .get(&(self.did_primary_key, version_id))
            .ok_or(Error::NotFound(
                "DID document for version ID not found in cache",
            ))?;
        Ok(self
            .mock_verified_cache
            .did_document(did_document_primary_key))
    }
    fn did_document_for_self_hash(
        &self,
        self_hash: &mbx::MBHashStr,
    ) -> Result<&'v DIDDocument, Error> {
        let self_hash_primary_key = *self
            .mock_verified_cache
            .self_hash_primary_key_m
            .get(self_hash)
            .ok_or(Error::NotFound("Self-hash not found in cache"))?;
        let did_document_primary_key = *self
            .mock_verified_cache
            .self_hash_did_document_m
            .get(&self_hash_primary_key)
            .ok_or(Error::NotFound("DID document not found in cache"))?;
        let did_document = self
            .mock_verified_cache
            .did_document(did_document_primary_key);
        if did_document.did != *self.did() {
            return Err(Error::NotFound("DID document not found in cache"));
        }
        Ok(did_document)
    }
    fn did_document_valid_at_time(
        &self,
        time: time::OffsetDateTime,
    ) -> Result<&'v DIDDocument, Error> {
        let did_document_primary_key = *self
            .mock_verified_cache
            .did_valid_from_m
            .range((
                std::ops::Bound::Included((self.did_primary_key, time::OffsetDateTime::UNIX_EPOCH)),
                std::ops::Bound::Included((self.did_primary_key, time)),
            ))
            .nth_back(0)
            .ok_or(Error::NotFound(
                "DID document valid at time not found in cache",
            ))?
            .1;
        Ok(self
            .mock_verified_cache
            .did_document(did_document_primary_key))
    }
}

/// This is a mutable view object for a particular DID's Microledger within a MockVerifiedCache.
struct MockVerifiedCacheMicroledgerMutView<'v> {
    mock_verified_cache: &'v mut MockVerifiedCache,
    /// Cached DID primary key, since it's used in basically every method.
    did_primary_key: DIDPrimaryKey,
}

impl<'v> MockVerifiedCacheMicroledgerMutView<'v> {
    fn new_with_did_primary_key(
        mock_verified_cache: &'v mut MockVerifiedCache,
        did_primary_key: DIDPrimaryKey,
    ) -> Self {
        if mock_verified_cache.did_v.len() <= *did_primary_key as usize {
            panic!("programmer error: DID primary key should be valid");
        }
        Self {
            mock_verified_cache,
            did_primary_key,
        }
    }
    #[allow(dead_code)]
    pub fn did(&self) -> &DID {
        &self.mock_verified_cache.did_v[*self.did_primary_key as usize]
    }
    // The 'v lifetime on self is probably not going to work.
    pub fn latest_did_document(&'v self) -> &'v DIDDocument {
        let latest_did_document_primary_key = *self
            .mock_verified_cache
            .did_version_id_m
            .range((self.did_primary_key, 0)..=(self.did_primary_key, u32::MAX))
            .nth_back(0)
            .expect("programmer error: root DID document for DID should exist")
            .1;
        self.mock_verified_cache
            .did_document(latest_did_document_primary_key)
    }
    #[allow(dead_code)]
    pub fn microledger_current_as_of(&self) -> time::OffsetDateTime {
        *self
            .mock_verified_cache
            .did_microledger_current_as_of_m
            .get(&self.did_primary_key)
            .expect("programmer error")
    }
    pub fn set_microledger_current_as_of(&mut self, time: time::OffsetDateTime) {
        let microledger_current_as_of = self
            .mock_verified_cache
            .did_microledger_current_as_of_m
            .get_mut(&self.did_primary_key)
            .expect("programmer error");
        assert!(
            *microledger_current_as_of <= time,
            "programmer error: microledger_current_as_of should never decrease"
        );
        *microledger_current_as_of = time;
    }
}

impl<'v> did_webplus_core::MicroledgerMutView<'v> for MockVerifiedCacheMicroledgerMutView<'v> {
    fn update(&mut self, new_did_document: DIDDocument) -> Result<(), Error> {
        // Verify that it is a valid update first.
        new_did_document.verify_non_root_nonrecursive(self.latest_did_document())?;
        assert!(!self.mock_verified_cache.self_hash_primary_key_m.contains_key(
            &new_did_document.self_hash
        ), "programmer error: it should not be practically possible (i.e. it should not be computationally feasible) for a valid update to have the same self-hash as an existing DID document -- this almost certainly means there's a bug somewhere.");

        // Now append it and update all relevant indexes.

        // Insert into DID document table.
        let did_document_primary_key =
            DIDDocumentPrimaryKey::from(self.mock_verified_cache.did_document_v.len() as u32);
        self.mock_verified_cache
            .did_document_v
            .push(new_did_document);
        let did_document = self
            .mock_verified_cache
            .did_document(did_document_primary_key);
        let did_document_self_hash = did_document.self_hash.clone();
        let did_document_version_id = did_document.version_id;
        let did_document_valid_from = did_document.valid_from;
        // Insert into self-hash table.
        let self_hash_primary_key =
            SelfHashPrimaryKey::from(self.mock_verified_cache.self_hash_v.len() as u32);
        self.mock_verified_cache
            .self_hash_v
            .push(did_document_self_hash.clone());
        // Update self-hash -> self-hash primary key index
        self.mock_verified_cache
            .self_hash_primary_key_m
            .insert(did_document_self_hash, self_hash_primary_key);
        // Update self-hash -> DID document index.
        self.mock_verified_cache
            .self_hash_did_document_m
            .insert(self_hash_primary_key, did_document_primary_key);
        // Update (DID, version_id) -> DID document index.
        self.mock_verified_cache.did_version_id_m.insert(
            (self.did_primary_key, did_document_version_id),
            did_document_primary_key,
        );
        // Update (DID, valid_from) -> DID document index.
        self.mock_verified_cache.did_valid_from_m.insert(
            (self.did_primary_key, did_document_valid_from),
            did_document_primary_key,
        );
        Ok(())
    }
}

/// This is the data model for a local, verified cache.  It verifies and stores DID microledgers for
/// multiple DIDs locally.  It is intended to be used by a DID resolver or a VDG.
///
/// This mock implementation uses a hand-coded relational database model in order to demonstrate and
/// simulate the exact data access patterns that would be used in a relational-database-backed
/// implementation.
// TODO: Maybe make a trait for this, so that it can be implemented for a real database-backed
// implementation in addition to this mock.
#[derive(Default)]
pub struct MockVerifiedCache {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    pub user_agent: String,

    // Tables -- hand-rolled "database" tables.
    /// Table of DIDs.  The indexes of these elements define the primary key for this table.
    did_v: Vec<DID>,
    /// Table of DID documents.  The indexes of these elements define the primary key for this table.
    did_document_v: Vec<DIDDocument>,
    /// Table of self-hash values of DID documents.  The indexes of these elements define the primary
    /// key for this table.
    self_hash_v: Vec<mbx::MBHash>,

    // Indexes -- hand-rolled "database" indexes.
    /// This is the index mapping DID to DID primary key.
    did_primary_key_m: HashMap<DID, DIDPrimaryKey>,
    /// This is the index mapping self-hash to self-hash primary key.
    self_hash_primary_key_m: HashMap<mbx::MBHash, SelfHashPrimaryKey>,
    /// This is the index mapping self-hash primary key to DID document primary key.
    self_hash_did_document_m: HashMap<SelfHashPrimaryKey, DIDDocumentPrimaryKey>,
    /// This is the index mapping (DID primary key, version_id) to the DID document primary key.
    did_version_id_m: BTreeMap<(DIDPrimaryKey, u32), DIDDocumentPrimaryKey>,
    /// This is the index mapping (DID primary key, valid_from) to the DID document primary key.
    did_valid_from_m: BTreeMap<(DIDPrimaryKey, time::OffsetDateTime), DIDDocumentPrimaryKey>,
    /// This is the index mapping DID primary key to the current_as_of timestamp, i.e. the timestamp
    /// at which this updates for this DID were last pulled from its VDR.
    did_microledger_current_as_of_m: HashMap<DIDPrimaryKey, time::OffsetDateTime>,
}

impl MockVerifiedCache {
    pub fn empty(user_agent: String) -> Self {
        Self {
            user_agent: user_agent,
            ..Default::default()
        }
    }
    /// Get the DID indexed by the given primary key.
    // TODO: Shouldn't need explicit lifetimes.
    fn did<'s>(&'s self, did_primary_key: DIDPrimaryKey) -> &'s DID {
        &self.did_v[*did_primary_key as usize]
    }
    /// Get the DID document indexed by the given primary key.
    fn did_document<'s>(
        &'s self,
        did_document_primary_key: DIDDocumentPrimaryKey,
    ) -> &'s DIDDocument {
        &self.did_document_v[*did_document_primary_key as usize]
    }
    /// Get a view of the Microledger for the given DID.
    pub fn microledger_view<'s>(
        &'s self,
        did: &DIDStr,
    ) -> Option<impl did_webplus_core::MicroledgerView<'s>> {
        if let Some(&did_primary_key) = self.did_primary_key_m.get(did) {
            Some(MockVerifiedCacheMicroledgerView::new_with_did_primary_key(
                self,
                did_primary_key,
            ))
        } else {
            None
        }
    }
    /// Get a mutable view of the Microledger for the given DID.
    // #[allow(dead_code)]
    pub fn microledger_mut_view<'s>(
        &'s mut self,
        did: &DIDStr,
    ) -> Option<impl did_webplus_core::MicroledgerMutView<'s>> {
        if let Some(&did_primary_key) = self.did_primary_key_m.get(did) {
            Some(
                MockVerifiedCacheMicroledgerMutView::new_with_did_primary_key(
                    self,
                    did_primary_key,
                ),
            )
        } else {
            None
        }
    }
    /// Create a new Microledger for the given DID and initialize it with the given root DID document.
    /// This will fail if the DID already exists in the cache.
    fn initialize_microledger(
        &mut self,
        root_did_document: DIDDocument,
        microledger_current_as_of: time::OffsetDateTime,
    ) -> Result<MockVerifiedCacheMicroledgerMutView, Error> {
        if self.did_primary_key_m.contains_key(&root_did_document.did) {
            return Err(Error::AlreadyExists("DID already exists in cache"));
        }
        // Verify the DID document.
        root_did_document.verify_root_nonrecursive()?;
        // Insert into DID table.
        let did_primary_key = DIDPrimaryKey::from(self.did_v.len() as u32);
        self.did_v.push(root_did_document.did.clone());
        // TODO: Factor this out into an "insert_did_document" method.
        // Insert into DID document table.
        let did_document_primary_key =
            DIDDocumentPrimaryKey::from(self.did_document_v.len() as u32);
        self.did_document_v.push(root_did_document);
        let (did, self_hash, version_id, valid_from) = {
            let did_document = self.did_document(did_document_primary_key);
            (
                did_document.did.clone(),
                did_document.self_hash.clone(),
                did_document.version_id,
                did_document.valid_from,
            )
        };

        // Insert its self-hash into the self-hash table.
        let self_hash_primary_key = SelfHashPrimaryKey::from(self.self_hash_v.len() as u32);
        self.self_hash_v.push(self_hash.clone());
        // Update DID -> DID primary key index.
        self.did_primary_key_m.insert(did, did_primary_key);
        // Update self-hash -> self-hash primary key index
        self.self_hash_primary_key_m
            .insert(self_hash, self_hash_primary_key);
        // Update self-hash -> DID document index.
        self.self_hash_did_document_m
            .insert(self_hash_primary_key, did_document_primary_key);
        // Update (DID, version_id) -> DID document index.
        self.did_version_id_m
            .insert((did_primary_key, version_id), did_document_primary_key);
        // Update (DID, valid_from) -> DID document index.
        self.did_valid_from_m
            .insert((did_primary_key, valid_from), did_document_primary_key);
        // Update DID -> current_as_of timestamp.
        self.did_microledger_current_as_of_m
            .insert(did_primary_key, microledger_current_as_of);

        Ok(MockVerifiedCacheMicroledgerMutView::new_with_did_primary_key(self, did_primary_key))
    }
    /// Ensures the DID documents having version_id less than or equal to the specified version
    /// are present in the cache, fetching any missing DID documents via the resolver.  If
    /// through_version_id_o is None, then it is treated as u32::MAX, and all DID documents up to the
    /// latest are fetched.  Returns the number of previously-uncached DID documents that were fetched
    /// in the operation.  In particular, if the returned value is 0, then the local cache was already
    /// up to date.
    pub fn ensure_cached_did_documents(
        &mut self,
        did: &DIDStr,
        through_version_id_o: Option<u32>,
        resolver: &mut dyn Resolver,
    ) -> Result<u32, Error> {
        println!(
            "MockVerifiedCache::ensure_cached_did_documents;\n    DID: {}",
            did
        );
        // Determine which version ID to start at.  If we have any DID documents for this DID, then
        // start at the next version ID after the latest.  Otherwise, start at 0 (root DID document).
        let (version_id_begin, did_primary_key_o) = if let Some(&did_primary_key) =
            self.did_primary_key_m.get(did)
        {
            let microledger_mut_view =
                MockVerifiedCacheMicroledgerMutView::new_with_did_primary_key(
                    self,
                    did_primary_key,
                );
            let version_id_begin = microledger_mut_view.latest_did_document().version_id.checked_add(1).expect("overflow in version_id -- this is so unlikely that it's probably a programmer error");
            (version_id_begin, Some(did_primary_key))
        } else {
            (0u32, None)
        };

        // Retrieve the next through through_version_id_o DID documents from the VDR.  Use a timestamp from
        // directly before the request to the VDR to define microledger_current_as_of.
        // TODO: This timestamp has to come from the VDR!
        let microledger_current_as_of = now_utc_milliseconds();
        let mut new_did_document_count = 0u32;
        let mut new_did_document_ib =
            resolver.get_did_documents(did, Some(version_id_begin), through_version_id_o)?;
        let mut microledger_mut_view = if version_id_begin == 0 {
            // If we didn't have this DID in the cache before, then we need to add it to the cache.
            new_did_document_count += 1;
            let root_did_document = new_did_document_ib
                .next()
                .expect(
                    "VDR should have returned error if there were no DID documents for this DID",
                )
                .clone();
            self.initialize_microledger(root_did_document.into_owned(), microledger_current_as_of)?
        } else {
            // If we have this DID in the cache, then return the MicroledgerMutView for it.
            let did_primary_key = did_primary_key_o.expect("programmer error");
            MockVerifiedCacheMicroledgerMutView::new_with_did_primary_key(self, did_primary_key)
        };
        // Add the rest of the DID documents via update.
        for new_did_document in new_did_document_ib {
            // All further updates should be non-root DID documents.  This Microledger should already have a root.
            assert!(!new_did_document.is_root_did_document());
            use did_webplus_core::MicroledgerMutView;
            new_did_document_count += 1;
            microledger_mut_view.update(new_did_document.into_owned())?;
        }
        // Update the microledger_current_as_of timestamp.
        microledger_mut_view.set_microledger_current_as_of(microledger_current_as_of);

        Ok(new_did_document_count)
    }
    pub fn get_did_documents<'s>(
        &'s mut self,
        requester_user_agent: &str,
        did: &DIDStr,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
        resolver: &mut dyn Resolver,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Cow<'s, DIDDocument>> + 's>, Error> {
        println!("MockVerifiedCache({:?})::fetch_did_documents;\n    requester_user_agent: {}\n    DID: {}\n    version_id_begin_o: {:?}\n    version_id_end_o: {:?}", self.user_agent, requester_user_agent, did, version_id_begin_o, version_id_end_o);

        self.ensure_cached_did_documents(did, version_id_end_o, resolver)?;

        // Now we can simply return the requested DID documents from the cache.
        {
            use did_webplus_core::MicroledgerView;
            let (_, did_document_ib) = self
                .microledger_view(did)
                .expect("programmer error: if we got this far, the DID should be in the cache")
                .select_did_documents(version_id_begin_o, version_id_end_o);
            let did_document_ib =
                Box::new(did_document_ib.map(|did_document| Cow::Borrowed(did_document)));
            Ok(did_document_ib)
        }
    }
    // TODO: Make a resolve_without_metadata version of this that can operate local-only in more cases.
    // TODO: Actually make a struct representing a subset of the metadata, and have that be the return type.
    // In particular, it would only indicate next_version_id_o and next_update_o, because the current-ness
    // of the DID document is not being queried, and this limited metadata structure will not change in
    // further updates once the resolved DID doc is followed by at least one update.
    // TODO: This probably doesn't belong in MockVerifiedCache, but rather in a DID resolver.
    pub fn resolve_did_document<'s>(
        &'s mut self,
        did: &DIDStr,
        version_id_o: Option<u32>,
        self_hash_o: Option<&mbx::MBHashStr>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
        resolver: &mut dyn Resolver,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        println!("MockVerifiedCache::resolve;\n    DID: {}\n    version_id_o: {:?}\n    self_hash_o: {:?}", did, version_id_o, self_hash_o);

        {
            // Ensure that the appropriate DID documents are in the cache.
            let version_id_end_o = if let Some(version_id) = version_id_o {
                match requested_did_document_metadata {
                    // Only need the requested one.
                    RequestedDIDDocumentMetadata {
                        constant: _,
                        idempotent: false,
                        currency: false,
                    } => Some(version_id),
                    // Need the next one in order to determine the full validity duration for this one.
                    RequestedDIDDocumentMetadata {
                        constant: _,
                        idempotent: true,
                        currency: false,
                    } => Some(
                        version_id
                            .checked_add(1)
                            .expect("overflow in version_id -- this is so unlikely that it's probably a programmer error"),
                    ),
                    // Need to fetch all of them.
                    RequestedDIDDocumentMetadata {
                        constant: _,
                        idempotent: _,
                        currency: true,
                    } => None,
                }
            } else {
                // Need to fetch the latest.
                None
            };
            self.ensure_cached_did_documents(did, version_id_end_o, resolver)?;
        }
        // Resolve the DID document from the cache.
        use did_webplus_core::MicroledgerView;
        let (did_document, did_document_metadata) = self
            .microledger_view(did)
            .expect("programmer error")
            .resolve(version_id_o, self_hash_o, requested_did_document_metadata)?;
        Ok((Cow::Borrowed(did_document), did_document_metadata))
    }
}
