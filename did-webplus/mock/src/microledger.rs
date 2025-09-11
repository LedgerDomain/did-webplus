use std::collections::{BTreeMap, HashMap};

use did_webplus_core::{DIDDocument, Error, MicroledgerMutView, MicroledgerView};

/// Purely in-memory data model of a single DID's microledger of DID documents.  Has indexes for
/// the self-hash and valid_from fields of each DID document, which are used in the query
/// params of the DID URI.  In a production system, this would be backed by a database (e.g.
/// postgres for a server, or sqlite for an edge device).
#[derive(Clone, Debug)]
pub struct Microledger {
    /// The DID documents in the microledger, in order from oldest to newest.  The first DID document
    /// is the root DID document.  Each successive DID document is a non-root DID document that
    /// updates the previous DID document.
    did_document_v: Vec<DIDDocument>,
    /// A map from the DID document's self-hash to its version_id field value.
    self_hash_version_id_m: HashMap<selfhash::KERIHash, u32>,
    /// An ordered map from the DID document's valid_from field value to its version_id field value.
    valid_from_version_id_m: BTreeMap<time::OffsetDateTime, u32>,
}

impl Microledger {
    /// Creates a new Microledger from the given root DID document.  This function will verify the
    /// root DID document.
    pub fn create(root_did_document: DIDDocument) -> Result<Self, Error> {
        root_did_document.verify_root_nonrecursive()?;
        assert!(root_did_document.self_hash_o().is_some());
        let self_hash = root_did_document.self_hash_o().unwrap();
        let version_id = root_did_document.version_id;
        let valid_from = root_did_document.valid_from;

        let mut self_hash_version_id_m = HashMap::new();
        self_hash_version_id_m.insert(self_hash.clone(), version_id);

        let mut valid_from_version_id_m = BTreeMap::new();
        valid_from_version_id_m.insert(valid_from, version_id);

        let retval = Self {
            did_document_v: vec![root_did_document],
            self_hash_version_id_m,
            valid_from_version_id_m,
        };
        Ok(retval)
    }
    /// Creates a Microledger from a given root DIDDocument and a (possibly empty) sequence of non-root
    /// DIDDocuments, verifying each DID document in the overall sequence.
    pub fn new_from_did_documents(did_document_v: Vec<DIDDocument>) -> Result<Self, Error> {
        if did_document_v.is_empty() {
            return Err(Error::Malformed("DID document list is empty"));
        }

        let mut self_hash_version_id_m = HashMap::with_capacity(did_document_v.len());
        let mut valid_from_version_id_m = BTreeMap::new();

        {
            let root_did_document = did_document_v.first().unwrap();
            {
                root_did_document.verify_root_nonrecursive()?;
                assert!(root_did_document.self_hash_o().is_some());
                let self_hash = root_did_document.self_hash_o().unwrap();
                let version_id = root_did_document.version_id;
                let valid_from = root_did_document.valid_from;

                self_hash_version_id_m.insert(self_hash.clone(), version_id);
                valid_from_version_id_m.insert(valid_from, version_id);
            }

            let mut prev_did_document = root_did_document;
            for non_root_did_document in did_document_v.iter().skip(1) {
                non_root_did_document.verify_non_root_nonrecursive(prev_did_document)?;
                assert!(non_root_did_document.self_hash_o().is_some());
                let self_hash = non_root_did_document.self_hash_o().unwrap();
                let version_id = non_root_did_document.version_id;
                let valid_from = non_root_did_document.valid_from;

                self_hash_version_id_m.insert(self_hash.clone(), version_id);
                valid_from_version_id_m.insert(valid_from, version_id);

                prev_did_document = non_root_did_document;
            }
        }
        let retval = Self {
            did_document_v,
            self_hash_version_id_m,
            valid_from_version_id_m,
        };
        Ok(retval)
    }
    /// Return an immutable view into the Microledger.
    pub fn view(&self) -> impl MicroledgerView<'_> {
        self
    }
    /// Return a mutable view into the Microledger.
    pub fn mut_view(&mut self) -> impl MicroledgerMutView<'_> {
        self
    }
}

impl<'m> MicroledgerView<'m> for &'m Microledger {
    fn did(&self) -> &'m did_webplus_core::DID {
        &self.root_did_document().did
    }
    fn root_did_document(&self) -> &'m did_webplus_core::DIDDocument {
        self.did_document_v
            .first()
            .expect("programmer error: DID document list should be nonempty by construction")
    }
    fn latest_did_document(&self) -> &'m did_webplus_core::DIDDocument {
        self.did_document_v
            .last()
            .expect("programmer error: DID document list should be nonempty by construction")
    }
    fn select_did_documents<'s>(
        &'s self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> (
        u32,
        Box<dyn std::iter::Iterator<Item = &'m did_webplus_core::DIDDocument> + 'm>,
    ) {
        let version_id_begin = version_id_begin_o.unwrap_or(0) as usize;
        let version_id_end = version_id_end_o
            .map(|version_id_end| version_id_end as usize)
            .unwrap_or(self.latest_did_document().version_id() as usize);
        if version_id_begin > version_id_end {
            // No DID documents requested.
            return (0, Box::new(std::iter::empty()));
        }
        let selected_did_document_count = version_id_end - version_id_begin + 1;
        let selected_did_document_ib = Box::new(
            self.did_document_v
                .iter()
                .skip(version_id_begin)
                .take(selected_did_document_count),
        );
        (selected_did_document_count as u32, selected_did_document_ib)
    }
    fn did_document_for_version_id(
        &self,
        version_id: u32,
    ) -> Result<&'m DIDDocument, did_webplus_core::Error> {
        self.did_document_v.get(version_id as usize).ok_or_else(|| {
            did_webplus_core::Error::NotFound("version_id does not match any existing DID document")
        })
    }
    fn did_document_for_self_hash(
        &self,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<&'m DIDDocument, Error> {
        let version_id = self.self_hash_version_id_m.get(self_hash).ok_or_else(|| {
            did_webplus_core::Error::NotFound("self-hash does not match any existing DID document")
        })?;
        self.did_document_for_version_id(*version_id)
    }
    fn did_document_valid_at_time(
        &self,
        time: time::OffsetDateTime,
    ) -> Result<&'m DIDDocument, Error> {
        let version_id = self
            .valid_from_version_id_m
            .range(..=time)
            .last()
            .ok_or_else(|| {
                did_webplus_core::Error::NotFound("time does not match any existing DID document")
            })?
            .1;
        self.did_document_for_version_id(*version_id)
    }
}

impl<'m> MicroledgerMutView<'m> for &'m mut Microledger {
    fn update(
        &mut self,
        new_did_document: did_webplus_core::DIDDocument,
    ) -> Result<(), did_webplus_core::Error> {
        new_did_document.verify_non_root_nonrecursive(self.view().latest_did_document())?;
        let self_hash = new_did_document.self_hash_o().unwrap();
        let version_id = new_did_document.version_id;
        let valid_from = new_did_document.valid_from;

        self.self_hash_version_id_m
            .insert(self_hash.clone(), version_id);
        self.valid_from_version_id_m.insert(valid_from, version_id);
        self.did_document_v.push(new_did_document);

        Ok(())
    }
}
