use std::collections::{BTreeMap, HashMap};

use did_webplus::{DIDDocument, Error, MicroledgerMutView, MicroledgerView};

/// Purely in-memory data model of a single DID's microledger of DID documents.  Has indexes for
/// the self-hash and valid_from fields of each DID document, which are used in the query
/// params of the DID URI.  In a production system, this would be backed by a database (e.g.
/// postgres for a server, or sqlite for an edge device).
#[derive(Clone, Debug)]
pub struct Microledger {
    // TODO: Combine these
    /// The root (first) DID document for this DID, forming the first node in the Microledger.
    root_did_document: DIDDocument,
    /// The sequence of non-root DID documents.  The version_id field in each non-root DID document
    /// must be equal to 1 + its index in this vector.
    non_root_did_document_v: Vec<DIDDocument>,

    /// A map from the DID document's self-hash to its version_id field value.
    self_hash_version_id_m: HashMap<selfhash::KERIHash<'static>, u32>,
    /// An ordered map from the DID document's valid_from field value to its version_id field value.
    valid_from_version_id_m: BTreeMap<time::OffsetDateTime, u32>,
}

impl Microledger {
    /// Creates a new Microledger from the given root DID document.  This function will verify the
    /// root DID document.
    pub fn create(root_did_document: DIDDocument) -> Result<Self, Error> {
        root_did_document.verify_root_nonrecursive()?;
        assert!(root_did_document.self_hash_o.is_some());
        assert!(root_did_document.self_signature_o.is_some());
        assert!(root_did_document.self_signature_verifier_o.is_some());
        let self_hash = root_did_document.self_hash_o.as_ref().unwrap();
        let version_id = root_did_document.version_id;
        let valid_from = root_did_document.valid_from;

        let mut self_hash_version_id_m = HashMap::new();
        self_hash_version_id_m.insert(self_hash.clone(), version_id);

        let mut valid_from_version_id_m = BTreeMap::new();
        valid_from_version_id_m.insert(valid_from, version_id);

        let retval = Self {
            root_did_document,
            non_root_did_document_v: Vec::new(),
            self_hash_version_id_m,
            valid_from_version_id_m,
        };
        // // Pedantic temporary check.
        // retval
        //     .verify_full()
        //     .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }
    /// Creates a Microledger from a given root DIDDocument and a (possibly empty) sequence of non-root
    /// DIDDocuments, verifying each DID document in the overall sequence.
    pub fn new(
        root_did_document: DIDDocument,
        non_root_did_document_v: Vec<DIDDocument>,
    ) -> Result<Self, Error> {
        let mut self_hash_version_id_m = HashMap::with_capacity(1 + non_root_did_document_v.len());
        let mut valid_from_version_id_m = BTreeMap::new();

        {
            root_did_document.verify_root_nonrecursive()?;
            assert!(root_did_document.self_hash_o.is_some());
            let self_hash = root_did_document.self_hash_o.as_ref().unwrap();
            let version_id = root_did_document.version_id;
            let valid_from = root_did_document.valid_from;

            self_hash_version_id_m.insert(self_hash.clone(), version_id);
            valid_from_version_id_m.insert(valid_from, version_id);
        }

        let mut prev_did_document = &root_did_document;
        for non_root_did_document in non_root_did_document_v.iter() {
            non_root_did_document.verify_non_root_nonrecursive(prev_did_document)?;
            assert!(non_root_did_document.self_hash_o.is_some());
            let self_hash = non_root_did_document.self_hash_o.as_ref().unwrap();
            let version_id = non_root_did_document.version_id;
            let valid_from = non_root_did_document.valid_from;

            self_hash_version_id_m.insert(self_hash.clone(), version_id);
            valid_from_version_id_m.insert(valid_from, version_id);

            prev_did_document = &non_root_did_document;
        }

        let retval = Self {
            root_did_document,
            non_root_did_document_v,
            self_hash_version_id_m,
            valid_from_version_id_m,
        };
        // // Sanity check -- should be valid by the checks above.  Eventually remove this check.
        // retval
        //     .verify_full()
        //     .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }
    // TODO: Maybe use an iterator for the argument.
    pub fn new_from_did_documents(did_document_v: Vec<DIDDocument>) -> Result<Self, Error> {
        if did_document_v.is_empty() {
            return Err(Error::Malformed("DID document list is empty"));
        }
        let mut did_document_i = did_document_v.into_iter();
        let root_did_document = did_document_i.next().unwrap();
        if !root_did_document.is_root_did_document() {
            return Err(Error::Malformed("expected root DID document as the first DID document, but got non-root DID document"));
        }
        let non_root_did_document_v = did_document_i.collect();
        // let did_document_count = did_document_v.len();
        // assert!(did_document_count > 0);
        // let mut did_document_i = did_document_v.into_iter();
        // let root_did_document = did_document_i
        //     .next()
        //     .unwrap()
        //     .into_root_did_document()
        //     .unwrap()
        //     .into_owned();
        // let mut non_root_did_document_v = Vec::with_capacity(did_document_count - 1);
        // for did_document in did_document_i {
        //     if !did_document.is_non_root_did_document() {
        //         return Err(Error::Malformed(
        //             "Expected non-root DID document as non-first DID document",
        //         ));
        //     }
        //     let non_root_did_document = did_document
        //         .into_non_root_did_document()
        //         .unwrap()
        //         .into_owned();
        //     non_root_did_document_v.push(non_root_did_document);
        // }
        Microledger::new(root_did_document, non_root_did_document_v)
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
    fn did(&self) -> &'m did_webplus::DID {
        &self.root_did_document.did
    }
    fn root_did_document(&self) -> &'m did_webplus::DIDDocument {
        (&self.root_did_document).into()
    }
    fn latest_did_document(&self) -> &'m did_webplus::DIDDocument {
        if self.non_root_did_document_v.is_empty() {
            &self.root_did_document
        } else {
            self.non_root_did_document_v.last().unwrap()
        }
    }
    fn select_did_documents<'s>(
        &'s self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> (
        u32,
        Box<dyn std::iter::Iterator<Item = &'m did_webplus::DIDDocument> + 'm>,
    ) {
        let version_id_begin = version_id_begin_o.unwrap_or(0) as usize;
        let version_id_end = version_id_end_o
            .map(|version_id_end| version_id_end as usize)
            .unwrap_or(self.latest_did_document().version_id() as usize);
        if version_id_begin > version_id_end {
            // No DID documents requested.
            return (0, Box::new(std::iter::empty()));
        }
        let mut did_document_count = (version_id_end as u32) - (version_id_begin as u32) + 1;
        let mut did_document_v = Vec::with_capacity(version_id_end - version_id_begin + 1);
        if version_id_begin == 0 {
            did_document_count += 1;
            did_document_v.push(&self.root_did_document);
        }
        let non_root_did_document_index_begin = version_id_begin.saturating_sub(1);
        let non_root_did_document_index_end = version_id_end.saturating_sub(1);
        did_document_v.extend(
            self.non_root_did_document_v
                .iter()
                .skip(non_root_did_document_index_begin)
                .take(non_root_did_document_index_end - non_root_did_document_index_begin + 1),
        );
        let did_document_ib = Box::new(did_document_v.into_iter());
        (did_document_count, did_document_ib)
    }
    fn did_document_for_version_id(
        &self,
        version_id: u32,
    ) -> Result<&'m DIDDocument, did_webplus::Error> {
        if version_id == 0 {
            Ok((&self.root_did_document).into())
        } else {
            let index = (version_id - 1) as usize;
            let non_root_did_document =
                self.non_root_did_document_v.get(index).ok_or_else(|| {
                    did_webplus::Error::NotFound(
                        "version_id does not match any existing DID document",
                    )
                })?;
            Ok(non_root_did_document.into())
        }
    }
    fn did_document_for_self_hash(
        &self,
        self_hash: &selfhash::KERIHash,
    ) -> Result<&'m DIDDocument, Error> {
        let version_id = self.self_hash_version_id_m.get(self_hash).ok_or_else(|| {
            did_webplus::Error::NotFound("self-hash does not match any existing DID document")
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
                did_webplus::Error::NotFound("time does not match any existing DID document")
            })?
            .1;
        self.did_document_for_version_id(*version_id)
    }
}

impl<'m> MicroledgerMutView<'m> for &'m mut Microledger {
    fn update(
        &mut self,
        non_root_did_document: did_webplus::DIDDocument,
    ) -> Result<(), did_webplus::Error> {
        non_root_did_document.verify_non_root_nonrecursive(self.view().latest_did_document())?;
        let self_hash = non_root_did_document
            .self_hash_o
            .as_ref()
            .expect("programmer error");
        let version_id = non_root_did_document.version_id;
        let valid_from = non_root_did_document.valid_from;

        self.self_hash_version_id_m
            .insert(self_hash.clone(), version_id);
        self.valid_from_version_id_m.insert(valid_from, version_id);
        self.non_root_did_document_v.push(non_root_did_document);

        // // TEMP HACK: Sanity check.
        // self.verify_full()
        //     .expect("programmer error: this should have been guaranteed by Microledger::create");

        Ok(())
    }
}
