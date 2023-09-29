use std::collections::{BTreeMap, HashMap};

use crate::{
    DIDDocument, DIDDocumentMetadata, DIDDocumentUpdateParams, DIDWebplus, Error,
    NonRootDIDDocument, RootDIDDocument,
};

/// Purely in-memory data model of a single DID's microledger of DID documents.  Has indexes for
/// the self-signature and valid_from fields of each DID document, which are used in the query
/// params of the DID URI.  In a production system, this would be backed by a database (e.g.
/// postgres for a server, or sqlite for an edge device).
#[derive(Clone, Debug)]
pub struct Microledger {
    /// The root (first) DID document for this DID, forming the first node in the Microledger.
    root_did_document: RootDIDDocument,
    /// The sequence of non-root DID documents.  The version_id field in each non-root DID document
    /// must be equal to 1 + its index in this vector.
    non_root_did_document_v: Vec<NonRootDIDDocument>,

    /// A map from the DID document's self-signature to its version_id field value.
    self_signature_version_id_m: HashMap<selfsign::KERISignature<'static>, u32>,
    /// An ordered map from the DID document's valid_from field value to its version_id field value.
    valid_from_version_id_m: BTreeMap<time::OffsetDateTime, u32>,
}

impl Microledger {
    /// Creates a new Microledger from the given root DID document.  This function will verify the
    /// root DID document.
    pub fn create(root_did_document: RootDIDDocument) -> Result<Self, Error> {
        root_did_document.verify_nonrecursive()?;
        assert!(root_did_document.self_signature_o.is_some());
        assert!(root_did_document.self_signature_verifier_o.is_some());
        let self_signature = root_did_document.self_signature_o.as_ref().unwrap();
        let version_id = root_did_document.version_id;
        let valid_from = root_did_document.valid_from;

        let mut self_signature_version_id_m = HashMap::new();
        self_signature_version_id_m.insert(self_signature.clone(), version_id);

        let mut valid_from_version_id_m = BTreeMap::new();
        valid_from_version_id_m.insert(valid_from, version_id);

        let retval = Self {
            root_did_document,
            non_root_did_document_v: Vec::new(),
            self_signature_version_id_m,
            valid_from_version_id_m,
        };
        // Pedantic temporary check.
        retval
            .verify_full()
            .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }
    /// Creates a Microledger from a given RootDIDDocument and a (possibly empty) sequence of NonRootDIDDocuments,
    /// verifying each DID document in the overall sequence.
    pub fn new(
        root_did_document: RootDIDDocument,
        non_root_did_document_v: Vec<NonRootDIDDocument>,
    ) -> Result<Self, Error> {
        let mut self_signature_version_id_m =
            HashMap::with_capacity(1 + non_root_did_document_v.len());
        let mut valid_from_version_id_m = BTreeMap::new();

        {
            root_did_document.verify_nonrecursive()?;
            assert!(root_did_document.self_signature_o.is_some());
            let self_signature = root_did_document.self_signature_o.as_ref().unwrap();
            let version_id = root_did_document.version_id;
            let valid_from = root_did_document.valid_from;

            self_signature_version_id_m.insert(self_signature.clone(), version_id);
            valid_from_version_id_m.insert(valid_from, version_id);
        }

        let mut prev_did_document = DIDDocument::from(&root_did_document);
        for non_root_did_document in non_root_did_document_v.iter() {
            non_root_did_document.verify_nonrecursive(prev_did_document)?;
            assert!(non_root_did_document.self_signature_o.is_some());
            let self_signature = non_root_did_document.self_signature_o.as_ref().unwrap();
            let version_id = non_root_did_document.version_id;
            let valid_from = non_root_did_document.valid_from;

            self_signature_version_id_m.insert(self_signature.clone(), version_id);
            valid_from_version_id_m.insert(valid_from, version_id);

            prev_did_document = DIDDocument::from(non_root_did_document);
        }

        let retval = Self {
            root_did_document,
            non_root_did_document_v,
            self_signature_version_id_m,
            valid_from_version_id_m,
        };
        // Sanity check -- should be valid by the checks above.  Eventually remove this check.
        retval
            .verify_full()
            .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }
    // TODO: Maybe use an iterator for the argument.
    pub fn new_from_did_documents(did_document_v: Vec<DIDDocument>) -> Result<Self, Error> {
        if did_document_v.is_empty() {
            return Err(Error::Malformed("DID document list is empty"));
        }
        if !did_document_v.first().unwrap().is_root_did_document() {
            return Err(Error::Malformed("expected root DID document as the first DID document, but got non-root DID document"));
        }
        let did_document_count = did_document_v.len();
        assert!(did_document_count > 0);
        let mut did_document_i = did_document_v.into_iter();
        let root_did_document = did_document_i
            .next()
            .unwrap()
            .into_root_did_document()
            .unwrap()
            .into_owned();
        let mut non_root_did_document_v = Vec::with_capacity(did_document_count - 1);
        for did_document in did_document_i {
            if !did_document.is_non_root_did_document() {
                return Err(Error::Malformed(
                    "Expected non-root DID document as non-first DID document",
                ));
            }
            let non_root_did_document = did_document
                .into_non_root_did_document()
                .unwrap()
                .into_owned();
            non_root_did_document_v.push(non_root_did_document);
        }
        Microledger::new(root_did_document, non_root_did_document_v)
    }

    /// This is the DID that controls this microledger and that all DID documents in this microledger share.
    pub fn did(&self) -> &DIDWebplus {
        &self.root_did_document.id
    }
    /// The microledger height is the number of nodes in the microledger.
    pub fn microledger_height(&self) -> u32 {
        assert_eq!(
            1 + self.non_root_did_document_v.len(),
            self.self_signature_version_id_m.len()
        );
        assert_eq!(
            1 + self.non_root_did_document_v.len(),
            self.valid_from_version_id_m.len()
        );
        1 + self.non_root_did_document_v.len() as u32
    }
    /// Returns the root (first) node of the microledger.
    // TODO: Return did doc metadata
    pub fn root_did_document(&self) -> &RootDIDDocument {
        &self.root_did_document
    }
    /// Returns the sequence of non-root nodes of the microledger.
    // TODO: Return did doc metadata
    pub fn non_root_did_document_v(&self) -> &[NonRootDIDDocument] {
        self.non_root_did_document_v.as_slice()
    }
    /// Returns the latest DID document in the microledger.
    pub fn latest_did_document(&self) -> DIDDocument {
        if self.non_root_did_document_v.is_empty() {
            DIDDocument::from(&self.root_did_document)
        } else {
            DIDDocument::from(self.non_root_did_document_v.last().unwrap())
        }
    }
    /// Select a range of DID documents based on version_id.  Optionally specify a begin (inclusive)
    /// and end (exclusive) version_id value for the range.  If version_id_begin_o is None, then the
    /// range begins with the first DID document in the microledger.  If version_id_end_o is None, then
    /// the range ends with the last DID document in the microledger.
    // TODO: Return a Box<&dyn std::iter::Iterator<...>> instead in order to minimize allocations.
    pub fn select_did_documents(
        &self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Vec<DIDDocument> {
        let version_id_begin = version_id_begin_o.unwrap_or(0) as usize;
        let version_id_end = version_id_end_o
            .unwrap_or(self.microledger_height())
            .min(self.microledger_height()) as usize;
        let mut did_document_v = Vec::with_capacity(version_id_end - version_id_begin);
        if version_id_begin == 0 {
            did_document_v.push(DIDDocument::from(&self.root_did_document));
        }
        let non_root_did_document_index_begin = version_id_begin.saturating_sub(1);
        let non_root_did_document_index_end = version_id_end.saturating_sub(1);
        did_document_v.extend(
            self.non_root_did_document_v
                .iter()
                .skip(non_root_did_document_index_begin)
                .take(non_root_did_document_index_end - non_root_did_document_index_begin)
                .map(|x| DIDDocument::from(x)),
        );
        did_document_v
    }
    /// Returns the node at the given version_id.
    // TODO: Return did doc metadata
    pub fn did_document_for_version_id(&self, version_id: u32) -> Result<DIDDocument, Error> {
        if version_id == 0 {
            Ok((&self.root_did_document).into())
        } else {
            let index = (version_id - 1) as usize;
            let non_root_did_document =
                self.non_root_did_document_v.get(index).ok_or_else(|| {
                    Error::NotFound("version_id does not match any existing DID document")
                })?;
            Ok(non_root_did_document.into())
        }
    }
    /// Returns the node whose DID document has the given self-signature.
    // TODO: Return did doc metadata
    pub fn did_document_for_self_signature<'a>(
        &self,
        self_signature: &selfsign::KERISignature<'a>,
    ) -> Result<DIDDocument, Error> {
        let version_id = self
            .self_signature_version_id_m
            .get(self_signature)
            .ok_or_else(|| {
                Error::NotFound("self-signature does not match any existing DID document")
            })?;
        self.did_document_for_version_id(*version_id)
    }
    /// Returns the node that is valid at the given time.
    // TODO: Return did doc metadata
    pub fn did_document_for_time(
        &self,
        time: time::OffsetDateTime,
    ) -> Result<DIDDocument, Error> {
        let version_id = self
            .valid_from_version_id_m
            .range(..=time)
            .last()
            .ok_or_else(|| Error::NotFound("time does not match any existing DID document"))?
            .1;
        self.did_document_for_version_id(*version_id)
    }
    /// Returns the DIDDocumentMetadata for the given DIDDocument.  Note that this depends on the
    /// whole state of the DID's Microledger -- in particular, on the first and last DID documents,
    /// as well as the "next" DID document from the specified one.
    pub fn did_document_metadata_for(&self, did_document: &DIDDocument) -> DIDDocumentMetadata {
        let latest_did_document = self.latest_did_document();
        let did_document_is_latest =
            did_document.self_signature() == latest_did_document.self_signature();
        let next_did_document_o = if did_document_is_latest {
            None
        } else {
            Some(
                self.did_document_for_version_id(did_document.version_id() + 1)
                    .unwrap(),
            )
        };
        DIDDocumentMetadata {
            created: self.root_did_document.valid_from,
            most_recent_update: latest_did_document.valid_from().clone(),
            next_update_o: next_did_document_o.as_ref().map(|x| x.valid_from().clone()),
            most_recent_version_id: latest_did_document.version_id(),
            next_version_id_o: next_did_document_o.as_ref().map(|x| x.version_id()),
        }
    }
    /// Resolve the DID document and associated DID document metadata with optional query params.  If no
    /// query params are given, then the latest will be returned.  If multiple query params are given,
    /// then they will all be checked for consistency.
    pub fn resolve<'a>(
        &self,
        version_id_o: Option<u32>,
        self_signature_o: Option<&selfsign::KERISignature<'a>>,
    ) -> Result<(DIDDocument<'static>, DIDDocumentMetadata), Error> {
        let did_document = match (version_id_o, self_signature_o) {
            (Some(version_id), None) => self.did_document_for_version_id(version_id)?,
            (None, Some(self_signature)) => self.did_document_for_self_signature(self_signature)?,
            (None, None) => self.latest_did_document(),
            (Some(version_id), Some(self_signature)) => {
                let did_document = self.did_document_for_version_id(version_id)?;
                if did_document.self_signature() != self_signature {
                    return Err(Error::Invalid("The self-signature of the DID document for given version_id does not match the given self-signature"));
                }
                did_document
            }
        };
        let did_document_metadata = self.did_document_metadata_for(&did_document);
        let did_document = did_document.into_owned();
        Ok((did_document, did_document_metadata))
    }
    /// This would be used when the new DID document is being specified by the DID controller.
    // TODO: Maybe just make a single `update` method which accepts NonRootDIDDocument and offloads
    // the selfsign::Signer logic to the call site.
    pub fn update_as_controller(
        &mut self,
        did_document_update_params: DIDDocumentUpdateParams,
        hasher_b: Box<dyn selfhash::Hasher>,
        signer: &dyn selfsign::Signer,
    ) -> Result<(), Error> {
        let non_root_did_document = NonRootDIDDocument::update_from_previous(
            self.latest_did_document(),
            did_document_update_params,
            hasher_b,
            signer,
        )?;
        self.update_from_non_root_did_document(non_root_did_document)
    }
    /// This would be used when the DID document comes from an external source, and the local model of
    /// the microledger needs to be updated to reflect that.
    pub fn update_from_non_root_did_document(
        &mut self,
        non_root_did_document: NonRootDIDDocument,
    ) -> Result<(), Error> {
        non_root_did_document.verify_nonrecursive(self.latest_did_document())?;
        assert!(
            non_root_did_document.self_signature_o.is_some(),
            "programmer error"
        );
        let self_signature = non_root_did_document.self_signature_o.as_ref().unwrap();
        let version_id = non_root_did_document.version_id;
        let valid_from = non_root_did_document.valid_from;

        self.self_signature_version_id_m
            .insert(self_signature.clone(), version_id);
        self.valid_from_version_id_m.insert(valid_from, version_id);
        self.non_root_did_document_v.push(non_root_did_document);

        // Sanity check.
        self.verify_full()
            .expect("programmer error: this should have been guaranteed by Microledger::create");

        Ok(())
    }
    /// Perform a full traversal and verification of the entire Microledger.  This is linear in the
    /// number of nodes in the Microledger, and it isn't intended to be called except in debugging and
    /// testing.
    pub fn verify_full(&self) -> Result<(), Error> {
        // TODO: implement a "verification cache" which stores the results of the verification so that
        // repeated calls to this function are not redundant.

        let microledger_height = 1 + self.non_root_did_document_v.len();
        if self.self_signature_version_id_m.len() != microledger_height {
            return Err(Error::Malformed(
                "said_version_id_m length does not match microledger height",
            ));
        }
        if self.valid_from_version_id_m.len() != microledger_height {
            return Err(Error::Malformed(
                "valid_from_version_id_m length does not match microledger height",
            ));
        }
        for version_id in self.self_signature_version_id_m.values() {
            if *version_id as usize >= microledger_height {
                return Err(Error::Malformed(
                    "said_version_id_m contains version_id that is >= microledger height",
                ));
            }
        }
        for version_id in self.valid_from_version_id_m.values() {
            if *version_id as usize >= microledger_height {
                return Err(Error::Malformed(
                    "valid_from_version_id_m contains version_id that is >= microledger height",
                ));
            }
        }

        // TODO: More verification regarding the said_version_id_m and valid_from_version_id_m maps.

        // Verify the root node.
        self.root_did_document.verify_nonrecursive()?;
        // Verify each non-root node.
        let mut prev_did_document = DIDDocument::from(&self.root_did_document);
        for non_root_did_document in self.non_root_did_document_v.iter() {
            non_root_did_document.verify_nonrecursive(prev_did_document)?;
            prev_did_document = DIDDocument::from(non_root_did_document);
        }

        Ok(())
    }
}
