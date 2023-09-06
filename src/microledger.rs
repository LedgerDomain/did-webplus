use std::collections::{BTreeMap, HashMap};

use crate::{
    DIDDocumentMetadata, DIDDocumentTrait, DIDWebplus, Error, NonRootDIDDocument,
    NonRootDIDDocumentParams, RootDIDDocument, RootDIDDocumentParams,
};

#[derive(Clone, Debug)]
pub struct Microledger {
    /// The root (first) DID document for this DID, forming the first node in the Microledger.
    root_did_document: RootDIDDocument,
    /// The sequence of non-root DID documents.  The version_id field in each non-root DID document
    /// must be equal to 1 + its index in this vector.
    non_root_did_document_v: Vec<NonRootDIDDocument>,

    /// A map from the DID document's SAID to its version_id field value.
    said_version_id_m: HashMap<String, u32>,
    /// An ordered map from the DID document's valid_from field value to its version_id field value.
    valid_from_version_id_m: BTreeMap<chrono::DateTime<chrono::Utc>, u32>,
}

impl Microledger {
    /// Creates a new Microledger from the given root DID document parameters.  This function will
    /// compute the SAID, thereby forming part of the DID itself.  Thus the DID can't be fully known
    /// until this function is called.
    pub fn create(root_did_document_params: RootDIDDocumentParams) -> Result<Self, Error> {
        let root_did_document = RootDIDDocument::try_from(root_did_document_params)?;
        assert!(root_did_document.said_o.is_some());
        let said = root_did_document.said_o.as_ref().unwrap().to_string();
        let version_id = root_did_document.version_id;
        let valid_from = root_did_document.valid_from;

        let mut said_version_id_m = HashMap::new();
        said_version_id_m.insert(said, version_id);

        let mut valid_from_version_id_m = BTreeMap::new();
        valid_from_version_id_m.insert(valid_from, version_id);

        let retval = Self {
            root_did_document,
            non_root_did_document_v: Vec::new(),
            said_version_id_m,
            valid_from_version_id_m,
        };
        // Just for good measure.
        retval
            .verify_full()
            .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }
    /// Creates a Microledger from a given RootDIDDocument and a (possibly empty) sequence of NonRootDIDDocuments,
    /// verifying each DID document in the overall sequence.
    pub fn new_from_did_documents(
        root_did_document: RootDIDDocument,
        non_root_did_document_v: Vec<NonRootDIDDocument>,
    ) -> Result<Self, Error> {
        let mut said_version_id_m = HashMap::with_capacity(1 + non_root_did_document_v.len());
        let mut valid_from_version_id_m = BTreeMap::new();

        {
            root_did_document.verify_root()?;
            assert!(root_did_document.said_o.is_some());
            let said = root_did_document.said_o.as_ref().unwrap().to_string();
            let version_id = root_did_document.version_id;
            let valid_from = root_did_document.valid_from;

            said_version_id_m.insert(said, version_id);
            valid_from_version_id_m.insert(valid_from, version_id);
        }

        let mut prev_did_document_b: Box<&dyn DIDDocumentTrait> = Box::new(&root_did_document);
        for non_root_did_document in non_root_did_document_v.iter() {
            non_root_did_document.verify_non_root(prev_did_document_b)?;
            assert!(non_root_did_document.said_o.is_some());
            let said = non_root_did_document.said_o.as_ref().unwrap().to_string();
            let version_id = non_root_did_document.version_id;
            let valid_from = non_root_did_document.valid_from;

            said_version_id_m.insert(said, version_id);
            valid_from_version_id_m.insert(valid_from, version_id);

            prev_did_document_b = Box::new(non_root_did_document);
        }

        let retval = Self {
            root_did_document,
            non_root_did_document_v,
            said_version_id_m,
            valid_from_version_id_m,
        };
        // Sanity check -- should be valid by the checks above.  Eventually remove this check.
        retval
            .verify_full()
            .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }

    /// This is the DID that controls this microledger and that all DID documents in this microledger share.
    pub fn did(&self) -> &DIDWebplus {
        &self.root_did_document.id
    }
    /// The microledger height is the number of nodes in the microledger.
    pub fn microledger_height(&self) -> u32 {
        assert_eq!(
            1 + self.non_root_did_document_v.len(),
            self.said_version_id_m.len()
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
    pub fn latest_did_document(&self) -> Box<&dyn DIDDocumentTrait> {
        if self.non_root_did_document_v.is_empty() {
            Box::new(&self.root_did_document)
        } else {
            Box::new(self.non_root_did_document_v.last().unwrap())
        }
    }
    /// Returns the node at the given version_id.
    // TODO: Return did doc metadata
    pub fn did_document_for_version_id(
        &self,
        version_id: u32,
    ) -> Result<Box<&dyn DIDDocumentTrait>, Error> {
        if version_id == 0 {
            Ok(Box::new(&self.root_did_document))
        } else {
            let index = (version_id - 1) as usize;
            Ok(Box::new(
                self.non_root_did_document_v.get(index).ok_or_else(|| {
                    Error::NotFound("version_id does not match any existing DID document")
                })?,
            ))
        }
    }
    /// Returns the node whose DID document has the given SAID.
    // TODO: Return did doc metadata
    pub fn did_document_for_said(&self, said: &str) -> Result<Box<&dyn DIDDocumentTrait>, Error> {
        let version_id = self
            .said_version_id_m
            .get(said)
            .ok_or_else(|| Error::NotFound("SAID does not match any existing DID document"))?;
        self.did_document_for_version_id(*version_id)
    }
    /// Returns the node that is valid at the given time.
    // TODO: Return did doc metadata
    pub fn did_document_for_time(
        &self,
        time: chrono::DateTime<chrono::Utc>,
    ) -> Result<Box<&dyn DIDDocumentTrait>, Error> {
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
    pub fn did_document_metadata_for(
        &self,
        did_document_b: Box<&dyn DIDDocumentTrait>,
    ) -> DIDDocumentMetadata {
        let latest_did_document_b = self.latest_did_document();
        let did_document_is_latest = did_document_b.said() == latest_did_document_b.said();
        let next_did_document_o = if did_document_is_latest {
            None
        } else {
            Some(
                self.did_document_for_version_id(did_document_b.version_id() + 1)
                    .unwrap(),
            )
        };
        DIDDocumentMetadata {
            created: self.root_did_document.valid_from,
            most_recent_update: latest_did_document_b.valid_from().clone(),
            next_update_o: next_did_document_o.as_ref().map(|x| x.valid_from().clone()),
            most_recent_version_id: latest_did_document_b.version_id(),
            next_version_id_o: next_did_document_o.as_ref().map(|x| x.version_id()),
        }
    }
    // pub fn did_document_iter<'a>(
    //     &'a self,
    // ) -> Box<dyn std::iter::Iterator<Item = Box<&'a dyn DIDDocumentTrait>> + 'a> {
    //     let root_did_document_b = Box::<&dyn DIDDocumentTrait>::new(&self.root_did_document);
    //     let non_root_did_document_bv = self
    //         .non_root_did_document_v
    //         .iter()
    //         .map(|x| Box::<&dyn DIDDocumentTrait>::new(x) as Box<&dyn DIDDocumentTrait>);
    //     Box::new(std::iter::once(root_did_document_b).chain(non_root_did_document_bv))
    // }
    /// This would be used when the new DID document is being specified by the DID controller.
    pub fn update_as_controller(
        &mut self,
        non_root_did_document_params: NonRootDIDDocumentParams,
    ) -> Result<(), Error> {
        let non_root_did_document =
            NonRootDIDDocument::create(non_root_did_document_params, self.latest_did_document())?;
        self.update_from_non_root_did_document(non_root_did_document)
    }
    /// This would be used when the DID document comes from an external source, and the local model of
    /// the microledger needs to be updated to reflect that.
    pub fn update_from_non_root_did_document(
        &mut self,
        non_root_did_document: NonRootDIDDocument,
    ) -> Result<(), Error> {
        non_root_did_document.verify_non_root(self.latest_did_document())?;
        assert!(non_root_did_document.said_o.is_some());
        let said = non_root_did_document.said_o.as_ref().unwrap().to_string();
        let version_id = non_root_did_document.version_id;
        let valid_from = non_root_did_document.valid_from;

        self.said_version_id_m.insert(said, version_id);
        self.valid_from_version_id_m.insert(valid_from, version_id);
        self.non_root_did_document_v.push(non_root_did_document);

        // Sanity check.
        self.verify_full()
            .expect("programmer error: this should have been guaranteed by Microledger::create");

        Ok(())
    }
    pub fn verify_full(&self) -> Result<(), Error> {
        // TODO: implement a "verification cache" which stores the results of the verification so that
        // repeated calls to this function are not redundant.

        let microledger_height = 1 + self.non_root_did_document_v.len();
        if self.said_version_id_m.len() != microledger_height {
            return Err(Error::Malformed(
                "said_version_id_m length does not match microledger height",
            ));
        }
        if self.valid_from_version_id_m.len() != microledger_height {
            return Err(Error::Malformed(
                "valid_from_version_id_m length does not match microledger height",
            ));
        }
        for version_id in self.said_version_id_m.values() {
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
        self.root_did_document.verify(None)?;
        // Verify each non-root node.
        let mut prev_did_document_b = Box::<&dyn DIDDocumentTrait>::new(&self.root_did_document);
        for non_root_did_document in self.non_root_did_document_v.iter() {
            non_root_did_document.verify_non_root(prev_did_document_b)?;
            prev_did_document_b = Box::new(non_root_did_document);
        }

        Ok(())
    }
}
