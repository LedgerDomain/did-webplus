use std::collections::{BTreeMap, HashMap};

use crate::{
    create_non_root_microledger_node, create_root_microledger_node, DIDWebplus, Error,
    MicroledgerNode, MicroledgerNodeTrait, NonRootDIDDocument, NonRootDIDDocumentParams,
    RootDIDDocument, RootDIDDocumentParams,
};

#[derive(Clone, Debug)]
pub struct Microledger {
    /// This is the single DID that all DID documents in this microledger share.
    did: DIDWebplus,
    /// The root node for this DID's microledger.  This formally has version_id = 0, so when
    /// the hash_version_id_m and valid_from_version_id_m maps produce 0, this is the node
    /// that is being referred to.
    root_microledger_node: MicroledgerNode<RootDIDDocument>,
    /// The sequence of non-root DID documents and their metadata.  Their version_id field be equal to
    /// 1 + their index in this vector.
    non_root_microledger_node_v: Vec<MicroledgerNode<NonRootDIDDocument>>,
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
        let root_microledger_node = create_root_microledger_node(root_did_document_params)?;

        let did = root_microledger_node.typed_did_document().id.clone();
        assert!(root_microledger_node.typed_did_document().said_o.is_some());
        let said = root_microledger_node
            .typed_did_document()
            .said_o
            .as_ref()
            .unwrap()
            .to_string();
        let version_id = root_microledger_node.typed_did_document().version_id;
        let valid_from = root_microledger_node.typed_did_document().valid_from;

        let mut said_version_id_m = HashMap::new();
        said_version_id_m.insert(said, version_id);

        let mut valid_from_version_id_m = BTreeMap::new();
        valid_from_version_id_m.insert(valid_from, version_id);

        let retval = Self {
            did,
            root_microledger_node,
            non_root_microledger_node_v: Vec::new(),
            said_version_id_m,
            valid_from_version_id_m,
        };
        // Just for good measure.
        retval
            .verify_full()
            .expect("programmer error: this should be valid by construction");
        Ok(retval)
    }
    /// This is the DID that controls this microledger and that all DID documents in this microledger share.
    pub fn did(&self) -> &DIDWebplus {
        &self.did
    }
    /// The microledger height is the number of nodes in the microledger.
    pub fn microledger_height(&self) -> u32 {
        assert_eq!(
            1 + self.non_root_microledger_node_v.len(),
            self.said_version_id_m.len()
        );
        assert_eq!(
            1 + self.non_root_microledger_node_v.len(),
            self.valid_from_version_id_m.len()
        );
        1 + self.non_root_microledger_node_v.len() as u32
    }
    /// Returns the root (first) node of the microledger.
    pub fn root(&self) -> &MicroledgerNode<RootDIDDocument> {
        &self.root_microledger_node
    }
    /// Returns the sequence of non-root nodes of the microledger.
    pub fn non_root_v(&self) -> &[MicroledgerNode<NonRootDIDDocument>] {
        self.non_root_microledger_node_v.as_slice()
    }
    /// Returns the head (latest) node of the microledger.
    pub fn head(&self) -> Box<&dyn MicroledgerNodeTrait> {
        if self.non_root_microledger_node_v.is_empty() {
            Box::new(&self.root_microledger_node)
        } else {
            Box::new(self.non_root_microledger_node_v.last().unwrap())
        }
    }
    /// Returns the head (latest) node of the microledger.
    pub fn head_mut(&mut self) -> Box<&mut dyn MicroledgerNodeTrait> {
        if self.non_root_microledger_node_v.is_empty() {
            Box::new(&mut self.root_microledger_node)
        } else {
            Box::new(self.non_root_microledger_node_v.last_mut().unwrap())
        }
    }
    /// Returns the node at the given version_id.
    pub fn node_for_version_id(
        &self,
        version_id: u32,
    ) -> Result<Box<&dyn MicroledgerNodeTrait>, Error> {
        if version_id == 0 {
            Ok(Box::new(&self.root_microledger_node))
        } else {
            let index = (version_id - 1) as usize;
            Ok(Box::new(
                self.non_root_microledger_node_v.get(index).ok_or_else(|| {
                    Error::NotFound("version_id does not match any existing DID document")
                })?,
            ))
        }
    }
    /// Returns the node whose DID document has the given SAID.
    pub fn node_for_said(&self, said: &str) -> Result<Box<&dyn MicroledgerNodeTrait>, Error> {
        let version_id = self
            .said_version_id_m
            .get(said)
            .ok_or_else(|| Error::NotFound("SAID does not match any existing DID document"))?;
        self.node_for_version_id(*version_id)
    }
    /// Returns the node that is valid at the given time.
    pub fn node_for_time(
        &self,
        time: chrono::DateTime<chrono::Utc>,
    ) -> Result<Box<&dyn MicroledgerNodeTrait>, Error> {
        let version_id = self
            .valid_from_version_id_m
            .range(..=time)
            .last()
            .ok_or_else(|| Error::NotFound("time does not match any existing DID document"))?
            .1;
        self.node_for_version_id(*version_id)
    }
    // pub fn node_iter<'a>(
    //     &'a self,
    // ) -> Box<dyn std::iter::Iterator<Item = Box<&'a dyn MicroledgerNodeTrait>> + 'a> {
    //     let root_microledger_node_b =
    //         Box::<&dyn MicroledgerNodeTrait>::new(&self.root_microledger_node);
    //     let non_root_microledger_node_v_b = self
    //         .non_root_microledger_node_v
    //         .iter()
    //         .map(|x| Box::<&dyn MicroledgerNodeTrait>::new(x) as Box<&dyn MicroledgerNodeTrait>);
    //     Box::new(std::iter::once(root_microledger_node_b).chain(non_root_microledger_node_v_b))
    // }
    /// This would be used when the new DID document is being specified by the DID controller.
    pub fn update_as_controller(
        &mut self,
        non_root_did_document_params: NonRootDIDDocumentParams,
    ) -> Result<(), Error> {
        let head = self.head();
        let non_root_microledger_node = create_non_root_microledger_node(
            non_root_did_document_params,
            head.did_document(),
            head.did_document_metadata(),
        )?;
        self.update_from_non_root_did_document(non_root_microledger_node)
    }
    /// This would be used when the DID document comes from an external source, and the local model of
    /// the microledger needs to be updated to reflect that.
    pub fn update_from_non_root_did_document(
        &mut self,
        non_root_microledger_node: MicroledgerNode<NonRootDIDDocument>,
    ) -> Result<(), Error> {
        let head = self.head_mut();

        // assert!(node.did_document().prev_did_document_hash_o.as_ref().map(String::as_str) == Some(head.did_document_hash()), "programmer error: this should be guaranteed by validation in MicroledgerNode::create_non_root");
        // assert!(node.did_document().valid_from > head.did_document().valid_from, "programmer error: this should be guaranteed by validation in MicroledgerNode::create_non_root");
        // assert!(node.did_document().version_id == head.did_document().version_id + 1, "programmer error: this should be guaranteed by validation in MicroledgerNode::create_non_root");

        // Update the head node's metadata valid_until_o field.
        head.set_did_document_metadata_valid_until(
            non_root_microledger_node.typed_did_document().valid_from,
        )?;

        assert!(non_root_microledger_node
            .typed_did_document()
            .said_o
            .is_some());
        let said = non_root_microledger_node
            .typed_did_document()
            .said_o
            .as_ref()
            .unwrap()
            .to_string();
        let version_id = non_root_microledger_node.typed_did_document().version_id;
        let valid_from = non_root_microledger_node.typed_did_document().valid_from;

        self.said_version_id_m.insert(said, version_id);
        self.valid_from_version_id_m.insert(valid_from, version_id);
        self.non_root_microledger_node_v
            .push(non_root_microledger_node);

        self.verify_full()
            .expect("programmer error: this should have been guaranteed by Microledger::create");
        // TODO: verify only one level deep

        Ok(())
    }
    pub fn verify_full(&self) -> Result<(), Error> {
        // TODO: implement a "verification cache" which stores the results of the verification so that
        // repeated calls to this function are not redundant.

        let microledger_height = 1 + self.non_root_microledger_node_v.len();
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
        self.root_microledger_node.verify(None)?;
        // Verify each non-root node.
        let mut prev_microledger_node_b =
            Box::<&dyn MicroledgerNodeTrait>::new(&self.root_microledger_node);
        for non_root_microledger_node in self.non_root_microledger_node_v.iter() {
            non_root_microledger_node.verify_non_root(prev_microledger_node_b)?;
            prev_microledger_node_b = Box::new(non_root_microledger_node);
        }

        Ok(())
    }
}
