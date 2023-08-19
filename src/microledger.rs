use std::collections::{BTreeMap, HashMap};

use crate::{DIDDocument, DIDWebplus, Error, MicroledgerNode};

pub struct Microledger {
    /// This is the single DID that all DID documents in this microledger share.
    pub did: DIDWebplus,
    /// The sequence of DID documents and their metadata.  Their version_id field must match their
    /// index in this vector.
    pub microledger_node_v: Vec<MicroledgerNode>,
    /// A map from the DID document's hash to its version_id field value.
    pub hash_version_id_m: HashMap<String, u32>,
    /// An ordered map from the DID document's valid_from field value to its version_id field value.
    pub valid_from_version_id_m: BTreeMap<chrono::DateTime<chrono::Utc>, u32>,
}

impl Microledger {
    pub fn microledger_height(&self) -> u32 {
        assert_eq!(self.microledger_node_v.len(), self.hash_version_id_m.len());
        assert_eq!(
            self.microledger_node_v.len(),
            self.valid_from_version_id_m.len()
        );
        self.microledger_node_v.len() as u32
    }
    /// Returns the root (first) node of the microledger.
    pub fn root(&self) -> &MicroledgerNode {
        assert!(self.microledger_height() > 0);
        self.microledger_node_v.first().unwrap()
    }
    /// Returns the head (latest) node of the microledger.
    pub fn head(&self) -> &MicroledgerNode {
        assert!(self.microledger_height() > 0);
        self.microledger_node_v.last().unwrap()
    }
    /// Returns the head (latest) node of the microledger.
    pub fn head_mut(&mut self) -> &mut MicroledgerNode {
        assert!(self.microledger_height() > 0);
        self.microledger_node_v.last_mut().unwrap()
    }
    /// Returns the node at the given version_id.
    pub fn node_for_version_id(&self, version_id: u32) -> Result<&MicroledgerNode, Error> {
        self.microledger_node_v
            .get(version_id as usize)
            .ok_or_else(|| Error::NotFound("version_id does not match any existing DID document"))
    }
    /// Returns the node that is valid at the given time.
    pub fn node_for_time(
        &self,
        time: chrono::DateTime<chrono::Utc>,
    ) -> Result<&MicroledgerNode, Error> {
        let version_id = self
            .valid_from_version_id_m
            .range(..=time)
            .last()
            .ok_or_else(|| Error::NotFound("time does not match any existing DID document"))?
            .1;
        self.node_for_version_id(*version_id)
    }
    // Note that this will compute the SAID for the document, overwriting the SAID portions of all the
    // DID fields in the document.  This is what seals the first document in the microledger and
    // the SAID forms part of the DID itself.
    pub fn create(did_document: DIDDocument) -> Result<Self, Error> {
        let root = MicroledgerNode::create_root(did_document)?;

        let did = root.did_document().id.clone();
        let hash = root.did_document_hash().to_string();
        let version_id = root.did_document().version_id;
        let valid_from = root.did_document().valid_from;

        let mut hash_version_id_m = HashMap::new();
        hash_version_id_m.insert(hash, version_id);

        let mut valid_from_version_id_m = BTreeMap::new();
        valid_from_version_id_m.insert(valid_from, version_id);

        let microledger_node_v = vec![root];

        let retval = Self {
            did,
            microledger_node_v,
            hash_version_id_m,
            valid_from_version_id_m,
        };

        // TODO: enable this.
        // retval.verify().expect("programmer error: this should have been guaranteed by Microledger::create");
        // TODO: verify only one level deep

        Ok(retval)
    }
    /// Note that this will overwrite the prev_did_document_hash_o and version_id fields of the given
    /// DIDDocument in order to guarantee the microledger constraints.
    pub fn update(&mut self, mut did_document: DIDDocument) -> Result<(), Error> {
        let head = self.head_mut();

        did_document.prev_did_document_hash_o = Some(head.did_document_hash().to_string());
        did_document.version_id = head.did_document().version_id + 1;

        let node = MicroledgerNode::create_non_root(did_document, &*head)?;

        assert!(node.did_document().prev_did_document_hash_o.as_ref().map(String::as_str) == Some(head.did_document_hash()), "programmer error: this should be guaranteed by validation in MicroledgerNode::create_non_root");
        assert!(node.did_document().valid_from > head.did_document().valid_from, "programmer error: this should be guaranteed by validation in MicroledgerNode::create_non_root");
        assert!(node.did_document().version_id == head.did_document().version_id + 1, "programmer error: this should be guaranteed by validation in MicroledgerNode::create_non_root");

        // Update the head node's metadata valid_until_o field.
        head.did_document_metadata_mut().valid_until_o = Some(node.did_document().valid_from);

        let hash = node.did_document_hash().to_string();
        let version_id = node.did_document().version_id;
        let valid_from = node.did_document().valid_from;

        self.hash_version_id_m.insert(hash, version_id);
        self.valid_from_version_id_m.insert(valid_from, version_id);
        self.microledger_node_v.push(node);

        // TODO: enable this.
        // retval.verify().expect("programmer error: this should have been guaranteed by Microledger::create");
        // TODO: verify only one level deep

        Ok(())
    }
}
