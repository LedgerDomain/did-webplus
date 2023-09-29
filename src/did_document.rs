use std::borrow::Cow;

use crate::{DIDWebplus, Error, NonRootDIDDocument, PublicKeyMaterial, RootDIDDocument};

/// A DIDDocument is either a RootDIDDocument or a NonRootDIDDocument.  The Cow part (copy-on-write)
/// simply allows the value to either be owned or borrowed, which assists in minimizing unnecessary
/// allocations.
#[derive(Clone, Debug, Eq, derive_more::From, PartialEq)]
pub enum DIDDocument<'d> {
    Root(Cow<'d, RootDIDDocument>),
    NonRoot(Cow<'d, NonRootDIDDocument>),
}

impl<'d> DIDDocument<'d> {
    pub fn into_owned(self) -> DIDDocument<'static> {
        match self {
            Self::Root(root_did_document) => {
                DIDDocument::Root(Cow::Owned(root_did_document.into_owned()))
            }
            Self::NonRoot(non_root_did_document) => {
                DIDDocument::NonRoot(Cow::Owned(non_root_did_document.into_owned()))
            }
        }
    }
    /// Returns true if and only if this is a root DID document.
    pub fn is_root_did_document(&self) -> bool {
        matches!(self, Self::Root(_))
    }
    /// Returns true if and only if this is a non-root DID document.
    pub fn is_non_root_did_document(&self) -> bool {
        matches!(self, Self::NonRoot(_))
    }
    /// Returns Some(_) if this is a root DID document, otherwise None.
    pub fn as_root_did_document(&self) -> Option<Cow<'d, RootDIDDocument>> {
        match self {
            Self::Root(root_did_document) => Some(root_did_document.clone()),
            Self::NonRoot(_) => None,
        }
    }
    /// Returns Some(_) if this is a non-root DID document, otherwise None.
    pub fn as_non_root_did_document(&self) -> Option<Cow<'d, NonRootDIDDocument>> {
        match self {
            Self::Root(_) => None,
            Self::NonRoot(non_root_did_document) => Some(non_root_did_document.clone()),
        }
    }
    /// Returns Some(_) if this is a root DID document, otherwise None.
    pub fn into_root_did_document(self) -> Option<Cow<'d, RootDIDDocument>> {
        match self {
            Self::Root(root_did_document) => Some(root_did_document),
            Self::NonRoot(_) => None,
        }
    }
    /// Returns Some(_) if this is a non-root DID document, otherwise None.
    pub fn into_non_root_did_document(self) -> Option<Cow<'d, NonRootDIDDocument>> {
        match self {
            Self::Root(_) => None,
            Self::NonRoot(non_root_did_document) => Some(non_root_did_document),
        }
    }
    // TODO: Rename to did
    pub fn id(&self) -> &DIDWebplus {
        match self {
            Self::Root(root_did_document) => &root_did_document.id,
            Self::NonRoot(non_root_did_document) => &non_root_did_document.id,
        }
    }
    // NOTE: This assumes this DIDDocument is self-hashed.
    pub fn self_hash(&self) -> &selfhash::KERIHash<'static> {
        match self {
            Self::Root(root_did_document) => root_did_document.self_hash_o.as_ref().unwrap(),
            Self::NonRoot(non_root_did_document) => {
                non_root_did_document.self_hash_o.as_ref().unwrap()
            }
        }
    }
    // NOTE: This assumes this DIDDocument is self-signed.
    pub fn self_signature(&self) -> &selfsign::KERISignature<'static> {
        match self {
            Self::Root(root_did_document) => root_did_document.self_signature_o.as_ref().unwrap(),
            Self::NonRoot(non_root_did_document) => {
                non_root_did_document.self_signature_o.as_ref().unwrap()
            }
        }
    }
    pub fn prev_did_document_self_hash_o(&self) -> Option<&selfhash::KERIHash<'static>> {
        match self {
            Self::Root(_) => None,
            Self::NonRoot(non_root_did_document) => {
                Some(&non_root_did_document.prev_did_document_self_hash)
            }
        }
    }
    pub fn valid_from(&self) -> time::OffsetDateTime {
        match self {
            Self::Root(root_did_document) => root_did_document.valid_from,
            Self::NonRoot(non_root_did_document) => non_root_did_document.valid_from,
        }
    }
    pub fn version_id(&self) -> u32 {
        match self {
            Self::Root(root_did_document) => root_did_document.version_id,
            Self::NonRoot(non_root_did_document) => non_root_did_document.version_id,
        }
    }
    pub fn public_key_material(&self) -> &PublicKeyMaterial {
        match self {
            Self::Root(root_did_document) => &root_did_document.public_key_material,
            Self::NonRoot(non_root_did_document) => &non_root_did_document.public_key_material,
        }
    }
    pub fn verify_nonrecursive(
        &self,
        expected_prev_did_document_o: Option<DIDDocument>,
    ) -> Result<&selfhash::KERIHash<'static>, Error> {
        match self {
            Self::Root(root_did_document) => {
                if expected_prev_did_document_o.is_some() {
                    return Err(Error::Malformed(
                        "Root DID document cannot have a previous DID document.",
                    ));
                }
                root_did_document.verify_nonrecursive()
            }
            Self::NonRoot(non_root_did_document) => {
                if expected_prev_did_document_o.is_none() {
                    return Err(Error::Malformed(
                        "Non-root DID document must have a previous DID document.",
                    ));
                }
                non_root_did_document.verify_nonrecursive(expected_prev_did_document_o.unwrap())
            }
        }
    }
    pub fn verify_self_signatures_and_hashes<'a, 'b: 'a>(
        &'b self,
    ) -> Result<(&'a dyn selfsign::Signature, &'a dyn selfhash::Hash), &'static str> {
        use selfsign::SelfSignAndHashable;
        match self {
            Self::Root(root_did_document) => root_did_document.verify_self_signatures_and_hashes(),
            Self::NonRoot(non_root_did_document) => {
                non_root_did_document.verify_self_signatures_and_hashes()
            }
        }
    }
    // TEMP HACK
    pub fn to_json_pretty(&self) -> String {
        match self {
            Self::Root(root_did_document) => {
                serde_json::to_string_pretty(root_did_document).expect("pass")
            }
            Self::NonRoot(non_root_did_document) => {
                serde_json::to_string_pretty(non_root_did_document).expect("pass")
            }
        }
    }
}

impl<'a, 'b: 'a> From<&'b RootDIDDocument> for DIDDocument<'a> {
    fn from(root_did_document: &'b RootDIDDocument) -> Self {
        // Re-borrow with the shorter lifetime.
        Self::Root(Cow::Borrowed(&*root_did_document))
    }
}

impl<'a, 'b: 'a> From<&'b NonRootDIDDocument> for DIDDocument<'a> {
    fn from(non_root_did_document: &'b NonRootDIDDocument) -> Self {
        // Re-borrow with the shorter lifetime.
        Self::NonRoot(Cow::Borrowed(&*non_root_did_document))
    }
}
