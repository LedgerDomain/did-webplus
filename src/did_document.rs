use std::borrow::Cow;

use crate::{DIDWebplus, Error, NonRootDIDDocument, PublicKeyMaterial, RootDIDDocument};

/// A DIDDocument is either a RootDIDDocument or a NonRootDIDDocument.  The Cow part (copy-on-write)
/// simply allows the value to either be owned or borrowed, which assists in minimizing unnecessary
/// allocations.
#[derive(Clone, Debug, Eq, derive_more::From, PartialEq)]
pub enum DIDDocument<'a> {
    Root(Cow<'a, RootDIDDocument>),
    NonRoot(Cow<'a, NonRootDIDDocument>),
}

impl<'a> DIDDocument<'a> {
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
    pub fn as_root_did_document(&self) -> Option<Cow<'a, RootDIDDocument>> {
        match self {
            Self::Root(root_did_document) => Some(root_did_document.clone()),
            Self::NonRoot(_) => None,
        }
    }
    /// Returns Some(_) if this is a non-root DID document, otherwise None.
    pub fn as_non_root_did_document(&self) -> Option<Cow<'a, NonRootDIDDocument>> {
        match self {
            Self::Root(_) => None,
            Self::NonRoot(non_root_did_document) => Some(non_root_did_document.clone()),
        }
    }
    /// Returns Some(_) if this is a root DID document, otherwise None.
    pub fn into_root_did_document(self) -> Option<Cow<'a, RootDIDDocument>> {
        match self {
            Self::Root(root_did_document) => Some(root_did_document),
            Self::NonRoot(_) => None,
        }
    }
    /// Returns Some(_) if this is a non-root DID document, otherwise None.
    pub fn into_non_root_did_document(self) -> Option<Cow<'a, NonRootDIDDocument>> {
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
    // NOTE: This assumes this DIDDocument is self-signed.
    pub fn self_signature(&self) -> &selfsign::KERISignature<'static> {
        match self {
            Self::Root(root_did_document) => root_did_document.self_signature_o.as_ref().unwrap(),
            Self::NonRoot(non_root_did_document) => {
                non_root_did_document.self_signature_o.as_ref().unwrap()
            }
        }
    }
    pub fn prev_did_document_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>> {
        match self {
            Self::Root(_) => None,
            Self::NonRoot(non_root_did_document) => {
                Some(&non_root_did_document.prev_did_document_self_signature)
            }
        }
    }
    pub fn valid_from(&self) -> chrono::DateTime<chrono::Utc> {
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
    pub fn verify_self_signatures<'s, 'b: 's>(
        &'b self,
    ) -> Result<&'s dyn selfsign::Signature, Error> {
        use selfsign::SelfSignable;
        match self {
            // Self::Root(root_did_document) => root_did_document.verify_self_signatures::<'s, 'b>(),
            Self::Root(root_did_document) => root_did_document
                .verify_self_signatures()
                .map_err(|e| Error::InvalidSelfSignature(e)),
            Self::NonRoot(non_root_did_document) => non_root_did_document
                .verify_self_signatures()
                .map_err(|e| Error::InvalidSelfSignature(e)),
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
