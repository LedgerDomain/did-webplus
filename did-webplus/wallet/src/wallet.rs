use crate::{Error, Result};
use did_webplus_core::{DIDFullyQualified, DIDStr};
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, VerificationMethodRecord,
};
use std::collections::HashSet;

/// Generalized wallet trait that can be implemented for any wallet type, e.g. edge wallet (software or hardware)
/// or cloud wallet.  This trait is intended to be used by higher-level code that needs to interact with a wallet
/// without knowing the specific implementation details of the wallet.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait Wallet: Send + Sync {
    /// Create a new (set of) private key(s), create a root DID document containing the corresponding public key(s),
    /// and send the DID document to the specified VDR.  This DID is now a locally-controlled DID.  Returns the
    /// fully qualified DID corresponding to the updated DID doc (i.e. the DID with selfHash and versionId query
    /// params; in this case, the query selfHash matches the DID doc selfHash, and the query versionId is 0).
    async fn create_did(&self, vdr_did_create_endpoint: &str) -> Result<DIDFullyQualified>;
    /// Retrieve all DID document updates for the given DID from the VDR, verify them, and store the latest DID document.
    // TODO: Figure out how to update any other local doc stores.
    async fn fetch_did(&self, did: &DIDStr, vdr_scheme: &'static str) -> Result<()>;
    /// Retrieve the latest DID document from the VDR, rotate the key(s) of a locally-controlled DID, update
    /// the DID document, and send the updated DID document to the VDR.  The initial retrieval step is necessary
    /// only if there are other wallets that control this DID and that have updated the DID document since the last
    /// time this wallet updated the DID document.  Returns the fully qualified DID corresponding to the updated
    /// DID doc (i.e. the DID with selfHash and versionId query params).
    async fn update_did(&self, did: &DIDStr, vdr_scheme: &'static str)
        -> Result<DIDFullyQualified>;

    // Below here are lower-level methods for accessing controlled DIDs and verification methods (i.e. private keys).

    /// Returns the list of DIDs that this wallet controls, subject to the given filter.
    async fn get_controlled_dids(&self, did_o: Option<&DIDStr>) -> Result<Vec<DIDFullyQualified>> {
        Ok(self
            .get_locally_controlled_verification_methods(
                &LocallyControlledVerificationMethodFilter {
                    did_o: did_o.map(|did| did.to_owned()),
                    version_id_o: None,
                    key_purpose_o: None,
                    key_id_o: None,
                    result_limit_o: None,
                },
            )
            .await?
            .into_iter()
            .map(|(verification_method_record, _signer_b)| {
                verification_method_record
                    .did_key_resource_fully_qualified
                    .without_fragment()
                    .to_owned()
            })
            .collect::<HashSet<DIDFullyQualified>>()
            .into_iter()
            .collect::<Vec<DIDFullyQualified>>())
    }
    /// If did_o is Some(_), then this returns the fully qualified form of the that DID if it is
    /// controlled by this wallet.  Otherwise, if this wallet controls exactly one DID, i.e. it is
    /// uniquely determinable, then this returns the fully qualified form of that DID.  Otherwise,
    /// an error is returned.
    async fn get_controlled_did(&self, did_o: Option<&DIDStr>) -> Result<DIDFullyQualified> {
        let controlled_did_v = self.get_controlled_dids(did_o).await?;
        if controlled_did_v.len() > 1 {
            return Err(Error::MultipleControlledDIDsFound(
                format!("DID filter was {:?}", did_o).into(),
            ));
        }
        assert!(controlled_did_v.len() <= 1, "programmer error");
        if controlled_did_v.is_empty() {
            if let Some(did) = did_o {
                return Err(Error::DIDNotControlledByWallet(did.to_string().into()));
            } else {
                return Err(Error::NoControlledDIDFound(
                    format!("DID filter was {:?}", did_o).into(),
                ));
            }
        }
        Ok(controlled_did_v.into_iter().next().unwrap())
    }
    /// This just begins a transaction and calls WalletStorage::get_locally_controlled_verification_methods.
    async fn get_locally_controlled_verification_methods(
        &self,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, Box<dyn selfsign::Signer>)>>;
    /// Calls get_locally_controlled_verification_methods and returns the single result if there is exactly one.
    /// Otherwise, returns an error.  Note that this method will ignore the result_limit_o field of the filter.
    async fn get_locally_controlled_verification_method(
        &self,
        mut locally_controlled_verification_method_filter: LocallyControlledVerificationMethodFilter,
    ) -> Result<(VerificationMethodRecord, Box<dyn selfsign::Signer>)> {
        locally_controlled_verification_method_filter.result_limit_o = Some(2);
        let query_result_v = self
            .get_locally_controlled_verification_methods(
                &locally_controlled_verification_method_filter,
            )
            .await?;
        if query_result_v.is_empty() {
            return Err(Error::NoLocallyControlledVerificationMethodFound(
                format!(
                    "filter was {:?}",
                    locally_controlled_verification_method_filter
                )
                .into(),
            ));
        }
        if query_result_v.len() > 1 {
            return Err(Error::MultipleLocallyControlledVerificationMethodsFound(
                format!(
                    "filter was {:?}",
                    locally_controlled_verification_method_filter
                )
                .into(),
            ));
        }
        let query_result = query_result_v.into_iter().next().unwrap();
        Ok(query_result)
    }
}
