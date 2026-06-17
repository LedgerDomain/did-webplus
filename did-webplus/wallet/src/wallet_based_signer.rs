use crate::{Result, Wallet};
use ssi_claims::data_integrity::AnySignatureAlgorithm;
use ssi_verification_methods::{SignatureProtocol, VerificationMethod, protocol::WithProtocol};
use std::borrow::Cow;

/// A signer corresponding to a particular Wallet, DID, key purpose, and, optionally, key ID.
#[derive(Clone)]
pub struct WalletBasedSigner<W: Wallet> {
    /// Specifies the wallet that will be used to sign.
    wallet: W,
    /// Specifies the KeyPurpose for the signing key.
    key_purpose: did_webplus_core::KeyPurpose,
    /// Specifies the specific key that will be used to sign.
    key_fully_qualified: did_webplus_core::DIDKeyResourceFullyQualified,
    /// Specifies the verifier for this key.
    verifier_bytes: signature_dyn::VerifierBytes<'static>,
}

impl<W: Wallet> WalletBasedSigner<W> {
    /// Resolves the signing key from the wallet's local store. When `fetch_did_first` is true, the
    /// latest DID document is fetched from the network before lookup (recommended when the wallet may
    /// be stale). When false, only locally stored documents are used (offline signing).
    ///
    /// If the filter doesn't match exactly one verification method record, then an error will be returned.
    pub async fn new(
        wallet: W,
        did: &did_webplus_core::DIDStr,
        key_purpose: did_webplus_core::KeyPurpose,
        key_id_o: Option<&str>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
        fetch_did_first: bool,
    ) -> Result<Self> {
        if fetch_did_first {
            wallet.fetch_did(did, http_options_o).await?;
        }
        let locally_controlled_verification_method_filter =
            did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                did_o: Some(did.to_owned()),
                key_purpose_o: Some(key_purpose),
                version_id_o: None,
                key_id_o: key_id_o.map(|key_id| key_id.to_owned()),
                result_limit_o: None,
            };
        let (verification_method_record, signer_bytes) = wallet
            .get_locally_controlled_verification_method(
                locally_controlled_verification_method_filter,
            )
            .await?;
        use signature_dyn::SignerT;
        let verifier_bytes = signer_bytes.get_verifier_bytes()?.into_owned();
        Ok(Self {
            wallet,
            key_purpose,
            key_fully_qualified: verification_method_record.did_key_resource_fully_qualified,
            verifier_bytes,
        })
    }
    pub fn key_purpose(&self) -> did_webplus_core::KeyPurpose {
        self.key_purpose
    }
    pub fn key_fully_qualified(&self) -> &did_webplus_core::DIDKeyResourceFullyQualifiedStr {
        &self.key_fully_qualified
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<W: Wallet> signature_dyn::AsyncSignerT for WalletBasedSigner<W> {
    async fn async_key_id(&self) -> signature_dyn::Result<Option<String>> {
        // Return the fully qualified DID key resource as a string.
        Ok(Some(self.key_fully_qualified.to_string()))
    }
    async fn async_key_type(&self) -> signature_dyn::Result<signature_dyn::KeyType> {
        // Return the key type of the signing key.
        Ok(self.verifier_bytes.key_type())
    }
    async fn async_get_verifier(&self) -> signature_dyn::Result<Box<dyn signature_dyn::VerifierT>> {
        Ok(Box::new(self.verifier_bytes.clone()))
    }
    async fn async_try_sign_message(
        &self,
        message_byte_v: &[u8],
    ) -> signature_dyn::Result<Box<dyn signature_dyn::SignatureT>> {
        let (_verification_method_record, signer_bytes) = self
            .wallet
            .get_locally_controlled_verification_method(
                did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                    did_o: Some(self.key_fully_qualified.did().to_owned()),
                    key_purpose_o: Some(self.key_purpose),
                    version_id_o: Some(self.key_fully_qualified.query_version_id()),
                    key_id_o: Some(self.key_fully_qualified.fragment().to_string()),
                    result_limit_o: None,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        use signature_dyn::SignerT;
        Ok(signer_bytes.try_sign_message(message_byte_v)?)
    }
}

// For signing JWS and JWT (plain JWT, but also VC-JWT and VP-JWT)
impl<W: Wallet> ssi_jws::JwsSigner for WalletBasedSigner<W> {
    async fn fetch_info(
        &self,
    ) -> std::result::Result<ssi_jws::JwsSignerInfo, ssi_claims::SignatureError> {
        let key_type = self.verifier_bytes.key_type();
        // Have to convert the JOSE algorithm to an ssi_jws::Algorithm.
        // NOTE: ssi-jwk crate does not support all the algorithms that did:webplus does.
        let algorithm = match key_type.jose_algorithm() {
            signature_dyn::ED25519_JOSE_ALGORITHM => ssi_jwk::Algorithm::EdDSA,
            signature_dyn::P256_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES256,
            signature_dyn::P384_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES384,
            // signature_dyn::P521_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES512,
            signature_dyn::SECP256K1_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES256K,
            _ => {
                return Err(ssi_claims::SignatureError::Other(format!(
                    "unsupported JOSE algorithm: {:?}",
                    key_type.jose_algorithm()
                )));
            }
        };
        Ok(ssi_jws::JwsSignerInfo {
            key_id: Some(self.key_fully_qualified.to_string()),
            algorithm,
        })
    }
    async fn sign_bytes(
        &self,
        signing_bytes: &[u8],
    ) -> std::result::Result<Vec<u8>, ssi_claims::SignatureError> {
        let (_verification_method_record, signer_bytes) = self
            .wallet
            .get_locally_controlled_verification_method(
                did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                    did_o: Some(self.key_fully_qualified.did().to_owned()),
                    key_purpose_o: Some(self.key_purpose),
                    version_id_o: Some(self.key_fully_qualified.query_version_id()),
                    key_id_o: Some(self.key_fully_qualified.fragment().to_string()),
                    result_limit_o: None,
                },
            )
            .await
            .map_err(|e| ssi_claims::SignatureError::Other(e.to_string()))?;
        use signature_dyn::SignerT;
        Ok(signer_bytes
            .try_sign_message(signing_bytes)
            .map_err(|e| ssi_claims::SignatureError::Other(e.to_string()))?
            .to_signature_bytes()
            .bytes()
            .to_vec())
    }
}

//
// Code below here is for LDP signing (LDP-formatted VCs and VPs)
//

impl<W: Wallet + Clone> ssi_verification_methods::Signer<ssi_verification_methods::AnyMethod>
    for WalletBasedSigner<W>
{
    type MessageSigner = Self;

    async fn for_method(
        &self,
        method: Cow<'_, ssi_verification_methods::AnyMethod>,
    ) -> std::result::Result<Option<Self::MessageSigner>, ssi_claims::SignatureError> {
        if method.id().as_str() == self.key_fully_qualified.as_str() {
            Ok(Some(self.clone()))
        } else {
            Ok(None)
        }
    }
}

impl<W: Wallet> ssi_verification_methods::MessageSigner<AnySignatureAlgorithm>
    for WalletBasedSigner<W>
{
    async fn sign(
        self,
        WithProtocol(algorithm_instance, protocol): <AnySignatureAlgorithm as ssi_crypto::algorithm::SignatureAlgorithmType>::Instance,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, ssi_claims::MessageSignatureError> {
        use ssi_jws::JwsSigner;

        // Validate that the algorithm matches our key's algorithm
        let expected_jose = match algorithm_instance {
            ssi_crypto::AlgorithmInstance::EdDSA => signature_dyn::ED25519_JOSE_ALGORITHM,
            ssi_crypto::AlgorithmInstance::ES256 => signature_dyn::P256_JOSE_ALGORITHM,
            ssi_crypto::AlgorithmInstance::ES384 => signature_dyn::P384_JOSE_ALGORITHM,
            ssi_crypto::AlgorithmInstance::ES256K => signature_dyn::SECP256K1_JOSE_ALGORITHM,
            _ => {
                return Err(ssi_claims::MessageSignatureError::UnsupportedAlgorithm(
                    algorithm_instance.algorithm().as_str().to_string(),
                ));
            }
        };
        let key_type = self.verifier_bytes.key_type();
        if key_type.jose_algorithm() != expected_jose {
            return Err(ssi_claims::MessageSignatureError::UnsupportedAlgorithm(
                format!(
                    "algorithm mismatch: key uses {}, suite requires {}",
                    key_type.jose_algorithm(),
                    expected_jose
                ),
            ));
        }

        let message = protocol.prepare_message(message);
        let signature = self
            .sign_bytes(&message)
            .await
            .map_err(|e| ssi_claims::MessageSignatureError::SignatureFailed(e.to_string()))?;
        protocol.encode_signature(algorithm_instance.algorithm(), signature)
    }
}
