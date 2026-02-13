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
    /// Specifies the key ID that will be used to select the signing key.
    key_id: did_webplus_core::DIDKeyResourceFullyQualified,
    /// Specifies the JOSE algorithm for this key.
    jose_algorithm: &'static str,
}

impl<W: Wallet> WalletBasedSigner<W> {
    /// This will fetch the latest DID document for the DID being used to sign, and then get the appropriate signing key.
    /// If the filter doesn't match exactly one verification method record, then an error will be returned.
    pub async fn new(
        wallet: W,
        did: &did_webplus_core::DIDStr,
        key_purpose: did_webplus_core::KeyPurpose,
        key_id_o: Option<&str>,
        http_options_o: Option<&did_webplus_core::HTTPOptions>,
    ) -> Result<Self> {
        wallet.fetch_did(did, http_options_o).await?;
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
        let key_id = verification_method_record.did_key_resource_fully_qualified;
        use signature_dyn::SignerDynT;
        let jose_algorithm = signer_bytes.jose_algorithm();
        Ok(Self {
            wallet,
            key_purpose,
            key_id,
            jose_algorithm,
        })
    }
    pub fn key_purpose(&self) -> did_webplus_core::KeyPurpose {
        self.key_purpose
    }
    pub fn key_id(&self) -> &did_webplus_core::DIDKeyResourceFullyQualifiedStr {
        &self.key_id
    }
}

// For signing JWS and JWT (plain JWT, but also VC-JWT and VP-JWT)
impl<W: Wallet> ssi_jws::JwsSigner for WalletBasedSigner<W> {
    async fn fetch_info(
        &self,
    ) -> std::result::Result<ssi_jws::JwsSignerInfo, ssi_claims::SignatureError> {
        // Have to convert the JOSE algorithm to an ssi_jws::Algorithm.
        // NOTE: ssi-jwk crate does not support all the algorithms that did:webplus does.
        let algorithm = match self.jose_algorithm {
            signature_dyn::ED25519_JOSE_ALGORITHM => ssi_jwk::Algorithm::EdDSA,
            signature_dyn::P256_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES256,
            signature_dyn::P384_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES384,
            // signature_dyn::P521_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES512,
            signature_dyn::SECP256K1_JOSE_ALGORITHM => ssi_jwk::Algorithm::ES256K,
            _ => {
                return Err(ssi_claims::SignatureError::Other(format!(
                    "unsupported JOSE algorithm: {:?}",
                    self.jose_algorithm
                )));
            }
        };
        Ok(ssi_jws::JwsSignerInfo {
            key_id: Some(self.key_id.to_string()),
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
                    did_o: Some(self.key_id.did().to_owned()),
                    key_purpose_o: Some(self.key_purpose),
                    version_id_o: None,
                    key_id_o: Some(self.key_id.to_string()),
                    result_limit_o: None,
                },
            )
            .await
            .map_err(|e| ssi_claims::SignatureError::Other(e.to_string()))?;
        use signature_dyn::SignerDynT;
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
        let method_id = method.id().as_str();
        let our_key_id = self.key_id.to_string();
        if method_id == our_key_id {
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
        if self.jose_algorithm != expected_jose {
            return Err(ssi_claims::MessageSignatureError::UnsupportedAlgorithm(
                format!(
                    "algorithm mismatch: key uses {}, suite requires {}",
                    self.jose_algorithm, expected_jose
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
