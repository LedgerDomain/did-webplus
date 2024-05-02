use std::borrow::Cow;

use did_webplus::{DIDWithQueryAndKeyIdFragment, Error, KeyPurpose, RequestedDIDDocumentMetadata};

use crate::Resolver;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JWSHeader {
    pub alg: String,
    pub kid: DIDWithQueryAndKeyIdFragment,
}

/// Light and minimal JWS implementation for mock purposes.  Not intended to be complete or secure.
/// Correctness and interoperability with other impls of JWS has not been tested.
#[derive(Clone, Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct JWS<'j> {
    pub header: JWSHeader,
    pub payload_byte_v: Cow<'j, [u8]>,
    pub signature_byte_v: Vec<u8>,
}

impl<'j> JWS<'j> {
    pub fn decoded_from_str(jws_str: &str) -> Result<Self, Error> {
        use std::str::FromStr;
        Self::from_str(jws_str)
    }
    /// Verify the JWS, returning the time range of validity of the DID document.
    /// If the resolved DID document is the latest, then the end bound on the range will
    /// be std::ops::Bound::Unbounded.
    pub fn verify(
        &self,
        verification_key_purpose: KeyPurpose,
        resolver: &mut dyn Resolver,
    ) -> Result<std::ops::Range<std::ops::Bound<time::OffsetDateTime>>, Error> {
        let did = self.header.kid.without_fragment().without_query();
        let key_id = &self.header.kid.fragment();
        if self.header.kid.query_self_hash_o().is_none() {
            return Err(Error::Malformed(
                "JWS header 'kid' field is missing 'selfHash'",
            ));
        }
        if self.header.kid.query_version_id_o().is_none() {
            return Err(Error::Invalid(
                "JWS header 'kid' field is missing 'versionId'",
            ));
        }

        // TODO: Minimal RequestedDIDDocumentMetadata
        let (did_document, did_document_metadata) = resolver.resolve_did_document(
            &did,
            self.header.kid.query_self_hash_o(),
            self.header.kid.query_version_id_o(),
            RequestedDIDDocumentMetadata::all(),
        )?;

        println!("key_id: {}", key_id);
        println!("did_document:\n{}", did_document.to_json_pretty());
        println!(
            "did_document.public_key_material().key_id_fragments_for_purpose(verification_key_purpose): {:#?}",
            did_document
                .public_key_material()
                .key_id_fragments_for_purpose(verification_key_purpose)
        );

        if !did_document
            .public_key_material()
            .key_id_fragments_for_purpose(verification_key_purpose)
            .contains(&key_id)
        {
            return Err(Error::Invalid("JWS signing key is not present in expected verification key purpose in resolved DID document"));
        }

        // Form the validity time range of the DID document.
        let valid_from = std::ops::Bound::Included(did_document.valid_from());
        let valid_until = if let Some(next_update) = did_document_metadata
            .idempotent_o
            .expect("programmer error")
            .next_update_o
        {
            std::ops::Bound::Excluded(next_update)
        } else {
            std::ops::Bound::Unbounded
        };

        Ok(std::ops::Range {
            start: valid_from,
            end: valid_until,
        })
    }
    /// Produce a JWS with the given bytes as a payload (payload_byte_v will be base64-encoded)
    pub fn signed(
        kid: DIDWithQueryAndKeyIdFragment,
        payload_byte_v: &'j [u8],
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
        let alg = match signer.signature_algorithm().named_signature_algorithm() {
            selfsign::NamedSignatureAlgorithm::ED25519_SHA_512 => "EdDSA".to_string(),
            selfsign::NamedSignatureAlgorithm::SECP256K1_SHA_256 => "ES256K".to_string(),
            _ => return Err(Error::Malformed("Unsupported signature algorithm for JWS")),
        };
        Ok(JWS {
            header: JWSHeader { alg, kid },
            payload_byte_v: Cow::Borrowed(payload_byte_v),
            signature_byte_v: signer
                .sign_message(payload_byte_v)?
                .to_signature_bytes()
                .to_vec(),
        })
    }
    /// Encode the DecodedJWS as a string as
    /// base64url(json(header)) || '.' || base64url(payload_byte_v) || '.' || base64url(signature_byte_v)
    pub fn encoded_to_string(&self) -> String {
        let mut message = String::new();
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(
            serde_json::to_string(&self.header)
                .expect("pass")
                .as_bytes(),
            &mut message,
        );
        message.push('.');
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode_string(&self.payload_byte_v, &mut message);
        message.push('.');
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode_string(&self.signature_byte_v, &mut message);
        message
    }
}

impl std::fmt::Display for JWS<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This is a little wasteful in that it allocates a string just to print it.
        // It would be better to have the base64 encoders write directly to the Formatter.
        write!(f, "{}", self.encoded_to_string())
    }
}

impl std::str::FromStr for JWS<'_> {
    type Err = Error;
    fn from_str(jws_str: &str) -> Result<Self, Self::Err> {
        let mut jws_parts = jws_str.split('.');
        let header_base64 = jws_parts
            .next()
            .ok_or(Error::Malformed("JWS missing header"))?;
        let payload_base64 = jws_parts
            .next()
            .ok_or(Error::Malformed("JWS missing payload"))?;
        let signature_base64 = jws_parts
            .next()
            .ok_or(Error::Malformed("JWS missing signature"))?;
        if jws_parts.next().is_some() {
            return Err(Error::Malformed("JWS has too many parts"));
        }

        println!("header_base64: {}", header_base64);
        println!("payload_base64: {}", payload_base64);
        println!("signature_base64: {}", signature_base64);

        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_base64)
            .map_err(|_| Error::Malformed("JWS header is not valid base64"))?;
        println!("header: {}", std::str::from_utf8(&header).unwrap());
        let header: JWSHeader = serde_json::from_slice(&header).map_err(|e| {
            println!("e: {}", e);
            Error::Malformed("JWS header failed to decode into JSON")
        })?;
        let payload_byte_v = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_base64)
            .map_err(|_| Error::Malformed("JWS payload is not valid base64"))?;
        let signature_byte_v = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_base64)
            .map_err(|_| Error::Malformed("JWS signature is not valid base64"))?;
        Ok(JWS {
            header,
            payload_byte_v: Cow::Owned(payload_byte_v),
            signature_byte_v,
        })
    }
}
