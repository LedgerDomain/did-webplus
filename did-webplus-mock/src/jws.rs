use crate::Resolver;
use base64::Engine;
use did_webplus::{
    DIDDocument, DIDDocumentMetadata, DIDKeyResourceFullyQualified, Error, KeyPurpose,
    RequestedDIDDocumentMetadata,
};
use std::{borrow::Cow, io::Write};

/// See RFC 7515, https://datatracker.ietf.org/doc/html/rfc7515
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JWSHeader {
    /// Signature algorithm used to sign the JWS.
    pub alg: String,
    /// Specifies the precise key used to sign the JWS by specifying the selfHash and versionId of the DID document
    /// and the ID of the public key.
    pub kid: DIDKeyResourceFullyQualified,
    /// Specifies critical headers that must be understood and processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// If present, then specifies if the payload is base64url-encoded or not.  This is used in combination
    /// with the "b64" element of the "crit" field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b64: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JWSPayloadPresence {
    /// The payload is included within the JWS.
    Attached,
    /// The payload is not included within the JWS.
    Detached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JWSPayloadEncoding {
    /// No encoding.
    None,
    /// This really means base64url-no-pad encoding.
    Base64URL,
}

/// This is the compact, encoded form of a JWS (JWS Compact Serialization).  Has the form:
/// <base64url(JSON(header))>.<base64url(payload)>.<base64url(signature)> if encoded, attached payload,
/// or <base64url(JSON(header))>.<payload>.<base64url(signature)> if unencoded, attached payload,
/// or <base64url(JSON(header))>..<base64url(signature)> if detached payload,
/// See RFC 7515 Section 7.1 https://datatracker.ietf.org/doc/html/rfc7515#section-7.1
/// Here, base64url(x) is the base64url-no-pad encoding of x.
#[derive(Clone, Debug)]
pub struct JWS<'j> {
    /// String representation of the JWS Compact Serialization.
    string: Cow<'j, str>,
    /// Parsed header.
    header: JWSHeader,
    /// Parsed signature.
    signature_bytes: selfsign::SignatureBytes<'static>,
}

impl<'j> JWS<'j> {
    pub fn into_string(self) -> String {
        self.string.into_owned()
    }
}

impl<'j> JWS<'j> {
    /// Return a reference to the str representation of the JWS Compact Serialization.
    pub fn as_str(&self) -> &str {
        self.string.as_ref()
    }
    /// This is the input to the signature algorithm: the concatenation of the base64url-encoded header,
    /// a period ('.') and the payload (which comes from detached_payload_bytes_o if Some(_), otherwise
    /// from the JWS itself).  If detached_payload_bytes_o is Some(_), then self.payload() must be the
    /// empty string.
    fn write_signing_input(
        &self,
        writer: &mut dyn std::io::Write,
        detached_payload_bytes_o: Option<&mut dyn std::io::Read>,
    ) -> Result<(), Error> {
        // Write the base64url-encoded header.
        writer
            .write_all(self.raw_header_base64().as_bytes())
            .map_err(|_| Error::Serialization("error while writing header"))?;
        // Write the '.' separator.
        writer
            .write_all(&[0x2Eu8])
            .map_err(|_| Error::Serialization("error while writing '.' separator"))?;

        if let Some(detached_payload_bytes) = detached_payload_bytes_o {
            if !self.raw_attached_payload_str().is_empty() {
                panic!("detached_payload_bytes_o must be None if the payload is not empty");
            }
            if self.payload_is_base64url_encoded() {
                let mut base64url_encoder = base64::write::EncoderWriter::new(
                    writer,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                );
                std::io::copy(detached_payload_bytes, &mut base64url_encoder).map_err(|_| {
                    Error::Serialization("error while writing base64url-encoded payload")
                })?;
            } else {
                std::io::copy(detached_payload_bytes, writer)
                    .map_err(|_| Error::Serialization("error while writing payload"))?;
            }
        } else {
            // Here, because the payload is attached, it's already in its signing input form,
            // so just write it.
            writer
                .write_all(self.raw_attached_payload_str().as_bytes())
                .map_err(|_| Error::Serialization("error while writing attached payload"))?;
        }
        Ok(())
    }
    /// This is the base64url-encoded header, which is the substring of the JWS Compact Serialization up to the
    /// first '.' separator.
    pub fn raw_header_base64(&self) -> &str {
        self.string.split('.').next().unwrap()
    }
    /// Returns the parsed header.
    pub fn header(&self) -> &JWSHeader {
        &self.header
    }
    /// Indicates if the payload should be base64url-encoded in producing the signing input.
    pub fn payload_is_base64url_encoded(&self) -> bool {
        // None, which is the default, is interpreted as true.
        self.header.b64 != Some(false)
    }
    /// This is the attached payload, which is the value between the two '.' separators in the JWS.
    /// In the case of a detached payload, this will be an empty string.  However, an attached payload can
    /// also be an empty string.
    pub fn raw_attached_payload_str(&self) -> &str {
        self.string.split('.').nth(1).unwrap()
    }
    /// Returns a reader into the decoded payload bytes.  If detached_payload_bytes_o is Some(_), then the
    /// payload is detached, and the payload is read from detached_payload_bytes_o.  Otherwise, the payload
    /// is considered to be attached, and the payload is read from the JWS itself.
    pub fn decoded_payload_bytes<'r, 's: 'r>(
        &'s self,
        detached_payload_bytes_o: Option<&'r mut dyn std::io::Read>,
    ) -> Box<dyn std::io::Read + 'r>
    where
        'j: 'r,
    {
        if let Some(detached_payload_bytes) = detached_payload_bytes_o {
            if !self.raw_attached_payload_str().is_empty() {
                panic!("detached_payload_bytes_o must be None if the payload is not empty");
            }
            if self.payload_is_base64url_encoded() {
                Box::new(base64::read::DecoderReader::new(
                    detached_payload_bytes,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                ))
            } else {
                Box::new(detached_payload_bytes)
            }
        } else {
            if self.payload_is_base64url_encoded() {
                Box::new(base64::read::DecoderReader::new(
                    &*self.raw_attached_payload_str().as_bytes(),
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                ))
            } else {
                Box::new(&*self.raw_attached_payload_str().as_bytes())
            }
        }
    }
    /// This parses the payload as the given type, base64url-decoding the payload first if necessary.
    pub fn parsed_decoded_payload<'r, 's: 'r, T: serde::de::DeserializeOwned>(
        &'s self,
        detached_payload_bytes_o: Option<&'r mut dyn std::io::Read>,
    ) -> Result<T, Error> {
        serde_json::from_reader(self.decoded_payload_bytes(detached_payload_bytes_o))
            .map_err(|_| Error::Malformed("JWS payload failed to parse as expected JSON structure"))
    }
    /// This is the base64url-encoded signature, which is the substring of the JWS Compact Serialization after
    /// the second '.' separator.
    pub fn raw_signature_base64(&self) -> &str {
        self.string.split('.').nth(2).unwrap()
    }
    /// This is the parsed signature.
    pub fn signature_bytes(&self) -> &selfsign::SignatureBytes {
        &self.signature_bytes
    }
    /// Generate a JWS Compact Serialization from the given header and payload, optionally encoding the given
    /// payload bytes, and then signing the signing input using the given signer.
    pub fn signed(
        kid: DIDKeyResourceFullyQualified,
        payload_bytes: &mut dyn std::io::Read,
        payload_presence: JWSPayloadPresence,
        payload_encoding: JWSPayloadEncoding,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self, Error> {
        let alg = signer
            .signature_algorithm()
            .named_signature_algorithm()
            .as_jws_alg()
            .to_string();

        let (crit, b64) = if payload_encoding == JWSPayloadEncoding::Base64URL {
            (None, None)
        } else {
            (Some(vec![String::from("b64")]), Some(false))
        };
        let header = JWSHeader {
            alg,
            kid,
            crit,
            b64,
        };

        // The signing input is `base64url(json(header)) || '.' || base64url(payload)`
        // if the payload is encoded (see RFC 7515, https://datatracker.ietf.org/doc/html/rfc7515)
        // or `base64url(json(header)) || '.' || payload` if the payload is not encoded.

        // This will be the buffer that holds the JWS compact serialization representation.
        let mut jws_string_byte_v = Vec::new();
        // This will accept the signing input.
        let mut hasher_b = signer
            .signature_algorithm()
            .message_digest_hash_function()
            .new_hasher();

        // Write the header and separator into the hasher and into the jws_string_byte_v array.
        {
            let mut tee_writer = TeeWriter(&mut hasher_b, &mut jws_string_byte_v);
            {
                let mut base64url_encoder = base64::write::EncoderWriter::new(
                    &mut tee_writer,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                );
                serde_json::to_writer(&mut base64url_encoder, &header)
                    .map_err(|_| Error::Serialization("JSON error"))?;
            }
            // Write the concatenation separator
            tee_writer
                .write_all(&[0x2Eu8])
                .map_err(|_| Error::Serialization("error in writing separator"))?;
        }
        // Write the payload
        {
            // Decide which writers the payload should be written to.
            let writer_b: Box<dyn std::io::Write> = match payload_presence {
                JWSPayloadPresence::Attached => {
                    Box::new(TeeWriter(&mut hasher_b, &mut jws_string_byte_v))
                }
                JWSPayloadPresence::Detached => Box::new(hasher_b.as_mut()),
            };
            // Apply an encoder, if necessary.
            let mut writer_b = match payload_encoding {
                JWSPayloadEncoding::None => writer_b,
                JWSPayloadEncoding::Base64URL => Box::new(base64::write::EncoderWriter::new(
                    writer_b,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                )),
            };
            // Write the payload.
            std::io::copy(payload_bytes, writer_b.as_mut())
                .map_err(|_| Error::Serialization("error in reading payload bytes"))?;
        }

        // Sign the digest.
        let signature_bytes = signer
            .sign_digest(hasher_b)?
            .to_signature_bytes()
            .into_owned();
        log::debug!(
            "JWS::signed; signature_bytes.len(): {}",
            signature_bytes.len()
        );

        // Append the separator character and base64url-encoded signature.
        {
            jws_string_byte_v.push(0x2Eu8);
            base64::write::EncoderWriter::new(
                &mut jws_string_byte_v,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            )
            .write_all(signature_bytes.as_ref())
            .map_err(|_| Error::Serialization("error in base64url-encoding signature"))?;
        }

        // Convert the byte vector to a string.  By construction, this should not fail.
        let jws_string = String::from_utf8(jws_string_byte_v).unwrap();

        Ok(Self {
            string: jws_string.into(),
            header,
            signature_bytes,
        })
    }
    /// Verifies the JWS using the given verifier.  detached_payload_bytes_o should be Some(_) if it's a
    /// detached payload, and None if it's an attached payload.
    pub fn verify(
        &self,
        verifier: &dyn selfsign::Verifier,
        detached_payload_bytes_o: Option<&mut dyn std::io::Read>,
    ) -> Result<(), Error> {
        let named_signature_algorithm =
            selfsign::NamedSignatureAlgorithm::try_from_jws_alg(self.header.alg.as_str())
                .map_err(|_| Error::Invalid("JWS alg not supported"))?;
        let mut hasher_b = named_signature_algorithm
            .as_signature_algorithm()
            .message_digest_hash_function()
            .new_hasher();
        self.write_signing_input(&mut hasher_b, detached_payload_bytes_o)?;
        verifier.verify_digest(hasher_b, &self.signature_bytes)?;
        Ok(())
    }
}

impl<'j> std::ops::Deref for JWS<'j> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.string.as_ref()
    }
}

impl<'j> std::fmt::Display for JWS<'j> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.string.as_ref())
    }
}

impl<'j> TryFrom<String> for JWS<'j> {
    type Error = Error;
    fn try_from(jws_string: String) -> Result<Self, Self::Error> {
        Self::try_from(Cow::Owned(jws_string))
    }
}

impl<'j> TryFrom<&'j str> for JWS<'j> {
    type Error = Error;
    fn try_from(jws_str: &'j str) -> Result<Self, Self::Error> {
        Self::try_from(Cow::Borrowed(jws_str))
    }
}

impl<'j> TryFrom<Cow<'j, str>> for JWS<'j> {
    type Error = Error;
    fn try_from(jws_str: Cow<'j, str>) -> Result<Self, Self::Error> {
        let mut split = jws_str.split('.');

        let header_base64 = split.next().ok_or(Error::Malformed("JWS missing header"))?;
        let payload_base64 = split
            .next()
            .ok_or(Error::Malformed("JWS missing payload"))?;
        let signature_base64 = split
            .next()
            .ok_or(Error::Malformed("JWS missing signature"))?;
        if split.next().is_some() {
            return Err(Error::Malformed("JWS has too many parts"));
        }

        if !is_base64urlnopad_encoded(header_base64) {
            return Err(Error::Malformed("JWS header is not base64urlnopad-encoded"));
        }
        if !is_base64urlnopad_encoded(payload_base64) {
            return Err(Error::Malformed(
                "JWS payload is not base64urlnopad-encoded",
            ));
        }
        if !is_base64urlnopad_encoded(signature_base64) {
            return Err(Error::Malformed(
                "JWS signature is not base64urlnopad-encoded",
            ));
        }

        let header = serde_json::from_reader::<_, JWSHeader>(base64::read::DecoderReader::new(
            header_base64.as_bytes(),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ))
        .map_err(|_| Error::Malformed("JWS header failed to parse as expected JSON structure"))?;

        let named_signature_algorithm =
            selfsign::NamedSignatureAlgorithm::try_from_jws_alg(header.alg.as_str())
                .map_err(|_| Error::Malformed("Unsupported JWS alg"))?;
        let signature_byte_v = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_base64.as_bytes())
            .map_err(|_| Error::Malformed("JWS signature failed to parse"))?;

        let signature_bytes = selfsign::SignatureBytes {
            named_signature_algorithm,
            signature_byte_v: signature_byte_v.into(),
        };

        Ok(JWS {
            string: jws_str,
            header,
            signature_bytes,
        })
    }
}

/// Resolves the DID of the signer to the appropriate DID document, then uses the appropriate public key
/// to verify the signature.  If the verification succeeds, then the resolved DID document is returned, along
/// with the metadata of the DID document.  This can be used to check other constraints pertaining to the
/// DID document, such as the KeyPurpose of the signing key or its validity time range.
pub fn resolve_did_and_verify_jws<'r, 'p>(
    jws: &JWS<'_>,
    resolver: &'r mut dyn Resolver,
    verification_key_purpose: KeyPurpose,
    requested_did_document_metadata: RequestedDIDDocumentMetadata,
    detached_payload_bytes_o: Option<&'p mut dyn std::io::Read>,
) -> Result<(Cow<'r, DIDDocument>, DIDDocumentMetadata), Error> {
    let kid_without_fragment = jws.header.kid.without_fragment();
    let did = kid_without_fragment.did();
    // This will not allocate once DIDFragmentStr exists
    let key_id = jws.header.kid.fragment();

    log::debug!(
        "resolve_did_and_verify_jws; JWS kid field is DID query: {}",
        jws.header.kid
    );
    let (did_document, did_document_metadata) = resolver.resolve_did_document(
        did,
        Some(jws.header.kid.query_self_hash()),
        Some(jws.header.kid.query_version_id()),
        requested_did_document_metadata,
    )?;
    log::trace!("resolved DID document: {:?}", did_document);
    log::trace!(
        "resolved DID document metadata: {:?}",
        did_document_metadata
    );
    // TODO: Probably sanity-check that the DIDDocument is valid (i.e. all its DID-specific constraints are satisfied),
    // though this should be guaranteed by the resolver.  In particular, that each key_id listed in each verification
    // key purpose is present in the verification method list of the DID document.

    if !did_document
        .public_key_material()
        .key_id_fragments_for_purpose(verification_key_purpose)
        .contains(&key_id)
    {
        return Err(Error::Invalid(
            "signing key is not present in specified verification method in resolved DID document",
        ));
    }

    // Retrieve the appropriate verifier from the DID document.
    let verification_method = did_document
        .public_key_material()
        .verification_method_v
        .iter()
        .find(|&verification_method| verification_method.id.fragment() == key_id)
        .expect("programmer error: this key_id should be present in the verification method list; this should have been guaranteed by the resolver");
    let verifier = selfsign::KERIVerifier::try_from(&verification_method.public_key_jwk)?;

    // Finally, verify the signature using the resolved verifier.
    jws.verify(&verifier, detached_payload_bytes_o)?;

    Ok((did_document, did_document_metadata))
}

fn is_base64urlnopad_encoded(s: &str) -> bool {
    // Base64urlnopad encoding is a subset of base64 encoding, so we can just check for the presence of
    // characters that are not in the base64url-nopad alphabet.
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

struct TeeWriter<'a>(&'a mut dyn std::io::Write, &'a mut dyn std::io::Write);

impl<'a> Write for TeeWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        self.1.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()?;
        self.1.flush()
    }
}
