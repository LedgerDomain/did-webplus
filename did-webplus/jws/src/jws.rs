use crate::{
    error, require, Error, JOSEAlgorithmT, JWSHeader, JWSPayloadEncoding, JWSPayloadPresence,
    Result,
};
use base64::Engine;
use std::{borrow::Cow, io::Write};

/// This is the compact, encoded form of a JWS (JWS Compact Serialization).  Has the form:
/// <base64url(JSON(header))>.<base64url(payload)>.<base64url(signature)> if encoded, attached payload,
/// or <base64url(JSON(header))>.<payload>.<base64url(signature)> if unencoded, attached payload,
/// or <base64url(JSON(header))>..<base64url(signature)> if detached payload,
/// See RFC 7515 Section 7.1 https://datatracker.ietf.org/doc/html/rfc7515#section-7.1
/// Here, base64url(x) is the base64url-no-pad encoding of x.
// TODO: Impl Zeroize (how does this work with Cow?  Maybe it doesn't and Cow should not be used)
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
    ) -> Result<()> {
        // Write the base64url-encoded header.
        writer
            .write_all(self.raw_header_base64().as_bytes())
            .map_err(|e| error!("error while writing header: {}", e))?;

        // Write the '.' separator.
        writer
            .write_all(b".".as_slice())
            .map_err(|e| error!("error while writing '.' separator: {}", e))?;

        if let Some(detached_payload_bytes) = detached_payload_bytes_o {
            require!(
                self.raw_attached_payload_str().is_empty(),
                "if the JWS payload is not empty, then no detached payload may be specified"
            );
            if self.payload_is_base64url_encoded() {
                let mut base64url_encoder = base64::write::EncoderWriter::new(
                    writer,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                );
                std::io::copy(detached_payload_bytes, &mut base64url_encoder)
                    .map_err(|e| error!("error while writing base64url-encoded payload: {}", e))?;
            } else {
                std::io::copy(detached_payload_bytes, writer)
                    .map_err(|e| error!("error while writing payload: {}", e))?;
            }
        } else {
            // Here, because the payload is attached, it's already in its signing input form,
            // so just write it.
            writer
                .write_all(self.raw_attached_payload_str().as_bytes())
                .map_err(|e| error!("error while writing attached payload: {}", e))?;
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
    ) -> Result<T> {
        serde_json::from_reader(self.decoded_payload_bytes(detached_payload_bytes_o)).map_err(|e| {
            error!(
                "JWS payload failed to parse as expected JSON structure: {}",
                e
            )
        })
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
        kid: String,
        // kid: DIDKeyResourceFullyQualified,
        payload_bytes: &mut dyn std::io::Read,
        payload_presence: JWSPayloadPresence,
        payload_encoding: JWSPayloadEncoding,
        signer: &dyn selfsign::Signer,
    ) -> Result<Self> {
        let alg = signer
            .signature_algorithm()
            .named_signature_algorithm()
            .as_jws_alg()
            .to_string();

        let (crit, b64) = if payload_encoding == JWSPayloadEncoding::Base64 {
            (None, None)
        } else {
            (Some(vec![String::from("b64")]), Some(false))
        };
        let header = JWSHeader {
            alg,
            crv_o: None,
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
                    .map_err(|e| error!("error while writing JWS header: {}", e))?;
            }
            // Write the concatenation separator
            tee_writer
                .write_all(&[0x2Eu8])
                .map_err(|e| error!("error in writing JWS separator: {}", e))?;
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
                JWSPayloadEncoding::Base64 => Box::new(base64::write::EncoderWriter::new(
                    writer_b,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                )),
            };
            // Write the payload.
            std::io::copy(payload_bytes, writer_b.as_mut())
                .map_err(|e| error!("error in reading JWS payload bytes: {}", e))?;
        }

        // Sign the digest.
        let signature_bytes = signer
            .sign_digest(hasher_b)
            .map_err(|e| error!("error while signing JWS digest: {}", e))?
            .to_signature_bytes()
            .into_owned();

        // Append the separator character and base64url-encoded signature.
        {
            jws_string_byte_v.push(0x2Eu8);
            base64::write::EncoderWriter::new(
                &mut jws_string_byte_v,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            )
            .write_all(signature_bytes.as_ref())
            .map_err(|e| error!("error in base64url-encoding JWS signature: {}", e))?;
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
    ) -> Result<()> {
        let named_signature_algorithm =
            selfsign::NamedSignatureAlgorithm::try_from_jws_alg(self.header.alg.as_str())
                .map_err(|e| error!("JWS alg not supported: {}", e))?;
        let mut hasher_b = named_signature_algorithm
            .as_signature_algorithm()
            .message_digest_hash_function()
            .new_hasher();
        self.write_signing_input(&mut hasher_b, detached_payload_bytes_o)
            .map_err(|e| error!("error while writing JWS signing input: {}", e))?;
        verifier
            .verify_digest(hasher_b, &self.signature_bytes)
            .map_err(|e| error!("JWS failed to verify; error was: {}", e))?;
        Ok(())
    }
    /// Generate a JWS Compact Serialization from the given header and payload, optionally encoding the given
    /// payload bytes, and then signing the signing input using the given signer.
    pub fn signed2<
        Signature: std::fmt::Debug + signature::SignatureEncoding,
        Signer: signature::Signer<Signature> + JOSEAlgorithmT,
    >(
        kid: String,
        payload_bytes: &mut dyn std::io::Read,
        payload_presence: JWSPayloadPresence,
        payload_encoding: JWSPayloadEncoding,
        signer: &Signer,
    ) -> Result<Self> {
        let (crit, b64) = if payload_encoding == JWSPayloadEncoding::Base64 {
            (None, None)
        } else {
            (Some(vec![String::from("b64")]), Some(false))
        };
        let header = JWSHeader {
            alg: signer.alg(),
            crv_o: signer.crv_o(),
            kid,
            crit,
            b64,
        };

        // The signing input is `base64url(json(header)) || '.' || base64url(payload)`
        // if the payload is encoded (see RFC 7515, https://datatracker.ietf.org/doc/html/rfc7515)
        // or `base64url(json(header)) || '.' || payload` if the payload is not encoded.

        // This is the message that will be signed.
        let mut signing_input = Vec::<u8>::new();

        // This is the JWS that will be returned.
        let mut jws = Vec::<u8>::new();

        // Write base64url(json(header)) into both the signing_input and the JWS,
        let mut tee_writer = TeeWriter(&mut signing_input, &mut jws);
        {
            let mut base64url_encoder = base64::write::EncoderWriter::new(
                &mut tee_writer,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            );
            serde_json::to_writer(&mut base64url_encoder, &header)
                .map_err(|e| error!("error while writing JWS header: {}", e))?;
        }

        // Write the concatenation separator '.' into both the signing_input and the JWS.
        tee_writer
            .write_all(b".".as_slice())
            .map_err(|e| error!("error in writing JWS separator: {}", e))?;

        if payload_presence == JWSPayloadPresence::Attached {
            // If the payload is to be attached, then write the payload into both the signing_input and the JWS.
            if payload_encoding == JWSPayloadEncoding::Base64 {
                // If the payload is to be encoded, then pipe it through the base64url encoder.
                let mut base64url_encoder = base64::write::EncoderWriter::new(
                    &mut tee_writer,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                );
                std::io::copy(payload_bytes, &mut base64url_encoder)
                    .map_err(|e| error!("error in writing encoded, attached JWS payload: {}", e))?;
            } else {
                std::io::copy(payload_bytes, &mut tee_writer).map_err(|e| {
                    error!("error in writing unencoded, attached JWS payload: {}", e)
                })?;
            }
        } else {
            // If the payload is to be detached, then write the payload only into the signing_input.
            if payload_encoding == JWSPayloadEncoding::Base64 {
                let mut base64url_encoder = base64::write::EncoderWriter::new(
                    &mut signing_input,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                );
                std::io::copy(payload_bytes, &mut base64url_encoder)
                    .map_err(|e| error!("error in writing encoded, detached JWS payload: {}", e))?;
            } else {
                std::io::copy(payload_bytes, &mut signing_input).map_err(|e| {
                    error!("error in writing unencoded, detached JWS payload: {}", e)
                })?;
            }
        }

        // Sign the signing_input.
        let signature = signer.sign(signing_input.as_slice());
        let signature_byte_v = signature.to_vec();

        // Write the concatenation separator '.' into the JWS.
        jws.push(b'.');

        // Write the base64url-encoded signature into the JWS.
        base64::write::EncoderWriter::new(
            &mut jws,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        )
        .write_all(signature_byte_v.as_ref())
        .map_err(|e| error!("error in base64url-encoding JWS signature: {}", e))?;

        // Convert the byte vector to a string.  By construction, this should not fail.
        let jws_string = String::from_utf8(jws).unwrap();

        let named_signature_algorithm = match header.alg.as_str() {
            // "ES256" => selfsign::NamedSignatureAlgorithm::...
            "ES256K" => selfsign::NamedSignatureAlgorithm::SECP256K1_SHA_256,
            "EdDSA" => match header.crv_o.as_deref() {
                Some("Ed25519") => selfsign::NamedSignatureAlgorithm::ED25519_SHA_512,
                // Some("Ed448") => selfsign::NamedSignatureAlgorithm::...
                Some(crv) => return Err(error!("Unsupported JWS EdDSA crv: {:?}", crv)),
                None => return Err(error!("JWS EdDSA crv is required")),
            },
            _ => return Err(error!("Unsupported JWS alg: {}", header.alg)),
        };

        Ok(Self {
            string: jws_string.into(),
            header,
            signature_bytes: selfsign::SignatureBytes {
                named_signature_algorithm,
                signature_byte_v: std::borrow::Cow::Owned(signature_byte_v),
            },
        })
    }
    /// Verifies the JWS using the given verifier.  detached_payload_bytes_o should be Some(_) if it's a
    /// detached payload, and None if it's an attached payload.
    pub fn verify2<
        Signature: std::fmt::Debug + signature::SignatureEncoding,
        Verifier: signature::Verifier<Signature> + JOSEAlgorithmT,
    >(
        &self,
        verifier: &Verifier,
        detached_payload_bytes_o: Option<&mut dyn std::io::Read>,
    ) -> Result<()> {
        // Verify the JWS alg and crv fields match the verifier.
        require!(
            self.header.alg == verifier.alg(),
            "JWS alg {:?} does not match that of the verifier {:?}",
            self.header.alg,
            verifier.alg()
        );
        require!(
            self.header.crv_o == verifier.crv_o(),
            "JWS crv {:?} does not match that of the verifier {:?}",
            self.header.crv_o,
            verifier.crv_o()
        );

        // The signing input is `base64url(json(header)) || '.' || base64url(payload)`
        // if the payload is encoded (see RFC 7515, https://datatracker.ietf.org/doc/html/rfc7515)
        // or `base64url(json(header)) || '.' || payload` if the payload is not encoded.
        let mut signing_input = Vec::<u8>::new();

        // Write the base64url-encoded header.
        signing_input
            .write_all(self.raw_header_base64().as_bytes())
            .map_err(|e| error!("error while writing JWS header: {}", e))?;

        // Write the concatenation separator '.'.
        signing_input
            .write_all(b".".as_slice())
            .map_err(|e| error!("error while writing '.' separator: {}", e))?;

        if let Some(detached_payload_bytes) = detached_payload_bytes_o {
            require!(
                self.raw_attached_payload_str().is_empty(),
                "if the JWS payload is not empty, then no detached payload may be specified"
            );
            if self.payload_is_base64url_encoded() {
                let mut base64url_encoder = base64::write::EncoderWriter::new(
                    &mut signing_input,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                );
                std::io::copy(detached_payload_bytes, &mut base64url_encoder)
                    .map_err(|e| error!("error while writing base64url-encoded payload: {}", e))?;
            } else {
                std::io::copy(detached_payload_bytes, &mut signing_input)
                    .map_err(|e| error!("error while writing payload: {}", e))?;
            }
        } else {
            // Here, because the payload is attached, it's already in its signing input form,
            // so just write it.  Note that it's possible to have an attached payload that is empty.
            signing_input
                .write_all(self.raw_attached_payload_str().as_bytes())
                .map_err(|e| error!("error while writing attached payload: {}", e))?;
        }

        let signature = Signature::try_from(self.signature_bytes.signature_byte_v.as_ref())
            .map_err(|_| error!("error while deserializing signature bytes to Signature",))?;

        // Verify the signature.
        verifier
            .verify(signing_input.as_slice(), &signature)
            .map_err(|e| error!("JWS failed to verify; error was: {}", e))?;

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
    fn try_from(jws_string: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(Cow::Owned(jws_string))
    }
}

impl<'j> TryFrom<&'j str> for JWS<'j> {
    type Error = Error;
    fn try_from(jws_str: &'j str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(Cow::Borrowed(jws_str))
    }
}

impl<'j> TryFrom<Cow<'j, str>> for JWS<'j> {
    type Error = Error;
    fn try_from(jws_str: Cow<'j, str>) -> std::result::Result<Self, Self::Error> {
        let mut split = jws_str.split('.');

        let header_base64 = split.next().ok_or(error!("JWS missing header"))?;
        let payload_base64 = split.next().ok_or(error!("JWS missing payload"))?;
        let signature_base64 = split.next().ok_or(error!("JWS missing signature"))?;
        if split.next().is_some() {
            return Err(error!("JWS has too many parts"));
        }

        // Warn of whitespace in the base64url(nopad)-encoded parts.
        if header_base64.contains(char::is_whitespace) {
            return Err(error!("Encoded JWS header contains whitespace"));
        }
        // TODO: This needs to change to support attached, non-encoded payloads.
        if payload_base64.contains(char::is_whitespace) {
            return Err(error!("Encoded JWS payload contains whitespace"));
        }
        if signature_base64.contains(char::is_whitespace) {
            return Err(error!("Encoded JWS signature contains whitespace",));
        }

        if !is_base64url_encoded(header_base64) {
            return Err(error!("JWS header is not base64url-encoded"));
        }
        // TODO: This needs to change to support attached, non-encoded payloads.
        if !is_base64url_encoded(payload_base64) {
            return Err(error!("JWS payload is not base64url-encoded",));
        }
        if !is_base64url_encoded(signature_base64) {
            return Err(error!("JWS signature is not base64url-encoded",));
        }

        let header = serde_json::from_reader::<_, JWSHeader>(base64::read::DecoderReader::new(
            header_base64.as_bytes(),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ))
        .map_err(|e| {
            error!(
                "JWS header failed to parse as expected JSON structure: {}",
                e
            )
        })?;

        let named_signature_algorithm =
            selfsign::NamedSignatureAlgorithm::try_from_jws_alg(header.alg.as_str())
                .map_err(|_| error!("Unsupported JWS alg"))?;
        let signature_byte_v = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_base64.as_bytes())
            .map_err(|_| error!("JWS signature failed to parse"))?;

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

/// This is base64url without padding.
fn is_base64url_encoded(s: &str) -> bool {
    // Base64urlnopad encoding is a subset of base64url encoding, so we can just check for the presence of
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
