// use did_webplus_core::DIDKeyResourceFullyQualified;

/// See RFC 7515, https://datatracker.ietf.org/doc/html/rfc7515
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JWSHeader {
    /// Signature algorithm used to sign the JWS.
    pub alg: String,
    /// Specifies the public key in some way.  This could be using a DID, or a multibase-encoded key.
    /// If it is a DID, then it could include any query parameters that are required by the DID method.
    pub kid: String,
    /// Specifies critical headers that must be understood and processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// If present, then specifies if the payload is base64url-encoded or not.  This is used in combination
    /// with the "b64" element of the "crit" field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b64: Option<bool>,
}
