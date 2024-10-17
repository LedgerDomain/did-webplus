use did_webplus::DIDKeyResourceFullyQualified;

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
