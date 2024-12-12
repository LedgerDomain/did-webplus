#[derive(clap::Args, Clone, Debug)]
pub struct JWSPayloadArgs {
    /// Specify if the payload is "attached" (meaning included in the JWS itself) or "detached" (meaning
    /// omitted from the JWS itself).
    #[arg(
        name = "payload",
        long,
        value_name = "VALUE",
        default_value = "attached",
        value_enum
    )]
    pub payload_presence: did_webplus_jws::JWSPayloadPresence,
    /// Specify how the payload should be interpreted -- "none" means that the bytes of the payload should
    /// not be base64url-nopad-decoded before processing.  "base64" means that the bytes of the payload
    /// should be base64url-nopad-decoded before processing.
    #[arg(
        name = "encoding",
        long,
        value_name = "ENCODING",
        default_value = "base64",
        value_enum
    )]
    pub payload_encoding: did_webplus_jws::JWSPayloadEncoding,
}
