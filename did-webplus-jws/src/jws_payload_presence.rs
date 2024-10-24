#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JWSPayloadPresence {
    /// The payload is included within the JWS.
    Attached,
    /// The payload is not included within the JWS.
    Detached,
}
