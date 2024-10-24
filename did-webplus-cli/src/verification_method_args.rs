/// Arguments for specifying a verification method associated with a controlled DID in a wallet.
#[derive(clap::Args)]
pub struct VerificationMethodArgs {
    /// Specify the DID to be used in this operation.  If not specified and there is exactly one DID
    /// controlled by the wallet, then that DID will be used -- it is uniquely determinable.  If not
    /// specified and there is no uniquely determinable DID, then an error will be returned.
    #[arg(name = "did", env = "DID_WEBPLUS_DID", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
    /// Specify which key purpose to use when selecting the key for in this operation.  Valid values
    /// are "authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", and
    /// "capabilityDelegation".
    #[arg(
        env = "DID_WEBPLUS_KEY_PURPOSE",
        short = 'p',
        long,
        value_name = "PURPOSE"
    )]
    pub key_purpose: did_webplus::KeyPurpose,
    /// If specified, then use key with the given public key in this operation.  If not specified,
    /// then use the uniquely determinable key if there is one.  Otherwise return error.
    #[arg(
        name = "key-id",
        env = "DID_WEBPLUS_KEY_ID",
        short = 'k',
        long,
        value_name = "KEY_ID"
    )]
    pub key_id_o: Option<String>,
}
