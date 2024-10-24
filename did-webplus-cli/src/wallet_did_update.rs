use crate::{determine_http_scheme, get_uniquely_determinable_did, Result, WalletArgs};

/// Update a DID that is controlled by the specified wallet by rotating the DID's current keys and
/// sending the updated DID document to its VDR.  If no --wallet-uuid argument is specified, then
/// there must only be one wallet in the database, and that wallet will be used.  If there is more
/// than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDUpdate {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    /// Specify the DID to be updated.  If not specified and there is exactly one DID controlled by
    /// the wallet, then that DID will be used -- it is uniquely determinable.  If there is no uniquely
    /// determinable DID, then an error will be returned.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
}

impl WalletDIDUpdate {
    pub async fn handle(self) -> Result<()> {
        let http_scheme = determine_http_scheme();

        let wallet = self.wallet_args.get_wallet().await?;

        let did = get_uniquely_determinable_did(&wallet, self.did_o).await?;
        use did_webplus_wallet::Wallet;
        let updated_did = wallet.update_did(&did, http_scheme).await?;
        println!("{}", updated_did);

        Ok(())
    }
}
