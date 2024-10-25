use crate::{
    DIDResolveFull, DIDResolveRaw, DIDResolveThin, VJSONSelfHash, VerifyJWS, VerifyVJSON,
    WalletDIDCreate, WalletDIDList, WalletDIDSignJWS, WalletDIDSignVJSON, WalletDIDUpdate,
    WalletList,
};

/// did:webplus CLI tool for all client-side operations and related utility operations.  Note that some subcommands
/// appear at  multiple places in the command hierarchy so each command group is "complete".
#[derive(clap::Parser)]
pub enum Root {
    #[command(subcommand)]
    DID(DID),
    #[command(subcommand)]
    DIDKey(DIDKey),
    #[command(subcommand)]
    JWS(JWS),
    #[command(subcommand)]
    Verify(Verify),
    #[command(subcommand)]
    VJSON(VJSON),
    #[command(subcommand)]
    Wallet(Wallet),
}

impl Root {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::DID(x) => x.handle().await,
            Self::DIDKey(x) => x.handle(),
            Self::JWS(x) => x.handle().await,
            Self::Verify(x) => x.handle().await,
            Self::VJSON(x) => x.handle().await,
            Self::Wallet(x) => x.handle().await,
        }
    }
}

use crate::{DIDKeyFromPrivate, DIDKeyGenerate, DIDKeySignJWS, DIDKeySignVJSON, DIDList, Result};

/// DID operations that don't require a wallet.  These are operations typically associated
/// with verifying parties that don't necessarily control a DID.
#[derive(clap::Subcommand)]
pub enum DID {
    List(DIDList),
    #[command(subcommand)]
    Resolve(DIDResolve),
}

impl DID {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::List(x) => x.handle().await,
            Self::Resolve(x) => x.handle().await,
        }
    }
}

/// Operations using the `did:key` DID method.
#[derive(clap::Subcommand)]
pub enum DIDKey {
    FromPrivate(DIDKeyFromPrivate),
    Generate(DIDKeyGenerate),
    #[command(subcommand)]
    Sign(DIDKeySign),
}

impl DIDKey {
    pub fn handle(self) -> Result<()> {
        match self {
            Self::FromPrivate(x) => x.handle(),
            Self::Generate(x) => x.handle(),
            Self::Sign(x) => x.handle(),
        }
    }
}

/// Signing operations using the `did:key` DID method.
#[derive(clap::Subcommand)]
pub enum DIDKeySign {
    JWS(DIDKeySignJWS),
    VJSON(DIDKeySignVJSON),
}

impl DIDKeySign {
    pub fn handle(self) -> Result<()> {
        match self {
            Self::JWS(x) => x.handle(),
            Self::VJSON(x) => x.handle(),
        }
    }
}

/// DID resolution operations.
#[derive(clap::Subcommand)]
pub enum DIDResolve {
    Full(DIDResolveFull),
    Thin(DIDResolveThin),
    Raw(DIDResolveRaw),
}

impl DIDResolve {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::Full(x) => x.handle().await,
            Self::Thin(x) => x.handle().await,
            Self::Raw(x) => x.handle().await,
        }
    }
}

/// JWS-related operations (JSON Web Signature).
#[derive(clap::Subcommand)]
pub enum JWS {
    Sign(WalletDIDSignJWS),
    Verify(VerifyJWS),
    // TODO: There could be a did:key form of sign
}

impl JWS {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::Sign(x) => x.handle().await,
            Self::Verify(x) => x.handle().await,
        }
    }
}

/// Verification operations.
#[derive(clap::Subcommand)]
pub enum Verify {
    JWS(VerifyJWS),
    VJSON(VerifyVJSON),
}

impl Verify {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::JWS(x) => x.handle().await,
            // Self::JWT(x) => x.handle().await,
            Self::VJSON(x) => x.handle().await,
        }
    }
}

/// VJSON-related operations (Verifiable JSON).
#[derive(clap::Subcommand)]
pub enum VJSON {
    SelfHash(VJSONSelfHash),
    Sign(WalletDIDSignVJSON),
    Verify(VerifyVJSON),
    // TODO: There could be a did:key form of sign
}

impl VJSON {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::SelfHash(x) => x.handle(),
            Self::Sign(x) => x.handle().await,
            Self::Verify(x) => x.handle().await,
        }
    }
}

/// Wallet operations.
#[derive(clap::Subcommand)]
pub enum Wallet {
    #[command(subcommand)]
    DID(WalletDID),
    List(WalletList),
    // TODO: sign using a private key from wallet, but with kid using did:key
}

impl Wallet {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::DID(x) => x.handle().await,
            // Self::KeyExchange(x) => x.handle().await,
            Self::List(x) => x.handle().await,
            // Self::Sign(x) => x.handle().await,
        }
    }
}

/// Wallet DID operations.
#[derive(clap::Subcommand)]
pub enum WalletDID {
    Create(WalletDIDCreate),
    List(WalletDIDList),
    #[command(subcommand)]
    Sign(WalletDIDSign),
    Update(WalletDIDUpdate),
}

impl WalletDID {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::Create(x) => x.handle().await,
            Self::List(x) => x.handle().await,
            Self::Sign(x) => x.handle().await,
            Self::Update(x) => x.handle().await,
        }
    }
}

/// Signing operations using a specified DID from a specified wallet.
#[derive(clap::Subcommand)]
pub enum WalletDIDSign {
    JWS(WalletDIDSignJWS),
    VJSON(WalletDIDSignVJSON),
}

impl WalletDIDSign {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::JWS(x) => x.handle().await,
            Self::VJSON(x) => x.handle().await,
        }
    }
}
