use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("hex decoding failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("utf8 decoding failed: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("protocol cryptography error: {0}")]
    Crypto(String),
    #[error("invalid product config: {0}")]
    InvalidProductConfig(String),
    #[error("invalid funding rail config: {0}")]
    InvalidFundingRailConfig(String),
    #[error("unsupported pair: {0}")]
    UnsupportedPair(String),
    #[error("invalid order: {0}")]
    InvalidOrder(String),
    #[error("invalid settlement proof: {0}")]
    InvalidSettlementProof(String),
}
