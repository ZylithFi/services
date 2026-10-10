use std::{collections::BTreeSet, fmt};

use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256};
use serde::{Deserialize, Serialize};
use starknet_crypto::Felt;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    MarketRegistry, OhttpPolicy, ProtocolError,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, field_from_u64, field_from_u128,
        poseidon_chain_hex,
    },
    wallet_crypto::parse_canonical_field_hex,
};

pub(crate) mod serde_u128_decimal {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U128DecimalVisitor)
    }

    struct U128DecimalVisitor;

    impl<'de> Visitor<'de> for U128DecimalVisitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u128 decimal string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_decimal_u128(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    fn parse_decimal_u128(value: &str) -> Result<u128, String> {
        if value != value.trim() {
            return Err("u128 decimal string must not include surrounding whitespace".into());
        }
        if value.is_empty() {
            return Err("empty u128 decimal string".into());
        }
        if value.starts_with('-') || value.starts_with('+') {
            return Err("u128 decimal string must not include a sign".into());
        }
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("invalid u128 decimal string '{value}'"));
        }
        value
            .parse::<u128>()
            .map_err(|error| format!("u128 decimal string out of range: {error}"))
    }
}

pub(crate) mod serde_u64_decimal {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U64DecimalVisitor)
    }

    struct U64DecimalVisitor;

    impl<'de> Visitor<'de> for U64DecimalVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u64 decimal string or integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value != value.trim() {
                return Err(E::custom(
                    "u64 string must not include surrounding whitespace",
                ));
            }
            if value.is_empty() {
                return Err(E::custom("empty u64 string"));
            }
            value
                .parse::<u64>()
                .map_err(|error| E::custom(format!("invalid u64: {error}")))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub String);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    pub owner_public_key: String,
    pub spend_authority: String,
    pub withdraw_authority: String,
    pub blinding: String,
    #[serde(with = "serde_u64_decimal")]
    pub nonce: u64,
    pub metadata_commitment: String,
}

impl fmt::Debug for Note {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Note")
            .field("asset_id", &"<redacted>")
            .field("amount", &"<redacted>")
            .field("owner_public_key", &"<redacted>")
            .field("spend_authority", &"<redacted>")
            .field("withdraw_authority", &"<redacted>")
            .field("blinding", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("metadata_commitment", &"<redacted>")
            .finish()
    }
}

impl Note {
    pub fn commitment(&self) -> Result<NoteCommitment, ProtocolError> {
        let asset_id = felt_from_hex_str(&encode_starknet_felt("asset-id", &self.asset_id.0))?;
        let owner_public_key = felt_from_hex_str(&self.owner_public_key)?;
        let blinding = felt_from_hex_str(&self.blinding)?;
        let nonce = field_from_u64(self.nonce);
        let metadata_commitment = felt_from_hex_str(&self.metadata_commitment)?;
        let amount = field_from_u128(self.amount);
        let spend_authority = felt_from_hex_str(&self.spend_authority)?;
        let withdraw_authority = felt_from_hex_str(&self.withdraw_authority)?;

        Ok(NoteCommitment(poseidon_chain_hex(
            domain_felt("zylith/note"),
            &[
                asset_id,
                amount,
                owner_public_key,
                spend_authority,
                withdraw_authority,
                blinding,
                nonce,
                metadata_commitment,
            ],
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositIntent {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    #[serde(with = "serde_u64_decimal")]
    pub deposit_nonce: u64,
    pub recipient_owner_public_key: String,
    pub recipient_spend_authority: String,
    pub recipient_withdraw_authority: String,
}

/// the mandatory deployment fields for wallet deposit derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositDerivationContext {
    pub chain_id: Felt,
    pub bridge_address: Felt,
}

impl DepositDerivationContext {
    pub fn from_hex(chain_id: &str, bridge_address: &str) -> Result<Self, ProtocolError> {
        let context = Self {
            chain_id: parse_canonical_field_hex(chain_id)?,
            bridge_address: parse_canonical_field_hex(bridge_address)?,
        };
        context.validate()?;
        Ok(context)
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.chain_id == Felt::ZERO {
            return Err(ProtocolError::Crypto(
                "deposit chain id must be nonzero".into(),
            ));
        }
        if self.bridge_address == Felt::ZERO {
            return Err(ProtocolError::Crypto(
                "deposit bridge address must be nonzero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendAuthorization {
    pub signature_r: String,
    pub signature_s: String,
}

impl fmt::Debug for SpendAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpendAuthorization")
            .field("signature_r", &"<redacted>")
            .field("signature_s", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateExecutionKeyPublicConfig {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateExecutionKeyPrivateConfig {
    pub key_id: String,
    pub algorithm: String,
    pub private_key: String,
    pub public_key: String,
}

impl fmt::Debug for PrivateExecutionKeyPrivateConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateExecutionKeyPrivateConfig")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Drop for PrivateExecutionKeyPrivateConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl PrivateExecutionKeyPrivateConfig {
    /// constructs one fixed-profile config from raw x25519 private bytes.
    pub fn from_private_key_bytes(
        key_id: &str,
        private_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ProtocolError> {
        validate_execution_key_id(key_id)?;
        if private_key.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::Crypto(
                "execution private key is zero".into(),
            ));
        }
        let secret = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(private_key.as_slice())
            .map_err(|_| ProtocolError::Crypto("execution private key is invalid".into()))?;
        let public_key = hex::encode(X25519HkdfSha256::sk_to_pk(&secret).to_bytes());
        let config = Self {
            key_id: key_id.into(),
            algorithm: crate::private_envelope::HPKE_PROFILE_ID.into(),
            private_key: hex::encode(private_key.as_slice()),
            public_key,
        };
        config.canonical_public_key()?;
        Ok(config)
    }

    /// validates the secret/public key pair and returns the canonical x25519 public key.
    pub fn canonical_public_key(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_execution_key_id(&self.key_id)?;
        validate_execution_algorithm(&self.algorithm)?;
        let private = parse_execution_private_key_hex(&self.private_key)?;
        if private.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::Crypto(
                "execution private key is zero".into(),
            ));
        }
        let secret = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(private.as_slice())
            .map_err(|_| ProtocolError::Crypto("execution private key is invalid".into()))?;
        let public = parse_execution_public_key(&self.public_key)?;
        let derived = X25519HkdfSha256::sk_to_pk(&secret);
        if derived.to_bytes().as_slice() != public {
            return Err(ProtocolError::Crypto(
                "execution private and public keys do not match".into(),
            ));
        }
        Ok(public.to_vec())
    }
}

fn validate_execution_algorithm(algorithm: &str) -> Result<(), ProtocolError> {
    if algorithm != crate::private_envelope::HPKE_PROFILE_ID {
        return Err(ProtocolError::Crypto(
            "unsupported execution key algorithm".into(),
        ));
    }
    Ok(())
}

pub fn validate_execution_key_id(key_id: &str) -> Result<(), ProtocolError> {
    let bytes = key_id.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_'
        })
    {
        return Err(ProtocolError::Crypto(
            "execution key id must be 1..=64 canonical ascii characters".into(),
        ));
    }
    Ok(())
}

fn parse_execution_key_hex(value: &str, kind: &str) -> Result<[u8; 32], ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::Crypto(format!(
            "execution {kind} key must be 64 lowercase hex characters"
        )));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)?;
    Ok(bytes)
}

fn parse_execution_private_key_hex(value: &str) -> Result<Zeroizing<[u8; 32]>, ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::Crypto(
            "execution private key must be 64 lowercase hex characters".into(),
        ));
    }
    let mut bytes = Zeroizing::new([0; 32]);
    hex::decode_to_slice(value, bytes.as_mut())?;
    Ok(bytes)
}

fn parse_execution_public_key(value: &str) -> Result<[u8; 32], ProtocolError> {
    let public = parse_execution_key_hex(value, "public")?;
    crate::private_envelope::validate_x25519_public_bytes(&public, "execution public key")?;
    Ok(public)
}

pub fn validate_private_execution_keys(
    keys: &[PrivateExecutionKeyPrivateConfig],
    active_key_id: &str,
) -> Result<(), ProtocolError> {
    if keys.is_empty() || keys.len() > 2 {
        return Err(ProtocolError::Crypto(
            "private execution keyring must hold one or two keys".into(),
        ));
    }
    validate_execution_key_id(active_key_id)?;
    let mut ids = BTreeSet::new();
    let mut points = BTreeSet::new();
    for key in keys {
        if !ids.insert(key.key_id.clone()) {
            return Err(ProtocolError::Crypto(
                "execution key ids must be unique".into(),
            ));
        }
        if !points.insert(key.canonical_public_key()?) {
            return Err(ProtocolError::Crypto(
                "execution public keys must be unique".into(),
            ));
        }
    }
    if !ids.contains(active_key_id) {
        return Err(ProtocolError::Crypto(
            "active execution key id is absent".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateExecutionKeyRegistry {
    pub keys: Vec<PrivateExecutionKeyPublicConfig>,
}

impl PrivateExecutionKeyRegistry {
    /// the pin a deployment manifest carries for its one active execution key.
    pub fn fingerprint(&self) -> Result<String, ProtocolError> {
        use sha2::{Digest, Sha256};
        if self.keys.len() != 1 {
            return Err(ProtocolError::Crypto(
                "the execution key registry must hold exactly one active key".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"zylith-execution-key-registry-v2");
        hasher.update(1_u32.to_be_bytes());
        for key in &self.keys {
            validate_execution_key_id(&key.key_id)?;
            validate_execution_algorithm(&key.algorithm)?;
            let public = parse_execution_public_key(&key.public_key)?;
            for part in [
                key.algorithm.as_bytes(),
                key.key_id.as_bytes(),
                public.as_slice(),
            ] {
                hasher.update((part.len() as u32).to_be_bytes());
                hasher.update(part);
            }
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

pub fn count_bucket_label(count: u64) -> String {
    match count {
        0..=7 => "0-7".into(),
        8..=31 => "8-31".into(),
        32..=127 => "32-127".into(),
        128..=511 => "128-511".into(),
        _ => "512+".into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCallArguments {
    pub funding_commitments: Vec<String>,
    pub deposit_roots: Vec<String>,
    pub encrypted_note_activations: Vec<String>,
    pub note_commitments: Vec<String>,
    pub asset_ids: Vec<String>,
    pub amounts: Vec<String>,
    pub withdraw_authorities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSubmissionPlan {
    pub funding_rail: FundingRailKind,
    pub note: Note,
    pub note_commitment: NoteCommitment,
    pub funding_commitment: String,
    pub deposit_root: String,
    pub encrypted_note_activation: String,
    pub encoded_args: DepositCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositActivationRecord {
    pub activation_id: u64,
    pub funding_commitment: String,
    pub deposit_root: String,
    pub encrypted_note_activation: String,
}

/// funding commitments of the most recent confirmed deposits. every wallet
/// fetches the same list and matches its pending deposits locally, so the
/// indexer never learns which deposits a requester owns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositConfirmationList {
    pub recent_funding_commitments: Vec<String>,
    pub last_successful_sync_unix_ms: u64,
    pub sync_lag_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositActivationRecordList {
    pub start: u64,
    pub end: u64,
    pub count_bucket: String,
    pub records: Vec<DepositActivationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryArtifactKind {
    Snapshot,
    WalletEvent,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRecoveryPayload {
    #[serde(deserialize_with = "crate::wallet_crypto::deserialize_wallet_key_schedule_version")]
    pub key_schedule_version: u16,
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl fmt::Debug for EncryptedRecoveryPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedRecoveryPayload")
            .field("algorithm", &self.algorithm)
            .field("nonce", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifact {
    #[serde(deserialize_with = "crate::wallet_crypto::deserialize_wallet_key_schedule_version")]
    pub key_schedule_version: u16,
    pub artifact_id: String,
    pub account_id: String,
    pub kind: RecoveryArtifactKind,
    pub sequence: u64,
    pub created_at_unix_ms: u64,
    pub payload: EncryptedRecoveryPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifactUpload {
    pub artifact: RecoveryArtifact,
    /// the current remote snapshot this update merged; none creates the first snapshot.
    pub previous_artifact_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifactList {
    pub account_id: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub artifacts: Vec<RecoveryArtifact>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingRailKind {
    StarknetPrivacy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StarknetPrivacyFundingRail {
    pub privacy_pool: String,
    pub privacy_pool_class_hash: String,
    pub bridge_adapter: String,
    pub proving_url: String,
    pub proving_ohttp_policy: OhttpPolicy,
    pub paymaster_address: String,
    pub paymaster_url: String,
    pub ingress_key_registry_fingerprint: String,
    /// during a rotation, the fingerprint of the registry that replaces the current one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_execution_pin"
    )]
    pub ingress_key_registry_next_fingerprint: Option<String>,
    pub sdk_package: String,
    pub sdk_version: String,
    pub min_proving_delay_blocks: u64,
    pub proof_signer_class_hash: String,
}

fn deserialize_present_execution_pin<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

impl StarknetPrivacyFundingRail {
    /// the current and optional next one-key registry pins must be canonical and distinct.
    pub fn pinned_registry_fingerprints(&self) -> Result<Vec<&str>, String> {
        let current = self.ingress_key_registry_fingerprint.as_str();
        let valid = |pin: &str| {
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && pin.bytes().any(|byte| byte != b'0')
        };
        if !valid(current) {
            return Err(
                "ingress_key_registry_fingerprint must be a nonzero lowercase sha256 fingerprint"
                    .into(),
            );
        }
        let mut pins = vec![current];
        if let Some(next) = self.ingress_key_registry_next_fingerprint.as_deref() {
            if !valid(next) || next == current {
                return Err("ingress_key_registry_next_fingerprint must be a distinct nonzero lowercase sha256 fingerprint".into());
            }
            pins.push(next);
        }
        Ok(pins)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingRailConfig {
    pub primary: FundingRailKind,
    pub starknet_privacy: StarknetPrivacyFundingRail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentContracts {
    pub commitment_registry: String,
    pub privacy_deposit_bridge: String,
    pub ekubo_external_match_router: String,
    pub exchange: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentProofConfig {
    /// `snip36-stwo`: every statement is a cairo program proven by the starknet transaction
    /// prover and consumed through the transaction's proof facts.
    pub scheme: String,
    pub proof_version: String,
    pub transition_proof_program_address: String,
    pub withdrawal_proof_program_address: String,
    pub residual_recovery_proof_program_address: String,
    pub virtual_program_hash: String,
    pub starknet_os_config_hash: String,
    pub proof_account_address: String,
    pub proof_account_class_hash: String,
    pub transition_proof_program_class_hash: String,
    pub withdrawal_proof_program_class_hash: String,
    pub residual_recovery_proof_program_class_hash: String,
    pub settlement_account_address: String,
    pub proof_validity_blocks: u64,
    pub config_locked_after_deploy: bool,
    pub prover_build_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentMetadata {
    pub finalized: bool,
    pub release_commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRoles {
    pub protocol_fee_recipient: String,
    pub pause_guardian_address: String,
    pub reference_price_signer: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRuntime {
    /// the epoch cadence: orders cross at every close, and only closes with something to settle
    /// send a transition.
    pub epoch_ms: u64,
    pub max_close_delay_ms: u64,
    pub withdrawal_delay_seconds: u64,
    pub external_window_seconds: u64,
    pub max_book_orders: u64,
    pub max_admissions_per_transition: u64,
    /// operator liveness policy, counted from the first scheduled close that constructs a
    /// nonzero crossing but defers it for economics. this is not proof-enforced.
    pub max_internal_deferral_epochs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifest {
    pub network: String,
    pub rpc_url: String,
    pub chain_id: String,
    pub contracts: DeploymentContracts,
    pub market_registry: MarketRegistry,
    pub funding: FundingRailConfig,
    pub proof: DeploymentProofConfig,
    pub deployment: DeploymentMetadata,
    pub roles: DeploymentRoles,
    pub runtime: DeploymentRuntime,
}

impl DeploymentManifest {
    pub fn validate_market_registry(&self) -> Result<(), String> {
        self.market_registry.validate()?;
        if self.network != self.market_registry.network
            || self.chain_id != self.market_registry.chain_id
        {
            return Err("deployment identity differs from the market registry".into());
        }
        Ok(())
    }

    pub fn validate_production(&self) -> Result<(), String> {
        self.validate_market_registry()?;
        if !self.deployment.finalized || !self.proof.config_locked_after_deploy {
            return Err(
                "deployment manifest must be finalized with locked proof configuration".into(),
            );
        }
        if self.funding.starknet_privacy.proving_ohttp_policy != OhttpPolicy::BestEffort {
            return Err("production funding must use best-effort ohttp".into());
        }
        if self.proof.scheme != "snip36-stwo" || self.proof.prover_build_id.is_empty() {
            return Err("deployment proof identity is incomplete".into());
        }
        if self.proof.proof_version != "PROOF2" {
            return Err("production supports only the PROOF2 proof family".into());
        }
        for (label, value) in [
            (
                "transition proof program address",
                &self.proof.transition_proof_program_address,
            ),
            (
                "withdrawal proof program address",
                &self.proof.withdrawal_proof_program_address,
            ),
            (
                "residual recovery proof program address",
                &self.proof.residual_recovery_proof_program_address,
            ),
            ("virtual program hash", &self.proof.virtual_program_hash),
            (
                "starknet os config hash",
                &self.proof.starknet_os_config_hash,
            ),
            ("proof account address", &self.proof.proof_account_address),
            (
                "proof account class hash",
                &self.proof.proof_account_class_hash,
            ),
            (
                "transition proof program class hash",
                &self.proof.transition_proof_program_class_hash,
            ),
            (
                "withdrawal proof program class hash",
                &self.proof.withdrawal_proof_program_class_hash,
            ),
            (
                "residual recovery proof program class hash",
                &self.proof.residual_recovery_proof_program_class_hash,
            ),
            (
                "settlement account address",
                &self.proof.settlement_account_address,
            ),
        ] {
            if !felt_from_hex_str(value).is_ok_and(|felt| felt != Felt::ZERO) {
                return Err(format!("deployment {label} must be a nonzero felt"));
            }
        }
        let runtime = &self.runtime;
        if !(1_000..=300_000).contains(&runtime.epoch_ms)
            || runtime.max_close_delay_ms == 0
            || runtime.withdrawal_delay_seconds == 0
            || runtime.max_book_orders == 0
            || runtime.max_book_orders as usize > crate::exchange::MAX_BOOK_ORDERS
            || runtime.max_admissions_per_transition == 0
            || runtime.max_admissions_per_transition > runtime.max_book_orders
            || runtime.max_internal_deferral_epochs == 0
        {
            return Err("deployment runtime limits are invalid".into());
        }
        let external_enabled = self
            .market_registry
            .enabled_markets()
            .any(|market| market.capabilities.external_matching);
        if external_enabled != (runtime.external_window_seconds != 0)
            || runtime.external_window_seconds > 300
        {
            return Err("deployment external window differs from market capabilities".into());
        }
        let commit = self.deployment.release_commit.as_bytes();
        if commit.len() != 40
            || commit.iter().all(|byte| *byte == b'0')
            || !commit
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err("deployment manifest has an invalid release commit".into());
        }
        self.funding
            .starknet_privacy
            .pinned_registry_fingerprints()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hpke::{Deserializable, Kem, Serializable};

    use super::{
        DeploymentManifest, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
        validate_private_execution_keys,
    };

    fn production_manifest() -> DeploymentManifest {
        let mut manifest: DeploymentManifest =
            serde_json::from_str(include_str!("../../client/public/deployment.example.json"))
                .unwrap();
        manifest.deployment.finalized = true;
        manifest.deployment.release_commit = "1".repeat(40);
        manifest.proof.config_locked_after_deploy = true;
        manifest.proof.transition_proof_program_address = "0x1".into();
        manifest.proof.withdrawal_proof_program_address = "0x2".into();
        manifest.proof.residual_recovery_proof_program_address = "0x3".into();
        manifest.proof.virtual_program_hash = "0x4".into();
        manifest.proof.starknet_os_config_hash = "0x5".into();
        manifest.proof.proof_account_address = "0x6".into();
        manifest.proof.proof_account_class_hash = "0x7".into();
        manifest.proof.transition_proof_program_class_hash = "0x8".into();
        manifest.proof.withdrawal_proof_program_class_hash = "0x9".into();
        manifest.proof.residual_recovery_proof_program_class_hash = "0xa".into();
        manifest.proof.settlement_account_address = "0xb".into();
        manifest
            .funding
            .starknet_privacy
            .ingress_key_registry_fingerprint = "ab".repeat(32);
        manifest
    }

    /// the manifest example the client ships must parse as the services read it.
    #[test]
    fn the_shipped_manifest_example_matches_the_schema() {
        let manifest: DeploymentManifest =
            serde_json::from_str(include_str!("../../client/public/deployment.example.json"))
                .unwrap();
        assert!(manifest.runtime.epoch_ms > 0);
        assert!(
            manifest.runtime.max_book_orders as usize
                <= crate::exchange::StepShape::max_book_orders(700_000)
        );
        assert!(
            manifest.runtime.max_admissions_per_transition as usize
                <= crate::exchange::StepShape::max_admissions(700_000)
        );
        manifest.validate_market_registry().unwrap();
        assert!(manifest.market_registry.enabled_markets().next().is_some());
    }

    #[test]
    fn deployment_and_registry_identity_must_match() {
        let mut manifest: DeploymentManifest =
            serde_json::from_str(include_str!("../../client/public/deployment.example.json"))
                .unwrap();
        manifest.chain_id = "0x1".into();
        assert!(
            manifest
                .validate_market_registry()
                .unwrap_err()
                .contains("identity differs")
        );
    }

    #[test]
    fn production_runtime_limits_fail_closed() {
        let mut manifest = production_manifest();
        manifest.runtime.max_admissions_per_transition = manifest.runtime.max_book_orders + 1;
        assert!(
            manifest
                .validate_production()
                .unwrap_err()
                .contains("runtime limits")
        );
    }

    #[test]
    fn production_manifest_accepts_only_the_enabled_proof2_family() {
        let mut manifest = production_manifest();
        manifest.validate_production().unwrap();
        for unsupported in ["PROOF1", "PROOF3", "0x50524f4f4632", ""] {
            manifest.proof.proof_version = unsupported.into();
            assert!(
                manifest
                    .validate_production()
                    .unwrap_err()
                    .contains("PROOF2"),
                "unsupported version was not rejected: {unsupported}"
            );
        }
    }

    #[test]
    fn production_manifest_rejects_malformed_or_duplicate_execution_pins() {
        let mut manifest = production_manifest();
        let current = "ab".repeat(32);
        manifest
            .funding
            .starknet_privacy
            .ingress_key_registry_fingerprint = current.clone();
        manifest
            .funding
            .starknet_privacy
            .ingress_key_registry_next_fingerprint = Some("cd".repeat(32));
        manifest.validate_production().unwrap();
        for bad in [
            current,
            "CD".repeat(32),
            "0".repeat(64),
            "bad".into(),
            String::new(),
        ] {
            manifest
                .funding
                .starknet_privacy
                .ingress_key_registry_next_fingerprint = Some(bad);
            assert!(manifest.validate_production().is_err());
        }
    }

    #[test]
    fn present_null_next_execution_pin_is_not_omission() {
        let mut raw: serde_json::Value =
            serde_json::from_str(include_str!("../../client/public/deployment.example.json"))
                .unwrap();
        raw["funding"]["starknet_privacy"]["ingress_key_registry_next_fingerprint"] =
            serde_json::Value::Null;
        assert!(serde_json::from_value::<DeploymentManifest>(raw).is_err());
    }

    fn execution_key(id: &str, scalar: u8) -> PrivateExecutionKeyPrivateConfig {
        let bytes = [scalar; 32];
        let secret =
            <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&bytes).unwrap();
        PrivateExecutionKeyPrivateConfig {
            key_id: id.into(),
            algorithm: crate::private_envelope::HPKE_PROFILE_ID.into(),
            private_key: hex::encode(bytes),
            public_key: hex::encode(hpke::kem::X25519HkdfSha256::sk_to_pk(&secret).to_bytes()),
        }
    }

    #[test]
    fn private_execution_keys_bind_each_secret_to_one_unique_public_point() {
        let first = execution_key("first", 1);
        let second = execution_key("second", 2);
        validate_private_execution_keys(&[first.clone(), second.clone()], "first").unwrap();

        let mut mismatched = first.clone();
        mismatched.public_key = second.public_key.clone();
        assert!(
            validate_private_execution_keys(&[mismatched], "first")
                .unwrap_err()
                .to_string()
                .contains("do not match")
        );

        let mut duplicate_id = second.clone();
        duplicate_id.key_id = first.key_id.clone();
        assert!(validate_private_execution_keys(&[first.clone(), duplicate_id], "first").is_err());

        let mut duplicate_point = first.clone();
        duplicate_point.key_id = "other".into();
        assert!(validate_private_execution_keys(&[first, duplicate_point], "first").is_err());
    }

    fn execution_key_v2(
        key_id: &str,
        private_key: &str,
        public_key: &str,
    ) -> PrivateExecutionKeyPrivateConfig {
        PrivateExecutionKeyPrivateConfig {
            key_id: key_id.into(),
            algorithm: crate::private_envelope::HPKE_PROFILE_ID.into(),
            private_key: private_key.into(),
            public_key: public_key.into(),
        }
    }

    #[test]
    fn execution_key_v2_accepts_one_active_key_and_one_unique_next_key() {
        let active = execution_key_v2(
            "active",
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        );
        let next = execution_key_v2(
            "next",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
        );

        validate_private_execution_keys(&[active, next], "active").unwrap();
    }

    #[test]
    fn execution_key_v2_rejects_bad_encoding_algorithm_and_key_mismatch() {
        let valid = execution_key_v2(
            "active",
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        );
        let mut invalid_cases = Vec::new();
        let mut invalid = valid.clone();
        invalid.public_key = format!("0x{}", valid.public_key);
        invalid_cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.public_key = valid.public_key.to_uppercase();
        invalid_cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.public_key = "00".repeat(32);
        invalid_cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.public_key = "11".repeat(32);
        invalid_cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.private_key = "00".repeat(32);
        invalid_cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.algorithm = "negotiated-algorithm".into();
        invalid_cases.push(invalid);
        for invalid in invalid_cases {
            assert!(validate_private_execution_keys(&[invalid], "active").is_err());
        }
    }

    #[test]
    fn execution_key_v2_rejects_ambiguous_rotation_sets() {
        let active = execution_key_v2(
            "active",
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        );
        let next = execution_key_v2(
            "next",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
        );
        let third = execution_key_v2(
            "third",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "ce8d3ad1ccb633ec7b70c17814a5c76ed78f787082717001265f9cfa1add7725",
        );

        assert!(validate_private_execution_keys(&[], "active").is_err());
        assert!(validate_private_execution_keys(std::slice::from_ref(&active), "missing").is_err());
        assert!(
            validate_private_execution_keys(&[active.clone(), next.clone(), third], "active")
                .is_err()
        );
        assert!(
            validate_private_execution_keys(&[active.clone(), active.clone()], "active").is_err()
        );
        let mut duplicate_public = next;
        duplicate_public.public_key = active.public_key.clone();
        assert!(validate_private_execution_keys(&[active, duplicate_public], "active").is_err());
    }

    #[test]
    fn execution_key_v2_registry_fingerprint_is_exact_and_single_recipient() {
        let public = PrivateExecutionKeyPublicConfig {
            key_id: "active".into(),
            algorithm: crate::private_envelope::HPKE_PROFILE_ID.into(),
            public_key: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a".into(),
        };
        let registry = crate::PrivateExecutionKeyRegistry {
            keys: vec![public.clone()],
        };

        assert_eq!(
            registry.fingerprint().unwrap(),
            "d2c009f2ef19ce5f504d4948424f2686711ad06d7b8d83d401912ea7fc514b4d"
        );
        assert!(
            crate::PrivateExecutionKeyRegistry {
                keys: vec![public.clone(), public]
            }
            .fingerprint()
            .is_err()
        );
    }

    #[test]
    fn execution_key_v2_rejects_noncanonical_ids_and_public_encodings() {
        let valid = execution_key("active_1", 7);
        for key_id in [
            "", "UPPER", " bad", "bad ", "-bad", "bad-", "bad.dot", "a/../b",
        ] {
            let mut key = valid.clone();
            key.key_id = key_id.into();
            assert!(validate_private_execution_keys(&[key], key_id).is_err());
        }
        let mut long_id = valid.clone();
        long_id.key_id = "a".repeat(65);
        assert!(validate_private_execution_keys(&[long_id], "a").is_err());

        for public_key in [
            "ff".repeat(32),
            format!("ed{}7f", "ff".repeat(30)),
            format!("{}80", "00".repeat(31)),
            format!("01{}", "00".repeat(31)),
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800".to_owned(),
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157".to_owned(),
        ] {
            let mut key = valid.clone();
            key.public_key = public_key;
            assert!(validate_private_execution_keys(&[key], "active_1").is_err());
        }
    }

    #[test]
    fn execution_key_v2_json_rejects_unknown_fields_and_missing_profile() {
        let private = execution_key("active", 8);
        let public = PrivateExecutionKeyPublicConfig {
            key_id: private.key_id.clone(),
            algorithm: private.algorithm.clone(),
            public_key: private.public_key.clone(),
        };
        let mut private_json = serde_json::to_value(&private).unwrap();
        private_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrivateExecutionKeyPrivateConfig>(private_json).is_err());
        let mut public_json = serde_json::to_value(&public).unwrap();
        public_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrivateExecutionKeyPublicConfig>(public_json).is_err());
        let mut public_json = serde_json::to_value(&public).unwrap();
        public_json.as_object_mut().unwrap().remove("algorithm");
        assert!(serde_json::from_value::<PrivateExecutionKeyPublicConfig>(public_json).is_err());
    }

    #[test]
    fn execution_key_v2_registry_rejects_bad_profile_id_and_public_key() {
        let private = execution_key("active", 9);
        let public = PrivateExecutionKeyPublicConfig {
            key_id: private.key_id.clone(),
            algorithm: private.algorithm.clone(),
            public_key: private.public_key.clone(),
        };
        let registry = |key| crate::PrivateExecutionKeyRegistry { keys: vec![key] };
        assert!(
            crate::PrivateExecutionKeyRegistry { keys: vec![] }
                .fingerprint()
                .is_err()
        );
        let mut invalid = public.clone();
        invalid.algorithm = "other".into();
        assert!(registry(invalid).fingerprint().is_err());
        let mut invalid = public.clone();
        invalid.public_key = "0x".to_owned() + &invalid.public_key;
        assert!(registry(invalid).fingerprint().is_err());
        let mut invalid = public;
        invalid.public_key = "00".repeat(32);
        assert!(registry(invalid).fingerprint().is_err());

        for low_order_key in [
            format!("01{}", "00".repeat(31)),
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800".to_owned(),
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157".to_owned(),
        ] {
            let private = execution_key("active", 9);
            let mut invalid = registry(PrivateExecutionKeyPublicConfig {
                key_id: private.key_id.clone(),
                algorithm: private.algorithm.clone(),
                public_key: private.public_key.clone(),
            });
            invalid.keys[0].public_key = low_order_key;
            assert!(invalid.fingerprint().is_err());
        }
    }
}
