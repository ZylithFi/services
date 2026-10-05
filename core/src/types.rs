use std::{collections::BTreeSet, fmt};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use starknet_crypto::get_public_key;
use zeroize::Zeroize;

use crate::{
    MarketRegistry, OhttpPolicy, ProtocolError,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, field_from_u64, field_from_u128,
        poseidon_chain_hex,
    },
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
        let owner_public_key = felt_from_hex_str(&encode_starknet_felt(
            "owner-public-key",
            &self.owner_public_key,
        ))?;
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

pub fn spend_auth_key_felt_from_raw_key_hex(spend_auth_key_hex: &str) -> String {
    encode_starknet_felt("spend-auth-key", spend_auth_key_hex)
}

pub fn spend_authority_from_spend_auth_key_felt(
    spend_auth_key_felt: &str,
) -> Result<String, ProtocolError> {
    let spend_auth_key = felt_from_hex_str(spend_auth_key_felt)?;
    if spend_auth_key == field_from_u64(0) {
        return Err(ProtocolError::Crypto(
            "spend authorization key cannot be zero".into(),
        ));
    }
    Ok(format!("{:#x}", get_public_key(&spend_auth_key)))
}

pub fn spend_authority_from_raw_key_hex(spend_auth_key_hex: &str) -> Result<String, ProtocolError> {
    spend_authority_from_spend_auth_key_felt(&spend_auth_key_felt_from_raw_key_hex(
        spend_auth_key_hex,
    ))
}

pub fn withdraw_auth_key_felt_from_raw_key_hex(withdraw_auth_key_hex: &str) -> String {
    encode_starknet_felt("withdraw-auth-key", withdraw_auth_key_hex)
}

pub fn withdraw_authority_from_withdraw_auth_key_felt(
    withdraw_auth_key_felt: &str,
) -> Result<String, ProtocolError> {
    let withdraw_auth_key = felt_from_hex_str(withdraw_auth_key_felt)?;
    Ok(crate::hash::felt_hex(&get_public_key(&withdraw_auth_key)))
}

pub fn withdraw_authority_from_raw_key_hex(
    withdraw_auth_key_hex: &str,
) -> Result<String, ProtocolError> {
    withdraw_authority_from_withdraw_auth_key_felt(&withdraw_auth_key_felt_from_raw_key_hex(
        withdraw_auth_key_hex,
    ))
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBlob {
    pub algorithm: String,
    pub key_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl fmt::Debug for EncryptedBlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedBlob")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("ephemeral_public_key", &self.ephemeral_public_key)
            .field("nonce", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionKeyPublicConfig {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionKeyPrivateConfig {
    pub key_id: String,
    pub private_key: String,
    pub public_key: String,
}

impl fmt::Debug for PrivateExecutionKeyPrivateConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateExecutionKeyPrivateConfig")
            .field("key_id", &self.key_id)
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
    /// validates the secret/public point pair and returns the canonical uncompressed point.
    pub fn canonical_public_key(&self) -> Result<Vec<u8>, ProtocolError> {
        let private = hex::decode(self.private_key.trim_start_matches("0x"))?;
        let secret = p256::SecretKey::from_slice(&private)
            .map_err(|_| ProtocolError::Crypto("execution private key is invalid".into()))?;
        let public = hex::decode(self.public_key.trim_start_matches("0x"))?;
        let supplied = p256::PublicKey::from_sec1_bytes(&public)
            .map_err(|_| ProtocolError::Crypto("execution public key is invalid".into()))?;
        let canonical = supplied.to_encoded_point(false);
        if public.as_slice() != canonical.as_bytes() {
            return Err(ProtocolError::Crypto(
                "execution public key is not canonical uncompressed sec1".into(),
            ));
        }
        let derived = secret.public_key().to_encoded_point(false);
        if derived.as_bytes() != canonical.as_bytes() {
            return Err(ProtocolError::Crypto(
                "execution private and public keys do not match".into(),
            ));
        }
        Ok(canonical.as_bytes().to_vec())
    }
}

pub fn validate_private_execution_keys(
    keys: &[PrivateExecutionKeyPrivateConfig],
) -> Result<(), ProtocolError> {
    if keys.is_empty() {
        return Err(ProtocolError::Crypto(
            "at least one private execution key is required".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut points = BTreeSet::new();
    for key in keys {
        if key.key_id.trim().is_empty() || !ids.insert(key.key_id.clone()) {
            return Err(ProtocolError::Crypto(
                "execution key ids must be nonempty and unique".into(),
            ));
        }
        if !points.insert(key.canonical_public_key()?) {
            return Err(ProtocolError::Crypto(
                "execution public keys must be unique".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionKeyRegistry {
    pub keys: Vec<PrivateExecutionKeyPublicConfig>,
}

impl PrivateExecutionKeyRegistry {
    /// the pin a deployment manifest carries for its execution keys: sha-256 over a domain tag,
    /// the key count and every key sorted by id, each id and point length-prefixed. a wallet
    /// seals only to a registry whose fingerprint the manifest pins.
    pub fn fingerprint(&self) -> Result<String, ProtocolError> {
        use sha2::{Digest, Sha256};
        let mut keys = self.keys.iter().collect::<Vec<_>>();
        keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        if keys.is_empty() || keys.windows(2).any(|pair| pair[0].key_id == pair[1].key_id) {
            return Err(ProtocolError::Crypto(
                "the execution key registry is empty or repeats a key id".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"zylith-execution-key-registry-v1");
        hasher.update((keys.len() as u32).to_be_bytes());
        for key in keys {
            let point = hex::decode(key.public_key.trim_start_matches("0x"))?;
            for part in [key.key_id.as_bytes(), point.as_slice()] {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_key_registry_next_fingerprint: Option<String>,
    pub sdk_package: String,
    pub sdk_version: String,
    pub min_proving_delay_blocks: u64,
    pub proof_signer_class_hash: String,
}

impl StarknetPrivacyFundingRail {
    /// the execution key registries a wallet may seal to: the current one and, while a rotation
    /// is published, its successor.
    pub fn pinned_registry_fingerprints(&self) -> Vec<&str> {
        std::iter::once(self.ingress_key_registry_fingerprint.as_str())
            .chain(self.ingress_key_registry_next_fingerprint.as_deref())
            .filter(|fingerprint| {
                fingerprint.len() == 64
                    && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && fingerprint.bytes().any(|byte| byte != b'0')
            })
            .collect()
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    use super::{
        DeploymentManifest, PrivateExecutionKeyPrivateConfig, validate_private_execution_keys,
    };

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
        let mut manifest: DeploymentManifest =
            serde_json::from_str(include_str!("../../client/public/deployment.example.json"))
                .unwrap();
        manifest.deployment.finalized = true;
        manifest.deployment.release_commit = "1".repeat(40);
        manifest.proof.config_locked_after_deploy = true;
        manifest.runtime.max_admissions_per_transition = manifest.runtime.max_book_orders + 1;
        assert!(
            manifest
                .validate_production()
                .unwrap_err()
                .contains("runtime limits")
        );
    }

    fn execution_key(id: &str, scalar: u8) -> PrivateExecutionKeyPrivateConfig {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let secret = p256::SecretKey::from_slice(&bytes).unwrap();
        PrivateExecutionKeyPrivateConfig {
            key_id: id.into(),
            private_key: hex::encode(bytes),
            public_key: hex::encode(secret.public_key().to_encoded_point(false).as_bytes()),
        }
    }

    #[test]
    fn private_execution_keys_bind_each_secret_to_one_unique_public_point() {
        let first = execution_key("first", 1);
        let second = execution_key("second", 2);
        validate_private_execution_keys(&[first.clone(), second.clone()]).unwrap();

        let mut mismatched = first.clone();
        mismatched.public_key = second.public_key.clone();
        assert!(
            validate_private_execution_keys(&[mismatched])
                .unwrap_err()
                .to_string()
                .contains("do not match")
        );

        let mut duplicate_id = second.clone();
        duplicate_id.key_id = first.key_id.clone();
        assert!(validate_private_execution_keys(&[first.clone(), duplicate_id]).is_err());

        let mut duplicate_point = first.clone();
        duplicate_point.key_id = "other".into();
        assert!(validate_private_execution_keys(&[first, duplicate_point]).is_err());
    }
}
