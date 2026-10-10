use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload, consts::U12},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use starknet_crypto::{Felt, poseidon_hash, rfc6979_generate_k, sign};
use zeroize::Zeroizing;

use crate::types::*;
use crate::{
    ProtocolError, RecoverySeed, ReferencePriceAttestation, ReferencePriceEnvelope,
    WalletDataError,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, felt_hex, normalize_felt_hex,
        poseidon_chain_hex, tagged_commitment_sha256, tagged_field_hex,
    },
    wallet_crypto::{
        WALLET_KEY_SCHEDULE_VERSION, WalletKeyScheduleV2, encode_context, parse_canonical_field_hex,
    },
};

const STRK20_EXIT_CLAIM_DOMAIN_HEX: &str = "0x7a796c6974685f7374726b32305f636c61696d5f7634";
const REFERENCE_PRICE_ATTESTATION_DOMAIN_TAG: &str = "zylith/reference-price-attestation-v1";
const REFERENCE_PRICE_BATCH_DOMAIN: &str = "zylith_price_batch_v1";
const RECOVERY_ARTIFACT_ALGORITHM: &str = "aes-256-gcm/recovery-v1";
const WALLET_HKDF_SALT: &[u8] = b"zylith/wallet-key-separation-v1";

fn aes_nonce_from_slice(bytes: &[u8]) -> Result<Nonce<U12>, ProtocolError> {
    let nonce: [u8; 12] = bytes
        .try_into()
        .map_err(|_| ProtocolError::Crypto("aes-gcm nonce must be 12 bytes".into()))?;
    Ok(nonce.into())
}

pub fn reference_price_source_set_commitment<T: Serialize>(
    sources: &T,
) -> Result<String, ProtocolError> {
    tagged_field_hex("zylith/reference-price-source-set-v1", sources)
}

/// what the batch commitment absorbs for one attestation, and its signed message starts with.
fn reference_price_batch_fields(
    envelope: &ReferencePriceEnvelope,
    source_set_commitment: &str,
    valid_until_unix_ms: u64,
    nonce: u64,
) -> Result<Vec<String>, ProtocolError> {
    let mut fields = vec![
        encode_starknet_felt("pair-id", &envelope.pair_id.0),
        encode_asset_id(&envelope.base_asset_id.0),
        encode_asset_id(&envelope.quote_asset_id.0),
        encode_u128(envelope.midpoint_price),
        encode_u128(envelope.lower_price),
        encode_u128(envelope.upper_price),
        encode_u128(envelope.price_base_scale),
    ];
    fields.extend(match &envelope.derivation {
        crate::ReferencePriceDerivation::DirectBbo {
            bid_price,
            ask_price,
        } => [
            encode_u64(u64::from(crate::exchange::REFERENCE_METHOD_DIRECT_BBO)),
            encode_u64(0),
            encode_u64(0),
            encode_u128(*bid_price),
            encode_u128(*ask_price),
            encode_u128(0),
            encode_u128(0),
            encode_u64(0),
        ],
        crate::ReferencePriceDerivation::SyntheticCrossBbo {
            base_market_id,
            quote_market_id,
            max_leg_skew_ms,
            base_bid_price,
            base_ask_price,
            quote_bid_price,
            quote_ask_price,
        } => [
            encode_u64(u64::from(
                crate::exchange::REFERENCE_METHOD_SYNTHETIC_CROSS_BBO,
            )),
            encode_starknet_felt("pair-id", &base_market_id.0),
            encode_starknet_felt("pair-id", &quote_market_id.0),
            encode_u128(*base_bid_price),
            encode_u128(*base_ask_price),
            encode_u128(*quote_bid_price),
            encode_u128(*quote_ask_price),
            encode_u64(*max_leg_skew_ms),
        ],
    });
    fields.extend([
        encode_u64(envelope.source_count as u64),
        encode_u64(envelope.observed_at_unix_ms),
        encode_u64(valid_until_unix_ms),
        normalize_felt_hex(source_set_commitment)?,
        encode_u64(nonce),
    ]);
    Ok(fields)
}

pub fn reference_price_attestation_commitment(
    attestation: &ReferencePriceAttestation,
) -> Result<String, ProtocolError> {
    let mut state = poseidon_hash(
        domain_felt(REFERENCE_PRICE_ATTESTATION_DOMAIN_TAG),
        felt_from_hex_str(&normalize_felt_hex(&attestation.exchange_address)?)?,
    );
    let mut fields = reference_price_batch_fields(
        &attestation.envelope,
        &attestation.source_set_commitment,
        attestation.valid_until_unix_ms,
        attestation.nonce,
    )?;
    fields.extend([
        normalize_felt_hex(&attestation.price_batch_commitment)?,
        normalize_felt_hex(&attestation.signer_public_key)?,
    ]);
    for field in fields {
        state = poseidon_hash(state, felt_from_hex_str(&field)?);
    }
    Ok(felt_hex(&state))
}

pub fn sign_reference_price_attestation(
    signer_private_key: &str,
    exchange_address: &str,
    envelope: ReferencePriceEnvelope,
    source_set_commitment: &str,
    valid_until_unix_ms: u64,
    nonce: u64,
) -> Result<ReferencePriceAttestation, ProtocolError> {
    let batch_commitment = reference_price_batch_commitment(
        exchange_address,
        &[ReferencePriceBatchEntry {
            envelope: envelope.clone(),
            source_set_commitment: source_set_commitment.to_owned(),
            valid_until_unix_ms,
            nonce,
        }],
    )?;
    sign_reference_price_attestation_in_batch(
        signer_private_key,
        exchange_address,
        envelope,
        source_set_commitment,
        valid_until_unix_ms,
        nonce,
        &batch_commitment,
    )
}

#[derive(Clone, Debug)]
pub struct ReferencePriceBatchEntry {
    pub envelope: ReferencePriceEnvelope,
    pub source_set_commitment: String,
    pub valid_until_unix_ms: u64,
    pub nonce: u64,
}

pub fn reference_price_batch_commitment(
    exchange_address: &str,
    entries: &[ReferencePriceBatchEntry],
) -> Result<String, ProtocolError> {
    if entries.is_empty() {
        return Err(ProtocolError::Crypto("price batch cannot be empty".into()));
    }
    let mut state = poseidon_hash(
        crate::exchange::short_string(REFERENCE_PRICE_BATCH_DOMAIN),
        felt_from_hex_str(&normalize_felt_hex(exchange_address)?)?,
    );
    state = poseidon_hash(state, Felt::from(entries.len() as u64));
    for entry in entries {
        for field in reference_price_batch_fields(
            &entry.envelope,
            &entry.source_set_commitment,
            entry.valid_until_unix_ms,
            entry.nonce,
        )? {
            state = poseidon_hash(state, felt_from_hex_str(&field)?);
        }
    }
    Ok(felt_hex(&state))
}

#[allow(clippy::too_many_arguments)]
pub fn sign_reference_price_attestation_in_batch(
    signer_private_key: &str,
    exchange_address: &str,
    envelope: ReferencePriceEnvelope,
    source_set_commitment: &str,
    valid_until_unix_ms: u64,
    nonce: u64,
    price_batch_commitment: &str,
) -> Result<ReferencePriceAttestation, ProtocolError> {
    if valid_until_unix_ms <= envelope.observed_at_unix_ms {
        return Err(ProtocolError::Crypto(
            "reference price attestation expiry must follow observation time".into(),
        ));
    }
    let private_key = felt_from_hex_str(&normalize_felt_hex(signer_private_key)?)?;
    if private_key == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "reference price attestation key cannot be zero".into(),
        ));
    }
    let signer_public_key = starknet_crypto::get_public_key(&private_key);
    let mut attestation = ReferencePriceAttestation {
        envelope,
        exchange_address: normalize_felt_hex(exchange_address)?,
        source_set_commitment: normalize_felt_hex(source_set_commitment)?,
        valid_until_unix_ms,
        nonce,
        price_batch_commitment: normalize_felt_hex(price_batch_commitment)?,
        signer_public_key: felt_hex(&signer_public_key),
        signature: crate::SpendAuthorization {
            signature_r: "0x0".into(),
            signature_s: "0x0".into(),
        },
    };
    let message = felt_from_hex_str(&reference_price_attestation_commitment(&attestation)?)?;
    let k = rfc6979_generate_k(&message, &private_key, None);
    let signature = sign(&private_key, &message, &k).map_err(|error| {
        ProtocolError::Crypto(format!(
            "reference price attestation signing failed: {error}"
        ))
    })?;
    attestation.signature = crate::SpendAuthorization {
        signature_r: felt_hex(&signature.r),
        signature_s: felt_hex(&signature.s),
    };
    Ok(attestation)
}

pub fn derive_account_id(seed: &RecoverySeed) -> String {
    WalletKeyScheduleV2::from_seed(seed).account_id()
}

fn build_wallet_deposit_note(
    schedule: &WalletKeyScheduleV2,
    context: &DepositDerivationContext,
    intent: &DepositIntent,
) -> Result<Note, ProtocolError> {
    context.validate()?;
    if intent.asset_id.0.is_empty() {
        return Err(ProtocolError::Crypto(
            "deposit asset id must not be empty".into(),
        ));
    }
    if intent.amount == 0 {
        return Err(ProtocolError::Crypto(
            "deposit amount must be nonzero".into(),
        ));
    }
    let owner_tag = parse_canonical_field_hex(&intent.recipient_owner_public_key)?;
    let spend_authority = parse_canonical_field_hex(&intent.recipient_spend_authority)?;
    let withdraw_authority = parse_canonical_field_hex(&intent.recipient_withdraw_authority)?;
    if owner_tag == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "deposit owner tag must be nonzero".into(),
        ));
    }
    if spend_authority == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "deposit spend authority must be nonzero".into(),
        ));
    }
    if withdraw_authority == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "deposit withdraw authority must be nonzero".into(),
        ));
    }
    let chain_bytes = context.chain_id.to_bytes_be();
    let bridge_bytes = context.bridge_address.to_bytes_be();
    let amount_bytes = intent.amount.to_be_bytes();
    let nonce_bytes = intent.deposit_nonce.to_be_bytes();
    let owner_bytes = owner_tag.to_bytes_be();
    let spend_bytes = spend_authority.to_bytes_be();
    let withdraw_bytes = withdraw_authority.to_bytes_be();
    let fields: [&[u8]; 8] = [
        &chain_bytes,
        &bridge_bytes,
        intent.asset_id.0.as_bytes(),
        &amount_bytes,
        &nonce_bytes,
        &owner_bytes,
        &spend_bytes,
        &withdraw_bytes,
    ];
    let blinding = felt_hex(&schedule.deposit_blinding(fields)?);
    let mut metadata_parts: [&[u8]; 9] = [&[]; 9];
    metadata_parts[0] = b"zylith/deposit-metadata/sha256/v2";
    metadata_parts[1..].copy_from_slice(&fields);
    let mut metadata_digest: [u8; 32] = Sha256::digest(encode_context(&metadata_parts)?).into();
    // this public commitment uses the existing 250-bit mapping, not secret field sampling.
    metadata_digest[0] &= 0x03;
    let metadata_commitment = felt_hex(&Felt::from_bytes_be(&metadata_digest));

    Ok(Note {
        asset_id: intent.asset_id.clone(),
        amount: intent.amount,
        owner_public_key: felt_hex(&owner_tag),
        spend_authority: felt_hex(&spend_authority),
        withdraw_authority: felt_hex(&withdraw_authority),
        blinding,
        nonce: intent.deposit_nonce,
        metadata_commitment,
    })
}

#[derive(Clone, Copy)]
pub struct Strk20ExitClaimMessage<'a> {
    pub chain_id: &'a str,
    pub bridge_address: &'a str,
    pub privacy_pool_address: &'a str,
    pub exchange_address: &'a str,
    pub asset_id: &'a str,
    pub token_address: &'a str,
    pub amount: &'a str,
    pub exit_commitment: &'a str,
    pub claim_account: &'a str,
    pub open_note_id: &'a str,
}

pub fn strk20_exit_claim_message_hash(
    message: Strk20ExitClaimMessage<'_>,
) -> Result<String, ProtocolError> {
    let Strk20ExitClaimMessage {
        chain_id,
        bridge_address,
        privacy_pool_address,
        exchange_address,
        asset_id,
        token_address,
        amount,
        exit_commitment,
        claim_account,
        open_note_id,
    } = message;
    let normalized_asset_id = normalize_asset_id_for_public_hash(asset_id)?;
    let normalized_amount = normalize_u128_for_public_hash(amount)?;
    Ok(poseidon_chain_hex(
        felt_from_hex_str(STRK20_EXIT_CLAIM_DOMAIN_HEX)?,
        &[
            felt_from_hex_str(chain_id)?,
            felt_from_hex_str(bridge_address)?,
            felt_from_hex_str(privacy_pool_address)?,
            felt_from_hex_str(exchange_address)?,
            felt_from_hex_str(&normalized_asset_id)?,
            felt_from_hex_str(token_address)?,
            felt_from_hex_str(&normalized_amount)?,
            felt_from_hex_str(exit_commitment)?,
            felt_from_hex_str(claim_account)?,
            felt_from_hex_str(open_note_id)?,
        ],
    ))
}

pub fn create_recovery_artifact(
    seed: &RecoverySeed,
    kind: RecoveryArtifactKind,
    sequence: u64,
    created_at_unix_ms: u64,
    payload: &Value,
) -> Result<RecoveryArtifact, ProtocolError> {
    let account_id = derive_account_id(seed);
    let key_bytes = Zeroizing::new(derive_wallet_aes_key(
        seed,
        b"zylith/recovery-artifact-aes-key",
    )?);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..])
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = random_nonce();
    let plaintext = Zeroizing::new(serde_json::to_vec(payload)?);
    let aad = recovery_artifact_aad(
        RECOVERY_ARTIFACT_ALGORITHM,
        &account_id,
        &kind,
        sequence,
        created_at_unix_ms,
    );
    let ciphertext = cipher
        .encrypt(
            &aes_nonce_from_slice(&nonce)?,
            Payload {
                msg: plaintext.as_ref(),
                aad: aad.as_ref(),
            },
        )
        .map_err(|err| ProtocolError::Crypto(format!("recovery encrypt failed: {err}")))?;
    let artifact_id = tagged_commitment_sha256(
        "zylith/recovery-artifact-id",
        &serde_json::json!({
            "key_schedule_version": WALLET_KEY_SCHEDULE_VERSION,
            "account_id": account_id,
            "kind": kind,
            "sequence": sequence,
            "created_at_unix_ms": created_at_unix_ms,
        }),
    )?;

    Ok(RecoveryArtifact {
        key_schedule_version: WALLET_KEY_SCHEDULE_VERSION,
        artifact_id,
        account_id,
        kind,
        sequence,
        created_at_unix_ms,
        payload: EncryptedRecoveryPayload {
            key_schedule_version: WALLET_KEY_SCHEDULE_VERSION,
            algorithm: RECOVERY_ARTIFACT_ALGORITHM.into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        },
    })
}

pub fn decrypt_recovery_artifact_payload(
    seed: &RecoverySeed,
    artifact: &RecoveryArtifact,
) -> Result<Value, ProtocolError> {
    decrypt_recovery_artifact_payload_classified(seed, artifact).map_err(ProtocolError::from)
}

pub fn decrypt_recovery_artifact_payload_classified(
    seed: &RecoverySeed,
    artifact: &RecoveryArtifact,
) -> Result<Value, WalletDataError> {
    if artifact.key_schedule_version != WALLET_KEY_SCHEDULE_VERSION
        || artifact.payload.key_schedule_version != WALLET_KEY_SCHEDULE_VERSION
    {
        return Err(WalletDataError::MigrationRequired);
    }
    if artifact.payload.algorithm != RECOVERY_ARTIFACT_ALGORITHM {
        return Err(WalletDataError::MigrationRequired);
    }
    if artifact.account_id != WalletKeyScheduleV2::from_seed(seed).account_id() {
        return Err(WalletDataError::DataInvalid);
    }

    let key_bytes = Zeroizing::new(
        derive_wallet_aes_key(seed, b"zylith/recovery-artifact-aes-key")
            .map_err(|_| WalletDataError::DataInvalid)?,
    );
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes[..]).map_err(|_| WalletDataError::DataInvalid)?;
    let nonce = hex::decode(&artifact.payload.nonce).map_err(|_| WalletDataError::DataInvalid)?;
    let ciphertext =
        hex::decode(&artifact.payload.ciphertext).map_err(|_| WalletDataError::DataInvalid)?;
    let aad = recovery_artifact_aad(
        &artifact.payload.algorithm,
        &artifact.account_id,
        &artifact.kind,
        artifact.sequence,
        artifact.created_at_unix_ms,
    );
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &aes_nonce_from_slice(&nonce).map_err(|_| WalletDataError::DataInvalid)?,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: aad.as_ref(),
                },
            )
            .map_err(|_| WalletDataError::DataInvalid)?,
    );
    match serde_json::from_slice::<UniqueRecoveryJson>(&plaintext) {
        Ok(value) => Ok(value.0),
        Err(_) if serde_json::from_slice::<Value>(&plaintext).is_ok() => {
            Err(WalletDataError::MigrationRequired)
        }
        Err(_) => Err(WalletDataError::DataInvalid),
    }
}

struct UniqueRecoveryJson(Value);

/// preserves version ambiguity as an error instead of discarding duplicate json keys.
pub fn deserialize_unique_wallet_json<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    UniqueRecoveryJson::deserialize(deserializer).map(|value| value.0)
}

impl<'de> Deserialize<'de> for UniqueRecoveryJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> serde::de::Visitor<'de> for UniqueVisitor {
            type Value = UniqueRecoveryJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("unambiguous recovery json")
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueRecoveryJson(Value::Bool(value)))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueRecoveryJson(value.into()))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueRecoveryJson(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueRecoveryJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("wallet migration required"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueRecoveryJson(Value::String(value.into())))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueRecoveryJson(Value::Null))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueRecoveryJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueRecoveryJson(Value::Array(values)))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("wallet migration required"));
                    }
                    values.insert(key, map.next_value::<UniqueRecoveryJson>()?.0);
                }
                Ok(UniqueRecoveryJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub fn sign_strk20_exit_claim_authorization(
    withdraw_auth_key_felt: &str,
    message: Strk20ExitClaimMessage<'_>,
) -> Result<crate::SpendAuthorization, ProtocolError> {
    let private_key = felt_from_hex_str(withdraw_auth_key_felt)?;
    let message = felt_from_hex_str(&strk20_exit_claim_message_hash(message)?)?;
    let k = rfc6979_generate_k(&message, &private_key, None);
    let signature = sign(&private_key, &message, &k)
        .map_err(|err| ProtocolError::Crypto(format!("STRK20 exit claim signing failed: {err}")))?;
    Ok(crate::SpendAuthorization {
        signature_r: felt_hex(&signature.r),
        signature_s: felt_hex(&signature.s),
    })
}

/// deposit construction requires secret wallet material and explicit deployment context.
///
/// ```compile_fail
/// zylith_core::build_wallet_deposit_submission_plan(&unreachable!());
/// ```
///
/// ```compile_fail
/// use zylith_core::build_deposit_submission_plan;
/// ```
///
/// ```compile_fail
/// use zylith_core::build_deposit_note;
/// ```
pub fn build_wallet_deposit_submission_plan(
    seed: &RecoverySeed,
    context: &DepositDerivationContext,
    intent: &DepositIntent,
) -> Result<DepositSubmissionPlan, ProtocolError> {
    let schedule = WalletKeyScheduleV2::from_seed(seed);
    let note = build_wallet_deposit_note(&schedule, context, intent)?;
    let note_commitment = note.commitment()?;
    let deposit_root = deposit_root_from_note(&note)?;
    let funding_commitment = funding_commitment_for_deposit(&note_commitment.0, &deposit_root)?;
    let encrypted_note_activation =
        encrypted_note_activation_commitment(&note_commitment.0, &deposit_root)?;
    let encoded_args = DepositCallArguments {
        funding_commitments: vec![funding_commitment.clone()],
        deposit_roots: vec![deposit_root.clone()],
        encrypted_note_activations: vec![encrypted_note_activation.clone()],
        note_commitments: vec![note_commitment.0.clone()],
        asset_ids: vec![encode_asset_id(&note.asset_id.0)],
        amounts: vec![note.amount.to_string()],
        withdraw_authorities: vec![note.withdraw_authority.clone()],
    };
    Ok(DepositSubmissionPlan {
        funding_rail: FundingRailKind::StarknetPrivacy,
        note,
        note_commitment,
        funding_commitment,
        deposit_root,
        encrypted_note_activation,
        encoded_args,
    })
}

/// a deposit is a batch of one note, so its root is the note's output leaf.
pub fn deposit_root_from_note(note: &Note) -> Result<String, ProtocolError> {
    Ok(felt_hex(
        &crate::exchange::NoteFields::from_note(note)?.output_leaf(),
    ))
}

pub fn funding_commitment_for_deposit(
    note_commitment: &str,
    deposit_root: &str,
) -> Result<String, ProtocolError> {
    tagged_field_hex(
        "zylith/private-funding-commitment-v1",
        &serde_json::json!({
            "note_commitment": normalize_felt_hex(note_commitment)?,
            "deposit_root": normalize_felt_hex(deposit_root)?,
        }),
    )
}

pub fn encrypted_note_activation_commitment(
    note_commitment: &str,
    deposit_root: &str,
) -> Result<String, ProtocolError> {
    tagged_field_hex(
        "zylith/encrypted-note-activation-v1",
        &serde_json::json!({
            "note_commitment": normalize_felt_hex(note_commitment)?,
            "deposit_root": normalize_felt_hex(deposit_root)?,
        }),
    )
}

pub(crate) fn encode_asset_id(asset_id: &str) -> String {
    encode_starknet_felt("asset-id", asset_id)
}

fn normalize_asset_id_for_public_hash(asset_id: &str) -> Result<String, ProtocolError> {
    let trimmed = asset_id.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        normalize_felt_hex(trimmed)
    } else {
        Ok(encode_asset_id(trimmed))
    }
}

fn normalize_u128_for_public_hash(value: &str) -> Result<String, ProtocolError> {
    let trimmed = value.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        normalize_felt_hex(trimmed)
    } else {
        let parsed = trimmed.parse::<u128>().map_err(|err| {
            ProtocolError::Crypto(format!("invalid u128 amount {trimmed}: {err}"))
        })?;
        Ok(encode_u128(parsed))
    }
}

fn derive_wallet_aes_key(seed: &RecoverySeed, info: &[u8]) -> Result<[u8; 32], ProtocolError> {
    let schedule = WalletKeyScheduleV2::from_seed(seed);
    let recovery_key = schedule.recovery_encryption_key();
    hkdf_expand(recovery_key.as_bytes(), WALLET_HKDF_SALT, info)
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], ProtocolError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut key = [0_u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| ProtocolError::Crypto("hkdf expansion failed".into()))?;
    Ok(key)
}

fn recovery_artifact_aad(
    algorithm: &str,
    account_id: &str,
    kind: &RecoveryArtifactKind,
    sequence: u64,
    created_at_unix_ms: u64,
) -> Vec<u8> {
    format!(
        "zylith-recovery-artifact:{WALLET_KEY_SCHEDULE_VERSION}:{algorithm}:{account_id}:{kind:?}:{sequence}:{created_at_unix_ms}"
    )
    .into_bytes()
}

pub(crate) fn encode_u64(value: u64) -> String {
    format!("0x{value:x}")
}

pub(crate) fn encode_u128(value: u128) -> String {
    format!("0x{value:x}")
}

fn random_nonce() -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use starknet_crypto::Felt;

    use crate::{
        AssetId, DepositDerivationContext, DepositIntent, DepositSubmissionPlan, ProtocolError,
        RecoveryArtifactKind, RecoverySeed, build_wallet_deposit_submission_plan,
        create_recovery_artifact, decrypt_recovery_artifact_payload_classified,
    };

    fn deposit_context() -> DepositDerivationContext {
        DepositDerivationContext::from_hex("0x534e5f5345504f4c4941", "0x123").unwrap()
    }

    fn deposit_intent(owner_tag: &str) -> DepositIntent {
        DepositIntent {
            asset_id: AssetId("STRK".into()),
            amount: 10,
            deposit_nonce: 42,
            recipient_owner_public_key: owner_tag.into(),
            recipient_spend_authority: "0x2".into(),
            recipient_withdraw_authority: "0x3".into(),
        }
    }

    #[test]
    fn deposit_blinding_v2_known_answers_bind_the_exact_binary_protocol() {
        for (seed_byte, amount, nonce, blinding, metadata, commitment) in [
            (
                0_u8,
                10_u128,
                42_u64,
                "0x4f8a477e2833d792392d6669c0f9419075b59e00b4dd412750d7d6be2fe55d4",
                "0x3780cf673145b5de1f7b610c7aed41696b016178b69c3712883152f04c8d4d7",
                "0x9a3521283841c42ed7fdeef1753be36b6113734984ee2e25ce6a6d6075ff06",
            ),
            (
                1,
                10,
                42,
                "0x2b64f4e0730aed11055c198140b6faf543f2ccc3d9978ed1079e7a469eab861",
                "0x3780cf673145b5de1f7b610c7aed41696b016178b69c3712883152f04c8d4d7",
                "0x6c1315ff3a7e71e2e376d7b81a3b54b3c79c24161182c8e58be912f05de8ded",
            ),
            (
                1,
                10,
                u64::MAX,
                "0x1177425d9f35ff08280355ea3f73b64700e64bf6dc451684afb028962d10332",
                "0x2e22efab00ee60ee75d0cc12ada43c3e60557dc15088498706282df8323a42c",
                "0x39bd47a415d176f6ea89d2f514ae8b2971b50fa9a94b3c6eaa79223b04f74d2",
            ),
            (
                1,
                u128::MAX,
                42,
                "0x2047e65cda9b79d90d2c50e82cca8cfe2cd001fbb6179e84b3c6dda62f097b3",
                "0x23ec4bf42673e030aaf5df95c5adcc5e59616c752f84fb767f52d7fe44b1efc",
                "0x80af6b21199bd7ef7e878aa0efcba080f713157b3c6ab8b1ce547724ac507a",
            ),
        ] {
            let mut intent = deposit_intent("0xa");
            intent.amount = amount;
            intent.deposit_nonce = nonce;
            let plan = build_wallet_deposit_submission_plan(
                &RecoverySeed([seed_byte; 32]),
                &deposit_context(),
                &intent,
            )
            .unwrap();
            assert_eq!(plan.note.blinding, blinding);
            assert_eq!(plan.note.metadata_commitment, metadata);
            assert_eq!(plan.note_commitment.0, commitment);
            assert_eq!(plan.note.nonce, nonce);
            assert_eq!(plan.note.commitment().unwrap(), plan.note_commitment);
            assert_eq!(
                crate::exchange::NoteFields::from_note(&plan.note)
                    .unwrap()
                    .commitment(),
                Felt::from_hex(commitment).unwrap()
            );
        }
    }

    #[test]
    fn deposit_blinding_v2_requires_a_seed_and_retries_deterministically() {
        let builder: fn(
            &RecoverySeed,
            &DepositDerivationContext,
            &DepositIntent,
        ) -> Result<DepositSubmissionPlan, ProtocolError> = build_wallet_deposit_submission_plan;
        let seed = RecoverySeed([1; 32]);
        let intent = deposit_intent("0xa");
        let context = deposit_context();
        let first = builder(&seed, &context, &intent).unwrap();
        assert_eq!(first, builder(&seed, &context, &intent).unwrap());
        let other_seed = builder(&RecoverySeed([2; 32]), &context, &intent).unwrap();
        assert_ne!(first.note.blinding, other_seed.note.blinding);
        assert_ne!(first.note_commitment, other_seed.note_commitment);
        assert_eq!(
            first.note.metadata_commitment,
            other_seed.note.metadata_commitment
        );
    }

    #[test]
    fn deposit_blinding_v2_separates_each_deployment_and_public_field() {
        let seed = RecoverySeed([1; 32]);
        let intent = deposit_intent("0xa");
        let context = deposit_context();
        let base = build_wallet_deposit_submission_plan(&seed, &context, &intent).unwrap();
        let mut variants = Vec::new();
        let mut changed_chain = context;
        changed_chain.chain_id += Felt::ONE;
        variants.push((changed_chain, intent.clone()));
        let mut changed_bridge = context;
        changed_bridge.bridge_address += Felt::ONE;
        variants.push((changed_bridge, intent.clone()));
        for changed in [
            DepositIntent {
                asset_id: AssetId("USDC".into()),
                ..intent.clone()
            },
            DepositIntent {
                asset_id: AssetId("strk".into()),
                ..intent.clone()
            },
            DepositIntent {
                amount: 11,
                ..intent.clone()
            },
            DepositIntent {
                deposit_nonce: 43,
                ..intent.clone()
            },
            DepositIntent {
                recipient_owner_public_key: "0xb".into(),
                ..intent.clone()
            },
            DepositIntent {
                recipient_spend_authority: "0x4".into(),
                ..intent.clone()
            },
            DepositIntent {
                recipient_withdraw_authority: "0x4".into(),
                ..intent.clone()
            },
        ] {
            variants.push((context, changed));
        }
        let mut blindings = std::collections::BTreeSet::new();
        blindings.insert(base.note.blinding.clone());
        for (changed_context, changed_intent) in variants {
            let changed =
                build_wallet_deposit_submission_plan(&seed, &changed_context, &changed_intent)
                    .unwrap();
            assert_ne!(changed.note.blinding, base.note.blinding);
            assert_ne!(
                changed.note.metadata_commitment,
                base.note.metadata_commitment
            );
            assert_ne!(changed.note_commitment, base.note_commitment);
            assert!(blindings.insert(changed.note.blinding));
        }
    }

    #[test]
    fn deposit_blinding_v2_canonicalizes_owner_and_both_authorities_once() {
        let seed = RecoverySeed([1; 32]);
        let context = deposit_context();
        let base =
            build_wallet_deposit_submission_plan(&seed, &context, &deposit_intent("0xa")).unwrap();
        let intent = DepositIntent {
            recipient_spend_authority: "0x0002".into(),
            recipient_withdraw_authority: "0003".into(),
            ..deposit_intent("0x000A")
        };
        let equivalent_context =
            DepositDerivationContext::from_hex("0x0000534e5f5345504f4c4941", "0x000123").unwrap();
        assert_eq!(
            build_wallet_deposit_submission_plan(&seed, &equivalent_context, &intent).unwrap(),
            base
        );
        assert_eq!(base.note.owner_public_key, "0xa");
        assert_eq!(base.note.spend_authority, "0x2");
        assert_eq!(base.note.withdraw_authority, "0x3");
    }

    #[test]
    fn deposit_blinding_v2_rejects_missing_zero_malformed_and_out_of_range_context() {
        for invalid in [
            "",
            "0",
            "0x0000",
            "-1",
            "0xno",
            " 0x1",
            "0x1 ",
            "0x0800000000000011000000000000000000000000000000000000000000000001",
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            assert!(
                DepositDerivationContext::from_hex(invalid, "0x123").is_err(),
                "accepted chain {invalid}"
            );
            assert!(
                DepositDerivationContext::from_hex("0x1", invalid).is_err(),
                "accepted bridge {invalid}"
            );
        }
        for context in [
            DepositDerivationContext {
                chain_id: Felt::ZERO,
                ..deposit_context()
            },
            DepositDerivationContext {
                bridge_address: Felt::ZERO,
                ..deposit_context()
            },
        ] {
            assert!(
                build_wallet_deposit_submission_plan(
                    &RecoverySeed([1; 32]),
                    &context,
                    &deposit_intent("0xa")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn deposit_blinding_v2_rejects_unusable_public_note_fields() {
        let seed = RecoverySeed([1; 32]);
        let context = deposit_context();
        let intent = deposit_intent("0xa");
        for changed in [
            DepositIntent {
                asset_id: AssetId("".into()),
                ..intent.clone()
            },
            DepositIntent {
                amount: 0,
                ..intent.clone()
            },
        ] {
            assert!(build_wallet_deposit_submission_plan(&seed, &context, &changed).is_err());
        }
        for invalid in [
            "0x0",
            "0x0000",
            "0",
            "",
            "invalid",
            "0x0800000000000011000000000000000000000000000000000000000000000001",
        ] {
            for changed in [
                DepositIntent {
                    recipient_owner_public_key: invalid.into(),
                    ..intent.clone()
                },
                DepositIntent {
                    recipient_spend_authority: invalid.into(),
                    ..intent.clone()
                },
                DepositIntent {
                    recipient_withdraw_authority: invalid.into(),
                    ..intent.clone()
                },
            ] {
                assert!(
                    build_wallet_deposit_submission_plan(&seed, &context, &changed).is_err(),
                    "accepted public field {invalid}"
                );
            }
        }
    }

    #[test]
    fn deposit_owner_tag_rejects_zero_before_creating_a_note() {
        for owner_tag in ["0x0", "0x0000", "0"] {
            let result = build_wallet_deposit_submission_plan(
                &RecoverySeed([1; 32]),
                &deposit_context(),
                &deposit_intent(owner_tag),
            );
            assert!(
                matches!(result, Err(ProtocolError::Crypto(message)) if message == "deposit owner tag must be nonzero"),
                "zero owner tag {owner_tag} was accepted"
            );
        }
    }

    #[test]
    fn deposit_owner_tag_equivalent_spellings_produce_the_same_canonical_plan() {
        let canonical = build_wallet_deposit_submission_plan(
            &RecoverySeed([1; 32]),
            &deposit_context(),
            &deposit_intent("0xa"),
        )
        .unwrap();
        assert_eq!(canonical.note.owner_public_key, "0xa");
        for owner_tag in ["0x000a", "0x000A", "000a", "A"] {
            let equivalent = build_wallet_deposit_submission_plan(
                &RecoverySeed([1; 32]),
                &deposit_context(),
                &deposit_intent(owner_tag),
            )
            .unwrap();
            assert_eq!(equivalent.note.owner_public_key, "0xa");
            assert_eq!(equivalent.note.blinding, canonical.note.blinding);
            assert_eq!(equivalent, canonical);
        }
    }

    #[test]
    fn recovery_artifact_classification_rejects_wrong_wallet_as_invalid_data() {
        let seed = RecoverySeed([7; 32]);
        let payload = serde_json::json!({"version": 2, "state": {}});
        let artifact =
            create_recovery_artifact(&seed, RecoveryArtifactKind::Snapshot, 1, 2, &payload)
                .unwrap();
        assert_eq!(
            decrypt_recovery_artifact_payload_classified(&RecoverySeed([8; 32]), &artifact)
                .unwrap_err(),
            crate::WalletDataError::DataInvalid
        );
        let mut incompatible = artifact.clone();
        incompatible.key_schedule_version = 1;
        assert_eq!(
            decrypt_recovery_artifact_payload_classified(&seed, &incompatible).unwrap_err(),
            crate::WalletDataError::MigrationRequired
        );
        incompatible = artifact.clone();
        incompatible.payload.algorithm = "AES-128-GCM".into();
        assert_eq!(
            decrypt_recovery_artifact_payload_classified(&seed, &incompatible).unwrap_err(),
            crate::WalletDataError::MigrationRequired
        );
        let mut invalid = artifact;
        invalid.payload.ciphertext = "not-hex".into();
        assert_eq!(
            decrypt_recovery_artifact_payload_classified(&seed, &invalid).unwrap_err(),
            crate::WalletDataError::DataInvalid
        );
    }
}
