use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload, consts::U12},
};
use hkdf::Hkdf;
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use starknet_crypto::{Felt, poseidon_hash, rfc6979_generate_k, sign};
use zeroize::Zeroizing;

use crate::types::*;
use crate::{
    ProtocolError, RecoverySeed, ReferencePriceAttestation, ReferencePriceEnvelope,
    derive_user_keys,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, felt_hex, normalize_felt_hex,
        poseidon_chain_hex, tagged_commitment_sha256, tagged_field_hex, tagged_sha256_bytes,
        tagged_sha256_hex,
    },
};

const STRK20_EXIT_CLAIM_DOMAIN_HEX: &str = "0x7a796c6974685f7374726b32305f636c61696d5f7631";
const REFERENCE_PRICE_ATTESTATION_DOMAIN_TAG: &str = "zylith/reference-price-attestation-v1";
const REFERENCE_PRICE_BATCH_DOMAIN: &str = "zylith_price_batch_v1";
const PRIVATE_ORDER_SHARE_ALGORITHM_V1: &str = "ecdh-p256+hkdf-sha256+aes-256-gcm/private-order-v1";
const PRIVATE_ORDER_SHARE_HKDF_SALT: &[u8] = b"zylith/private-order-share-key-separation-v1";
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
    let recovery_key_hex = Zeroizing::new(hex::encode(derive_user_keys(seed).recovery_key));
    tagged_sha256_hex("zylith/account-id:", recovery_key_hex.as_bytes())
}

pub fn build_deposit_note(intent: &DepositIntent) -> Result<Note, ProtocolError> {
    let blinding = tagged_field_hex(
        "zylith/deposit-blinding",
        &serde_json::json!({
            "asset_id": intent.asset_id.0,
            "amount": intent.amount.to_string(),
            "deposit_nonce": intent.deposit_nonce,
            "recipient_owner_public_key": intent.recipient_owner_public_key,
            "recipient_spend_authority": intent.recipient_spend_authority,
        }),
    )?;
    let metadata_commitment = tagged_field_hex(
        "zylith/deposit-metadata",
        &serde_json::json!({
            "asset_id": intent.asset_id.0,
            "amount": intent.amount.to_string(),
            "deposit_nonce": intent.deposit_nonce,
            "recipient_spend_authority": intent.recipient_spend_authority,
            "recipient_withdraw_authority": intent.recipient_withdraw_authority,
        }),
    )?;

    Ok(Note {
        asset_id: intent.asset_id.clone(),
        amount: intent.amount,
        owner_public_key: intent.recipient_owner_public_key.clone(),
        spend_authority: intent.recipient_spend_authority.clone(),
        withdraw_authority: intent.recipient_withdraw_authority.clone(),
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
            "account_id": account_id,
            "kind": kind,
            "sequence": sequence,
            "created_at_unix_ms": created_at_unix_ms,
        }),
    )?;

    Ok(RecoveryArtifact {
        artifact_id,
        account_id,
        kind,
        sequence,
        created_at_unix_ms,
        payload: EncryptedRecoveryPayload {
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
    if artifact.payload.algorithm != RECOVERY_ARTIFACT_ALGORITHM {
        return Err(ProtocolError::Crypto(format!(
            "unsupported recovery algorithm {}",
            artifact.payload.algorithm
        )));
    }

    let key_bytes = Zeroizing::new(derive_wallet_aes_key(
        seed,
        b"zylith/recovery-artifact-aes-key",
    )?);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..])
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = hex::decode(&artifact.payload.nonce)?;
    let ciphertext = hex::decode(&artifact.payload.ciphertext)?;
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
                &aes_nonce_from_slice(&nonce)?,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: aad.as_ref(),
                },
            )
            .map_err(|err| ProtocolError::Crypto(format!("recovery decrypt failed: {err}")))?,
    );
    Ok(serde_json::from_slice(&plaintext)?)
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

pub fn build_deposit_submission_plan(
    intent: &DepositIntent,
) -> Result<DepositSubmissionPlan, ProtocolError> {
    let note = build_deposit_note(intent)?;
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

pub(crate) fn split_into_xor_shares(plaintext: &[u8], share_count: usize) -> Vec<Vec<u8>> {
    let mut shares: Vec<Vec<u8>> = (0..share_count.saturating_sub(1))
        .map(|_| {
            let mut share = vec![0_u8; plaintext.len()];
            OsRng.fill_bytes(share.as_mut_slice());
            share
        })
        .collect();

    let mut final_share = vec![0_u8; plaintext.len()];
    for (index, byte) in plaintext.iter().enumerate() {
        let mut accumulator = *byte;
        for share in &shares {
            accumulator ^= share[index];
        }
        final_share[index] = accumulator;
    }
    shares.push(final_share);
    shares
}

pub(crate) fn encrypt_for_private_execution_key(
    key_id: &str,
    public_key_hex: &str,
    plaintext: &[u8],
) -> Result<EncryptedBlob, ProtocolError> {
    let recipient_public = parse_public_key(public_key_hex)?;
    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();
    let shared = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_public.as_affine(),
    );
    let ephemeral_public_key = hex::encode(ephemeral_public.to_encoded_point(false).as_bytes());
    let aes_key_material = Zeroizing::new(derive_private_order_share_key(
        shared.raw_secret_bytes(),
        key_id,
        &ephemeral_public_key,
    )?);
    let cipher = Aes256Gcm::new_from_slice(&aes_key_material[..])
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = random_nonce();
    let nonce_hex = hex::encode(nonce);
    let aad = encrypted_blob_aad(PRIVATE_ORDER_SHARE_ALGORITHM_V1, key_id, &nonce_hex);
    let ciphertext = cipher
        .encrypt(
            &aes_nonce_from_slice(&nonce)?,
            Payload {
                msg: plaintext,
                aad: aad.as_ref(),
            },
        )
        .map_err(|err| {
            ProtocolError::Crypto(format!("private execution key encrypt failed: {err}"))
        })?;

    Ok(EncryptedBlob {
        algorithm: PRIVATE_ORDER_SHARE_ALGORITHM_V1.into(),
        key_id: key_id.into(),
        ephemeral_public_key,
        nonce: nonce_hex,
        ciphertext: hex::encode(ciphertext),
    })
}

pub(crate) fn decrypt_encrypted_blob(
    private_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Vec<u8>, ProtocolError> {
    if blob.algorithm != PRIVATE_ORDER_SHARE_ALGORITHM_V1 {
        return Err(ProtocolError::Crypto(format!(
            "unsupported private execution key encryption algorithm {}",
            blob.algorithm
        )));
    }

    let private_key_bytes = Zeroizing::new(hex::decode(private_key_hex)?);
    let private_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("invalid private execution key: {err}")))?;
    let encoded_point = p256::EncodedPoint::from_bytes(hex::decode(&blob.ephemeral_public_key)?)
        .map_err(|err| ProtocolError::Crypto(format!("invalid ephemeral public key: {err}")))?;
    let ephemeral_public = PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| ProtocolError::Crypto("ephemeral public key not on curve".into()))?;
    let shared = diffie_hellman(
        private_key.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let aes_key_material = Zeroizing::new(derive_private_order_share_key(
        shared.raw_secret_bytes(),
        &blob.key_id,
        &blob.ephemeral_public_key,
    )?);
    let cipher = Aes256Gcm::new_from_slice(&aes_key_material[..])
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = hex::decode(&blob.nonce)?;
    let ciphertext = hex::decode(&blob.ciphertext)?;
    let aad = encrypted_blob_aad(&blob.algorithm, &blob.key_id, &blob.nonce);
    cipher
        .decrypt(
            &aes_nonce_from_slice(&nonce)?,
            Payload {
                msg: ciphertext.as_ref(),
                aad: aad.as_ref(),
            },
        )
        .map_err(|err| {
            ProtocolError::Crypto(format!("private execution key decrypt failed: {err}"))
        })
}

fn parse_public_key(public_key_hex: &str) -> Result<PublicKey, ProtocolError> {
    let encoded_point =
        p256::EncodedPoint::from_bytes(hex::decode(public_key_hex.trim_start_matches("0x"))?)
            .map_err(|err| ProtocolError::Crypto(format!("invalid public key: {err}")))?;
    PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| ProtocolError::Crypto("public key not on curve".into()))
}

fn note_recognition_secret_from_raw_key_hex(raw_key_hex: &str) -> Result<SecretKey, ProtocolError> {
    let raw_key = Zeroizing::new(hex::decode(raw_key_hex.trim_start_matches("0x"))?);
    if raw_key.len() != 32 {
        return Err(ProtocolError::Crypto(format!(
            "note recognition key must be 32 bytes, got {}",
            raw_key.len()
        )));
    }

    for counter in 0_u16..=255 {
        let mut material = Zeroizing::new(Vec::with_capacity(raw_key.len() + 2));
        material.extend_from_slice(&raw_key);
        material.extend_from_slice(&counter.to_be_bytes());
        let candidate = Zeroizing::new(tagged_sha256_bytes(
            "zylith/note-recognition-p256-secret-v1",
            &material,
        ));
        if let Ok(secret) = SecretKey::from_slice(&candidate[..]) {
            return Ok(secret);
        }
    }

    Err(ProtocolError::Crypto(
        "failed to derive note recognition secret".into(),
    ))
}

pub fn note_recognition_public_key_from_raw_key_hex(
    raw_key_hex: &str,
) -> Result<String, ProtocolError> {
    Ok(hex::encode(
        note_recognition_secret_from_raw_key_hex(raw_key_hex)?
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    ))
}

fn derive_private_order_share_key(
    shared_secret: &[u8],
    key_id: &str,
    ephemeral_public_key_hex: &str,
) -> Result<[u8; 32], ProtocolError> {
    hkdf_expand(
        shared_secret,
        PRIVATE_ORDER_SHARE_HKDF_SALT,
        format!("zylith/private-order-share-aes-key:{key_id}:{ephemeral_public_key_hex}")
            .as_bytes(),
    )
}

fn derive_wallet_aes_key(seed: &RecoverySeed, info: &[u8]) -> Result<[u8; 32], ProtocolError> {
    hkdf_expand(&derive_user_keys(seed).recovery_key, WALLET_HKDF_SALT, info)
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], ProtocolError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut key = [0_u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| ProtocolError::Crypto("hkdf expansion failed".into()))?;
    Ok(key)
}

fn encrypted_blob_aad(algorithm: &str, key_id: &str, nonce: &str) -> Vec<u8> {
    format!("zylith-encrypted-blob:{algorithm}:{key_id}:{nonce}").into_bytes()
}

fn recovery_artifact_aad(
    algorithm: &str,
    account_id: &str,
    kind: &RecoveryArtifactKind,
    sequence: u64,
    created_at_unix_ms: u64,
) -> Vec<u8> {
    format!(
        "zylith-recovery-artifact:{algorithm}:{account_id}:{kind:?}:{sequence}:{created_at_unix_ms}"
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
