use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::Rng;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use starknet_crypto::{Felt, poseidon_hash};

use crate::{
    ApprovalCallArguments, AssetId, CommitteeKeyRegistry, CommitteeMemberPrivateConfig, DecryptedOrderShare,
    DepositCallArguments, DepositIntent, DepositSubmissionPlan, EncryptedBlob,
    EncryptedRecoveryPayload, MatchedOrderWitness, Note, OrderCommitment, OrderIntent, OrderShare,
    OrderShareBundle, OrderSide, OrderSubmission, PairId, PrivateOrderPayload, ProtocolError,
    RecoveryArtifact, RecoveryArtifactKind, RecoverySeed, SettlementCallArguments,
    SettlementSubmissionPlan, SettlementTranscript, SettlementWitness, StarknetCall,
    WithdrawalCallArguments, WithdrawalSubmissionPlan, derive_user_keys,
    hash::{
        domain_felt_hex, encode_starknet_felt, felt_from_hex_str, felt_hex, normalize_felt_hex,
        tagged_commitment_sha256, tagged_field_hex, tagged_sha256_bytes, tagged_sha256_hex,
    },
};

const PROOF_FRIENDLY_ACCOUNT_DOMAIN_HEX: &str = "0x7a796c5f7066615f7631";
const PROOF_FRIENDLY_ACCOUNT_CALL_DOMAIN_HEX: &str = "0x7a796c5f7066615f63616c6c";
const PROOF_FRIENDLY_ACCOUNT_CALLDATA_DOMAIN_HEX: &str = "0x7a796c5f7066615f64617461";
const PROOF_FRIENDLY_ACCOUNT_VERSION: u64 = 3;
const NATIVE_SETTLEMENT_MESSAGE_DOMAIN_HEX: &str =
    "0x0326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a";
const PUBLIC_SETTLEMENT_DOMAIN_HEX: &str =
    "0x0283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecretSharePayload {
    order_commitment: String,
    share_index: usize,
    share_count: usize,
    plaintext_len: usize,
    share_hex: String,
}

pub fn derive_account_id(seed: &RecoverySeed) -> String {
    let recovery_key_hex = hex::encode(derive_user_keys(seed).recovery_key);
    tagged_sha256_hex("zylith/account-id:", recovery_key_hex.as_bytes())
}

pub fn build_order_submission(
    payload: &PrivateOrderPayload,
    registry: &CommitteeKeyRegistry,
    order_cancellation_key_hex: &str,
) -> Result<OrderSubmission, ProtocolError> {
    if registry.members.len() < 2 {
        return Err(ProtocolError::Crypto(
            "committee registry must contain at least two members".into(),
        ));
    }

    let order_commitment = payload.order.commitment()?;
    let cancellation_auth_tag =
        derive_order_cancellation_auth_tag(order_cancellation_key_hex, &order_commitment)?;
    let funding_note_commitment = payload.funding_note.commitment()?;
    if funding_note_commitment != payload.order.funding_note_ref {
        return Err(ProtocolError::Crypto(
            "funding note commitment does not match order funding_note_ref".into(),
        ));
    }

    let plaintext = serde_json::to_vec(payload)?;
    let split_shares = split_into_xor_shares(&plaintext, registry.members.len());

    let shares = registry
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let payload = SecretSharePayload {
                order_commitment: order_commitment.0.clone(),
                share_index: index,
                share_count: registry.members.len(),
                plaintext_len: plaintext.len(),
                share_hex: hex::encode(&split_shares[index]),
            };

            Ok(OrderShare {
                committee_member_id: member.member_id.clone(),
                encrypted_share: encrypt_for_committee_member(
                    &member.member_id,
                    &member.public_key,
                    &serde_json::to_vec(&payload)?,
                )?,
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;

    Ok(OrderSubmission {
        order_bundle: OrderShareBundle {
            order_commitment,
            cancellation_auth_tag,
            pair_id: payload.order.pair_id.clone(),
            epoch_id: payload.order.expiry_epoch,
            transport_envelope: None,
            shares,
        },
    })
}

pub fn decrypt_order_bundle(
    bundle: &OrderShareBundle,
    committee_keys: &[CommitteeMemberPrivateConfig],
) -> Result<PrivateOrderPayload, ProtocolError> {
    let share_payloads = committee_keys
        .iter()
        .map(|member_key| decrypt_order_share(bundle, member_key))
        .collect::<Result<Vec<_>, ProtocolError>>()?;

    reconstruct_order_from_shares(bundle, &share_payloads)
}

pub fn decrypt_order_share(
    bundle: &OrderShareBundle,
    member_key: &CommitteeMemberPrivateConfig,
) -> Result<DecryptedOrderShare, ProtocolError> {
    let share = bundle
        .shares
        .iter()
        .find(|share| share.committee_member_id == member_key.member_id)
        .ok_or_else(|| {
            ProtocolError::Crypto(format!(
                "order bundle missing share for committee member {}",
                member_key.member_id
            ))
        })?;
    let plaintext = decrypt_encrypted_blob(&member_key.private_key, &share.encrypted_share)?;
    let payload = serde_json::from_slice::<SecretSharePayload>(&plaintext)?;

    if payload.order_commitment != bundle.order_commitment.0 {
        return Err(ProtocolError::Crypto(
            "share payload order commitment mismatch".into(),
        ));
    }

    Ok(DecryptedOrderShare {
        member_id: member_key.member_id.clone(),
        order_commitment: bundle.order_commitment.clone(),
        share_index: payload.share_index as u64,
        share_count: payload.share_count as u64,
        plaintext_len: payload.plaintext_len as u64,
        share_hex: payload.share_hex,
    })
}

pub fn reconstruct_order_from_shares(
    bundle: &OrderShareBundle,
    share_payloads: &[DecryptedOrderShare],
) -> Result<PrivateOrderPayload, ProtocolError> {
    if share_payloads.is_empty() {
        return Err(ProtocolError::Crypto(
            "order bundle contained no shares".into(),
        ));
    }

    let mut ordered_payloads = share_payloads.to_vec();
    ordered_payloads.sort_by_key(|payload| payload.share_index);

    for payload in &ordered_payloads {
        if payload.order_commitment != bundle.order_commitment {
            return Err(ProtocolError::Crypto(
                "share payload order commitment mismatch".into(),
            ));
        }
    }

    let plaintext_len = ordered_payloads[0].plaintext_len as usize;
    let share_count = ordered_payloads[0].share_count as usize;

    if ordered_payloads.len() != share_count {
        return Err(ProtocolError::Crypto(
            "order bundle did not contain the full share set".into(),
        ));
    }

    for (expected_index, payload) in ordered_payloads.iter().enumerate() {
        if payload.plaintext_len as usize != plaintext_len
            || payload.share_count as usize != share_count
            || payload.share_index as usize != expected_index
        {
            return Err(ProtocolError::Crypto(
                "share payload metadata mismatch".into(),
            ));
        }
    }

    let mut plaintext = vec![0_u8; plaintext_len];
    for payload in &ordered_payloads {
        let share_bytes = hex::decode(&payload.share_hex)?;
        if share_bytes.len() != plaintext_len {
            return Err(ProtocolError::Crypto(
                "share payload length mismatch".into(),
            ));
        }

        for (index, byte) in share_bytes.iter().enumerate() {
            plaintext[index] ^= *byte;
        }
    }

    let payload = serde_json::from_slice::<PrivateOrderPayload>(&plaintext)?;
    let reconstructed_commitment = payload.order.commitment()?;
    if reconstructed_commitment != bundle.order_commitment {
        return Err(ProtocolError::Crypto(
            "reconstructed order commitment mismatch".into(),
        ));
    }

    let funding_note_commitment = payload.funding_note.commitment()?;
    if funding_note_commitment != payload.order.funding_note_ref {
        return Err(ProtocolError::Crypto(
            "funding note commitment did not match shared order payload".into(),
        ));
    }

    Ok(payload)
}

pub fn build_output_note(
    batch_id: &str,
    output_index: usize,
    order_commitment: &OrderCommitment,
    order: &OrderIntent,
    asset_id: AssetId,
    amount: u128,
) -> Result<Note, ProtocolError> {
    let blinding = tagged_field_hex(
        "zylith/output-blinding",
        &serde_json::json!({
            "batch_id": batch_id,
            "order_commitment": order_commitment.0,
            "output_index": output_index,
        }),
    )?;
    let metadata_commitment = tagged_field_hex(
        "zylith/output-metadata",
        &serde_json::json!({
            "batch_id": batch_id,
            "order_commitment": order_commitment.0,
            "funding_note_ref": order.funding_note_ref.0,
            "pair_id": order.pair_id.0,
            "recipient_withdraw_authority": order.recipient_withdraw_authority,
        }),
    )?;

    Ok(Note {
        asset_id,
        amount,
        owner_public_key: order.recipient_owner_public_key.clone(),
        withdraw_authority: order.recipient_withdraw_authority.clone(),
        blinding,
        nonce: output_index as u64,
        metadata_commitment,
    })
}

pub fn derive_order_cancellation_secret(
    order_cancellation_key_hex: &str,
    order_commitment: &OrderCommitment,
) -> Result<String, ProtocolError> {
    let normalized = order_cancellation_key_hex.trim_start_matches("0x");
    let key_bytes = hex::decode(normalized)?;
    let mut material = Vec::with_capacity(key_bytes.len() + order_commitment.0.len());
    material.extend_from_slice(&key_bytes);
    material.extend_from_slice(order_commitment.0.as_bytes());
    Ok(tagged_sha256_hex("zylith/order-cancel-secret", &material))
}

pub fn derive_order_cancellation_tag(cancellation_secret: &str) -> String {
    tagged_sha256_hex("zylith/order-cancel-tag", cancellation_secret.as_bytes())
}

pub fn derive_order_cancellation_auth_tag(
    order_cancellation_key_hex: &str,
    order_commitment: &OrderCommitment,
) -> Result<String, ProtocolError> {
    let secret = derive_order_cancellation_secret(order_cancellation_key_hex, order_commitment)?;
    Ok(derive_order_cancellation_tag(&secret))
}

pub fn build_deposit_note(intent: &DepositIntent) -> Result<Note, ProtocolError> {
    let blinding = tagged_field_hex(
        "zylith/deposit-blinding",
        &serde_json::json!({
            "asset_id": intent.asset_id.0,
            "amount": intent.amount,
            "deposit_nonce": intent.deposit_nonce,
            "recipient_owner_public_key": intent.recipient_owner_public_key,
        }),
    )?;
    let metadata_commitment = tagged_field_hex(
        "zylith/deposit-metadata",
        &serde_json::json!({
            "asset_id": intent.asset_id.0,
            "amount": intent.amount,
            "deposit_nonce": intent.deposit_nonce,
            "recipient_withdraw_authority": intent.recipient_withdraw_authority,
        }),
    )?;

    Ok(Note {
        asset_id: intent.asset_id.clone(),
        amount: intent.amount,
        owner_public_key: intent.recipient_owner_public_key.clone(),
        withdraw_authority: intent.recipient_withdraw_authority.clone(),
        blinding,
        nonce: intent.deposit_nonce,
        metadata_commitment,
    })
}

pub fn build_deposit_submission_plan(
    intent: &DepositIntent,
    deposit_router_address: &str,
    token_address: &str,
    shielded_asset_adapter_address: &str,
) -> Result<DepositSubmissionPlan, ProtocolError> {
    let note = build_deposit_note(intent)?;
    let note_commitment = note.commitment()?;
    let approval_args = ApprovalCallArguments {
        spender: normalize_felt_hex(shielded_asset_adapter_address)?,
        amount: encode_u128(intent.amount),
    };
    let encoded_args = DepositCallArguments {
        asset_id: encode_starknet_felt("asset-id", &intent.asset_id.0),
        amount: encode_u128(intent.amount),
        deposit_nonce: encode_u64(intent.deposit_nonce),
        note_commitment: normalize_felt_hex(&note_commitment.0)?,
        withdraw_authority: normalize_felt_hex(&intent.recipient_withdraw_authority)?,
    };
    let approval_call = StarknetCall {
        contract_address: normalize_felt_hex(token_address)?,
        entrypoint: "approve".into(),
        calldata: vec![
            approval_args.spender.clone(),
            approval_args.amount.clone(),
            "0x0".into(),
        ],
    };
    let deposit_call = StarknetCall {
        contract_address: deposit_router_address.into(),
        entrypoint: "register_shielded_deposit".into(),
        calldata: vec![
            encoded_args.asset_id.clone(),
            encoded_args.amount.clone(),
            encoded_args.deposit_nonce.clone(),
            encoded_args.note_commitment.clone(),
            encoded_args.withdraw_authority.clone(),
        ],
    };

    Ok(DepositSubmissionPlan {
        note,
        note_commitment,
        approval_call: approval_call.clone(),
        starknet_call: deposit_call.clone(),
        starknet_calls: vec![approval_call, deposit_call],
        approval_args,
        encoded_args,
    })
}

pub fn build_withdrawal_submission_plan(
    note_commitment: &str,
    recipient: &str,
    shielded_asset_adapter_address: &str,
) -> Result<WithdrawalSubmissionPlan, ProtocolError> {
    let encoded_args = WithdrawalCallArguments {
        note_commitment: normalize_felt_hex(note_commitment)?,
        recipient: normalize_felt_hex(recipient)?,
    };

    Ok(WithdrawalSubmissionPlan {
        note_commitment: crate::types::NoteCommitment(encoded_args.note_commitment.clone()),
        starknet_call: StarknetCall {
            contract_address: shielded_asset_adapter_address.into(),
            entrypoint: "withdraw_to_l2".into(),
            calldata: vec![
                encoded_args.note_commitment.clone(),
                encoded_args.recipient.clone(),
            ],
        },
        encoded_args,
    })
}

pub fn encrypt_note_for_owner(
    batch_id: &str,
    output_index: usize,
    note: &Note,
    recipient_owner_public_key: &str,
) -> Result<EncryptedBlob, ProtocolError> {
    let key_bytes = derive_output_encryption_key(recipient_owner_public_key);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce_hex = tagged_commitment_sha256(
        "zylith/output-nonce",
        &serde_json::json!({
            "batch_id": batch_id,
            "output_index": output_index,
            "owner": recipient_owner_public_key,
        }),
    )?;
    let nonce_bytes = hex::decode(&nonce_hex[..24])?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(note)?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|err| ProtocolError::Crypto(format!("note encryption failed: {err}")))?;

    Ok(EncryptedBlob {
        algorithm: "aes-256-gcm/note-recognition".into(),
        key_id: recipient_owner_public_key.into(),
        ephemeral_public_key: String::new(),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn decrypt_note_for_owner(
    note_recognition_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Option<Note>, ProtocolError> {
    if blob.algorithm != "aes-256-gcm/note-recognition" {
        return Ok(None);
    }

    let key_bytes = derive_output_encryption_key(note_recognition_key_hex);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce_bytes = hex::decode(&blob.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex::decode(&blob.ciphertext)?;
    let plaintext = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => plaintext,
        Err(_) => return Ok(None),
    };

    let note = serde_json::from_slice::<Note>(&plaintext)?;
    if note.owner_public_key != note_recognition_key_hex {
        return Ok(None);
    }

    Ok(Some(note))
}

pub fn create_recovery_artifact(
    seed: &RecoverySeed,
    kind: RecoveryArtifactKind,
    sequence: u64,
    created_at_unix_ms: u64,
    payload: &Value,
) -> Result<RecoveryArtifact, ProtocolError> {
    let account_id = derive_account_id(seed);
    let recovery_key = derive_user_keys(seed).recovery_key;
    let key_bytes = recovery_key;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = random_nonce();
    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
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
            algorithm: "aes-256-gcm/recovery".into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        },
    })
}

pub fn decrypt_recovery_artifact_payload(
    seed: &RecoverySeed,
    artifact: &RecoveryArtifact,
) -> Result<Value, ProtocolError> {
    if artifact.payload.algorithm != "aes-256-gcm/recovery" {
        return Err(ProtocolError::Crypto(format!(
            "unsupported recovery algorithm {}",
            artifact.payload.algorithm
        )));
    }

    let recovery_key = derive_user_keys(seed).recovery_key;
    let cipher = Aes256Gcm::new_from_slice(&recovery_key)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = hex::decode(&artifact.payload.nonce)?;
    let ciphertext = hex::decode(&artifact.payload.ciphertext)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|err| ProtocolError::Crypto(format!("recovery decrypt failed: {err}")))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

pub fn settlement_transcript_commitment(
    transcript: &SettlementTranscript,
) -> Result<String, ProtocolError> {
    let batch_id = felt_from_hex_str(&normalize_felt_hex(&encode_starknet_felt(
        "batch-id",
        &transcript.batch_id.0,
    ))?)?;
    let mut state = poseidon_hash(felt_from_hex_str(PUBLIC_SETTLEMENT_DOMAIN_HEX)?, batch_id);
    state = poseidon_hash(state, Felt::from(transcript.clearing_price));
    state = poseidon_hash(
        state,
        felt_from_hex_str(&encode_starknet_felt(
            "output-bundle-ref",
            &transcript.output_ciphertext_bundle_ref,
        ))?,
    );

    for input in &transcript.consumed_inputs {
        state = poseidon_hash(
            state,
            felt_from_hex_str(&normalize_felt_hex(&input.note_commitment.0)?)?,
        );
        state = poseidon_hash(
            state,
            felt_from_hex_str(&normalize_felt_hex(&input.nullifier.0)?)?,
        );
    }

    for output in &transcript.output_notes {
        state = poseidon_hash(
            state,
            felt_from_hex_str(&normalize_felt_hex(&output.note_commitment.0)?)?,
        );
        state = poseidon_hash(
            state,
            felt_from_hex_str(&encode_starknet_felt("asset-id", &output.asset_id.0))?,
        );
        state = poseidon_hash(state, Felt::from(output.amount));
        state = poseidon_hash(
            state,
            felt_from_hex_str(&normalize_felt_hex(&output.withdraw_authority)?)?,
        );
    }

    for fee in &transcript.fees {
        state = poseidon_hash(
            state,
            felt_from_hex_str(&encode_starknet_felt("asset-id", &fee.asset_id.0))?,
        );
        state = poseidon_hash(
            state,
            felt_from_hex_str(&encode_starknet_felt("fee-recipient", &fee.recipient))?,
        );
        state = poseidon_hash(state, Felt::from(fee.amount));
    }

    Ok(felt_hex(&state))
}

pub fn proof_artifact_commitment(
    proof_sha256: &str,
    public_inputs_sha256: &str,
) -> Result<String, ProtocolError> {
    tagged_field_hex(
        "zylith/proof-artifact",
        &serde_json::json!({
            "proof_sha256": proof_sha256,
            "public_inputs_sha256": public_inputs_sha256,
        }),
    )
}

pub fn native_settlement_message_hash(
    settlement_verifier_address: &str,
    transcript_commitment: &str,
) -> Result<String, ProtocolError> {
    let mut state = poseidon_hash(
        felt_from_hex_str(NATIVE_SETTLEMENT_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(&normalize_felt_hex(settlement_verifier_address)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(transcript_commitment)?)?,
    );
    Ok(felt_hex(&state))
}

pub fn proof_friendly_account_message_hash(
    account_address: &str,
    chain_id: &str,
    nonce: &str,
    call_target: &str,
    call_selector: &str,
    call_calldata: &[String],
) -> Result<String, ProtocolError> {
    let call_hash = proof_friendly_call_hash(call_target, call_selector, call_calldata)?;
    let mut state = poseidon_hash(
        felt_from_hex_str(PROOF_FRIENDLY_ACCOUNT_DOMAIN_HEX)?,
        Felt::from(PROOF_FRIENDLY_ACCOUNT_VERSION),
    );
    state = poseidon_hash(state, felt_from_hex_str(account_address)?);
    state = poseidon_hash(state, felt_from_hex_str(chain_id)?);
    state = poseidon_hash(state, felt_from_hex_str(nonce)?);
    state = poseidon_hash(state, call_hash);

    Ok(felt_hex(&state))
}

fn proof_friendly_call_hash(
    call_target: &str,
    call_selector: &str,
    call_calldata: &[String],
) -> Result<Felt, ProtocolError> {
    let calldata_inputs = call_calldata
        .iter()
        .map(|felt| felt_from_hex_str(felt))
        .collect::<Result<Vec<_>, _>>()?;
    let mut calldata_hash = poseidon_hash(
        felt_from_hex_str(PROOF_FRIENDLY_ACCOUNT_CALLDATA_DOMAIN_HEX)?,
        Felt::from(calldata_inputs.len() as u64),
    );
    for input in &calldata_inputs {
        calldata_hash = poseidon_hash(calldata_hash, *input);
    }

    let mut state = poseidon_hash(
        felt_from_hex_str(PROOF_FRIENDLY_ACCOUNT_CALL_DOMAIN_HEX)?,
        felt_from_hex_str(call_target)?,
    );
    state = poseidon_hash(state, felt_from_hex_str(call_selector)?);
    state = poseidon_hash(state, calldata_hash);
    Ok(state)
}

pub fn build_settlement_submission_plan(
    transcript: &SettlementTranscript,
    verifier_address: &str,
    proof_artifact_commitment: &str,
) -> Result<SettlementSubmissionPlan, ProtocolError> {
    let transcript_commitment = settlement_transcript_commitment(transcript)?;
    let encoded_args = SettlementCallArguments {
        batch_id: encode_starknet_felt("batch-id", &transcript.batch_id.0),
        transcript_commitment: normalize_felt_hex(&transcript_commitment)?,
        proof_artifact_commitment: normalize_felt_hex(proof_artifact_commitment)?,
        clearing_price: encode_u128(transcript.clearing_price),
        matched_order_count: encode_u64(transcript.matched_orders.len() as u64),
        output_bundle_ref: encode_starknet_felt(
            "output-bundle-ref",
            &transcript.output_ciphertext_bundle_ref,
        ),
        consumed_note_commitments: transcript
            .consumed_inputs
            .iter()
            .map(|input| normalize_felt_hex(&input.note_commitment.0))
            .collect::<Result<Vec<_>, _>>()?,
        consumed_nullifiers: transcript
            .consumed_inputs
            .iter()
            .map(|input| normalize_felt_hex(&input.nullifier.0))
            .collect::<Result<Vec<_>, _>>()?,
        output_note_commitments: transcript
            .output_notes
            .iter()
            .map(|output| normalize_felt_hex(&output.note_commitment.0))
            .collect::<Result<Vec<_>, _>>()?,
        output_note_asset_ids: transcript
            .output_notes
            .iter()
            .map(|output| encode_starknet_felt("asset-id", &output.asset_id.0))
            .collect(),
        output_note_amounts: transcript
            .output_notes
            .iter()
            .map(|output| encode_u128(output.amount))
            .collect(),
        output_note_withdraw_authorities: transcript
            .output_notes
            .iter()
            .map(|output| normalize_felt_hex(&output.withdraw_authority))
            .collect::<Result<Vec<_>, _>>()?,
        fee_asset_ids: transcript
            .fees
            .iter()
            .map(|fee| encode_starknet_felt("asset-id", &fee.asset_id.0))
            .collect(),
        fee_recipients: transcript
            .fees
            .iter()
            .map(|fee| encode_starknet_felt("fee-recipient", &fee.recipient))
            .collect(),
        fee_amounts: transcript
            .fees
            .iter()
            .map(|fee| encode_u128(fee.amount))
            .collect(),
    };

    let calldata = flatten_settlement_call_arguments(&encoded_args);

    Ok(SettlementSubmissionPlan {
        batch_id: transcript.batch_id.clone(),
        transcript_commitment,
        proof_artifact_commitment: proof_artifact_commitment.into(),
        settlement_call: StarknetCall {
            contract_address: verifier_address.into(),
            entrypoint: "submit_settlement_native".into(),
            calldata,
        },
        encoded_args,
    })
}

pub fn build_settlement_witness(
    transcript: &SettlementTranscript,
    pair_id: PairId,
    verifier_address: &str,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    matched_order_witnesses: Vec<MatchedOrderWitness>,
) -> Result<SettlementWitness, ProtocolError> {
    Ok(SettlementWitness {
        batch_id: transcript.batch_id.clone(),
        pair_id,
        transcript_commitment: settlement_transcript_commitment(transcript)?,
        settlement_verifier_address: verifier_address.into(),
        clearing_price: transcript.clearing_price,
        base_asset_id,
        quote_asset_id,
        matched_orders: transcript.matched_orders.clone(),
        matched_order_witnesses,
        consumed_inputs: transcript.consumed_inputs.clone(),
        fees: transcript.fees.clone(),
        output_notes: transcript.output_notes.clone(),
        output_ciphertext_bundle_ref: transcript.output_ciphertext_bundle_ref.clone(),
    })
}

pub fn build_stwo_serialized_input(witness: &SettlementWitness) -> Vec<String> {
    let mut payload = vec![
        encode_u64(5),
        domain_felt_hex("zylith/note"),
        domain_felt_hex("zylith/order"),
        PUBLIC_SETTLEMENT_DOMAIN_HEX.into(),
        encode_starknet_felt("batch-id", &witness.batch_id.0),
        normalize_felt_hex(&witness.transcript_commitment).expect("transcript commitment"),
        encode_starknet_felt("pair-id", &witness.pair_id.0),
        encode_asset_id(&witness.base_asset_id.0),
        encode_asset_id(&witness.quote_asset_id.0),
        encode_u128(witness.clearing_price),
        encode_u64(witness.matched_orders.len() as u64),
        encode_starknet_felt("output-bundle-ref", &witness.output_ciphertext_bundle_ref),
    ];

    push_span(
        &mut payload,
        &witness
            .matched_orders
            .iter()
            .map(|matched| matched.order_commitment.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_orders
            .iter()
            .map(|matched| encode_u128(matched.filled_amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_order_side(&entry.side))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u128(entry.limit_price))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u128(entry.order_amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u128(entry.min_fill))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u64(entry.expiry_epoch))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u64(entry.order_nonce))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                if entry.auditor_view_allowed {
                    "0x1".into()
                } else {
                    "0x0".into()
                }
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| entry.funding_note_ref.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                entry
                    .funding_note
                    .commitment()
                    .map(|commitment| commitment.0)
                    .expect("funding note commitment")
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_asset_id(&entry.funding_note.asset_id.0))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u128(entry.funding_note.amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_owner_public_key(&entry.funding_note.owner_public_key))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                normalize_felt_hex(&entry.funding_note.withdraw_authority)
                    .expect("funding authority")
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| entry.funding_note.blinding.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u64(entry.funding_note.nonce))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| entry.funding_note.metadata_commitment.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| entry.funding_nullifier.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_owner_public_key(&entry.recipient_owner_public_key))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                normalize_felt_hex(&entry.recipient_withdraw_authority)
                    .expect("recipient authority")
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                entry
                    .output_note
                    .commitment()
                    .map(|commitment| commitment.0)
                    .expect("output note commitment")
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_asset_id(&entry.output_note.asset_id.0))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u128(entry.output_note.amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_owner_public_key(&entry.output_note.owner_public_key))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                normalize_felt_hex(&entry.output_note.withdraw_authority).expect("output authority")
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| entry.output_note.blinding.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u64(entry.output_note.nonce))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| entry.output_note.metadata_commitment.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .consumed_inputs
            .iter()
            .map(|input| input.note_commitment.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .consumed_inputs
            .iter()
            .map(|input| input.nullifier.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .output_notes
            .iter()
            .map(|output| output.note_commitment.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .output_notes
            .iter()
            .map(|output| encode_asset_id(&output.asset_id.0))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .output_notes
            .iter()
            .map(|output| encode_u128(output.amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .output_notes
            .iter()
            .map(|output| {
                normalize_felt_hex(&output.withdraw_authority).expect("public output authority")
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .fees
            .iter()
            .map(|fee| encode_asset_id(&fee.asset_id.0))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .fees
            .iter()
            .map(|fee| encode_starknet_felt("fee-recipient", &fee.recipient))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .fees
            .iter()
            .map(|fee| encode_u128(fee.amount))
            .collect::<Vec<_>>(),
    );

    let mut serialized = vec![encode_usize(payload.len())];
    serialized.extend(payload);
    serialized
}

fn encode_order_side(side: &OrderSide) -> String {
    match side {
        OrderSide::Buy => "0x0".into(),
        OrderSide::Sell => "0x1".into(),
    }
}

fn encode_asset_id(asset_id: &str) -> String {
    encode_starknet_felt("asset-id", asset_id)
}

fn encode_owner_public_key(owner_public_key: &str) -> String {
    encode_starknet_felt("owner-public-key", owner_public_key)
}

fn split_into_xor_shares(plaintext: &[u8], share_count: usize) -> Vec<Vec<u8>> {
    let mut rng = rand::rng();
    let mut shares: Vec<Vec<u8>> = (0..share_count.saturating_sub(1))
        .map(|_| {
            let mut share = vec![0_u8; plaintext.len()];
            rng.fill(share.as_mut_slice());
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

fn encrypt_for_committee_member(
    member_id: &str,
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
    let aes_key_material: [u8; 32] = Sha256::digest(shared.raw_secret_bytes()).into();
    let cipher = Aes256Gcm::new_from_slice(&aes_key_material)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = random_nonce();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|err| ProtocolError::Crypto(format!("committee encrypt failed: {err}")))?;

    Ok(EncryptedBlob {
        algorithm: "ecdh-p256+aes-256-gcm".into(),
        key_id: member_id.into(),
        ephemeral_public_key: hex::encode(ephemeral_public.to_encoded_point(false).as_bytes()),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

fn decrypt_encrypted_blob(
    private_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Vec<u8>, ProtocolError> {
    if blob.algorithm != "ecdh-p256+aes-256-gcm" {
        return Err(ProtocolError::Crypto(format!(
            "unsupported committee encryption algorithm {}",
            blob.algorithm
        )));
    }

    let private_key_bytes = hex::decode(private_key_hex)?;
    let private_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("invalid committee private key: {err}")))?;
    let encoded_point = p256::EncodedPoint::from_bytes(hex::decode(&blob.ephemeral_public_key)?)
        .map_err(|err| ProtocolError::Crypto(format!("invalid ephemeral public key: {err}")))?;
    let ephemeral_public = PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| ProtocolError::Crypto("ephemeral public key not on curve".into()))?;
    let shared = diffie_hellman(
        private_key.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let aes_key_material: [u8; 32] = Sha256::digest(shared.raw_secret_bytes()).into();
    let cipher = Aes256Gcm::new_from_slice(&aes_key_material)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = hex::decode(&blob.nonce)?;
    let ciphertext = hex::decode(&blob.ciphertext)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|err| ProtocolError::Crypto(format!("committee decrypt failed: {err}")))
}

fn parse_public_key(public_key_hex: &str) -> Result<PublicKey, ProtocolError> {
    let encoded_point = p256::EncodedPoint::from_bytes(hex::decode(public_key_hex)?)
        .map_err(|err| ProtocolError::Crypto(format!("invalid public key: {err}")))?;
    PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| ProtocolError::Crypto("public key not on curve".into()))
}

fn derive_output_encryption_key(note_recognition_key_hex: &str) -> [u8; 32] {
    tagged_sha256_bytes(
        "zylith/output-encryption",
        note_recognition_key_hex.as_bytes(),
    )
}

fn flatten_settlement_call_arguments(args: &SettlementCallArguments) -> Vec<String> {
    let mut calldata = vec![
        args.batch_id.clone(),
        args.transcript_commitment.clone(),
        args.proof_artifact_commitment.clone(),
        args.clearing_price.clone(),
        args.matched_order_count.clone(),
        args.output_bundle_ref.clone(),
    ];
    push_span(&mut calldata, &args.consumed_note_commitments);
    push_span(&mut calldata, &args.consumed_nullifiers);
    push_span(&mut calldata, &args.output_note_commitments);
    push_span(&mut calldata, &args.output_note_asset_ids);
    push_span(&mut calldata, &args.output_note_amounts);
    push_span(&mut calldata, &args.output_note_withdraw_authorities);
    push_span(&mut calldata, &args.fee_asset_ids);
    push_span(&mut calldata, &args.fee_recipients);
    push_span(&mut calldata, &args.fee_amounts);
    calldata
}

fn push_span(calldata: &mut Vec<String>, values: &[String]) {
    calldata.push(encode_usize(values.len()));
    calldata.extend(values.iter().cloned());
}

fn encode_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn encode_u128(value: u128) -> String {
    format!("0x{value:x}")
}

fn encode_usize(value: usize) -> String {
    format!("0x{value:x}")
}

fn random_nonce() -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;

    use super::{
        build_deposit_note, build_deposit_submission_plan, build_order_submission,
        build_output_note, build_settlement_submission_plan, build_settlement_witness,
        build_stwo_serialized_input, build_withdrawal_submission_plan, create_recovery_artifact,
        decrypt_note_for_owner, decrypt_order_bundle, decrypt_order_share,
        decrypt_recovery_artifact_payload, derive_account_id, encrypt_note_for_owner,
        proof_artifact_commitment, proof_friendly_account_message_hash,
        reconstruct_order_from_shares, settlement_transcript_commitment,
    };
    use crate::{
        AssetId, CommitteeKeyRegistry, CommitteeMemberPrivateConfig, CommitteeMemberPublicConfig,
        ConsumedInput, DepositIntent, FeeEntry, MatchedOrderWitness, Note, NoteCommitment,
        Nullifier, OrderIntent, OrderSide, OutputNoteRecord, PairId, PrivateOrderPayload,
        RecoveryArtifactKind, RecoverySeed, SettlementTranscript, hash::encode_starknet_felt,
    };

    #[test]
    fn order_submission_roundtrip_recovers_original_intent() {
        let committee = committee_members();
        let registry = CommitteeKeyRegistry {
            members: committee
                .iter()
                .map(|member| CommitteeMemberPublicConfig {
                    member_id: member.member_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let cancellation_key = "11".repeat(32);
        let submission =
            build_order_submission(&payload, &registry, &cancellation_key).expect("submission");
        let decrypted =
            decrypt_order_bundle(&submission.order_bundle, &committee).expect("decrypted order");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn distributed_share_reconstruction_recovers_original_intent() {
        let committee = committee_members();
        let registry = CommitteeKeyRegistry {
            members: committee
                .iter()
                .map(|member| CommitteeMemberPublicConfig {
                    member_id: member.member_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let cancellation_key = "11".repeat(32);
        let submission =
            build_order_submission(&payload, &registry, &cancellation_key).expect("submission");
        let shares = committee
            .iter()
            .map(|member| decrypt_order_share(&submission.order_bundle, member))
            .collect::<Result<Vec<_>, _>>()
            .expect("decrypted shares");

        let reconstructed = reconstruct_order_from_shares(&submission.order_bundle, &shares)
            .expect("reconstructed");
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn output_note_roundtrip_recovers_for_correct_owner() {
        let payload = sample_private_order();
        let order = payload.order;
        let note = build_output_note(
            "batch-1",
            0,
            &order.commitment().expect("commitment"),
            &order,
            AssetId("STRK".into()),
            500,
        )
        .expect("output note");
        let blob = encrypt_note_for_owner("batch-1", 0, &note, &order.recipient_owner_public_key)
            .expect("encrypted note");

        let decrypted = decrypt_note_for_owner(&order.recipient_owner_public_key, &blob)
            .expect("decrypt")
            .expect("matching owner");

        assert_eq!(decrypted, note);
    }

    #[test]
    fn recovery_artifact_roundtrip_recovers_payload_and_account_id() {
        let seed = RecoverySeed([9_u8; 32]);
        let artifact = create_recovery_artifact(
            &seed,
            RecoveryArtifactKind::Snapshot,
            3,
            12345,
            &serde_json::json!({"trackedOrders": ["abc"]}),
        )
        .expect("artifact");

        assert_eq!(artifact.account_id, derive_account_id(&seed));

        let payload =
            decrypt_recovery_artifact_payload(&seed, &artifact).expect("decrypted payload");
        assert_eq!(payload["trackedOrders"][0], "abc");
    }

    #[test]
    fn deposit_note_and_plan_are_deterministic() {
        let intent = DepositIntent {
            asset_id: AssetId("USDC".into()),
            amount: 1_500,
            deposit_nonce: 9,
            recipient_owner_public_key: "ab".repeat(32),
            recipient_withdraw_authority: "0x1234".into(),
        };

        let note_a = build_deposit_note(&intent).expect("note a");
        let note_b = build_deposit_note(&intent).expect("note b");
        assert_eq!(note_a, note_b);

        let plan =
            build_deposit_submission_plan(&intent, "0xabc", "0xdef", "0x456").expect("plan");
        assert_eq!(plan.approval_call.contract_address, "0xdef");
        assert_eq!(plan.approval_call.entrypoint, "approve");
        assert_eq!(plan.approval_call.calldata.len(), 3);
        assert_eq!(plan.starknet_call.contract_address, "0xabc");
        assert_eq!(plan.starknet_call.entrypoint, "register_shielded_deposit");
        assert_eq!(plan.starknet_call.calldata.len(), 5);
        assert_eq!(plan.starknet_calls.len(), 2);
        assert_eq!(plan.note_commitment, note_a.commitment().unwrap());
    }

    #[test]
    fn withdrawal_plan_normalizes_note_commitment_and_recipient() {
        let plan = build_withdrawal_submission_plan("abc", "def", "0x123").expect("plan");

        assert_eq!(plan.starknet_call.contract_address, "0x123");
        assert_eq!(plan.starknet_call.entrypoint, "withdraw_to_l2");
        assert_eq!(plan.starknet_call.calldata, vec!["0xabc", "0xdef"]);
        assert_eq!(plan.note_commitment.0, "0xabc");
        assert_eq!(plan.encoded_args.recipient, "0xdef");
    }

    #[test]
    fn settlement_submission_plan_flattens_contract_call_arguments() {
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-1".into()),
            clearing_price: 145,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-1".into()),
                filled_amount: 500,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: NoteCommitment("0x123".into()),
                nullifier: Nullifier("0x456".into()),
            }],
            fees: vec![FeeEntry {
                asset_id: AssetId("USDC".into()),
                amount: 10,
                recipient: "fee-recipient".into(),
            }],
            output_notes: vec![OutputNoteRecord {
                note_commitment: NoteCommitment("0x789".into()),
                asset_id: AssetId("STRK".into()),
                amount: 490,
                withdraw_authority: "0xaaa".into(),
            }],
            output_ciphertext_bundle_ref: "bundle-1".into(),
        };

        let proof_commitment =
            proof_artifact_commitment("proof-sha", "public-inputs-sha").expect("proof");
        let plan = build_settlement_submission_plan(&transcript, "0x123", &proof_commitment)
            .expect("plan");
        assert_eq!(plan.settlement_call.contract_address, "0x123");
        assert_eq!(plan.settlement_call.entrypoint, "submit_settlement_native");
        assert!(!plan.settlement_call.calldata.is_empty());
        assert_eq!(
            plan.transcript_commitment,
            settlement_transcript_commitment(&transcript).unwrap()
        );
        assert_eq!(plan.proof_artifact_commitment, proof_commitment);
        assert_eq!(plan.encoded_args.consumed_note_commitments.len(), 1);
        assert_eq!(plan.encoded_args.output_note_commitments.len(), 1);
    }

    #[test]
    fn settlement_transcript_commitment_matches_cairo_contract_formula() {
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-strk-usdc-1".into()),
            clearing_price: 300,
            matched_orders: vec![
                crate::MatchedOrder {
                    order_commitment: crate::OrderCommitment(
                        "0x4b292dd88ea26e4bb36a2b96aa3a5ab8989528e1cc8820ed601b593d652e6e3"
                            .into(),
                    ),
                    filled_amount: 100,
                },
                crate::MatchedOrder {
                    order_commitment: crate::OrderCommitment(
                        "0x29ce97d838b12ca71cb08896fd7a17507c1349a3306180167c22787005dca0d"
                            .into(),
                    ),
                    filled_amount: 100,
                },
            ],
            consumed_inputs: vec![
                ConsumedInput {
                    note_commitment: NoteCommitment(
                        "0x2ac19e1535f0c09faf01e2fc6553af0805e4c729aef2b334170eacfe9acde37"
                            .into(),
                    ),
                    nullifier: Nullifier(
                        "0x7dbd3c7c2fe8baa75ef2bc40b202170de6302e979147b0891c85153286ad4d5"
                            .into(),
                    ),
                },
                ConsumedInput {
                    note_commitment: NoteCommitment(
                        "0x7a72976550f4e23619ace1ea4dd5d1a9ab69f2e1eed70ddf29f850d26cfe02f"
                            .into(),
                    ),
                    nullifier: Nullifier(
                        "0x44802cf244cbe3834896c577766d307936fbc62646e9d6b135b42987a38a3c1"
                            .into(),
                    ),
                },
            ],
            fees: vec![FeeEntry {
                asset_id: AssetId("USDC".into()),
                amount: 30,
                recipient: "zylith-protocol-fee".into(),
            }],
            output_notes: vec![
                OutputNoteRecord {
                    note_commitment: NoteCommitment(
                        "0x78bebb5dd3299517a9eb30c046dad25e9cc638ecc86982392ee5a4a6f7a7418"
                            .into(),
                    ),
                    asset_id: AssetId("USDC".into()),
                    amount: 29970,
                    withdraw_authority: "0x2065".into(),
                },
                OutputNoteRecord {
                    note_commitment: NoteCommitment(
                        "0x4d8df0f876f2b996b107dec093de913dbca4e46adf95416dff638cc5c30b567"
                            .into(),
                    ),
                    asset_id: AssetId("STRK".into()),
                    amount: 100,
                    withdraw_authority: "0x1001".into(),
                },
            ],
            output_ciphertext_bundle_ref: "a9bfa0d37d7a84cc26c1fec3e7dd0e00d463a93f886e6e62ada07470b1a4ea4a"
                .into(),
        };

        assert_eq!(
            settlement_transcript_commitment(&transcript).expect("transcript commitment"),
            "0x138abaea23db40236cd08551b2bd4b745b629a285944bff31abad9f555e2745"
        );
    }

    #[test]
    fn settlement_witness_wraps_plan_and_transcript_material() {
        let funding_note = sample_note("ETH", 700, 2);
        let output_note = sample_note("USDC", 700, 3);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-2".into()),
            clearing_price: 200,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-2".into()),
                filled_amount: 700,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: Nullifier("0x222".into()),
            }],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("USDC".into()),
                amount: 700,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-2".into(),
        };

        let witness = build_settlement_witness(
            &transcript,
            PairId("ETH/USDC".into()),
            "0x456",
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-2".into()),
                funding_note,
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier: Nullifier("0x222".into()),
                side: OrderSide::Sell,
                limit_price: 180,
                order_amount: 700,
                min_fill: 100,
                expiry_epoch: 9,
                order_nonce: 11,
                auditor_view_allowed: false,
                recipient_owner_public_key: "ab".repeat(32),
                recipient_withdraw_authority: "0xbbb".into(),
                filled_amount: 700,
                output_note,
            }],
        )
        .expect("witness");
        assert_eq!(witness.batch_id.0, "batch-2");
        assert_eq!(witness.pair_id.0, "ETH/USDC");
        assert_eq!(witness.settlement_verifier_address, "0x456");
        assert_eq!(witness.clearing_price, 200);
        assert_eq!(witness.base_asset_id.0, "ETH");
        assert_eq!(witness.quote_asset_id.0, "USDC");
        assert_eq!(witness.consumed_inputs.len(), 1);
        assert_eq!(witness.output_notes.len(), 1);
        assert_eq!(witness.matched_order_witnesses.len(), 1);
        assert_eq!(witness.output_ciphertext_bundle_ref, "bundle-2");
    }

    #[test]
    fn stwo_serialized_input_includes_expected_sections() {
        let funding_note = sample_note("USDC", 111 * 400, 4);
        let output_note = sample_note("STRK", 104, 5);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-3".into()),
            clearing_price: 321,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-3".into()),
                filled_amount: 111,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: Nullifier("0x333".into()),
            }],
            fees: vec![FeeEntry {
                asset_id: AssetId("USDC".into()),
                amount: 7,
                recipient: "recipient-3".into(),
            }],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("STRK".into()),
                amount: 104,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-3".into(),
        };

        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-3".into()),
                funding_note,
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier: Nullifier("0x333".into()),
                side: OrderSide::Buy,
                limit_price: 400,
                order_amount: 111,
                min_fill: 10,
                expiry_epoch: 12,
                order_nonce: 21,
                auditor_view_allowed: false,
                recipient_owner_public_key: "ab".repeat(32),
                recipient_withdraw_authority: "0xccc".into(),
                filled_amount: 111,
                output_note,
            }],
        )
        .expect("witness");
        let serialized = build_stwo_serialized_input(&witness);

        assert_eq!(serialized[0], format!("0x{:x}", serialized.len() - 1));
        assert_eq!(serialized[1], "0x5");
        assert_eq!(serialized[10], "0x141");
        assert!(!serialized.is_empty());
    }

    #[test]
    fn stwo_serialized_input_uses_consistent_asset_and_owner_encodings() {
        let owner_public_key = "ab".repeat(32);
        let funding_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 111 * 400,
            owner_public_key: owner_public_key.clone(),
            withdraw_authority: "0xddd".into(),
            blinding: "0x104".into(),
            nonce: 4,
            metadata_commitment: "0x204".into(),
        };
        let output_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 104,
            owner_public_key: owner_public_key.clone(),
            withdraw_authority: "0xeee".into(),
            blinding: "0x105".into(),
            nonce: 5,
            metadata_commitment: "0x205".into(),
        };
        let funding_note_commitment = funding_note
            .commitment()
            .expect("funding note commitment")
            .0;
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-asset-owner".into()),
            clearing_price: 321,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-asset-owner".into()),
                filled_amount: 111,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: Nullifier("0x333".into()),
            }],
            fees: vec![FeeEntry {
                asset_id: AssetId("STRK".into()),
                amount: 7,
                recipient: "recipient-asset-owner".into(),
            }],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("STRK".into()),
                amount: 104,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-asset-owner".into(),
        };

        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-asset-owner".into()),
                funding_note,
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier: Nullifier("0x333".into()),
                side: OrderSide::Buy,
                limit_price: 400,
                order_amount: 111,
                min_fill: 10,
                expiry_epoch: 22,
                order_nonce: 33,
                auditor_view_allowed: true,
                recipient_owner_public_key: owner_public_key.clone(),
                recipient_withdraw_authority: output_note.withdraw_authority.clone(),
                filled_amount: 111,
                output_note,
            }],
        )
        .expect("witness");
        let serialized = build_stwo_serialized_input(&witness);

        let base_asset = encode_starknet_felt("asset-id", "STRK");
        let quote_asset = encode_starknet_felt("asset-id", "USDC");
        let owner_key = encode_starknet_felt("owner-public-key", &owner_public_key);

        let mut index = 1;
        index += 12;

        let _matched_order_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_fill_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_sides = read_serialized_span(&serialized, &mut index);
        let _matched_limit_prices = read_serialized_span(&serialized, &mut index);
        let _matched_order_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_min_fills = read_serialized_span(&serialized, &mut index);
        let matched_expiry_epochs = read_serialized_span(&serialized, &mut index);
        let matched_order_nonces = read_serialized_span(&serialized, &mut index);
        let matched_auditor_flags = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_refs = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_commitments = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_amounts = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_blindings = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let _matched_funding_nullifiers = read_serialized_span(&serialized, &mut index);
        let matched_recipient_owner_keys = read_serialized_span(&serialized, &mut index);
        let _matched_recipient_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_commitments = read_serialized_span(&serialized, &mut index);
        let matched_output_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_amounts = read_serialized_span(&serialized, &mut index);
        let matched_output_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_output_note_blindings = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let _consumed_note_commitments = read_serialized_span(&serialized, &mut index);
        let _consumed_nullifiers = read_serialized_span(&serialized, &mut index);
        let _output_note_commitments = read_serialized_span(&serialized, &mut index);
        let output_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _output_note_amounts = read_serialized_span(&serialized, &mut index);
        let _output_note_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let fee_asset_ids = read_serialized_span(&serialized, &mut index);

        assert_eq!(serialized[8], base_asset);
        assert_eq!(serialized[9], quote_asset);
        assert_eq!(matched_expiry_epochs, vec!["0x16".to_string()]);
        assert_eq!(matched_order_nonces, vec!["0x21".to_string()]);
        assert_eq!(matched_auditor_flags, vec!["0x1".to_string()]);
        assert_eq!(matched_funding_note_refs, vec![funding_note_commitment]);
        assert_eq!(matched_funding_note_asset_ids, vec![quote_asset.clone()]);
        assert_eq!(matched_output_note_asset_ids, vec![base_asset.clone()]);
        assert_eq!(output_note_asset_ids, vec![base_asset.clone()]);
        assert_eq!(fee_asset_ids, vec![base_asset]);
        assert_eq!(matched_funding_note_owner_keys, vec![owner_key.clone()]);
        assert_eq!(matched_recipient_owner_keys, vec![owner_key.clone()]);
        assert_eq!(matched_output_note_owner_keys, vec![owner_key]);
    }

    fn sample_order() -> OrderIntent {
        let funding_note = sample_note("USDC", 200_000, 7);
        OrderIntent {
            pair_id: crate::PairId("STRK/USDC".into()),
            side: OrderSide::Buy,
            limit_price: 145,
            amount: 1000,
            min_fill: 100,
            expiry_epoch: 42,
            order_nonce: 7,
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: Nullifier("0x777".into()),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_withdraw_authority: "0xfff".into(),
            auditor_view_allowed: false,
        }
    }

    fn sample_private_order() -> PrivateOrderPayload {
        let funding_note = sample_note("USDC", 200_000, 7);
        let mut order = sample_order();
        order.funding_note_ref = funding_note.commitment().expect("funding note commitment");

        PrivateOrderPayload {
            order,
            funding_note,
        }
    }

    fn sample_note(asset_id: &str, amount: u128, nonce: u64) -> Note {
        Note {
            asset_id: AssetId(asset_id.into()),
            amount,
            owner_public_key: "ab".repeat(32),
            withdraw_authority: "0x123".into(),
            blinding: format!("0x{:x}", nonce + 0x100),
            nonce,
            metadata_commitment: format!("0x{:x}", nonce + 0x200),
        }
    }

    #[test]
    fn proof_friendly_account_message_hash_changes_with_nonce() {
        let calldata = vec!["0x1".into(), "0x2".into(), "0x3".into()];
        let hash_a = proof_friendly_account_message_hash(
            "0x111",
            "0x222",
            "0x1",
            "0x333",
            "0x444",
            &calldata,
        )
        .expect("hash a");
        let hash_b = proof_friendly_account_message_hash(
            "0x111",
            "0x222",
            "0x2",
            "0x333",
            "0x444",
            &calldata,
        )
        .expect("hash b");

        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn proof_friendly_account_message_hash_changes_with_call_payload() {
        let hash_a = proof_friendly_account_message_hash(
            "0x111",
            "0x222",
            "0x1",
            "0x333",
            "0x444",
            &["0x1".into(), "0x2".into()],
        )
        .expect("hash a");
        let hash_b = proof_friendly_account_message_hash(
            "0x111",
            "0x222",
            "0x1",
            "0x333",
            "0x444",
            &["0x1".into(), "0x9".into()],
        )
        .expect("hash b");

        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn proof_friendly_account_message_hash_changes_with_chain_id() {
        let calldata = vec!["0x1".into()];
        let hash_a = proof_friendly_account_message_hash(
            "0x111",
            "0x222",
            "0x1",
            "0x333",
            "0x444",
            &calldata,
        )
        .expect("hash a");
        let hash_b = proof_friendly_account_message_hash(
            "0x111",
            "0x223",
            "0x1",
            "0x333",
            "0x444",
            &calldata,
        )
        .expect("hash b");

        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn native_settlement_message_hash_matches_cairo_contract_formula() {
        let hash = crate::native_settlement_message_hash(
            "0x030f8072f3c6a9261704b056875cc0983335f7e95540026bfd359c9ee5c1041d",
            "0x34f779a519b7c0ffb1db2f00d7683befa23663c929cbce579c87d4fb0dbb89b",
        )
        .expect("native settlement message hash");

        assert_eq!(
            hash,
            "0x4a97eeca5c02b9944edc993761b04c20a788f02b380419d29f8a337d92ef2ac"
        );
    }

    fn committee_members() -> Vec<CommitteeMemberPrivateConfig> {
        (0..3)
            .map(|index| {
                let secret = SecretKey::random(&mut OsRng);
                let public = secret.public_key();
                CommitteeMemberPrivateConfig {
                    member_id: format!("member-{index}"),
                    private_key: hex::encode(secret.to_bytes()),
                    public_key: hex::encode(public.to_encoded_point(false).as_bytes()),
                }
            })
            .collect()
    }

    fn read_serialized_span(serialized: &[String], index: &mut usize) -> Vec<String> {
        let len = usize::from_str_radix(serialized[*index].trim_start_matches("0x"), 16)
            .expect("valid serialized span length");
        *index += 1;
        let values = serialized[*index..*index + len].to_vec();
        *index += len;
        values
    }
}
