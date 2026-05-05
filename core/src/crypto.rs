use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use starknet_crypto::{Felt, poseidon_hash, rfc6979_generate_k, sign, verify};

use crate::{
    ApprovalCallArguments, AssetId, AuctionOrderWitness, DecryptedOrderShare, DepositCallArguments,
    DepositIntent, DepositSubmissionPlan, EncryptedBlob, EncryptedRecoveryPayload, FundingRailKind,
    MatchedOrderWitness, Note, OrderCommitment, OrderIngressReceipt, OrderIntent, OrderShare,
    OrderShareBundle, OrderSide, OrderSubmission, OrderType, PairId,
    PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyRegistry, PrivateOrderPayload,
    ProtocolError, RecoveryArtifact, RecoveryArtifactKind, RecoverySeed, RenewalChildUse,
    SettlementCallArguments, SettlementSubmissionPlan, SettlementTranscript, SettlementWitness,
    StarknetCall, TimeInForce, WithdrawalCallArguments, WithdrawalSubmissionPlan, derive_user_keys,
    hash::{
        domain_felt, domain_felt_hex, encode_starknet_felt, felt_from_hex_str, felt_hex,
        normalize_felt_hex, poseidon_chain_hex, tagged_commitment_sha256, tagged_field_hex,
        tagged_sha256_bytes, tagged_sha256_hex,
    },
    types::renewal_child_nullifier,
};

const NATIVE_SETTLEMENT_MESSAGE_DOMAIN_HEX: &str =
    "0x0326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a";
const PUBLIC_SETTLEMENT_DOMAIN_HEX: &str =
    "0x0283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205";
const SETTLEMENT_PROOF_MESSAGE_DOMAIN_HEX: &str = "0x7a796c6974685f736574746c655f7631";
const NOTE_RECOGNITION_ALGORITHM: &str = "aes-256-gcm/note-recognition";
const PRIVATE_ORDER_SHARE_ALGORITHM_V1: &str = "ecdh-p256+hkdf-sha256+aes-256-gcm/private-order-v1";
const PRIVATE_ORDER_SHARE_HKDF_SALT: &[u8] = b"zylith/private-order-share-key-separation-v1";
const RECOVERY_ARTIFACT_ALGORITHM_V2: &str = "aes-256-gcm/recovery-v2";
const WALLET_HKDF_SALT: &[u8] = b"zylith/wallet-key-separation-v2";
const ORDER_INGRESS_RECEIPT_VERSION: u32 = 1;
const SETTLEMENT_STATEMENT_TYPE_TAG: u64 = 1;
const AUCTION_STATEMENT_TYPE_TAG: u64 = 2;

type HmacSha256 = Hmac<Sha256>;

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
    registry: &PrivateExecutionKeyRegistry,
    order_cancellation_key_hex: &str,
) -> Result<OrderSubmission, ProtocolError> {
    if registry.keys.is_empty() {
        return Err(ProtocolError::Crypto(
            "private execution key registry must contain at least one key".into(),
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
    validate_private_order_spend_authorization(payload, &funding_note_commitment)?;

    let plaintext = serde_json::to_vec(payload)?;
    let split_shares = split_into_xor_shares(&plaintext, registry.keys.len());

    let shares = registry
        .keys
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let payload = SecretSharePayload {
                order_commitment: order_commitment.0.clone(),
                share_index: index,
                share_count: registry.keys.len(),
                plaintext_len: plaintext.len(),
                share_hex: hex::encode(&split_shares[index]),
            };

            Ok(OrderShare {
                execution_key_id: member.key_id.clone(),
                encrypted_share: encrypt_for_private_execution_key(
                    &member.key_id,
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
            batch_id: payload.order.batch_id.clone(),
            epoch_id: payload.order.expiry_epoch,
            transport_envelope: None,
            ingress_receipt: None,
            shares,
        },
    })
}

pub fn private_order_payload_commitment(
    bundle: &OrderShareBundle,
) -> Result<String, ProtocolError> {
    if bundle.transport_envelope.is_none() && bundle.shares.is_empty() {
        return Err(ProtocolError::Crypto(
            "order bundle does not contain a private ingress payload".into(),
        ));
    }

    #[derive(Serialize)]
    struct PrivatePayloadCommitmentView<'a> {
        transport_envelope: &'a Option<EncryptedBlob>,
        shares: &'a [OrderShare],
    }

    tagged_commitment_sha256(
        "zylith/private-order-payload-v1",
        &PrivatePayloadCommitmentView {
            transport_envelope: &bundle.transport_envelope,
            shares: &bundle.shares,
        },
    )
}

pub fn private_execution_key_registry_fingerprint(
    registry: &PrivateExecutionKeyRegistry,
) -> Result<String, ProtocolError> {
    tagged_commitment_sha256("zylith/private-execution-key-registry-v1", registry)
}

pub fn validate_private_execution_key_registry_pin(
    registry: &PrivateExecutionKeyRegistry,
    expected_fingerprint: &str,
) -> Result<(), ProtocolError> {
    let expected = expected_fingerprint.trim().to_ascii_lowercase();
    if expected.is_empty() {
        return Err(ProtocolError::Crypto(
            "private execution key registry pin is empty".into(),
        ));
    }
    let actual = private_execution_key_registry_fingerprint(registry)?;
    if !crate::constant_time_eq(&actual, &expected) {
        return Err(ProtocolError::Crypto(
            "private execution key registry fingerprint mismatch".into(),
        ));
    }
    Ok(())
}

pub fn create_order_ingress_receipt(
    bundle: &OrderShareBundle,
    ingress_id: &str,
    signer: &str,
    receipt_secret: &str,
    issued_at_unix_ms: u64,
) -> Result<OrderIngressReceipt, ProtocolError> {
    let payload_commitment = private_order_payload_commitment(bundle)?;
    let mut receipt = OrderIngressReceipt {
        version: ORDER_INGRESS_RECEIPT_VERSION,
        ingress_id: ingress_id.into(),
        order_commitment: bundle.order_commitment.clone(),
        pair_id: bundle.pair_id.clone(),
        batch_id: bundle.batch_id.clone(),
        epoch_id: bundle.epoch_id,
        payload_commitment,
        issued_at_unix_ms,
        signer: signer.into(),
        signature: String::new(),
    };
    receipt.signature = sign_order_ingress_receipt(&receipt, receipt_secret)?;
    Ok(receipt)
}

pub fn sanitize_order_submission_for_coordinator(
    submission: &OrderSubmission,
    receipt: OrderIngressReceipt,
) -> Result<OrderSubmission, ProtocolError> {
    validate_order_ingress_receipt_fields(&submission.order_bundle, &receipt)?;

    Ok(OrderSubmission {
        order_bundle: OrderShareBundle {
            order_commitment: submission.order_bundle.order_commitment.clone(),
            cancellation_auth_tag: submission.order_bundle.cancellation_auth_tag.clone(),
            pair_id: submission.order_bundle.pair_id.clone(),
            batch_id: submission.order_bundle.batch_id.clone(),
            epoch_id: submission.order_bundle.epoch_id,
            transport_envelope: None,
            ingress_receipt: Some(receipt),
            shares: Vec::new(),
        },
    })
}

pub fn verify_order_ingress_receipt(
    receipt: &OrderIngressReceipt,
    receipt_secret: &str,
) -> Result<(), ProtocolError> {
    if receipt.version != ORDER_INGRESS_RECEIPT_VERSION {
        return Err(ProtocolError::Crypto(format!(
            "unsupported order ingress receipt version {}",
            receipt.version
        )));
    }

    let signature = hex::decode(&receipt.signature)?;
    let payload = order_ingress_receipt_payload(receipt)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(receipt_secret.as_bytes()).map_err(|_| {
        ProtocolError::Crypto("order ingress receipt secret could not initialize HMAC".into())
    })?;
    mac.update(&payload);
    mac.verify_slice(&signature)
        .map_err(|_| ProtocolError::Crypto("order ingress receipt signature mismatch".into()))
}

pub fn verify_order_ingress_receipt_with_secrets(
    receipt: &OrderIngressReceipt,
    receipt_secrets: &[String],
) -> Result<(), ProtocolError> {
    let mut configured_secret_count = 0_u64;
    for receipt_secret in receipt_secrets {
        if receipt_secret.trim().is_empty() {
            continue;
        }
        configured_secret_count += 1;
        if verify_order_ingress_receipt(receipt, receipt_secret).is_ok() {
            return Ok(());
        }
    }

    if configured_secret_count == 0 {
        return Err(ProtocolError::Crypto(
            "order ingress receipt secret keyring is empty".into(),
        ));
    }
    Err(ProtocolError::Crypto(
        "order ingress receipt signature mismatch for configured keyring".into(),
    ))
}

pub fn validate_order_ingress_receipt_for_manifest(
    bundle: &OrderShareBundle,
    receipt_secret: &str,
) -> Result<(), ProtocolError> {
    let receipt = bundle.ingress_receipt.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("order submission is missing prover ingress receipt".into())
    })?;
    validate_order_ingress_receipt_fields(bundle, receipt)?;
    verify_order_ingress_receipt(receipt, receipt_secret)
}

pub fn validate_order_ingress_receipt_for_manifest_with_secrets(
    bundle: &OrderShareBundle,
    receipt_secrets: &[String],
) -> Result<(), ProtocolError> {
    let receipt = bundle.ingress_receipt.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("order submission is missing prover ingress receipt".into())
    })?;
    validate_order_ingress_receipt_fields(bundle, receipt)?;
    verify_order_ingress_receipt_with_secrets(receipt, receipt_secrets)
}

fn validate_order_ingress_receipt_fields(
    bundle: &OrderShareBundle,
    receipt: &OrderIngressReceipt,
) -> Result<(), ProtocolError> {
    if receipt.order_commitment != bundle.order_commitment
        || receipt.pair_id != bundle.pair_id
        || receipt.batch_id != bundle.batch_id
        || receipt.epoch_id != bundle.epoch_id
    {
        return Err(ProtocolError::Crypto(
            "order ingress receipt does not match order bundle metadata".into(),
        ));
    }
    if receipt.ingress_id.trim().is_empty() || receipt.signer.trim().is_empty() {
        return Err(ProtocolError::Crypto(
            "order ingress receipt is missing ingress identity".into(),
        ));
    }
    if receipt.payload_commitment.trim().is_empty() || receipt.signature.trim().is_empty() {
        return Err(ProtocolError::Crypto(
            "order ingress receipt is missing payload commitment or signature".into(),
        ));
    }
    Ok(())
}

fn sign_order_ingress_receipt(
    receipt: &OrderIngressReceipt,
    receipt_secret: &str,
) -> Result<String, ProtocolError> {
    if receipt_secret.trim().is_empty() {
        return Err(ProtocolError::Crypto(
            "order ingress receipt secret is not configured".into(),
        ));
    }
    let payload = order_ingress_receipt_payload(receipt)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(receipt_secret.as_bytes()).map_err(|_| {
        ProtocolError::Crypto("order ingress receipt secret could not initialize HMAC".into())
    })?;
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn order_ingress_receipt_payload(receipt: &OrderIngressReceipt) -> Result<Vec<u8>, ProtocolError> {
    #[derive(Serialize)]
    struct OrderIngressReceiptSigningPayload<'a> {
        version: u32,
        ingress_id: &'a str,
        order_commitment: &'a OrderCommitment,
        pair_id: &'a PairId,
        batch_id: &'a crate::BatchId,
        epoch_id: u64,
        payload_commitment: &'a str,
        issued_at_unix_ms: u64,
        signer: &'a str,
    }

    Ok(serde_json::to_vec(&OrderIngressReceiptSigningPayload {
        version: receipt.version,
        ingress_id: &receipt.ingress_id,
        order_commitment: &receipt.order_commitment,
        pair_id: &receipt.pair_id,
        batch_id: &receipt.batch_id,
        epoch_id: receipt.epoch_id,
        payload_commitment: &receipt.payload_commitment,
        issued_at_unix_ms: receipt.issued_at_unix_ms,
        signer: &receipt.signer,
    })?)
}

pub fn decrypt_order_bundle(
    bundle: &OrderShareBundle,
    private_execution_keys: &[PrivateExecutionKeyPrivateConfig],
) -> Result<PrivateOrderPayload, ProtocolError> {
    let share_payloads = private_execution_keys
        .iter()
        .map(|member_key| decrypt_order_share(bundle, member_key))
        .collect::<Result<Vec<_>, ProtocolError>>()?;

    reconstruct_order_from_shares(bundle, &share_payloads)
}

pub fn decrypt_order_share(
    bundle: &OrderShareBundle,
    member_key: &PrivateExecutionKeyPrivateConfig,
) -> Result<DecryptedOrderShare, ProtocolError> {
    let share = bundle
        .shares
        .iter()
        .find(|share| share.execution_key_id == member_key.key_id)
        .ok_or_else(|| {
            ProtocolError::Crypto(format!(
                "order bundle missing share for private execution key {}",
                member_key.key_id
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
        key_id: member_key.key_id.clone(),
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
    validate_private_order_spend_authorization(&payload, &funding_note_commitment)?;

    Ok(payload)
}

fn validate_private_order_spend_authorization(
    payload: &PrivateOrderPayload,
    funding_note_commitment: &crate::NoteCommitment,
) -> Result<(), ProtocolError> {
    let expected_order_commitment = payload.order.commitment()?;
    let public_key = felt_from_hex_str(&payload.funding_note.spend_authority)?;
    let signature_r = felt_from_hex_str(&payload.funding_authorization.signature_r)?;
    let signature_s = felt_from_hex_str(&payload.funding_authorization.signature_s)?;
    let message = felt_from_hex_str(&expected_order_commitment.0)?;
    if !verify(&public_key, &message, &signature_r, &signature_s).map_err(|err| {
        ProtocolError::Crypto(format!("funding authorization verify failed: {err}"))
    })? {
        return Err(ProtocolError::Crypto(
            "funding authorization signature does not match note spend authority".into(),
        ));
    }

    if *funding_note_commitment != payload.order.funding_note_ref {
        return Err(ProtocolError::Crypto(
            "funding note commitment does not match authorization payload".into(),
        ));
    }
    Ok(())
}

pub fn sign_order_authorization(
    spend_auth_key_felt: &str,
    order_commitment: &OrderCommitment,
) -> Result<crate::SpendAuthorization, ProtocolError> {
    let private_key = felt_from_hex_str(spend_auth_key_felt)?;
    let message = felt_from_hex_str(&order_commitment.0)?;
    let k = rfc6979_generate_k(&message, &private_key, None);
    let signature = sign(&private_key, &message, &k).map_err(|err| {
        ProtocolError::Crypto(format!("order authorization signing failed: {err}"))
    })?;
    Ok(crate::SpendAuthorization {
        signature_r: felt_hex(&signature.r),
        signature_s: felt_hex(&signature.s),
    })
}

pub fn build_output_note(
    batch_id: &str,
    output_index: usize,
    order_commitment: &OrderCommitment,
    order: &OrderIntent,
    asset_id: AssetId,
    amount: u128,
    withdraw_authority: &str,
) -> Result<Note, ProtocolError> {
    let withdraw_authority = normalize_felt_hex(withdraw_authority)?;
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
            "recipient_spend_authority": order.recipient_spend_authority,
            "withdraw_authority": withdraw_authority,
        }),
    )?;

    Ok(Note {
        asset_id,
        amount,
        owner_public_key: order.recipient_owner_public_key.clone(),
        spend_authority: order.recipient_spend_authority.clone(),
        withdraw_authority,
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
    if key_bytes.len() != 32 {
        return Err(ProtocolError::Crypto(format!(
            "order cancellation key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }
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

pub fn build_deposit_submission_plan(
    intent: &DepositIntent,
    deposit_authority_address: &str,
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
        contract_address: normalize_felt_hex(deposit_authority_address)?,
        entrypoint: "execute_actions".into(),
        calldata: vec![
            encoded_args.asset_id.clone(),
            encoded_args.amount.clone(),
            encoded_args.deposit_nonce.clone(),
            encoded_args.note_commitment.clone(),
            encoded_args.withdraw_authority.clone(),
        ],
    };

    Ok(DepositSubmissionPlan {
        funding_rail: FundingRailKind::StarknetPrivacy,
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
    withdraw_auth_key_felt: &str,
    recipient: &str,
    shielded_asset_adapter_address: &str,
    chain_id: &str,
) -> Result<WithdrawalSubmissionPlan, ProtocolError> {
    let note_commitment = normalize_felt_hex(note_commitment)?;
    let recipient = normalize_felt_hex(recipient)?;
    let shielded_asset_adapter_address = normalize_felt_hex(shielded_asset_adapter_address)?;
    let chain_id = normalize_felt_hex(chain_id)?;
    let message = withdrawal_message_hash(
        &note_commitment,
        &recipient,
        &shielded_asset_adapter_address,
        &chain_id,
    )?;
    let private_key = felt_from_hex_str(withdraw_auth_key_felt)?;
    let message = felt_from_hex_str(&message)?;
    let k = rfc6979_generate_k(&message, &private_key, None);
    let signature = sign(&private_key, &message, &k).map_err(|err| {
        ProtocolError::Crypto(format!("withdrawal authorization signing failed: {err}"))
    })?;
    let encoded_args = WithdrawalCallArguments {
        note_commitment,
        withdraw_authorization_r: felt_hex(&signature.r),
        withdraw_authorization_s: felt_hex(&signature.s),
        recipient,
    };

    Ok(WithdrawalSubmissionPlan {
        funding_rail: FundingRailKind::StarknetPrivacy,
        note_commitment: crate::types::NoteCommitment(encoded_args.note_commitment.clone()),
        starknet_call: StarknetCall {
            contract_address: shielded_asset_adapter_address,
            entrypoint: "withdraw_to_l2".into(),
            calldata: vec![
                encoded_args.note_commitment.clone(),
                encoded_args.withdraw_authorization_r.clone(),
                encoded_args.withdraw_authorization_s.clone(),
                encoded_args.recipient.clone(),
            ],
        },
        encoded_args,
    })
}

pub fn withdrawal_message_hash(
    note_commitment: &str,
    recipient: &str,
    shielded_asset_adapter_address: &str,
    chain_id: &str,
) -> Result<String, ProtocolError> {
    let note_commitment = felt_from_hex_str(note_commitment)?;
    let recipient = felt_from_hex_str(recipient)?;
    let shielded_asset_adapter_address = felt_from_hex_str(shielded_asset_adapter_address)?;
    let chain_id = felt_from_hex_str(chain_id)?;
    Ok(poseidon_chain_hex(
        domain_felt("zylith/withdrawal"),
        &[
            chain_id,
            shielded_asset_adapter_address,
            note_commitment,
            recipient,
        ],
    ))
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
    let note_commitment = note.commitment()?;
    let nonce_hex = tagged_commitment_sha256(
        "zylith/output-nonce",
        &serde_json::json!({
            "batch_id": batch_id,
            "output_index": output_index,
            "note_commitment": note_commitment.0,
            "owner": recipient_owner_public_key,
        }),
    )?;
    let nonce_bytes = hex::decode(&nonce_hex[..24])?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(note)?;
    let nonce_hex = hex::encode(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: encrypted_blob_aad(
                    NOTE_RECOGNITION_ALGORITHM,
                    recipient_owner_public_key,
                    &nonce_hex,
                )
                .as_ref(),
            },
        )
        .map_err(|err| ProtocolError::Crypto(format!("note encryption failed: {err}")))?;

    Ok(EncryptedBlob {
        algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
        key_id: recipient_owner_public_key.into(),
        ephemeral_public_key: String::new(),
        nonce: nonce_hex,
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn decrypt_note_for_owner(
    note_recognition_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Option<Note>, ProtocolError> {
    if blob.algorithm != NOTE_RECOGNITION_ALGORITHM {
        return Ok(None);
    }

    let key_bytes = derive_output_encryption_key(note_recognition_key_hex);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce_bytes = hex::decode(&blob.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex::decode(&blob.ciphertext)?;
    let aad = encrypted_blob_aad(&blob.algorithm, &blob.key_id, &blob.nonce);
    let plaintext = match cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext.as_ref(),
            aad: aad.as_ref(),
        },
    ) {
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
    let key_bytes = derive_wallet_aes_key(seed, b"zylith/recovery-artifact-aes-key")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = random_nonce();
    let plaintext = serde_json::to_vec(payload)?;
    let aad = recovery_artifact_aad(
        RECOVERY_ARTIFACT_ALGORITHM_V2,
        &account_id,
        &kind,
        sequence,
        created_at_unix_ms,
    );
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
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
            algorithm: RECOVERY_ARTIFACT_ALGORITHM_V2.into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        },
    })
}

pub fn decrypt_recovery_artifact_payload(
    seed: &RecoverySeed,
    artifact: &RecoveryArtifact,
) -> Result<Value, ProtocolError> {
    if artifact.payload.algorithm != RECOVERY_ARTIFACT_ALGORITHM_V2 {
        return Err(ProtocolError::Crypto(format!(
            "unsupported recovery algorithm {}",
            artifact.payload.algorithm
        )));
    }

    let key_bytes = derive_wallet_aes_key(seed, b"zylith/recovery-artifact-aes-key")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
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
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_ref(),
                aad: aad.as_ref(),
            },
        )
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
    state = poseidon_hash(
        state,
        felt_from_hex_str(&encode_starknet_felt("pair-id", &transcript.pair_id.0))?,
    );
    state = poseidon_hash(state, Felt::from(transcript.batch_epoch));
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_batch_order_commitment_root(
            &transcript.order_commitment_root,
        )?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_encrypted_order_set_commitment(
            &transcript.encrypted_order_set_commitment,
        )?)?,
    );
    state = poseidon_hash(state, Felt::from(transcript.clearing_price));
    state = poseidon_hash(
        state,
        felt_from_hex_str(&encode_starknet_felt(
            "output-bundle-ref",
            &transcript.output_ciphertext_bundle_ref,
        ))?,
    );
    state = poseidon_hash(state, Felt::from(transcript.consumed_inputs.len() as u64));

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

    state = poseidon_hash(
        state,
        Felt::from(transcript.renewal_child_uses.len() as u64),
    );
    for renewal in &transcript.renewal_child_uses {
        state = poseidon_hash(
            state,
            felt_from_hex_str(&normalize_felt_hex(&renewal.parent_order_commitment)?)?,
        );
        state = poseidon_hash(
            state,
            felt_from_hex_str(&normalize_felt_hex(&renewal.child_nullifier)?)?,
        );
    }

    state = poseidon_hash(state, Felt::from(transcript.output_notes.len() as u64));
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

    state = poseidon_hash(state, Felt::from(transcript.fees.len() as u64));
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

pub fn renewal_child_uses_from_matched_witnesses(
    matched_order_witnesses: &[MatchedOrderWitness],
) -> Result<Vec<RenewalChildUse>, ProtocolError> {
    matched_order_witnesses
        .iter()
        .filter(|entry| {
            normalize_felt_hex(&entry.parent_order_commitment)
                .map(|parent| parent != "0x0")
                .unwrap_or(true)
        })
        .map(|entry| {
            Ok(RenewalChildUse {
                parent_order_commitment: normalize_felt_hex(&entry.parent_order_commitment)?,
                child_nullifier: renewal_child_nullifier(
                    &entry.parent_order_commitment,
                    entry.parent_child_index,
                    &entry.parent_authorization_secret,
                )?,
            })
        })
        .collect()
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
    auction_verifier_address: &str,
    transcript_commitment: &str,
) -> Result<String, ProtocolError> {
    let mut state = poseidon_hash(
        felt_from_hex_str(NATIVE_SETTLEMENT_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(&normalize_felt_hex(auction_verifier_address)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(transcript_commitment)?)?,
    );
    Ok(felt_hex(&state))
}

pub fn build_settlement_submission_plan(
    transcript: &SettlementTranscript,
    verifier_address: &str,
    proof_artifact_commitment: &str,
) -> Result<SettlementSubmissionPlan, ProtocolError> {
    let transcript_commitment = settlement_transcript_commitment(transcript)?;
    let normalized_proof_artifact_commitment = normalize_felt_hex(proof_artifact_commitment)?;
    let settlement_entrypoint = "submit_settlement_with_proof_facts";
    let encoded_args = SettlementCallArguments {
        batch_id: encode_starknet_felt("batch-id", &transcript.batch_id.0),
        order_commitment_root: normalize_batch_order_commitment_root(
            &transcript.order_commitment_root,
        )?,
        encrypted_order_set_commitment: normalize_encrypted_order_set_commitment(
            &transcript.encrypted_order_set_commitment,
        )?,
        transcript_commitment: normalize_felt_hex(&transcript_commitment)?,
        proof_artifact_commitment: normalized_proof_artifact_commitment.clone(),
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
        renewal_parent_order_commitments: transcript
            .renewal_child_uses
            .iter()
            .map(|renewal| normalize_felt_hex(&renewal.parent_order_commitment))
            .collect::<Result<Vec<_>, _>>()?,
        renewal_child_nullifiers: transcript
            .renewal_child_uses
            .iter()
            .map(|renewal| normalize_felt_hex(&renewal.child_nullifier))
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
        proof_artifact_commitment: normalized_proof_artifact_commitment,
        settlement_call: StarknetCall {
            contract_address: normalize_felt_hex(verifier_address)?,
            entrypoint: settlement_entrypoint.into(),
            calldata,
        },
        encoded_args,
    })
}

pub fn settlement_proof_message_hash(
    auction_verifier_address: &str,
    transcript_commitment: &str,
) -> Result<String, ProtocolError> {
    let statement_message_hash =
        native_settlement_message_hash(auction_verifier_address, transcript_commitment)?;
    settlement_proof_message_hash_from_statement(auction_verifier_address, &statement_message_hash)
}

pub fn settlement_proof_message_hash_from_statement(
    auction_verifier_address: &str,
    statement_message_hash: &str,
) -> Result<String, ProtocolError> {
    let fields = [
        felt_from_hex_str(auction_verifier_address)?,
        Felt::ZERO,
        Felt::from(2_u64),
        felt_from_hex_str(SETTLEMENT_PROOF_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(statement_message_hash)?,
    ];
    Ok(crate::hash::poseidon_hash_hex(&fields))
}

pub fn build_settlement_witness(
    transcript: &SettlementTranscript,
    pair_id: PairId,
    verifier_address: &str,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    matched_order_witnesses: Vec<MatchedOrderWitness>,
) -> Result<SettlementWitness, ProtocolError> {
    if transcript.pair_id != pair_id {
        return Err(ProtocolError::Crypto(
            "settlement witness pair does not match transcript pair".into(),
        ));
    }
    let renewal_child_uses = renewal_child_uses_from_matched_witnesses(&matched_order_witnesses)?;
    if transcript.renewal_child_uses != renewal_child_uses {
        return Err(ProtocolError::Crypto(
            "settlement transcript renewal child uses do not match matched witness parent links"
                .into(),
        ));
    }
    Ok(SettlementWitness {
        batch_id: transcript.batch_id.clone(),
        pair_id: pair_id.clone(),
        batch_epoch: transcript.batch_epoch,
        order_commitment_root: transcript.order_commitment_root.clone(),
        encrypted_order_set_commitment: transcript.encrypted_order_set_commitment.clone(),
        transcript_commitment: settlement_transcript_commitment(transcript)?,
        auction_verifier_address: verifier_address.into(),
        clearing_price: transcript.clearing_price,
        base_asset_id,
        quote_asset_id,
        matched_orders: transcript.matched_orders.clone(),
        matched_order_witnesses,
        consumed_inputs: transcript.consumed_inputs.clone(),
        renewal_child_uses,
        fees: transcript.fees.clone(),
        output_notes: transcript.output_notes.clone(),
        output_ciphertext_bundle_ref: transcript.output_ciphertext_bundle_ref.clone(),
    })
}

pub fn build_stwo_serialized_input(
    witness: &SettlementWitness,
) -> Result<Vec<String>, ProtocolError> {
    if witness.batch_epoch == 0 {
        return Err(ProtocolError::Crypto(
            "settlement witness batch_epoch must be non-zero".into(),
        ));
    }
    for entry in &witness.matched_order_witnesses {
        if entry.expiry_epoch != witness.batch_epoch {
            return Err(ProtocolError::Crypto(
                "matched order expiry_epoch does not match settlement batch_epoch".into(),
            ));
        }
    }
    if witness.matched_orders.len() != witness.matched_order_witnesses.len() {
        return Err(ProtocolError::Crypto(format!(
            "matched order count {} does not match witness count {}",
            witness.matched_orders.len(),
            witness.matched_order_witnesses.len()
        )));
    }

    let maker_curve_commitments = witness
        .matched_order_witnesses
        .iter()
        .map(encode_maker_curve_commitment)
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let maker_curve_point_counts = witness
        .matched_order_witnesses
        .iter()
        .map(|entry| {
            encode_u64(
                entry
                    .maker_curve
                    .as_ref()
                    .map(|curve| curve.points.len())
                    .unwrap_or(0) as u64,
            )
        })
        .collect::<Vec<_>>();
    let maker_curve_prices = witness
        .matched_order_witnesses
        .iter()
        .flat_map(|entry| {
            entry
                .maker_curve
                .as_ref()
                .into_iter()
                .flat_map(|curve| curve.points.iter().map(|point| encode_u128(point.price)))
        })
        .collect::<Vec<_>>();
    let maker_curve_base_amounts = witness
        .matched_order_witnesses
        .iter()
        .flat_map(|entry| {
            entry.maker_curve.as_ref().into_iter().flat_map(|curve| {
                curve
                    .points
                    .iter()
                    .map(|point| encode_u128(point.base_amount))
            })
        })
        .collect::<Vec<_>>();
    let mut payload = vec![
        encode_u64(SETTLEMENT_STATEMENT_TYPE_TAG),
        domain_felt_hex("zylith/note"),
        domain_felt_hex("zylith/spend-authority"),
        domain_felt_hex("zylith/nullifier"),
        domain_felt_hex("zylith/order"),
        domain_felt_hex("zylith/maker-curve"),
        PUBLIC_SETTLEMENT_DOMAIN_HEX.into(),
        encode_starknet_felt("batch-id", &witness.batch_id.0),
        encode_starknet_felt("pair-id", &witness.pair_id.0),
        encode_u64(witness.batch_epoch),
        normalize_batch_order_commitment_root(&witness.order_commitment_root)?,
        normalize_encrypted_order_set_commitment(&witness.encrypted_order_set_commitment)?,
        normalize_felt_hex(&witness.transcript_commitment)?,
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
            .map(|entry| encode_order_type(&entry.order_type))
            .collect::<Vec<_>>(),
    );
    push_span(&mut payload, &maker_curve_commitments);
    push_span(&mut payload, &maker_curve_point_counts);
    push_span(&mut payload, &maker_curve_prices);
    push_span(&mut payload, &maker_curve_base_amounts);
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
            .map(|entry| encode_time_in_force(&entry.time_in_force))
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
            .map(|entry| normalize_felt_hex(&entry.parent_order_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| encode_u64(entry.parent_child_index))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.parent_secret_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.parent_cancel_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.parent_authorization_secret))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            .map(|entry| normalize_felt_hex(&entry.funding_note.spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_note.withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            .map(|entry| normalize_felt_hex(&entry.funding_authorization.signature_r))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_authorization.signature_s))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            .map(|entry| normalize_felt_hex(&entry.recipient_spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.recipient_withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.recipient_residual_withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            .map(|entry| normalize_felt_hex(&entry.output_note.spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| normalize_felt_hex(&entry.output_note.withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                if entry.residual_note.is_some() {
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
            .map(|entry| match entry.residual_note.as_ref() {
                Some(note) => note.commitment().map(|commitment| commitment.0),
                None => Ok("0x0".into()),
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                entry
                    .residual_note
                    .as_ref()
                    .map(|note| encode_asset_id(&note.asset_id.0))
                    .unwrap_or_else(|| "0x0".into())
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
                    .residual_note
                    .as_ref()
                    .map(|note| encode_u128(note.amount))
                    .unwrap_or_else(|| "0x0".into())
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
                    .residual_note
                    .as_ref()
                    .map(|note| encode_owner_public_key(&note.owner_public_key))
                    .unwrap_or_else(|| "0x0".into())
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
                    .residual_note
                    .as_ref()
                    .map(|note| normalize_felt_hex(&note.spend_authority))
                    .transpose()
                    .map(|value| value.unwrap_or_else(|| "0x0".into()))
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| match entry.residual_note.as_ref() {
                Some(note) => normalize_felt_hex(&note.withdraw_authority),
                None => Ok("0x0".into()),
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .matched_order_witnesses
            .iter()
            .map(|entry| {
                entry
                    .residual_note
                    .as_ref()
                    .map(|note| note.blinding.clone())
                    .unwrap_or_else(|| "0x0".into())
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
                    .residual_note
                    .as_ref()
                    .map(|note| encode_u64(note.nonce))
                    .unwrap_or_else(|| "0x0".into())
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
                    .residual_note
                    .as_ref()
                    .map(|note| note.metadata_commitment.clone())
                    .unwrap_or_else(|| "0x0".into())
            })
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
            .renewal_child_uses
            .iter()
            .map(|renewal| normalize_felt_hex(&renewal.parent_order_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .renewal_child_uses
            .iter()
            .map(|renewal| normalize_felt_hex(&renewal.child_nullifier))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
            .map(|output| normalize_felt_hex(&output.withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
    Ok(serialized)
}

pub fn build_auction_serialized_input(
    witness: &SettlementWitness,
    all_orders: &[AuctionOrderWitness],
) -> Result<Vec<String>, ProtocolError> {
    let settlement_calldata = build_stwo_serialized_input(witness)?;
    let (settlement_len, settlement_payload) = settlement_calldata
        .split_first()
        .ok_or_else(|| ProtocolError::Crypto("empty settlement proof input".into()))?;
    let expected_len = usize::from_str_radix(settlement_len.trim_start_matches("0x"), 16)
        .map_err(|error| ProtocolError::Crypto(format!("bad settlement proof length: {error}")))?;
    if expected_len != settlement_payload.len() {
        return Err(ProtocolError::Crypto(format!(
            "settlement proof input length mismatch: expected {expected_len}, got {}",
            settlement_payload.len()
        )));
    }
    for entry in all_orders {
        if entry.order.batch_id != witness.batch_id {
            return Err(ProtocolError::Crypto(
                "auction order batch_id does not match settlement batch_id".into(),
            ));
        }
        if entry.order.expiry_epoch != witness.batch_epoch {
            return Err(ProtocolError::Crypto(
                "auction order expiry_epoch does not match settlement batch_epoch".into(),
            ));
        }
        let recomputed_order_commitment = entry.order.commitment()?;
        if recomputed_order_commitment != entry.order_commitment {
            return Err(ProtocolError::Crypto(
                "auction order witness commitment does not match order preimage".into(),
            ));
        }
        let funding_note_commitment = entry.funding_note.commitment()?;
        if funding_note_commitment != entry.order.funding_note_ref {
            return Err(ProtocolError::Crypto(
                "auction order funding note does not match funding_note_ref".into(),
            ));
        }
        let public_key = felt_from_hex_str(&entry.funding_note.spend_authority)?;
        let signature_r = felt_from_hex_str(&entry.funding_authorization.signature_r)?;
        let signature_s = felt_from_hex_str(&entry.funding_authorization.signature_s)?;
        let message = felt_from_hex_str(&entry.order_commitment.0)?;
        if !verify(&public_key, &message, &signature_r, &signature_s).map_err(|err| {
            ProtocolError::Crypto(format!("auction order authorization verify failed: {err}"))
        })? {
            return Err(ProtocolError::Crypto(
                "auction order authorization signature does not match note spend authority".into(),
            ));
        }
    }
    for matched in &witness.matched_orders {
        if !all_orders
            .iter()
            .any(|entry| entry.order_commitment == matched.order_commitment)
        {
            return Err(ProtocolError::Crypto(
                "matched order is not present in full auction order set".into(),
            ));
        }
    }

    let maker_curve_commitments = all_orders
        .iter()
        .map(|entry| encode_order_maker_curve_commitment(&entry.order))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let maker_curve_point_counts = all_orders
        .iter()
        .map(|entry| {
            encode_u64(
                entry
                    .order
                    .maker_curve
                    .as_ref()
                    .map(|curve| curve.points.len())
                    .unwrap_or(0) as u64,
            )
        })
        .collect::<Vec<_>>();
    let maker_curve_prices = all_orders
        .iter()
        .flat_map(|entry| {
            entry
                .order
                .maker_curve
                .as_ref()
                .into_iter()
                .flat_map(|curve| curve.points.iter().map(|point| encode_u128(point.price)))
        })
        .collect::<Vec<_>>();
    let maker_curve_base_amounts = all_orders
        .iter()
        .flat_map(|entry| {
            entry
                .order
                .maker_curve
                .as_ref()
                .into_iter()
                .flat_map(|curve| {
                    curve
                        .points
                        .iter()
                        .map(|point| encode_u128(point.base_amount))
                })
        })
        .collect::<Vec<_>>();
    let allocation_fill_amounts = all_orders
        .iter()
        .map(|entry| {
            let mut matched_count = 0_u64;
            let mut filled_amount = 0_u128;
            for matched in &witness.matched_orders {
                if matched.order_commitment == entry.order_commitment {
                    matched_count += 1;
                    filled_amount = matched.filled_amount;
                }
            }
            if matched_count > 1 {
                return Err(ProtocolError::Crypto(
                    "matched order appears more than once in settlement witness".into(),
                ));
            }
            Ok(encode_u128(filled_amount))
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;

    let mut payload = vec![encode_u64(AUCTION_STATEMENT_TYPE_TAG)];
    push_span(&mut payload, settlement_payload);
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| entry.order_commitment.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_order_side(&entry.order.side))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_order_type(&entry.order.order_type))
            .collect::<Vec<_>>(),
    );
    push_span(&mut payload, &maker_curve_commitments);
    push_span(&mut payload, &maker_curve_point_counts);
    push_span(&mut payload, &maker_curve_prices);
    push_span(&mut payload, &maker_curve_base_amounts);
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u128(entry.order.limit_price))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u128(entry.order.amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u128(entry.order.min_fill))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_time_in_force(&entry.order.time_in_force))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u64(entry.order.expiry_epoch))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u64(entry.order.order_nonce))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_order_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u64(entry.order.parent_child_index))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_secret_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_cancel_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_authorization_secret))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| {
                if entry.order.auditor_view_allowed {
                    "0x1".into()
                } else {
                    "0x0".into()
                }
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| entry.order.funding_note_ref.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| {
                entry
                    .funding_note
                    .commitment()
                    .map(|commitment| commitment.0)
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_asset_id(&entry.funding_note.asset_id.0))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u128(entry.funding_note.amount))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_owner_public_key(&entry.funding_note.owner_public_key))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_note.spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_note.withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| entry.funding_note.blinding.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_u64(entry.funding_note.nonce))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| entry.funding_note.metadata_commitment.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_authorization.signature_r))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_authorization.signature_s))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| entry.order.funding_nullifier.0.clone())
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| encode_owner_public_key(&entry.order.recipient_owner_public_key))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.recipient_spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.recipient_withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.recipient_residual_withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(&mut payload, &allocation_fill_amounts);

    let mut serialized = vec![encode_usize(payload.len())];
    serialized.extend(payload);
    Ok(serialized)
}

fn encode_order_side(side: &OrderSide) -> String {
    match side {
        OrderSide::Buy => "0x0".into(),
        OrderSide::Sell => "0x1".into(),
    }
}

fn encode_order_type(order_type: &OrderType) -> String {
    match order_type {
        OrderType::LimitBatch => "0x0".into(),
        OrderType::MakerCurve => "0x1".into(),
    }
}

fn encode_order_maker_curve_commitment(order: &OrderIntent) -> Result<String, ProtocolError> {
    match (&order.order_type, order.maker_curve.as_ref()) {
        (OrderType::MakerCurve, Some(curve)) => curve.commitment(),
        (OrderType::MakerCurve, None) => Err(ProtocolError::Crypto(
            "maker curve order missing curve points".into(),
        )),
        (_, Some(_)) => Err(ProtocolError::Crypto(
            "non-maker-curve order carries curve points".into(),
        )),
        _ => Ok("0x0".into()),
    }
}

fn encode_maker_curve_commitment(witness: &MatchedOrderWitness) -> Result<String, ProtocolError> {
    match (&witness.order_type, witness.maker_curve.as_ref()) {
        (OrderType::MakerCurve, Some(curve)) => curve.commitment(),
        (OrderType::MakerCurve, None) => Err(ProtocolError::Crypto(
            "maker curve witness is missing curve points".into(),
        )),
        (_, Some(_)) => Err(ProtocolError::Crypto(
            "non-maker-curve witness carries curve points".into(),
        )),
        _ => Ok("0x0".into()),
    }
}

fn encode_time_in_force(time_in_force: &TimeInForce) -> String {
    match time_in_force {
        TimeInForce::CurrentBatchOnly => "0x0".into(),
        TimeInForce::FillOrKill => "0x1".into(),
    }
}

fn encode_asset_id(asset_id: &str) -> String {
    encode_starknet_felt("asset-id", asset_id)
}

fn normalize_batch_order_commitment_root(root: &str) -> Result<String, ProtocolError> {
    normalize_felt_hex(root)
}

fn normalize_encrypted_order_set_commitment(commitment: &str) -> Result<String, ProtocolError> {
    normalize_felt_hex(commitment)
}

fn encode_owner_public_key(owner_public_key: &str) -> String {
    encode_starknet_felt("owner-public-key", owner_public_key)
}

fn split_into_xor_shares(plaintext: &[u8], share_count: usize) -> Vec<Vec<u8>> {
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

fn encrypt_for_private_execution_key(
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
    let aes_key_material =
        derive_private_order_share_key(shared.raw_secret_bytes(), key_id, &ephemeral_public_key)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key_material)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = random_nonce();
    let nonce_hex = hex::encode(nonce);
    let aad = encrypted_blob_aad(PRIVATE_ORDER_SHARE_ALGORITHM_V1, key_id, &nonce_hex);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
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

fn decrypt_encrypted_blob(
    private_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Vec<u8>, ProtocolError> {
    if blob.algorithm != PRIVATE_ORDER_SHARE_ALGORITHM_V1 {
        return Err(ProtocolError::Crypto(format!(
            "unsupported private execution key encryption algorithm {}",
            blob.algorithm
        )));
    }

    let private_key_bytes = hex::decode(private_key_hex)?;
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
    let aes_key_material = derive_private_order_share_key(
        shared.raw_secret_bytes(),
        &blob.key_id,
        &blob.ephemeral_public_key,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key_material)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce = hex::decode(&blob.nonce)?;
    let ciphertext = hex::decode(&blob.ciphertext)?;
    let aad = encrypted_blob_aad(&blob.algorithm, &blob.key_id, &blob.nonce);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
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
    let encoded_point = p256::EncodedPoint::from_bytes(hex::decode(public_key_hex)?)
        .map_err(|err| ProtocolError::Crypto(format!("invalid public key: {err}")))?;
    PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| ProtocolError::Crypto("public key not on curve".into()))
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

fn derive_output_encryption_key(note_recognition_key_hex: &str) -> [u8; 32] {
    tagged_sha256_bytes(
        "zylith/output-encryption",
        note_recognition_key_hex.as_bytes(),
    )
}

fn flatten_settlement_call_arguments(args: &SettlementCallArguments) -> Vec<String> {
    let mut calldata = vec![
        args.batch_id.clone(),
        args.order_commitment_root.clone(),
        args.encrypted_order_set_commitment.clone(),
        args.transcript_commitment.clone(),
        args.proof_artifact_commitment.clone(),
    ];
    calldata.push(args.clearing_price.clone());
    calldata.push(args.matched_order_count.clone());
    calldata.push(args.output_bundle_ref.clone());
    push_span(&mut calldata, &args.consumed_note_commitments);
    push_span(&mut calldata, &args.consumed_nullifiers);
    push_span(&mut calldata, &args.renewal_parent_order_commitments);
    push_span(&mut calldata, &args.renewal_child_nullifiers);
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
        build_auction_serialized_input, build_deposit_note, build_deposit_submission_plan,
        build_order_submission, build_output_note, build_settlement_submission_plan,
        build_settlement_witness, build_stwo_serialized_input, build_withdrawal_submission_plan,
        create_order_ingress_receipt, create_recovery_artifact, decrypt_note_for_owner,
        decrypt_order_bundle, decrypt_order_share, decrypt_recovery_artifact_payload,
        derive_account_id, derive_order_cancellation_secret, derive_order_cancellation_tag,
        encrypt_note_for_owner, private_execution_key_registry_fingerprint,
        proof_artifact_commitment, reconstruct_order_from_shares, renewal_child_nullifier,
        sanitize_order_submission_for_coordinator, settlement_transcript_commitment,
        sign_order_authorization, validate_order_ingress_receipt_for_manifest,
        validate_order_ingress_receipt_for_manifest_with_secrets,
        validate_private_execution_key_registry_pin, verify_order_ingress_receipt,
        verify_order_ingress_receipt_with_secrets, withdrawal_message_hash,
    };
    use crate::{
        AssetId, AuctionOrderWitness, ConsumedInput, DepositIntent, FeeEntry, MatchedOrderWitness,
        Note, NoteCommitment, Nullifier, OrderCommitment, OrderIntent, OrderSide, OutputNoteRecord,
        PairId, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
        PrivateExecutionKeyRegistry, PrivateOrderPayload, ProtocolError, RecoveryArtifactKind,
        RecoverySeed, SettlementTranscript,
        hash::{encode_starknet_felt, ordered_felt_list_commitment},
        nullifier_from_spend_auth_key_felt, spend_auth_key_felt_from_raw_key_hex,
        spend_authority_from_raw_key_hex,
    };

    #[test]
    fn order_submission_roundtrip_recovers_original_intent() {
        let execution_keys = private_execution_keys();
        let registry = PrivateExecutionKeyRegistry {
            keys: execution_keys
                .iter()
                .map(|member| PrivateExecutionKeyPublicConfig {
                    key_id: member.key_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let cancellation_key = "11".repeat(32);
        let submission =
            build_order_submission(&payload, &registry, &cancellation_key).expect("submission");
        let decrypted = decrypt_order_bundle(&submission.order_bundle, &execution_keys)
            .expect("decrypted order");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn order_ingress_receipt_sanitizes_coordinator_submission() {
        let execution_keys = private_execution_keys();
        let registry = PrivateExecutionKeyRegistry {
            keys: execution_keys
                .iter()
                .map(|member| PrivateExecutionKeyPublicConfig {
                    key_id: member.key_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let receipt_secret = "test-order-ingress-receipt-secret";
        let submission =
            build_order_submission(&payload, &registry, &"11".repeat(32)).expect("submission");
        let receipt = create_order_ingress_receipt(
            &submission.order_bundle,
            "test-ingress",
            "zylith-prover",
            receipt_secret,
            123,
        )
        .expect("receipt");
        verify_order_ingress_receipt(&receipt, receipt_secret).expect("receipt verifies");

        let coordinator_submission =
            sanitize_order_submission_for_coordinator(&submission, receipt.clone())
                .expect("sanitized submission");
        assert!(coordinator_submission.order_bundle.shares.is_empty());
        assert!(
            coordinator_submission
                .order_bundle
                .transport_envelope
                .is_none()
        );
        assert_eq!(
            coordinator_submission.order_bundle.ingress_receipt,
            Some(receipt)
        );
        validate_order_ingress_receipt_for_manifest(
            &coordinator_submission.order_bundle,
            receipt_secret,
        )
        .expect("manifest receipt verifies");
        decrypt_order_bundle(&coordinator_submission.order_bundle, &execution_keys)
            .expect_err("coordinator manifest must not be decryptable");
    }

    #[test]
    fn order_ingress_receipt_rotation_accepts_previous_secret() {
        let execution_keys = private_execution_keys();
        let registry = PrivateExecutionKeyRegistry {
            keys: execution_keys
                .iter()
                .map(|member| PrivateExecutionKeyPublicConfig {
                    key_id: member.key_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let submission =
            build_order_submission(&payload, &registry, &"11".repeat(32)).expect("submission");
        let receipt = create_order_ingress_receipt(
            &submission.order_bundle,
            "test-ingress",
            "zylith-prover",
            "previous-secret",
            123,
        )
        .expect("receipt");

        let keyring = vec!["current-secret".to_string(), "previous-secret".to_string()];
        verify_order_ingress_receipt_with_secrets(&receipt, &keyring)
            .expect("previous receipt secret remains valid during rotation");

        let coordinator_submission =
            sanitize_order_submission_for_coordinator(&submission, receipt)
                .expect("sanitized submission");
        validate_order_ingress_receipt_for_manifest_with_secrets(
            &coordinator_submission.order_bundle,
            &keyring,
        )
        .expect("manifest validates against keyring");
    }

    #[test]
    fn private_execution_key_registry_pin_rejects_unpinned_keyset() {
        let execution_keys = private_execution_keys();
        let registry = PrivateExecutionKeyRegistry {
            keys: execution_keys
                .iter()
                .map(|member| PrivateExecutionKeyPublicConfig {
                    key_id: member.key_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let fingerprint =
            private_execution_key_registry_fingerprint(&registry).expect("registry fingerprint");
        validate_private_execution_key_registry_pin(&registry, &fingerprint)
            .expect("expected registry pin matches");

        let mut rotated = registry.clone();
        rotated.keys[0].key_id = "unexpected-key".into();
        validate_private_execution_key_registry_pin(&rotated, &fingerprint)
            .expect_err("changed registry must not satisfy old pin");
    }

    #[test]
    fn private_execution_share_metadata_is_authenticated() {
        let execution_keys = private_execution_keys();
        let registry = PrivateExecutionKeyRegistry {
            keys: execution_keys
                .iter()
                .map(|member| PrivateExecutionKeyPublicConfig {
                    key_id: member.key_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let submission =
            build_order_submission(&payload, &registry, &"11".repeat(32)).expect("submission");
        let mut tampered_bundle = submission.order_bundle;
        tampered_bundle.shares[0].encrypted_share.key_id = "different-key".into();

        let error = decrypt_order_share(&tampered_bundle, &execution_keys[0])
            .expect_err("share metadata tampering should fail");
        assert!(matches!(error, ProtocolError::Crypto(message) if message.contains("decrypt")));
    }

    #[test]
    fn private_order_share_reconstruction_recovers_original_intent() {
        let execution_keys = private_execution_keys();
        let registry = PrivateExecutionKeyRegistry {
            keys: execution_keys
                .iter()
                .map(|member| PrivateExecutionKeyPublicConfig {
                    key_id: member.key_id.clone(),
                    public_key: member.public_key.clone(),
                })
                .collect(),
        };
        let payload = sample_private_order();
        let cancellation_key = "11".repeat(32);
        let submission =
            build_order_submission(&payload, &registry, &cancellation_key).expect("submission");
        let shares = execution_keys
            .iter()
            .map(|member| decrypt_order_share(&submission.order_bundle, member))
            .collect::<Result<Vec<_>, _>>()
            .expect("decrypted shares");

        let reconstructed = reconstruct_order_from_shares(&submission.order_bundle, &shares)
            .expect("reconstructed");
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn order_cancellation_secret_rejects_short_keys() {
        let payload = sample_private_order();
        let order_commitment = payload.order.commitment().expect("commitment");

        let error = derive_order_cancellation_secret("abcd", &order_commitment)
            .expect_err("short key rejected");

        assert!(matches!(error, ProtocolError::Crypto(message) if message.contains("32 bytes")));
    }

    #[test]
    fn order_cancellation_hashes_match_client_vectors() {
        let order_commitment = crate::OrderCommitment("0xabc".into());
        let secret =
            derive_order_cancellation_secret(&"11".repeat(32), &order_commitment).expect("secret");

        assert_eq!(
            secret,
            "5aa58d5e4e85ecdf61415cd22a0041cbf4c48523074870856ed6489f93ddd0c9"
        );
        assert_eq!(
            derive_order_cancellation_tag(&secret),
            "b1bea75869f771826c0ffac4adf83d3d38dca48b4fb653c7c27c7555afbd895c"
        );
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
            &order.recipient_withdraw_authority,
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
    fn recovery_artifact_metadata_is_authenticated() {
        let seed = RecoverySeed([9_u8; 32]);
        let mut artifact = create_recovery_artifact(
            &seed,
            RecoveryArtifactKind::Snapshot,
            3,
            12345,
            &serde_json::json!({"trackedOrders": ["abc"]}),
        )
        .expect("artifact");

        artifact.sequence = 4;

        let error = decrypt_recovery_artifact_payload(&seed, &artifact)
            .expect_err("metadata tampering should fail");
        assert!(matches!(error, ProtocolError::Crypto(message) if message.contains("decrypt")));
    }

    #[test]
    fn deposit_note_and_plan_are_deterministic() {
        let intent = DepositIntent {
            asset_id: AssetId("USDC".into()),
            amount: 1_500,
            deposit_nonce: 9,
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: sample_spend_authority(),
            recipient_withdraw_authority: "0x1234".into(),
        };

        let note_a = build_deposit_note(&intent).expect("note a");
        let note_b = build_deposit_note(&intent).expect("note b");
        assert_eq!(note_a, note_b);

        let plan = build_deposit_submission_plan(&intent, "0xabc", "0xdef", "0x456").expect("plan");
        assert_eq!(plan.approval_call.contract_address, "0xdef");
        assert_eq!(plan.approval_call.entrypoint, "approve");
        assert_eq!(plan.approval_call.calldata.len(), 3);
        assert_eq!(plan.starknet_call.contract_address, "0xabc");
        assert_eq!(plan.starknet_call.entrypoint, "execute_actions");
        assert_eq!(plan.starknet_call.calldata.len(), 5);
        assert_eq!(plan.starknet_calls.len(), 2);
        assert_eq!(plan.note_commitment, note_a.commitment().unwrap());
    }

    #[test]
    fn withdrawal_plan_normalizes_note_commitment_and_recipient() {
        let plan = build_withdrawal_submission_plan(
            "abc",
            "456",
            "def",
            "0x123",
            "0x534e5f5345504f4c4941",
        )
        .expect("plan");

        assert_eq!(plan.starknet_call.contract_address, "0x123");
        assert_eq!(plan.starknet_call.entrypoint, "withdraw_to_l2");
        assert_eq!(plan.starknet_call.calldata.len(), 4);
        assert_eq!(plan.starknet_call.calldata[0], "0xabc");
        assert_eq!(plan.starknet_call.calldata[3], "0xdef");
        assert_eq!(plan.note_commitment.0, "0xabc");
        assert_ne!(plan.encoded_args.withdraw_authorization_r, "0x0");
        assert_ne!(plan.encoded_args.withdraw_authorization_s, "0x0");
        assert_eq!(plan.encoded_args.recipient, "0xdef");
    }

    #[test]
    fn withdrawal_authorization_hash_is_chain_and_adapter_bound() {
        let base = withdrawal_message_hash("0xabc", "0xdef", "0x123", "0x534e5f5345504f4c4941")
            .expect("base hash");
        let other_adapter =
            withdrawal_message_hash("0xabc", "0xdef", "0x124", "0x534e5f5345504f4c4941")
                .expect("adapter-bound hash");
        let other_chain = withdrawal_message_hash("0xabc", "0xdef", "0x123", "0x534e5f4d41494e")
            .expect("chain-bound hash");

        assert_ne!(base, other_adapter);
        assert_ne!(base, other_chain);
    }

    #[test]
    fn settlement_submission_plan_flattens_proof_facts_call_arguments() {
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 145,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-1".into()),
                filled_amount: 500,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: NoteCommitment("0x123".into()),
                nullifier: Nullifier("0x456".into()),
            }],
            renewal_child_uses: vec![],
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
        assert_eq!(
            plan.settlement_call.entrypoint,
            "submit_settlement_with_proof_facts"
        );
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
    fn settlement_submission_plan_targets_native_proof_facts_entrypoint() {
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 145,
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![],
            output_ciphertext_bundle_ref: "bundle-1".into(),
        };

        let proof_commitment =
            proof_artifact_commitment("proof-sha", "public-inputs-sha").expect("proof");
        let plan = build_settlement_submission_plan(&transcript, "0x123", &proof_commitment)
            .expect("plan");

        assert_eq!(
            plan.settlement_call.entrypoint,
            "submit_settlement_with_proof_facts"
        );
        assert_eq!(
            plan.settlement_call.calldata[5],
            plan.encoded_args.clearing_price
        );
    }

    #[test]
    fn settlement_transcript_commitment_matches_cairo_contract_formula() {
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-strk-usdc-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 300,
            matched_orders: vec![
                crate::MatchedOrder {
                    order_commitment: crate::OrderCommitment(
                        "0x4b292dd88ea26e4bb36a2b96aa3a5ab8989528e1cc8820ed601b593d652e6e3".into(),
                    ),
                    filled_amount: 100,
                },
                crate::MatchedOrder {
                    order_commitment: crate::OrderCommitment(
                        "0x29ce97d838b12ca71cb08896fd7a17507c1349a3306180167c22787005dca0d".into(),
                    ),
                    filled_amount: 100,
                },
            ],
            consumed_inputs: vec![
                ConsumedInput {
                    note_commitment: NoteCommitment(
                        "0x2ac19e1535f0c09faf01e2fc6553af0805e4c729aef2b334170eacfe9acde37".into(),
                    ),
                    nullifier: Nullifier(
                        "0x7dbd3c7c2fe8baa75ef2bc40b202170de6302e979147b0891c85153286ad4d5".into(),
                    ),
                },
                ConsumedInput {
                    note_commitment: NoteCommitment(
                        "0x7a72976550f4e23619ace1ea4dd5d1a9ab69f2e1eed70ddf29f850d26cfe02f".into(),
                    ),
                    nullifier: Nullifier(
                        "0x44802cf244cbe3834896c577766d307936fbc62646e9d6b135b42987a38a3c1".into(),
                    ),
                },
            ],
            renewal_child_uses: vec![],
            fees: vec![FeeEntry {
                asset_id: AssetId("USDC".into()),
                amount: 30,
                recipient: "zylith-protocol-fee".into(),
            }],
            output_notes: vec![
                OutputNoteRecord {
                    note_commitment: NoteCommitment(
                        "0x78bebb5dd3299517a9eb30c046dad25e9cc638ecc86982392ee5a4a6f7a7418".into(),
                    ),
                    asset_id: AssetId("USDC".into()),
                    amount: 29970,
                    withdraw_authority: "0x2065".into(),
                },
                OutputNoteRecord {
                    note_commitment: NoteCommitment(
                        "0x4d8df0f876f2b996b107dec093de913dbca4e46adf95416dff638cc5c30b567".into(),
                    ),
                    asset_id: AssetId("STRK".into()),
                    amount: 100,
                    withdraw_authority: "0x1001".into(),
                },
            ],
            output_ciphertext_bundle_ref:
                "a9bfa0d37d7a84cc26c1fec3e7dd0e00d463a93f886e6e62ada07470b1a4ea4a".into(),
        };

        assert_eq!(
            settlement_transcript_commitment(&transcript).expect("transcript commitment"),
            "0x34a5b48431c05875b3303511e0d0cc03d02e97c46391029fb5d22c6877af19f"
        );
    }

    #[test]
    fn renewal_child_nullifier_hash_is_parent_and_index_bound() {
        let child_1 = renewal_child_nullifier("0x1234", 1, "0x777").expect("child nullifier");
        let child_2 = renewal_child_nullifier("0x1234", 2, "0x777").expect("child nullifier");
        let other_parent = renewal_child_nullifier("0x1235", 1, "0x777").expect("child nullifier");
        let other_secret = renewal_child_nullifier("0x1234", 1, "0x778").expect("child nullifier");

        assert_ne!(child_1, child_2);
        assert_ne!(child_1, other_parent);
        assert_ne!(child_1, other_secret);
        assert!(renewal_child_nullifier("0x0", 1, "0x777").is_err());
        assert!(renewal_child_nullifier("0x1234", 0, "0x777").is_err());
        assert!(renewal_child_nullifier("0x1234", 1, "0x0").is_err());
    }

    #[test]
    fn settlement_witness_wraps_plan_and_transcript_material() {
        let funding_note = sample_note("STRK", 700, 2);
        let output_note = sample_note("ETH", 700, 3);
        let funding_nullifier = sample_nullifier(&funding_note);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-2".into()),
            pair_id: PairId("STRK/ETH".into()),
            batch_epoch: 9,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 200,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-2".into()),
                filled_amount: 700,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: funding_nullifier.clone(),
            }],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("ETH".into()),
                amount: 700,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-2".into(),
        };

        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/ETH".into()),
            "0x456",
            AssetId("STRK".into()),
            AssetId("ETH".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-2".into()),
                funding_note,
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier,
                funding_authorization: sample_authorization_unchecked(),
                side: OrderSide::Sell,
                order_type: crate::OrderType::LimitBatch,
                maker_curve: None,
                limit_price: 180,
                order_amount: 700,
                min_fill: 100,
                time_in_force: crate::TimeInForce::CurrentBatchOnly,
                expiry_epoch: 9,
                order_nonce: 11,
                parent_order_commitment: "0x0".into(),
                parent_child_index: 0,
                parent_secret_commitment: "0x0".into(),
                parent_cancel_authority: "0x0".into(),
                parent_authorization_secret: "0x0".into(),
                auditor_view_allowed: false,
                recipient_owner_public_key: "ab".repeat(32),
                recipient_spend_authority: sample_spend_authority(),
                recipient_withdraw_authority: "0xbbb".into(),
                recipient_residual_withdraw_authority: "0xbbc".into(),
                filled_amount: 700,
                output_note,
                residual_note: None,
            }],
        )
        .expect("witness");
        assert_eq!(witness.batch_id.0, "batch-2");
        assert_eq!(witness.pair_id.0, "STRK/ETH");
        assert_eq!(witness.auction_verifier_address, "0x456");
        assert_eq!(witness.clearing_price, 200);
        assert_eq!(witness.base_asset_id.0, "STRK");
        assert_eq!(witness.quote_asset_id.0, "ETH");
        assert_eq!(witness.consumed_inputs.len(), 1);
        assert_eq!(witness.output_notes.len(), 1);
        assert_eq!(witness.matched_order_witnesses.len(), 1);
        assert_eq!(witness.output_ciphertext_bundle_ref, "bundle-2");
    }

    #[test]
    fn stwo_serialized_input_includes_expected_sections() {
        let funding_note = sample_note("USDC", 111 * 400, 4);
        let output_note = sample_note("STRK", 104, 5);
        let funding_nullifier = sample_nullifier(&funding_note);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-3".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 12,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 321,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-3".into()),
                filled_amount: 111,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: funding_nullifier.clone(),
            }],
            renewal_child_uses: vec![],
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
                funding_nullifier,
                funding_authorization: sample_authorization_unchecked(),
                side: OrderSide::Buy,
                order_type: crate::OrderType::LimitBatch,
                maker_curve: None,
                limit_price: 400,
                order_amount: 111,
                min_fill: 10,
                time_in_force: crate::TimeInForce::CurrentBatchOnly,
                expiry_epoch: 12,
                order_nonce: 21,
                parent_order_commitment: "0x0".into(),
                parent_child_index: 0,
                parent_secret_commitment: "0x0".into(),
                parent_cancel_authority: "0x0".into(),
                parent_authorization_secret: "0x0".into(),
                auditor_view_allowed: false,
                recipient_owner_public_key: "ab".repeat(32),
                recipient_spend_authority: sample_spend_authority(),
                recipient_withdraw_authority: "0xccc".into(),
                recipient_residual_withdraw_authority: "0xccd".into(),
                filled_amount: 111,
                output_note,
                residual_note: None,
            }],
        )
        .expect("witness");
        let serialized = build_stwo_serialized_input(&witness).expect("serialized input");

        assert_eq!(serialized[0], format!("0x{:x}", serialized.len() - 1));
        assert_eq!(serialized[1], "0x1");
        assert_eq!(serialized[16], "0x141");
        assert_eq!(serialized[17], "0x1");
        assert!(!serialized.is_empty());
    }

    #[test]
    fn stwo_serialized_input_rejects_mismatched_witness_count() {
        let output_note = sample_note("STRK", 104, 5);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-mismatched-witnesses".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 321,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-mismatched-witness".into()),
                filled_amount: 111,
            }],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("STRK".into()),
                amount: 104,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-ref-mismatch".into(),
        };
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![],
        )
        .expect("witness");

        let error = build_stwo_serialized_input(&witness).expect_err("mismatch rejected");
        assert!(
            matches!(error, ProtocolError::Crypto(message) if message.contains("matched order count"))
        );
    }

    #[test]
    fn stwo_serialized_input_uses_consistent_asset_and_owner_encodings() {
        let owner_public_key = "ab".repeat(32);
        let funding_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 111 * 400,
            owner_public_key: owner_public_key.clone(),
            spend_authority: sample_spend_authority(),
            withdraw_authority: "0xddd".into(),
            blinding: "0x104".into(),
            nonce: 4,
            metadata_commitment: "0x204".into(),
        };
        let output_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 104,
            owner_public_key: owner_public_key.clone(),
            spend_authority: sample_spend_authority(),
            withdraw_authority: "0xeee".into(),
            blinding: "0x105".into(),
            nonce: 5,
            metadata_commitment: "0x205".into(),
        };
        let funding_nullifier = sample_nullifier(&funding_note);
        let funding_note_commitment = funding_note
            .commitment()
            .expect("funding note commitment")
            .0;
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-asset-owner".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 22,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 321,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-asset-owner".into()),
                filled_amount: 111,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: funding_nullifier.clone(),
            }],
            renewal_child_uses: vec![],
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
                funding_nullifier,
                funding_authorization: sample_authorization_unchecked(),
                side: OrderSide::Buy,
                order_type: crate::OrderType::LimitBatch,
                maker_curve: None,
                limit_price: 400,
                order_amount: 111,
                min_fill: 10,
                time_in_force: crate::TimeInForce::CurrentBatchOnly,
                expiry_epoch: 22,
                order_nonce: 33,
                parent_order_commitment: "0x0".into(),
                parent_child_index: 0,
                parent_secret_commitment: "0x0".into(),
                parent_cancel_authority: "0x0".into(),
                parent_authorization_secret: "0x0".into(),
                auditor_view_allowed: true,
                recipient_owner_public_key: owner_public_key.clone(),
                recipient_spend_authority: sample_spend_authority(),
                recipient_withdraw_authority: output_note.withdraw_authority.clone(),
                recipient_residual_withdraw_authority: "0xccd".into(),
                filled_amount: 111,
                output_note,
                residual_note: None,
            }],
        )
        .expect("witness");
        let serialized = build_stwo_serialized_input(&witness).expect("serialized input");

        let base_asset = encode_starknet_felt("asset-id", "STRK");
        let quote_asset = encode_starknet_felt("asset-id", "USDC");
        let owner_key = encode_starknet_felt("owner-public-key", &owner_public_key);

        let mut index = 1;
        index += 18;

        let _matched_order_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_fill_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_sides = read_serialized_span(&serialized, &mut index);
        let matched_order_types = read_serialized_span(&serialized, &mut index);
        let matched_maker_curve_commitments = read_serialized_span(&serialized, &mut index);
        let matched_maker_curve_point_counts = read_serialized_span(&serialized, &mut index);
        let matched_maker_curve_prices = read_serialized_span(&serialized, &mut index);
        let matched_maker_curve_base_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_limit_prices = read_serialized_span(&serialized, &mut index);
        let _matched_order_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_min_fills = read_serialized_span(&serialized, &mut index);
        let matched_time_in_force = read_serialized_span(&serialized, &mut index);
        let matched_expiry_epochs = read_serialized_span(&serialized, &mut index);
        let matched_order_nonces = read_serialized_span(&serialized, &mut index);
        let matched_parent_order_commitments = read_serialized_span(&serialized, &mut index);
        let matched_parent_child_indexes = read_serialized_span(&serialized, &mut index);
        let matched_parent_secret_commitments = read_serialized_span(&serialized, &mut index);
        let matched_parent_cancel_authorities = read_serialized_span(&serialized, &mut index);
        let matched_parent_authorization_secrets = read_serialized_span(&serialized, &mut index);
        let matched_auditor_flags = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_refs = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_commitments = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_amounts = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_blindings = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let matched_funding_authorization_rs = read_serialized_span(&serialized, &mut index);
        let matched_funding_authorization_ss = read_serialized_span(&serialized, &mut index);
        let _matched_funding_nullifiers = read_serialized_span(&serialized, &mut index);
        let matched_recipient_owner_keys = read_serialized_span(&serialized, &mut index);
        let matched_recipient_spend_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_recipient_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_recipient_residual_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_output_note_commitments = read_serialized_span(&serialized, &mut index);
        let matched_output_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_amounts = read_serialized_span(&serialized, &mut index);
        let matched_output_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let matched_output_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_output_note_blindings = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_output_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let matched_residual_note_flags = read_serialized_span(&serialized, &mut index);
        let _matched_residual_note_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_residual_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _matched_residual_note_amounts = read_serialized_span(&serialized, &mut index);
        let matched_residual_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let matched_residual_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let matched_residual_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let matched_residual_note_blindings = read_serialized_span(&serialized, &mut index);
        let matched_residual_note_nonces = read_serialized_span(&serialized, &mut index);
        let matched_residual_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let _consumed_note_commitments = read_serialized_span(&serialized, &mut index);
        let _consumed_nullifiers = read_serialized_span(&serialized, &mut index);
        let renewal_parent_order_commitments = read_serialized_span(&serialized, &mut index);
        let renewal_child_nullifiers = read_serialized_span(&serialized, &mut index);
        let _output_note_commitments = read_serialized_span(&serialized, &mut index);
        let output_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _output_note_amounts = read_serialized_span(&serialized, &mut index);
        let _output_note_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let fee_asset_ids = read_serialized_span(&serialized, &mut index);

        assert_eq!(serialized[14], base_asset);
        assert_eq!(serialized[15], quote_asset);
        assert_eq!(matched_order_types, vec!["0x0".to_string()]);
        assert_eq!(matched_maker_curve_commitments, vec!["0x0".to_string()]);
        assert_eq!(matched_maker_curve_point_counts, vec!["0x0".to_string()]);
        assert!(matched_maker_curve_prices.is_empty());
        assert!(matched_maker_curve_base_amounts.is_empty());
        assert_eq!(matched_time_in_force, vec!["0x0".to_string()]);
        assert_eq!(matched_expiry_epochs, vec!["0x16".to_string()]);
        assert_eq!(matched_order_nonces, vec!["0x21".to_string()]);
        assert_eq!(matched_parent_order_commitments, vec!["0x0".to_string()]);
        assert_eq!(matched_parent_child_indexes, vec!["0x0".to_string()]);
        assert_eq!(matched_parent_secret_commitments, vec!["0x0".to_string()]);
        assert_eq!(matched_parent_cancel_authorities, vec!["0x0".to_string()]);
        assert_eq!(
            matched_parent_authorization_secrets,
            vec!["0x0".to_string()]
        );
        assert_eq!(matched_auditor_flags, vec!["0x1".to_string()]);
        assert_eq!(matched_funding_note_refs, vec![funding_note_commitment]);
        assert_eq!(matched_funding_note_asset_ids, vec![quote_asset.clone()]);
        assert_eq!(matched_output_note_asset_ids, vec![base_asset.clone()]);
        assert_eq!(output_note_asset_ids, vec![base_asset.clone()]);
        assert_eq!(fee_asset_ids, vec![base_asset]);
        assert_eq!(matched_funding_note_owner_keys, vec![owner_key.clone()]);
        assert_eq!(
            matched_funding_note_spend_authorities,
            vec![sample_spend_authority()]
        );
        assert_eq!(
            matched_funding_authorization_rs,
            vec![sample_authorization_unchecked().signature_r]
        );
        assert_eq!(
            matched_funding_authorization_ss,
            vec![sample_authorization_unchecked().signature_s]
        );
        assert_eq!(matched_recipient_owner_keys, vec![owner_key.clone()]);
        assert_eq!(
            matched_recipient_spend_authorities,
            vec![sample_spend_authority()]
        );
        assert_eq!(matched_output_note_owner_keys, vec![owner_key]);
        assert_eq!(
            matched_output_note_spend_authorities,
            vec![sample_spend_authority()]
        );
        assert_eq!(matched_residual_note_flags, vec!["0x0".to_string()]);
        assert!(renewal_parent_order_commitments.is_empty());
        assert!(renewal_child_nullifiers.is_empty());
        assert_eq!(matched_residual_note_owner_keys, vec!["0x0".to_string()]);
        assert_eq!(
            matched_residual_note_spend_authorities,
            vec!["0x0".to_string()]
        );
        assert_eq!(
            matched_residual_note_withdraw_authorities,
            vec!["0x0".to_string()]
        );
        assert_eq!(matched_residual_note_blindings, vec!["0x0".to_string()]);
        assert_eq!(matched_residual_note_nonces, vec!["0x0".to_string()]);
        assert_eq!(
            matched_residual_note_metadata_commitments,
            vec!["0x0".to_string()]
        );
    }

    #[test]
    fn auction_serialized_input_binds_full_order_preimages_and_allocations() {
        let private_order = sample_private_order();
        let order_commitment = private_order.order.commitment().expect("order commitment");
        let funding_note_commitment = private_order
            .funding_note
            .commitment()
            .expect("funding note commitment");
        let order_root = ordered_felt_list_commitment(
            "zylith/batch-order-root",
            std::slice::from_ref(&order_commitment.0),
        )
        .expect("order root");
        let output_note = sample_note("STRK", 997, 8);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-auction-bind".into()),
            pair_id: private_order.order.pair_id.clone(),
            batch_epoch: private_order.order.expiry_epoch,
            order_commitment_root: order_root,
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 145,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: order_commitment.clone(),
                filled_amount: 1000,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note_commitment.clone(),
                nullifier: private_order.order.funding_nullifier.clone(),
            }],
            renewal_child_uses: vec![],
            fees: vec![FeeEntry {
                asset_id: AssetId("STRK".into()),
                amount: 3,
                recipient: "zylith-protocol-fees".into(),
            }],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("STRK".into()),
                amount: 997,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-auction-bind".into(),
        };
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: order_commitment.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_note_ref: funding_note_commitment.clone(),
                funding_nullifier: private_order.order.funding_nullifier.clone(),
                funding_authorization: private_order.funding_authorization.clone(),
                side: private_order.order.side.clone(),
                order_type: private_order.order.order_type.clone(),
                maker_curve: private_order.order.maker_curve.clone(),
                limit_price: private_order.order.limit_price,
                order_amount: private_order.order.amount,
                min_fill: private_order.order.min_fill,
                time_in_force: private_order.order.time_in_force.clone(),
                expiry_epoch: private_order.order.expiry_epoch,
                order_nonce: private_order.order.order_nonce,
                parent_order_commitment: private_order.order.parent_order_commitment.clone(),
                parent_child_index: private_order.order.parent_child_index,
                parent_secret_commitment: private_order.order.parent_secret_commitment.clone(),
                parent_cancel_authority: private_order.order.parent_cancel_authority.clone(),
                parent_authorization_secret: private_order
                    .order
                    .parent_authorization_secret
                    .clone(),
                auditor_view_allowed: private_order.order.auditor_view_allowed,
                recipient_owner_public_key: private_order.order.recipient_owner_public_key.clone(),
                recipient_spend_authority: private_order.order.recipient_spend_authority.clone(),
                recipient_withdraw_authority: private_order
                    .order
                    .recipient_withdraw_authority
                    .clone(),
                recipient_residual_withdraw_authority: private_order
                    .order
                    .recipient_residual_withdraw_authority
                    .clone(),
                filled_amount: 1000,
                output_note,
                residual_note: None,
            }],
        )
        .expect("witness");
        let serialized = build_auction_serialized_input(
            &witness,
            &[AuctionOrderWitness {
                order_commitment: order_commitment.clone(),
                order: private_order.order.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_authorization: private_order.funding_authorization.clone(),
            }],
        )
        .expect("auction serialized input");

        let mut index = 1;
        assert_eq!(serialized[index], "0x2");
        index += 1;
        let settlement_payload = read_serialized_span(&serialized, &mut index);
        assert_eq!(settlement_payload[0], "0x1");

        let order_commitments = read_serialized_span(&serialized, &mut index);
        let sides = read_serialized_span(&serialized, &mut index);
        let order_types = read_serialized_span(&serialized, &mut index);
        let maker_curve_commitments = read_serialized_span(&serialized, &mut index);
        let maker_curve_point_counts = read_serialized_span(&serialized, &mut index);
        let maker_curve_prices = read_serialized_span(&serialized, &mut index);
        let maker_curve_base_amounts = read_serialized_span(&serialized, &mut index);
        let limit_prices = read_serialized_span(&serialized, &mut index);
        let order_amounts = read_serialized_span(&serialized, &mut index);
        let min_fills = read_serialized_span(&serialized, &mut index);
        let time_in_force = read_serialized_span(&serialized, &mut index);
        let expiry_epochs = read_serialized_span(&serialized, &mut index);
        let order_nonces = read_serialized_span(&serialized, &mut index);
        let parent_order_commitments = read_serialized_span(&serialized, &mut index);
        let parent_child_indexes = read_serialized_span(&serialized, &mut index);
        let parent_secret_commitments = read_serialized_span(&serialized, &mut index);
        let parent_cancel_authorities = read_serialized_span(&serialized, &mut index);
        let parent_authorization_secrets = read_serialized_span(&serialized, &mut index);
        let auditor_flags = read_serialized_span(&serialized, &mut index);
        let funding_note_refs = read_serialized_span(&serialized, &mut index);
        let funding_note_commitments = read_serialized_span(&serialized, &mut index);
        let funding_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let funding_note_amounts = read_serialized_span(&serialized, &mut index);
        let funding_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let funding_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let funding_note_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let funding_note_blindings = read_serialized_span(&serialized, &mut index);
        let funding_note_nonces = read_serialized_span(&serialized, &mut index);
        let funding_note_metadata_commitments = read_serialized_span(&serialized, &mut index);
        let funding_authorization_rs = read_serialized_span(&serialized, &mut index);
        let funding_authorization_ss = read_serialized_span(&serialized, &mut index);
        let funding_nullifiers = read_serialized_span(&serialized, &mut index);
        let recipient_owner_keys = read_serialized_span(&serialized, &mut index);
        let recipient_spend_authorities = read_serialized_span(&serialized, &mut index);
        let recipient_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let recipient_residual_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let allocation_fill_amounts = read_serialized_span(&serialized, &mut index);

        assert_eq!(order_commitments, vec![order_commitment.0]);
        assert_eq!(sides, vec!["0x0".to_string()]);
        assert_eq!(order_types, vec!["0x0".to_string()]);
        assert_eq!(maker_curve_commitments, vec!["0x0".to_string()]);
        assert_eq!(maker_curve_point_counts, vec!["0x0".to_string()]);
        assert!(maker_curve_prices.is_empty());
        assert!(maker_curve_base_amounts.is_empty());
        assert_eq!(limit_prices, vec!["0x91".to_string()]);
        assert_eq!(order_amounts, vec!["0x3e8".to_string()]);
        assert_eq!(min_fills, vec!["0x64".to_string()]);
        assert_eq!(time_in_force, vec!["0x0".to_string()]);
        assert_eq!(expiry_epochs, vec!["0x2a".to_string()]);
        assert_eq!(order_nonces, vec!["0x7".to_string()]);
        assert_eq!(parent_order_commitments, vec!["0x0".to_string()]);
        assert_eq!(parent_child_indexes, vec!["0x0".to_string()]);
        assert_eq!(parent_secret_commitments, vec!["0x0".to_string()]);
        assert_eq!(parent_cancel_authorities, vec!["0x0".to_string()]);
        assert_eq!(parent_authorization_secrets, vec!["0x0".to_string()]);
        assert_eq!(auditor_flags, vec!["0x0".to_string()]);
        assert_eq!(funding_note_refs, vec![funding_note_commitment.0.clone()]);
        assert_eq!(funding_note_commitments, vec![funding_note_commitment.0]);
        assert_eq!(
            funding_note_asset_ids,
            vec![encode_starknet_felt("asset-id", "USDC")]
        );
        assert_eq!(funding_note_amounts, vec!["0x30d40".to_string()]);
        assert_eq!(
            funding_note_owner_keys,
            vec![encode_starknet_felt("owner-public-key", &"ab".repeat(32))]
        );
        assert_eq!(
            funding_note_spend_authorities,
            vec![sample_spend_authority()]
        );
        assert_eq!(funding_note_withdraw_authorities, vec!["0x123".to_string()]);
        assert_eq!(funding_note_blindings, vec!["0x107".to_string()]);
        assert_eq!(funding_note_nonces, vec!["0x7".to_string()]);
        assert_eq!(funding_note_metadata_commitments, vec!["0x207".to_string()]);
        assert_eq!(
            funding_authorization_rs,
            vec![private_order.funding_authorization.signature_r]
        );
        assert_eq!(
            funding_authorization_ss,
            vec![private_order.funding_authorization.signature_s]
        );
        assert_eq!(
            funding_nullifiers,
            vec![private_order.order.funding_nullifier.0]
        );
        assert_eq!(recipient_owner_keys, funding_note_owner_keys);
        assert_eq!(recipient_spend_authorities, vec![sample_spend_authority()]);
        assert_eq!(recipient_withdraw_authorities, vec!["0xfff".to_string()]);
        assert_eq!(
            recipient_residual_withdraw_authorities,
            vec!["0xffe".to_string()]
        );
        assert_eq!(allocation_fill_amounts, vec!["0x3e8".to_string()]);
    }

    #[test]
    fn auction_serialized_input_rejects_wrong_order_batch_domain() {
        let mut private_order = sample_private_order();
        private_order.order.batch_id = crate::BatchId("batch-wrong-domain".into());
        let order_commitment = private_order.order.commitment().expect("order commitment");
        let funding_note_commitment = private_order
            .funding_note
            .commitment()
            .expect("funding note commitment");
        let order_root = ordered_felt_list_commitment(
            "zylith/batch-order-root",
            std::slice::from_ref(&order_commitment.0),
        )
        .expect("order root");
        let output_note = sample_note("STRK", 997, 8);
        let transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-auction-bind".into()),
            pair_id: private_order.order.pair_id.clone(),
            batch_epoch: private_order.order.expiry_epoch,
            order_commitment_root: order_root,
            encrypted_order_set_commitment: "0x222".into(),
            clearing_price: 145,
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: order_commitment.clone(),
                filled_amount: 1000,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note_commitment.clone(),
                nullifier: private_order.order.funding_nullifier.clone(),
            }],
            renewal_child_uses: vec![],
            fees: vec![FeeEntry {
                asset_id: AssetId("STRK".into()),
                amount: 3,
                recipient: "zylith-protocol-fees".into(),
            }],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("STRK".into()),
                amount: 997,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_ciphertext_bundle_ref: "bundle-auction-bind".into(),
        };
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: order_commitment.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_note_ref: funding_note_commitment,
                funding_nullifier: private_order.order.funding_nullifier.clone(),
                funding_authorization: private_order.funding_authorization.clone(),
                side: private_order.order.side.clone(),
                order_type: private_order.order.order_type.clone(),
                maker_curve: private_order.order.maker_curve.clone(),
                limit_price: private_order.order.limit_price,
                order_amount: private_order.order.amount,
                min_fill: private_order.order.min_fill,
                time_in_force: private_order.order.time_in_force.clone(),
                expiry_epoch: private_order.order.expiry_epoch,
                order_nonce: private_order.order.order_nonce,
                parent_order_commitment: private_order.order.parent_order_commitment.clone(),
                parent_child_index: private_order.order.parent_child_index,
                parent_secret_commitment: private_order.order.parent_secret_commitment.clone(),
                parent_cancel_authority: private_order.order.parent_cancel_authority.clone(),
                parent_authorization_secret: private_order
                    .order
                    .parent_authorization_secret
                    .clone(),
                auditor_view_allowed: private_order.order.auditor_view_allowed,
                recipient_owner_public_key: private_order.order.recipient_owner_public_key.clone(),
                recipient_spend_authority: private_order.order.recipient_spend_authority.clone(),
                recipient_withdraw_authority: private_order
                    .order
                    .recipient_withdraw_authority
                    .clone(),
                recipient_residual_withdraw_authority: private_order
                    .order
                    .recipient_residual_withdraw_authority
                    .clone(),
                filled_amount: 1000,
                output_note,
                residual_note: None,
            }],
        )
        .expect("witness");
        let error = build_auction_serialized_input(
            &witness,
            &[AuctionOrderWitness {
                order_commitment,
                order: private_order.order,
                funding_note: private_order.funding_note,
                funding_authorization: private_order.funding_authorization,
            }],
        )
        .expect_err("wrong order batch domain rejected");

        assert!(matches!(error, ProtocolError::Crypto(message) if message.contains("batch_id")));
    }

    fn sample_order() -> OrderIntent {
        let funding_note = sample_note("USDC", 200_000, 7);
        let funding_nullifier = sample_nullifier(&funding_note);
        OrderIntent {
            pair_id: crate::PairId("STRK/USDC".into()),
            batch_id: crate::BatchId("batch-auction-bind".into()),
            side: OrderSide::Buy,
            order_type: crate::OrderType::LimitBatch,
            maker_curve: None,
            limit_price: 145,
            amount: 1000,
            min_fill: 100,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 7,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier,
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: sample_spend_authority(),
            recipient_withdraw_authority: "0xfff".into(),
            recipient_residual_withdraw_authority: "0xffe".into(),
            auditor_view_allowed: false,
        }
    }

    fn sample_private_order() -> PrivateOrderPayload {
        let funding_note = sample_note("USDC", 200_000, 7);
        let mut order = sample_order();
        order.funding_note_ref = funding_note.commitment().expect("funding note commitment");

        PrivateOrderPayload {
            funding_authorization: sample_authorization_for_order(&order),
            funding_note,
            order,
        }
    }

    fn sample_authorization_for_order(order: &OrderIntent) -> crate::SpendAuthorization {
        let order_commitment = order.commitment().expect("order commitment");
        sample_authorization_for_commitment(&order_commitment)
    }

    fn sample_authorization_for_commitment(
        order_commitment: &OrderCommitment,
    ) -> crate::SpendAuthorization {
        sign_order_authorization(&sample_spend_auth_key(), order_commitment)
            .expect("sample spend authorization")
    }

    fn sample_authorization_unchecked() -> crate::SpendAuthorization {
        crate::SpendAuthorization {
            signature_r: "0x1".into(),
            signature_s: "0x2".into(),
        }
    }

    fn sample_note(asset_id: &str, amount: u128, nonce: u64) -> Note {
        Note {
            asset_id: AssetId(asset_id.into()),
            amount,
            owner_public_key: "ab".repeat(32),
            spend_authority: sample_spend_authority(),
            withdraw_authority: "0x123".into(),
            blinding: format!("0x{:x}", nonce + 0x100),
            nonce,
            metadata_commitment: format!("0x{:x}", nonce + 0x200),
        }
    }

    fn sample_spend_key_hex() -> String {
        "22".repeat(32)
    }

    fn sample_spend_auth_key() -> String {
        spend_auth_key_felt_from_raw_key_hex(&sample_spend_key_hex())
    }

    fn sample_spend_authority() -> String {
        spend_authority_from_raw_key_hex(&sample_spend_key_hex()).expect("spend authority")
    }

    fn sample_nullifier(note: &Note) -> Nullifier {
        nullifier_from_spend_auth_key_felt(
            &note.commitment().expect("note commitment"),
            &sample_spend_auth_key(),
        )
        .expect("sample nullifier")
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

    fn private_execution_keys() -> Vec<PrivateExecutionKeyPrivateConfig> {
        (0..3)
            .map(|index| {
                let secret = SecretKey::random(&mut OsRng);
                let public = secret.public_key();
                PrivateExecutionKeyPrivateConfig {
                    key_id: format!("execution-key-{index}"),
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
