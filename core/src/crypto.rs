use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload, consts::U12},
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
use starknet_crypto::{
    Felt, poseidon_hash, poseidon_permute_comp, rfc6979_generate_k, sign, verify,
};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ApprovalCallArguments, AssetId, AuctionOrderWitness, BatchId, BatchSummary, ConsumedInput,
    DecryptedOrderShare, DepositCallArguments, DepositIntent, DepositSubmissionPlan, EncryptedBlob,
    EncryptedRecoveryPayload, FundingRailKind, MatchedOrderWitness, Note, NoteCommitment,
    NoteMembershipKind, NoteMembershipWitness, Nullifier, NullifierHistoryBatch,
    NullifierSparseUpdateWitness, OrderCommitment, OrderIngressReceipt, OrderIntent, OrderShare,
    OrderShareBundle, OrderSide, OrderSubmission, OrderType, OutputNoteMerkleProof,
    OutputNoteRecord, OutputRecoveryRecord, OwnedOutputNotePayload, PairId,
    PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyRegistry, PrivateOrderPayload,
    ProtocolError, RecoveryArtifact, RecoveryArtifactKind, RecoverySeed, RenewalChildUse,
    RenewalParentCancelCallArguments, RenewalParentCancelPlanRequest,
    RenewalParentCancelSubmissionPlan, RenewalStateHistoryBatch, RootOnlySettlementCommitments,
    SettlementCallArguments, SettlementOutputWithdrawalCallArguments,
    SettlementOutputWithdrawalSubmissionPlan, SettlementSubmissionPlan, SettlementTranscript,
    SettlementWitness, StarknetCall, TimeInForce, WithdrawalCallArguments,
    WithdrawalSubmissionPlan, derive_user_keys,
    hash::{
        domain_felt, domain_felt_hex, encode_starknet_felt, felt_from_hex_str, felt_hex,
        normalize_felt_hex, poseidon_chain_hex, tagged_commitment_sha256, tagged_field_hex,
        tagged_sha256_bytes, tagged_sha256_hex,
    },
    types::{
        MAX_ORDER_FUNDING_INPUTS, NOTE_RECOGNITION_ALGORITHM, OUTPUT_NOTE_PLAINTEXT_PADDED_LEN,
        OUTPUT_RECOVERY_FIELD_COUNT, OUTPUT_RECOVERY_PROOF_SLOTS, RENEWAL_PARENT_CANCEL_DOMAIN_HEX,
        funding_input_set_commitment, funding_nullifier_set_commitment, nullifier_from_note_secret,
        output_recovery_bundle_root, output_recovery_record_commitment, renewal_child_nullifier,
        renewal_parent_cancel_marker, spend_auth_key_felt_from_raw_key_hex,
        spend_authority_from_raw_key_hex, withdraw_authority_from_raw_key_hex,
    },
};

const NATIVE_SETTLEMENT_MESSAGE_DOMAIN_HEX: &str =
    "0x0326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a";
const PUBLIC_SETTLEMENT_DOMAIN_HEX: &str =
    "0x0283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205";
const ROOT_ONLY_STATE_TRANSITION_DOMAIN_HEX: &str =
    "0x01f14f0555b0b80fd6af9553623a021c472d8c930dfcb5b204b35b26f0d2b1b2";
const OUTPUT_NOTE_LEAF_DOMAIN_HEX: &str =
    "0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3";
const OUTPUT_NOTE_NODE_DOMAIN_HEX: &str =
    "0x03c6998f476a618431be1c1764a6724f13c0739be395bab4c1217bc0a65b2ee7";
const EMPTY_OUTPUT_NOTE_ROOT_DOMAIN_HEX: &str =
    "0x0279c22958925b34e81138c0d651a82cdbfd3287fa3de370e021a7201b4ce30b";
const OUTPUT_RECOVERY_STREAM_DOMAIN_HEX: &str = "0x7a796c6974685f6f75745f73747265616d5f7631";
const OUTPUT_RECOVERY_AUTH_DOMAIN_HEX: &str = "0x7a796c6974685f6f75745f617574685f7631";
const OUTPUT_RECOVERY_TAG_DOMAIN_HEX: &str = "0x7a796c6974685f6f75745f7461675f7631";
const DEPOSIT_NOTE_ROOT_DOMAIN_HEX: &str =
    "0x7a796c6974685f6465706f7369745f6e6f74655f726f6f745f7631";
const NULLIFIER_SPARSE_LEAF_DOMAIN_HEX: &str =
    "0x03fd7c748b95292c230aa528dc391912cd4557ad3e157e94ab06b22af433f967";
const NULLIFIER_SPARSE_NODE_DOMAIN_HEX: &str =
    "0x02de7e98b8f1ba580329d7cfcf51a36f6eb4f8611cae6f82b34e116bb9c2588c";
pub const NULLIFIER_SPARSE_TREE_DEPTH: usize = 64;
const NULLIFIER_KEY_LOW_BITS: usize = NULLIFIER_SPARSE_TREE_DEPTH;
const NULLIFIER_KEY_HIGH_BITS: usize = 124;
const NULLIFIER_KEY_HIGH_BOUND: u128 = 1_u128 << NULLIFIER_KEY_HIGH_BITS;
pub const RENEWAL_SPARSE_TREE_DEPTH: usize = 128;
const SETTLEMENT_PROOF_MESSAGE_DOMAIN_HEX: &str = "0x7a796c6974685f736574746c655f7631";
const RENEWAL_PROOF_MESSAGE_DOMAIN_HEX: &str = "0x7a796c6974685f72656e65775f7631";
const ADMISSION_PROOF_MESSAGE_DOMAIN_HEX: &str = "0x7a796c6974685f61646d69745f7631";
const AUCTION_RESULT_MESSAGE_DOMAIN_HEX: &str = "0x7a796c6974685f6175637265735f7631";
const ADMISSION_ROOT_DOMAIN_HEX: &str = "0x7a796c6974685f61646d69745f726f6f745f7631";
const ADMISSION_LEAF_DOMAIN_HEX: &str = "0x7a796c6974685f61646d69745f6c6561665f7631";
const PRIVATE_ORDER_SHARE_ALGORITHM_V1: &str = "ecdh-p256+hkdf-sha256+aes-256-gcm/private-order-v1";
const PRIVATE_ORDER_SHARE_HKDF_SALT: &[u8] = b"zylith/private-order-share-key-separation-v1";
const OUTPUT_NOTE_HKDF_SALT: &[u8] = b"zylith/output-note-key-separation-v2";
const RECOVERY_ARTIFACT_ALGORITHM_V2: &str = "aes-256-gcm/recovery-v2";
const WALLET_HKDF_SALT: &[u8] = b"zylith/wallet-key-separation-v2";
const ORDER_INGRESS_RECEIPT_VERSION: u32 = 1;

fn aes_nonce_from_slice(bytes: &[u8]) -> Result<Nonce<U12>, ProtocolError> {
    let nonce: [u8; 12] = bytes
        .try_into()
        .map_err(|_| ProtocolError::Crypto("aes-gcm nonce must be 12 bytes".into()))?;
    Ok(nonce.into())
}
const SETTLEMENT_STATEMENT_TYPE_TAG: u64 = 1;
const ADMISSION_STATEMENT_TYPE_TAG: u64 = 3;
const AUCTION_RESULT_STATEMENT_TYPE_TAG: u64 = 4;

type HmacSha256 = Hmac<Sha256>;

pub struct SettlementOutputWithdrawalPlanRequest<'a> {
    pub batch_id: &'a BatchId,
    pub output_note: &'a OutputNoteRecord,
    pub output_proof: &'a OutputNoteMerkleProof,
    pub withdraw_auth_key_felt: &'a str,
    pub recipient: &'a str,
    pub auction_verifier_address: &'a str,
    pub shielded_asset_adapter_address: &'a str,
    pub chain_id: &'a str,
}

pub struct SettlementOutputWithdrawalMessage<'a> {
    pub auction_verifier_address: &'a str,
    pub shielded_asset_adapter_address: &'a str,
    pub chain_id: &'a str,
    pub batch_id: &'a str,
    pub note_commitment: &'a str,
    pub asset_id: &'a str,
    pub amount: &'a str,
    pub recipient: &'a str,
}

#[derive(Clone, Debug)]
pub struct HeartbeatCoverOrder {
    pub order_commitment: OrderCommitment,
    pub payload: PrivateOrderPayload,
}

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
    validate_private_order_spend_authorization(payload)?;

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

    validate_private_order_spend_authorization(&payload)?;

    Ok(payload)
}

fn validate_private_order_spend_authorization(
    payload: &PrivateOrderPayload,
) -> Result<(), ProtocolError> {
    let expected_order_commitment = payload.order.commitment()?;
    let funding_notes = payload.effective_funding_notes();
    if funding_notes.is_empty() || funding_notes.len() > MAX_ORDER_FUNDING_INPUTS {
        return Err(ProtocolError::Crypto("invalid funding input count".into()));
    }
    let first_spend_authority = funding_notes[0].spend_authority.clone();
    let first_owner_public_key = funding_notes[0].owner_public_key.clone();
    let mut commitments = Vec::with_capacity(funding_notes.len());
    let mut nullifiers = Vec::with_capacity(funding_notes.len());
    let mut seen_commitments = BTreeSet::new();
    for note in funding_notes {
        if note.spend_authority != first_spend_authority {
            return Err(ProtocolError::Crypto(
                "multi-note funding inputs must share spend authority".into(),
            ));
        }
        if note.owner_public_key != first_owner_public_key {
            return Err(ProtocolError::Crypto(
                "multi-note funding inputs must share note owner".into(),
            ));
        }
        let commitment = note.commitment()?;
        if !seen_commitments.insert(commitment.0.clone()) {
            return Err(ProtocolError::Crypto(
                "multi-note funding inputs must be unique".into(),
            ));
        }
        nullifiers.push(nullifier_from_note_secret(&commitment, &note.blinding)?);
        commitments.push(commitment);
    }
    let funding_note_commitment = funding_input_set_commitment(&commitments)?;
    if funding_note_commitment != payload.order.funding_note_ref {
        return Err(ProtocolError::Crypto(
            "funding input commitment does not match authorization payload".into(),
        ));
    }
    let funding_nullifier_commitment = funding_nullifier_set_commitment(&nullifiers)?;
    if funding_nullifier_commitment != payload.order.funding_nullifier {
        return Err(ProtocolError::Crypto(
            "funding nullifier commitment does not match authorization payload".into(),
        ));
    }

    let public_key = felt_from_hex_str(&first_spend_authority)?;
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

    Ok(())
}

pub fn heartbeat_cover_order_count(real_order_count: usize) -> usize {
    if real_order_count == 0 {
        4
    } else {
        real_order_count
    }
}

pub fn heartbeat_cover_order_commitments(
    secret: &str,
    batch: &BatchSummary,
    base_asset_id: &AssetId,
    quote_asset_id: &AssetId,
    cover_price: u128,
    real_order_count: usize,
) -> Result<Vec<OrderCommitment>, ProtocolError> {
    build_heartbeat_cover_orders(
        secret,
        batch,
        base_asset_id,
        quote_asset_id,
        cover_price,
        real_order_count,
    )
    .map(|orders| {
        orders
            .into_iter()
            .map(|order| order.order_commitment)
            .collect()
    })
}

pub fn build_heartbeat_cover_orders(
    secret: &str,
    batch: &BatchSummary,
    _base_asset_id: &AssetId,
    quote_asset_id: &AssetId,
    cover_price: u128,
    real_order_count: usize,
) -> Result<Vec<HeartbeatCoverOrder>, ProtocolError> {
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(ProtocolError::Crypto(
            "heartbeat cover secret is not configured".into(),
        ));
    }
    if cover_price == 0 {
        return Err(ProtocolError::Crypto(
            "heartbeat cover price must be positive".into(),
        ));
    }
    let target_count = heartbeat_cover_order_count(real_order_count);
    if real_order_count >= target_count {
        return Ok(Vec::new());
    }

    let mut orders = Vec::with_capacity(target_count - real_order_count);
    for public_index in real_order_count..target_count {
        let spend_key_hex = heartbeat_cover_key_material(secret, batch, public_index, "spend");
        let owner_key_hex = heartbeat_cover_key_material(secret, batch, public_index, "owner");
        let withdraw_key_hex =
            heartbeat_cover_key_material(secret, batch, public_index, "withdraw");
        let residual_withdraw_key_hex =
            heartbeat_cover_key_material(secret, batch, public_index, "residual-withdraw");
        let spend_auth_key_felt = spend_auth_key_felt_from_raw_key_hex(&spend_key_hex);
        let spend_authority = spend_authority_from_raw_key_hex(&spend_key_hex)?;
        let owner_public_key = note_recognition_public_key_from_raw_key_hex(&owner_key_hex)?;
        let withdraw_authority = withdraw_authority_from_raw_key_hex(&withdraw_key_hex)?;
        let residual_withdraw_authority =
            withdraw_authority_from_raw_key_hex(&residual_withdraw_key_hex)?;
        let blinding = heartbeat_cover_felt(secret, batch, public_index, "note-blinding")?;
        let metadata_commitment =
            heartbeat_cover_felt(secret, batch, public_index, "note-metadata")?;
        let nonce = heartbeat_cover_nonce(secret, batch, public_index).saturating_add(1);
        let funding_note = Note {
            asset_id: quote_asset_id.clone(),
            amount: 1,
            owner_public_key,
            spend_authority: spend_authority.clone(),
            withdraw_authority,
            blinding,
            nonce,
            metadata_commitment,
        };
        let funding_note_ref = funding_note.commitment()?;
        let funding_nullifier =
            nullifier_from_note_secret(&funding_note_ref, &funding_note.blinding)?;
        let order = OrderIntent {
            pair_id: batch.pair_id.clone(),
            batch_id: batch.batch_id.clone(),
            side: OrderSide::Buy,
            order_type: OrderType::HeartbeatCover,
            maker_curve: None,
            limit_price: cover_price,
            amount: 1,
            min_fill: 1,
            time_in_force: TimeInForce::CurrentBatchOnly,
            expiry_epoch: batch.epoch_id,
            order_nonce: nonce,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref,
            funding_nullifier,
            recipient_owner_public_key: note_recognition_public_key_from_raw_key_hex(
                &heartbeat_cover_key_material(secret, batch, public_index, "recipient-owner"),
            )?,
            recipient_spend_authority: spend_authority_from_raw_key_hex(
                &heartbeat_cover_key_material(secret, batch, public_index, "recipient-spend"),
            )?,
            recipient_withdraw_authority: withdraw_authority_from_raw_key_hex(
                &heartbeat_cover_key_material(secret, batch, public_index, "recipient-withdraw"),
            )?,
            recipient_residual_withdraw_authority: residual_withdraw_authority,
            auditor_view_allowed: false,
        };
        let order_commitment = order.commitment()?;
        let funding_authorization =
            sign_order_authorization(&spend_auth_key_felt, &order_commitment)?;
        orders.push(HeartbeatCoverOrder {
            order_commitment,
            payload: PrivateOrderPayload {
                order,
                funding_note,
                funding_notes: Vec::new(),
                funding_authorization,
            },
        });
    }
    Ok(orders)
}

fn heartbeat_cover_key_material(
    secret: &str,
    batch: &BatchSummary,
    public_index: usize,
    label: &str,
) -> String {
    hex::encode(tagged_sha256_bytes(
        "zylith/heartbeat-cover/key-v1",
        heartbeat_cover_material(secret, batch, public_index, label).as_bytes(),
    ))
}

fn heartbeat_cover_felt(
    secret: &str,
    batch: &BatchSummary,
    public_index: usize,
    label: &str,
) -> Result<String, ProtocolError> {
    tagged_field_hex(
        "zylith/heartbeat-cover/felt-v1",
        &serde_json::json!({
            "secret": secret,
            "batch_id": batch.batch_id.0,
            "pair_id": batch.pair_id.0,
            "epoch_id": batch.epoch_id,
            "public_index": public_index,
            "label": label,
        }),
    )
}

fn heartbeat_cover_nonce(secret: &str, batch: &BatchSummary, public_index: usize) -> u64 {
    let seed = tagged_sha256_bytes(
        "zylith/heartbeat-cover/nonce-v1",
        heartbeat_cover_material(secret, batch, public_index, "nonce").as_bytes(),
    );
    u64::from_be_bytes(seed[..8].try_into().expect("seed prefix"))
}

fn heartbeat_cover_material(
    secret: &str,
    batch: &BatchSummary,
    public_index: usize,
    label: &str,
) -> String {
    serde_json::json!({
        "secret": secret,
        "batch_id": batch.batch_id.0,
        "pair_id": batch.pair_id.0,
        "epoch_id": batch.epoch_id,
        "public_index": public_index,
        "label": label,
    })
    .to_string()
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
    let metadata_commitment = output_note_metadata_commitment(
        batch_id,
        order_commitment,
        &order.funding_note_ref,
        &order.pair_id,
        &order.recipient_spend_authority,
        &withdraw_authority,
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

pub fn output_note_metadata_commitment(
    batch_id: &str,
    order_commitment: &OrderCommitment,
    funding_note_ref: &NoteCommitment,
    pair_id: &PairId,
    recipient_spend_authority: &str,
    withdraw_authority: &str,
) -> Result<String, ProtocolError> {
    tagged_field_hex(
        "zylith/output-metadata",
        &serde_json::json!({
            "batch_id": batch_id,
            "order_commitment": order_commitment.0,
            "funding_note_ref": funding_note_ref.0,
            "pair_id": pair_id.0,
            "recipient_spend_authority": recipient_spend_authority,
            "withdraw_authority": withdraw_authority,
        }),
    )
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

pub fn build_settlement_output_withdrawal_submission_plan(
    request: SettlementOutputWithdrawalPlanRequest<'_>,
) -> Result<SettlementOutputWithdrawalSubmissionPlan, ProtocolError> {
    let SettlementOutputWithdrawalPlanRequest {
        batch_id,
        output_note,
        output_proof,
        withdraw_auth_key_felt,
        recipient,
        auction_verifier_address,
        shielded_asset_adapter_address,
        chain_id,
    } = request;
    let batch_id_felt = encode_starknet_felt("batch-id", &batch_id.0);
    let note_commitment = normalize_felt_hex(&output_note.note_commitment.0)?;
    let asset_id = encode_starknet_felt("asset-id", &output_note.asset_id.0);
    let amount = encode_u128(output_note.amount);
    let withdraw_authority = normalize_felt_hex(&output_note.withdraw_authority)?;
    let recipient = normalize_felt_hex(recipient)?;
    let auction_verifier_address = normalize_felt_hex(auction_verifier_address)?;
    let shielded_asset_adapter_address = normalize_felt_hex(shielded_asset_adapter_address)?;
    let chain_id = normalize_felt_hex(chain_id)?;
    let merkle_path = output_proof
        .merkle_path
        .iter()
        .map(|entry| normalize_felt_hex(entry))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let merkle_directions = output_proof
        .merkle_directions
        .iter()
        .map(|entry| normalize_felt_hex(entry))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    if merkle_path.len() != merkle_directions.len() {
        return Err(ProtocolError::Crypto(
            "output-note merkle path and direction lengths differ".into(),
        ));
    }

    let message = settlement_output_withdrawal_message_hash(SettlementOutputWithdrawalMessage {
        auction_verifier_address: &auction_verifier_address,
        shielded_asset_adapter_address: &shielded_asset_adapter_address,
        chain_id: &chain_id,
        batch_id: &batch_id_felt,
        note_commitment: &note_commitment,
        asset_id: &asset_id,
        amount: &amount,
        recipient: &recipient,
    })?;
    let private_key = felt_from_hex_str(withdraw_auth_key_felt)?;
    let message = felt_from_hex_str(&message)?;
    let k = rfc6979_generate_k(&message, &private_key, None);
    let signature = sign(&private_key, &message, &k).map_err(|err| {
        ProtocolError::Crypto(format!(
            "settlement output withdrawal signing failed: {err}"
        ))
    })?;

    let encoded_args = SettlementOutputWithdrawalCallArguments {
        batch_id: batch_id_felt,
        note_commitment: note_commitment.clone(),
        asset_id,
        amount,
        withdraw_authority,
        merkle_path,
        merkle_directions,
        withdraw_authorization_r: felt_hex(&signature.r),
        withdraw_authorization_s: felt_hex(&signature.s),
        recipient,
    };
    let calldata = flatten_settlement_output_withdrawal_call_arguments(&encoded_args);

    Ok(SettlementOutputWithdrawalSubmissionPlan {
        funding_rail: FundingRailKind::StarknetPrivacy,
        batch_id: batch_id.clone(),
        note_commitment: NoteCommitment(note_commitment),
        starknet_call: StarknetCall {
            contract_address: auction_verifier_address,
            entrypoint: "withdraw_settlement_output_to_l2".into(),
            calldata,
        },
        encoded_args,
    })
}

pub fn build_renewal_parent_cancel_submission_plan(
    request: RenewalParentCancelPlanRequest,
) -> Result<RenewalParentCancelSubmissionPlan, ProtocolError> {
    let chain_id = normalize_felt_hex(&request.chain_id)?;
    let auction_verifier_address = normalize_felt_hex(&request.auction_verifier_address)?;
    let cancel_authority = normalize_felt_hex(&request.parent_cancel_authority)?;
    let renewal_cancel_auth_key = normalize_felt_hex(&request.renewal_cancel_auth_key)?;
    let cancel_marker =
        renewal_parent_cancel_marker(&request.parent_secret_commitment, &cancel_authority)?;

    let mut entries = BTreeMap::<Vec<bool>, Felt>::new();
    for entry in &request.prior_renewal_entries {
        insert_renewal_sparse_entry(&mut entries, entry)?;
    }
    let witness = renewal_sparse_witness_for_entry(&entries, &cancel_marker)?;

    let message = renewal_parent_cancel_marker_message_hash(
        &chain_id,
        &auction_verifier_address,
        &cancel_marker,
    )?;
    let private_key = felt_from_hex_str(&renewal_cancel_auth_key)?;
    let message = felt_from_hex_str(&message)?;
    let k = rfc6979_generate_k(&message, &private_key, None);
    let signature = sign(&private_key, &message, &k).map_err(|err| {
        ProtocolError::Crypto(format!("renewal parent cancellation signing failed: {err}"))
    })?;

    let encoded_args = RenewalParentCancelCallArguments {
        cancel_marker,
        cancel_authority,
        sparse_key_low: witness.key_low,
        sparse_key_high: witness.key_high,
        merkle_path: witness.merkle_path,
        merkle_directions: witness.merkle_directions,
        signature_r: felt_hex(&signature.r),
        signature_s: felt_hex(&signature.s),
    };
    let calldata = flatten_renewal_parent_cancel_call_arguments(&encoded_args);

    Ok(RenewalParentCancelSubmissionPlan {
        starknet_call: StarknetCall {
            contract_address: auction_verifier_address,
            entrypoint: "cancel_renewal_parent_marker".into(),
            calldata,
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
        felt_from_hex_str("0x008c9bee4df79ca43188c02c21699eee1b86520e8bbe0291c437af32d37ff0e4")?,
        &[
            chain_id,
            shielded_asset_adapter_address,
            note_commitment,
            recipient,
        ],
    ))
}

pub fn renewal_parent_cancel_marker_message_hash(
    chain_id: &str,
    auction_verifier_address: &str,
    cancel_marker: &str,
) -> Result<String, ProtocolError> {
    Ok(poseidon_chain_hex(
        felt_from_hex_str(RENEWAL_PARENT_CANCEL_DOMAIN_HEX)?,
        &[
            felt_from_hex_str(chain_id)?,
            felt_from_hex_str(auction_verifier_address)?,
            felt_from_hex_str(cancel_marker)?,
        ],
    ))
}

pub fn settlement_output_withdrawal_message_hash(
    message: SettlementOutputWithdrawalMessage<'_>,
) -> Result<String, ProtocolError> {
    let SettlementOutputWithdrawalMessage {
        auction_verifier_address,
        shielded_asset_adapter_address,
        chain_id,
        batch_id,
        note_commitment,
        asset_id,
        amount,
        recipient,
    } = message;
    Ok(poseidon_chain_hex(
        felt_from_hex_str("0x031ff5b95d48149e26b5a946562ff5ea925eb8b3ea09d3b389b209b672a37b6e")?,
        &[
            felt_from_hex_str(chain_id)?,
            felt_from_hex_str(auction_verifier_address)?,
            felt_from_hex_str(shielded_asset_adapter_address)?,
            felt_from_hex_str(batch_id)?,
            felt_from_hex_str(note_commitment)?,
            felt_from_hex_str(asset_id)?,
            felt_from_hex_str(amount)?,
            felt_from_hex_str(recipient)?,
        ],
    ))
}

pub fn encrypt_note_for_owner(
    batch_id: &str,
    output_index: usize,
    note: &Note,
    recipient_owner_public_key: &str,
) -> Result<EncryptedBlob, ProtocolError> {
    let output_note = OutputNoteRecord {
        note_commitment: note.commitment()?,
        asset_id: note.asset_id.clone(),
        amount: note.amount,
        withdraw_authority: note.withdraw_authority.clone(),
    };
    encrypt_output_note_for_owner(
        batch_id,
        output_index,
        note,
        &output_note,
        &OutputNoteMerkleProof {
            merkle_path: Vec::new(),
            merkle_directions: Vec::new(),
        },
        recipient_owner_public_key,
    )
}

pub fn encrypt_output_note_for_owner(
    batch_id: &str,
    output_index: usize,
    note: &Note,
    output_note: &OutputNoteRecord,
    output_proof: &OutputNoteMerkleProof,
    recipient_owner_public_key: &str,
) -> Result<EncryptedBlob, ProtocolError> {
    let recipient_public_key = parse_note_recognition_public_key(recipient_owner_public_key)?;
    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public_key = hex::encode(
        ephemeral_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let shared_secret = diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_public_key.as_affine(),
    );
    let mut key_id = [0_u8; 32];
    OsRng.fill_bytes(&mut key_id);
    let key_id_hex = hex::encode(key_id);
    let key_bytes = derive_output_note_key(
        shared_secret.raw_secret_bytes(),
        &key_id_hex,
        &ephemeral_public_key,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let note_commitment = note.commitment()?;
    if output_note.note_commitment != note_commitment {
        return Err(ProtocolError::Crypto(
            "output note payload commitment does not match note".into(),
        ));
    }
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_nonce_from_slice(&nonce_bytes)?;
    let nonce_hex = hex::encode(nonce_bytes);
    let plaintext = padded_output_note_plaintext(&OwnedOutputNotePayload {
        version: 1,
        batch_id: BatchId(batch_id.into()),
        output_index: output_index as u64,
        note: note.clone(),
        output_note: output_note.clone(),
        output_proof: output_proof.clone(),
    })?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: output_note_blob_aad(
                    NOTE_RECOGNITION_ALGORITHM,
                    &key_id_hex,
                    &ephemeral_public_key,
                    &nonce_hex,
                )
                .as_ref(),
            },
        )
        .map_err(|err| ProtocolError::Crypto(format!("note encryption failed: {err}")))?;

    Ok(EncryptedBlob {
        algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
        key_id: key_id_hex,
        ephemeral_public_key,
        nonce: nonce_hex,
        ciphertext: hex::encode(ciphertext),
        recovery: Some(encrypt_output_recovery_record(
            batch_id,
            output_index,
            note,
            output_note,
            output_proof,
        )?),
    })
}

pub fn decrypt_note_for_owner(
    note_recognition_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Option<Note>, ProtocolError> {
    Ok(decrypt_output_note_for_owner(note_recognition_key_hex, blob)?.map(|payload| payload.note))
}

pub fn decrypt_output_note_for_owner(
    note_recognition_key_hex: &str,
    blob: &EncryptedBlob,
) -> Result<Option<OwnedOutputNotePayload>, ProtocolError> {
    if blob.algorithm != NOTE_RECOGNITION_ALGORITHM {
        return Ok(None);
    }

    let recipient_secret = note_recognition_secret_from_raw_key_hex(note_recognition_key_hex)?;
    let recipient_public_key =
        note_recognition_public_key_from_raw_key_hex(note_recognition_key_hex)?;
    let ephemeral_public_key = parse_public_key(&blob.ephemeral_public_key)?;
    let shared_secret = diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );
    let key_bytes = derive_output_note_key(
        shared_secret.raw_secret_bytes(),
        &blob.key_id,
        &blob.ephemeral_public_key,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|err| ProtocolError::Crypto(format!("aes key init failed: {err}")))?;
    let nonce_bytes = hex::decode(&blob.nonce)?;
    let nonce = aes_nonce_from_slice(&nonce_bytes)?;
    let ciphertext = hex::decode(&blob.ciphertext)?;
    let aad = output_note_blob_aad(
        &blob.algorithm,
        &blob.key_id,
        &blob.ephemeral_public_key,
        &blob.nonce,
    );
    let plaintext = match cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext.as_ref(),
            aad: aad.as_ref(),
        },
    ) {
        Ok(plaintext) => plaintext,
        Err(_) => return Ok(None),
    };

    let payload = parse_padded_output_note_plaintext(&plaintext)?;
    let normalized_secret = note_recognition_key_hex
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    if payload.note.owner_public_key != recipient_public_key
        && payload.note.owner_public_key != normalized_secret
    {
        return Ok(None);
    }

    Ok(Some(payload))
}

pub fn encrypt_output_recovery_record(
    batch_id: &str,
    output_index: usize,
    note: &Note,
    output_note: &OutputNoteRecord,
    output_proof: &OutputNoteMerkleProof,
) -> Result<OutputRecoveryRecord, ProtocolError> {
    let recovery_key = normalize_felt_hex(&note.spend_authority)?;
    let batch_id_felt = encode_starknet_felt("batch-id", batch_id);
    let plaintext_fields =
        output_recovery_plaintext_fields(batch_id, output_index, note, output_note, output_proof)?;
    let key_tag = output_recovery_key_tag(&recovery_key, &batch_id_felt, output_index)?;
    let auth_tag = output_recovery_auth_tag(&recovery_key, &plaintext_fields)?;
    let mut stream_state =
        output_recovery_stream_seed(&recovery_key, &batch_id_felt, output_index)?;
    let ciphertext_fields = plaintext_fields
        .iter()
        .enumerate()
        .map(|(field_index, plaintext)| {
            let stream = output_recovery_next_stream_field(&mut stream_state, field_index)?;
            let ciphertext = felt_from_hex_str(plaintext)? + stream;
            Ok(felt_hex(&ciphertext))
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let mut record = OutputRecoveryRecord {
        key_tag,
        ciphertext_fields,
        auth_tag,
        commitment: "0x0".into(),
    };
    record.commitment = output_recovery_record_commitment(&record)?;
    Ok(record)
}

pub fn decrypt_output_recovery_record(
    spend_authority: &str,
    owner_public_key: &str,
    batch_id: &BatchId,
    output_index: usize,
    record: &OutputRecoveryRecord,
) -> Result<Option<OwnedOutputNotePayload>, ProtocolError> {
    if record.ciphertext_fields.len() != OUTPUT_RECOVERY_FIELD_COUNT {
        return Ok(None);
    }
    let recovery_key = normalize_felt_hex(spend_authority)?;
    let batch_id_felt = encode_starknet_felt("batch-id", &batch_id.0);
    if felt_from_hex_str(&record.key_tag)?
        != felt_from_hex_str(&output_recovery_key_tag(
            &recovery_key,
            &batch_id_felt,
            output_index,
        )?)?
    {
        return Ok(None);
    }
    let mut stream_state =
        output_recovery_stream_seed(&recovery_key, &batch_id_felt, output_index)?;
    let plaintext_fields = record
        .ciphertext_fields
        .iter()
        .enumerate()
        .map(|(field_index, ciphertext)| {
            let stream = output_recovery_next_stream_field(&mut stream_state, field_index)?;
            let plaintext = felt_from_hex_str(ciphertext)? - stream;
            Ok(felt_hex(&plaintext))
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    if felt_from_hex_str(&record.auth_tag)?
        != felt_from_hex_str(&output_recovery_auth_tag(&recovery_key, &plaintext_fields)?)?
    {
        return Ok(None);
    }
    output_recovery_payload_from_plaintext(owner_public_key, batch_id, &plaintext_fields)
}

fn output_recovery_plaintext_fields(
    batch_id: &str,
    output_index: usize,
    note: &Note,
    output_note: &OutputNoteRecord,
    output_proof: &OutputNoteMerkleProof,
) -> Result<Vec<String>, ProtocolError> {
    if output_proof.merkle_path.len() != output_proof.merkle_directions.len() {
        return Err(ProtocolError::Crypto(
            "output recovery proof path and directions length mismatch".into(),
        ));
    }
    if output_proof.merkle_path.len() > OUTPUT_RECOVERY_PROOF_SLOTS {
        return Err(ProtocolError::Crypto(format!(
            "output recovery proof exceeds {OUTPUT_RECOVERY_PROOF_SLOTS} slots"
        )));
    }
    let note_commitment = note.commitment()?;
    if output_note.note_commitment != note_commitment {
        return Err(ProtocolError::Crypto(
            "output recovery note commitment mismatch".into(),
        ));
    }
    let mut fields = vec![
        "0x1".into(),
        encode_starknet_felt("batch-id", batch_id),
        encode_usize(output_index),
        normalize_felt_hex(&note_commitment.0)?,
        encode_asset_id(&note.asset_id.0),
        encode_u128(note.amount),
        encode_owner_public_key(&note.owner_public_key),
        normalize_felt_hex(&note.spend_authority)?,
        normalize_felt_hex(&note.withdraw_authority)?,
        normalize_felt_hex(&note.blinding)?,
        encode_u64(note.nonce),
        normalize_felt_hex(&note.metadata_commitment)?,
        encode_usize(output_proof.merkle_path.len()),
    ];
    for index in 0..OUTPUT_RECOVERY_PROOF_SLOTS {
        fields.push(
            output_proof
                .merkle_path
                .get(index)
                .map(|value| normalize_felt_hex(value))
                .transpose()?
                .unwrap_or_else(|| "0x0".into()),
        );
    }
    for index in 0..OUTPUT_RECOVERY_PROOF_SLOTS {
        fields.push(
            output_proof
                .merkle_directions
                .get(index)
                .map(|value| normalize_felt_hex(value))
                .transpose()?
                .unwrap_or_else(|| "0x0".into()),
        );
    }
    debug_assert_eq!(fields.len(), OUTPUT_RECOVERY_FIELD_COUNT);
    Ok(fields)
}

fn output_recovery_payload_from_plaintext(
    owner_public_key: &str,
    batch_id: &BatchId,
    fields: &[String],
) -> Result<Option<OwnedOutputNotePayload>, ProtocolError> {
    if fields.len() != OUTPUT_RECOVERY_FIELD_COUNT || felt_from_hex_str(&fields[0])? != Felt::ONE {
        return Ok(None);
    }
    if felt_from_hex_str(&fields[1])?
        != felt_from_hex_str(&encode_starknet_felt("batch-id", &batch_id.0))?
    {
        return Ok(None);
    }
    if felt_from_hex_str(&fields[6])?
        != felt_from_hex_str(&encode_owner_public_key(owner_public_key))?
    {
        return Ok(None);
    }
    let output_index = felt_to_u64(&fields[2])? as usize;
    let note_commitment = NoteCommitment(normalize_felt_hex(&fields[3])?);
    let asset_id = decode_known_asset_id(&fields[4])?;
    let amount = felt_to_u128(&fields[5])?;
    let proof_len = felt_to_u64(&fields[12])? as usize;
    if proof_len > OUTPUT_RECOVERY_PROOF_SLOTS {
        return Ok(None);
    }
    let output_proof = OutputNoteMerkleProof {
        merkle_path: fields[13..13 + proof_len]
            .iter()
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        merkle_directions: fields
            [13 + OUTPUT_RECOVERY_PROOF_SLOTS..13 + OUTPUT_RECOVERY_PROOF_SLOTS + proof_len]
            .iter()
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    };
    let note = Note {
        asset_id: asset_id.clone(),
        amount,
        owner_public_key: owner_public_key.into(),
        spend_authority: normalize_felt_hex(&fields[7])?,
        withdraw_authority: normalize_felt_hex(&fields[8])?,
        blinding: normalize_felt_hex(&fields[9])?,
        nonce: felt_to_u64(&fields[10])?,
        metadata_commitment: normalize_felt_hex(&fields[11])?,
    };
    if note.commitment()? != note_commitment {
        return Ok(None);
    }
    let output_note = OutputNoteRecord {
        note_commitment,
        asset_id,
        amount,
        withdraw_authority: note.withdraw_authority.clone(),
    };
    Ok(Some(OwnedOutputNotePayload {
        version: 1,
        batch_id: batch_id.clone(),
        output_index: output_index as u64,
        note,
        output_note,
        output_proof,
    }))
}

fn output_recovery_key_tag(
    recovery_key: &str,
    batch_id_felt: &str,
    output_index: usize,
) -> Result<String, ProtocolError> {
    poseidon_chain_hex_from_hexes(
        OUTPUT_RECOVERY_TAG_DOMAIN_HEX,
        &[recovery_key, batch_id_felt, &encode_usize(output_index)],
    )
}

fn output_recovery_auth_tag(
    recovery_key: &str,
    plaintext_fields: &[String],
) -> Result<String, ProtocolError> {
    let mut values = Vec::with_capacity(plaintext_fields.len() + 1);
    values.push(recovery_key);
    values.extend(plaintext_fields.iter().map(String::as_str));
    poseidon_chain_hex_from_hexes(OUTPUT_RECOVERY_AUTH_DOMAIN_HEX, &values)
}

fn output_recovery_stream_seed(
    recovery_key: &str,
    batch_id_felt: &str,
    output_index: usize,
) -> Result<Felt, ProtocolError> {
    let value = poseidon_chain_hex_from_hexes(
        OUTPUT_RECOVERY_STREAM_DOMAIN_HEX,
        &[recovery_key, batch_id_felt, &encode_usize(output_index)],
    )?;
    felt_from_hex_str(&value)
}

fn output_recovery_next_stream_field(
    stream_state: &mut Felt,
    field_index: usize,
) -> Result<Felt, ProtocolError> {
    *stream_state = poseidon_hash(
        *stream_state,
        felt_from_hex_str(&encode_usize(field_index))?,
    );
    Ok(*stream_state)
}

fn poseidon_chain_hex_from_hexes(seed_hex: &str, inputs: &[&str]) -> Result<String, ProtocolError> {
    let seed = felt_from_hex_str(seed_hex)?;
    let values = inputs
        .iter()
        .map(|value| felt_from_hex_str(&normalize_felt_hex(value)?))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    Ok(poseidon_chain_hex(seed, &values))
}

fn felt_to_u64(value: &str) -> Result<u64, ProtocolError> {
    let felt = felt_from_hex_str(value)?;
    let bytes = felt.to_bytes_be();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::Crypto(format!(
            "felt {value} does not fit u64"
        )));
    }
    Ok(u64::from_be_bytes(bytes[24..32].try_into().map_err(
        |_| ProtocolError::Crypto("felt u64 slice failed".into()),
    )?))
}

fn felt_to_u128(value: &str) -> Result<u128, ProtocolError> {
    let felt = felt_from_hex_str(value)?;
    let bytes = felt.to_bytes_be();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::Crypto(format!(
            "felt {value} does not fit u128"
        )));
    }
    Ok(u128::from_be_bytes(bytes[16..32].try_into().map_err(
        |_| ProtocolError::Crypto("felt u128 slice failed".into()),
    )?))
}

fn decode_known_asset_id(encoded_asset_id: &str) -> Result<AssetId, ProtocolError> {
    let encoded = felt_from_hex_str(&normalize_felt_hex(encoded_asset_id)?)?;
    for symbol in ["STRK", "ETH", "USDC", "strkBTC", "WBTC", "BTC", "ZUSD"] {
        if felt_from_hex_str(&encode_asset_id(symbol))? == encoded {
            return Ok(AssetId(symbol.into()));
        }
    }
    Err(ProtocolError::Crypto(format!(
        "unknown proof-bound recovery asset id {encoded_asset_id}"
    )))
}

fn encode_output_bundle_ref(output_bundle_ref: &str) -> Result<String, ProtocolError> {
    match normalize_felt_hex(output_bundle_ref) {
        Ok(felt) => Ok(felt),
        Err(_) => Ok(encode_starknet_felt("output-bundle-ref", output_bundle_ref)),
    }
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
            &aes_nonce_from_slice(&nonce)?,
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
    let roots = root_only_settlement_commitments(transcript)?;
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
    state = poseidon_hash(state, Felt::from(transcript.price_base_scale));
    state = poseidon_hash(state, Felt::from(transcript.taker_fee_bps));
    state = poseidon_hash(state, Felt::from(transcript.maker_fee_bps));
    state = poseidon_hash(
        state,
        felt_from_hex_str(&encode_fee_recipient(&transcript.protocol_fee_recipient))?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&encode_output_bundle_ref(
            &transcript.output_ciphertext_bundle_ref,
        )?)?,
    );
    for root in [
        roots.prior_note_root,
        roots.prior_nullifier_root,
        roots.prior_renewal_root,
        roots.prior_fee_root,
        roots.consumed_note_root,
        roots.consumed_nullifier_root,
        roots.renewal_child_root,
        roots.output_note_root,
        roots.fee_root,
        roots.new_note_root,
        roots.new_nullifier_root,
        roots.new_renewal_root,
        roots.new_fee_root,
    ] {
        state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(&root)?)?);
    }

    Ok(felt_hex(&state))
}

pub fn root_only_settlement_commitments(
    transcript: &SettlementTranscript,
) -> Result<RootOnlySettlementCommitments, ProtocolError> {
    for fee in &transcript.fees {
        if fee.recipient != transcript.protocol_fee_recipient {
            return Err(ProtocolError::InvalidSettlementProof(
                "fee recipient does not match settlement protocol fee recipient".into(),
            ));
        }
    }
    let prior_note_root = normalize_felt_hex(&transcript.prior_note_root)?;
    let prior_nullifier_root = normalize_felt_hex(&transcript.prior_nullifier_root)?;
    let prior_renewal_root = normalize_felt_hex(&transcript.prior_renewal_root)?;
    let prior_fee_root = normalize_felt_hex(&transcript.prior_fee_root)?;
    let consumed_note_root = settlement_root(
        "zylith/root/consumed-notes-v1",
        transcript
            .consumed_inputs
            .iter()
            .map(|input| Ok(vec![normalize_felt_hex(&input.note_commitment.0)?])),
    )?;
    let consumed_nullifier_root = settlement_consumed_nullifier_root(&transcript.consumed_inputs)?;
    let renewal_child_root = settlement_root(
        "zylith/root/renewal-children-v1",
        transcript
            .renewal_child_uses
            .iter()
            .map(|renewal| Ok(vec![normalize_felt_hex(&renewal.child_nullifier)?])),
    )?;
    let output_note_root = output_note_merkle_root(
        &transcript.output_notes,
        &transcript.output_ciphertext_bundle_ref,
    )?;
    let fee_root = settlement_root(
        "zylith/root/fees-v1",
        transcript.fees.iter().map(|fee| {
            Ok(vec![
                encode_starknet_felt("asset-id", &fee.asset_id.0),
                encode_starknet_felt("fee-recipient", &fee.recipient),
                encode_u128(fee.amount),
            ])
        }),
    )?;

    let new_note_root = settlement_state_transition_root(&prior_note_root, &output_note_root)?;
    let mut new_nullifier_root = normalize_felt_hex(&transcript.new_nullifier_root)?;
    if transcript.consumed_inputs.is_empty() && new_nullifier_root == "0x0" {
        new_nullifier_root = prior_nullifier_root.clone();
    }
    if !transcript.consumed_inputs.is_empty() && new_nullifier_root == "0x0" {
        return Err(ProtocolError::Crypto(
            "settlement transcript missing sparse new_nullifier_root".into(),
        ));
    }
    let mut new_renewal_root = normalize_felt_hex(&transcript.new_renewal_root)?;
    if transcript.renewal_child_uses.is_empty() && new_renewal_root == "0x0" {
        new_renewal_root = prior_renewal_root.clone();
    }
    if !transcript.renewal_child_uses.is_empty() && new_renewal_root == "0x0" {
        return Err(ProtocolError::Crypto(
            "settlement transcript missing sparse new_renewal_root".into(),
        ));
    }
    let new_fee_root = settlement_state_transition_root(&prior_fee_root, &fee_root)?;

    Ok(RootOnlySettlementCommitments {
        prior_note_root,
        prior_nullifier_root,
        prior_renewal_root,
        prior_fee_root,
        consumed_note_root,
        consumed_nullifier_root,
        renewal_child_root,
        output_note_root,
        fee_root,
        new_note_root,
        new_nullifier_root,
        new_renewal_root,
        new_fee_root,
    })
}

fn settlement_consumed_nullifier_root(
    consumed_inputs: &[ConsumedInput],
) -> Result<String, ProtocolError> {
    settlement_root(
        "zylith/root/consumed-nullifiers-v1",
        consumed_inputs
            .iter()
            .map(|input| Ok(vec![normalize_felt_hex(&input.nullifier.0)?])),
    )
}

fn settlement_root<I>(domain: &str, rows: I) -> Result<String, ProtocolError>
where
    I: IntoIterator<Item = Result<Vec<String>, ProtocolError>>,
{
    let mut state = domain_felt(domain);
    let mut count = 0_u64;
    for row in rows {
        count += 1;
        for value in row? {
            state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(&value)?)?);
        }
    }
    Ok(felt_hex(&poseidon_hash(state, Felt::from(count))))
}

pub fn output_note_merkle_proof(
    outputs: &[OutputNoteRecord],
    note_commitment: &NoteCommitment,
) -> Result<OutputNoteMerkleProof, ProtocolError> {
    let mut target_index = outputs
        .iter()
        .position(|output| output.note_commitment == *note_commitment)
        .ok_or_else(|| {
            ProtocolError::Crypto("output note commitment is not present in output set".into())
        })?;
    let mut level = outputs
        .iter()
        .map(output_note_leaf)
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    if level.is_empty() {
        return Err(ProtocolError::Crypto(
            "cannot build a merkle proof for an empty output set".into(),
        ));
    }

    let mut merkle_path = Vec::new();
    let mut merkle_directions = Vec::new();
    while level.len() > 1 {
        let is_right = target_index % 2 == 1;
        let sibling_index = if is_right {
            target_index - 1
        } else {
            target_index + 1
        };
        let sibling = level.get(sibling_index).copied().unwrap_or(Felt::ZERO);
        merkle_path.push(felt_hex(&sibling));
        merkle_directions.push(if is_right { "0x1".into() } else { "0x0".into() });

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            let left = level[index];
            let right = level.get(index + 1).copied().unwrap_or(Felt::ZERO);
            next.push(output_note_node(left, right)?);
            index += 2;
        }
        level = next;
        target_index /= 2;
    }

    Ok(OutputNoteMerkleProof {
        merkle_path,
        merkle_directions,
    })
}

pub fn verify_output_note_membership(
    output_note: &OutputNoteRecord,
    output_proof: &OutputNoteMerkleProof,
    expected_output_note_root: &str,
) -> Result<(), ProtocolError> {
    if output_proof.merkle_path.len() != output_proof.merkle_directions.len() {
        return Err(ProtocolError::Crypto(
            "output-note merkle path and direction lengths differ".into(),
        ));
    }
    let mut current = output_note_leaf(output_note)?;
    for (sibling, direction) in output_proof
        .merkle_path
        .iter()
        .zip(output_proof.merkle_directions.iter())
    {
        let sibling = felt_from_hex_str(&normalize_felt_hex(sibling)?)?;
        let direction = felt_from_hex_str(&normalize_felt_hex(direction)?)?;
        current = if direction == Felt::ONE {
            output_note_node(sibling, current)?
        } else if direction == Felt::ZERO {
            output_note_node(current, sibling)?
        } else {
            return Err(ProtocolError::Crypto(
                "output-note merkle direction must be 0 or 1".into(),
            ));
        };
    }
    let expected = felt_from_hex_str(&normalize_felt_hex(expected_output_note_root)?)?;
    if current != expected {
        return Err(ProtocolError::Crypto(
            "output-note proof does not match expected output root".into(),
        ));
    }
    Ok(())
}

fn output_note_merkle_root(
    outputs: &[OutputNoteRecord],
    output_bundle_ref: &str,
) -> Result<String, ProtocolError> {
    if outputs.is_empty() {
        let mut state = felt_from_hex_str(EMPTY_OUTPUT_NOTE_ROOT_DOMAIN_HEX)?;
        state = poseidon_hash(
            state,
            felt_from_hex_str(&encode_output_bundle_ref(output_bundle_ref)?)?,
        );
        return Ok(felt_hex(&state));
    }

    let mut level = outputs
        .iter()
        .map(output_note_leaf)
        .collect::<Result<Vec<_>, ProtocolError>>()?;

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            let left = level[index];
            let right = level.get(index + 1).copied().unwrap_or(Felt::ZERO);
            next.push(output_note_node(left, right)?);
            index += 2;
        }
        level = next;
    }

    Ok(felt_hex(&level[0]))
}

fn output_note_leaf(output: &crate::OutputNoteRecord) -> Result<Felt, ProtocolError> {
    let mut state = felt_from_hex_str(OUTPUT_NOTE_LEAF_DOMAIN_HEX)?;
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
    Ok(state)
}

fn output_note_node(left: Felt, right: Felt) -> Result<Felt, ProtocolError> {
    let mut state = felt_from_hex_str(OUTPUT_NOTE_NODE_DOMAIN_HEX)?;
    state = poseidon_hash(state, left);
    Ok(poseidon_hash(state, right))
}

pub fn settlement_state_transition_root(
    prior_root: &str,
    batch_root: &str,
) -> Result<String, ProtocolError> {
    let mut state = felt_from_hex_str(ROOT_ONLY_STATE_TRANSITION_DOMAIN_HEX)?;
    state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(prior_root)?)?);
    state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(batch_root)?)?);
    Ok(felt_hex(&state))
}

pub fn deposit_note_root(note_commitment: &str) -> Result<String, ProtocolError> {
    let mut state = felt_from_hex_str(DEPOSIT_NOTE_ROOT_DOMAIN_HEX)?;
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(note_commitment)?)?,
    );
    Ok(felt_hex(&poseidon_hash(state, Felt::ONE)))
}

pub fn settlement_note_root_after_deposit_chain(
    note_commitments: &[String],
) -> Result<String, ProtocolError> {
    let mut root = "0x0".to_string();
    for note_commitment in note_commitments {
        let batch_root = deposit_note_root(note_commitment)?;
        root = settlement_state_transition_root(&root, &batch_root)?;
    }
    Ok(root)
}

pub fn settlement_nullifier_root_after_history(
    history: &[NullifierHistoryBatch],
) -> Result<String, ProtocolError> {
    let mut entries = BTreeMap::<Vec<bool>, Felt>::new();
    for batch in history {
        if batch.repeat_count == 0 {
            return Err(ProtocolError::Crypto(
                "nullifier history repeat_count must be non-zero".into(),
            ));
        }
        if !batch.nullifiers.is_empty() && batch.repeat_count != 1 {
            return Err(ProtocolError::Crypto(
                "non-empty nullifier history batches cannot be repeated".into(),
            ));
        }
        for nullifier in &batch.nullifiers {
            insert_nullifier_sparse_entry(&mut entries, &normalize_felt_hex(&nullifier.0)?)?;
        }
    }
    sparse_nullifier_root(&entries)
}

fn nullifier_sparse_leaf(nullifier: Felt) -> Result<Felt, ProtocolError> {
    let leaf_domain = felt_from_hex_str(NULLIFIER_SPARSE_LEAF_DOMAIN_HEX)?;
    Ok(poseidon_hash(leaf_domain, nullifier))
}

fn nullifier_sparse_node(left: Felt, right: Felt) -> Result<Felt, ProtocolError> {
    if left == Felt::ZERO {
        return Ok(right);
    }
    if right == Felt::ZERO {
        return Ok(left);
    }
    let node_domain = felt_from_hex_str(NULLIFIER_SPARSE_NODE_DOMAIN_HEX)?;
    let mut state = [node_domain, left, right];
    poseidon_permute_comp(&mut state);
    Ok(state[0])
}

fn nullifier_key_low_high(nullifier: &str) -> Result<(u128, u128), ProtocolError> {
    let normalized = normalize_felt_hex(nullifier)?;
    let hex = normalized.trim_start_matches("0x");
    let low_start = hex.len().saturating_sub(32);
    let low_hex = &hex[low_start..];
    let high_hex = &hex[..low_start];
    let low = if low_hex.is_empty() {
        0
    } else {
        u128::from_str_radix(low_hex, 16).map_err(|err| {
            ProtocolError::Crypto(format!("invalid nullifier low limb {low_hex}: {err}"))
        })?
    };
    let high = if high_hex.is_empty() {
        0
    } else {
        u128::from_str_radix(high_hex, 16).map_err(|err| {
            ProtocolError::Crypto(format!("invalid nullifier high limb {high_hex}: {err}"))
        })?
    };
    if high >= NULLIFIER_KEY_HIGH_BOUND {
        return Err(ProtocolError::Crypto(
            "nullifier high limb exceeds sparse key width".into(),
        ));
    }
    Ok((low, high))
}

fn nullifier_key_bits(nullifier: &str) -> Result<Vec<bool>, ProtocolError> {
    sparse_key_bits(nullifier, NULLIFIER_KEY_LOW_BITS)
}

fn renewal_key_bits(entry: &str) -> Result<Vec<bool>, ProtocolError> {
    sparse_key_bits(entry, RENEWAL_SPARSE_TREE_DEPTH)
}

fn sparse_key_bits(entry: &str, bit_count: usize) -> Result<Vec<bool>, ProtocolError> {
    if bit_count > 128 {
        return Err(ProtocolError::Crypto(
            "sparse key bit count exceeds low-limb width".into(),
        ));
    }
    let (low, _high) = nullifier_key_low_high(entry)?;
    let mut bits = Vec::with_capacity(bit_count);
    for index in 0..bit_count {
        bits.push(((low >> index) & 1) == 1);
    }
    Ok(bits)
}

fn sparse_nullifier_levels(
    entries: &BTreeMap<Vec<bool>, Felt>,
) -> Result<Vec<BTreeMap<Vec<bool>, Felt>>, ProtocolError> {
    let mut levels = Vec::with_capacity(NULLIFIER_SPARSE_TREE_DEPTH + 1);
    levels.push(entries.clone());
    for _ in 0..NULLIFIER_SPARSE_TREE_DEPTH {
        let current = levels
            .last()
            .expect("sparse tree always has a current level");
        let mut parent_pairs = BTreeMap::<Vec<bool>, (Felt, Felt)>::new();
        for (key, value) in current {
            if key.is_empty() {
                return Err(ProtocolError::Crypto(
                    "sparse nullifier tree level underflow".into(),
                ));
            }
            let parent_key = key[1..].to_vec();
            let entry = parent_pairs
                .entry(parent_key)
                .or_insert((Felt::ZERO, Felt::ZERO));
            if key[0] {
                entry.1 = *value;
            } else {
                entry.0 = *value;
            }
        }
        let mut parent_level = BTreeMap::<Vec<bool>, Felt>::new();
        for (key, (left, right)) in parent_pairs {
            let node = nullifier_sparse_node(left, right)?;
            if node != Felt::ZERO {
                parent_level.insert(key, node);
            }
        }
        levels.push(parent_level);
    }
    Ok(levels)
}

fn sparse_nullifier_root(entries: &BTreeMap<Vec<bool>, Felt>) -> Result<String, ProtocolError> {
    let levels = sparse_nullifier_levels(entries)?;
    let root = levels
        .last()
        .and_then(|level| level.get(&Vec::<bool>::new()))
        .copied()
        .unwrap_or(Felt::ZERO);
    Ok(felt_hex(&root))
}

fn insert_nullifier_sparse_entry(
    entries: &mut BTreeMap<Vec<bool>, Felt>,
    nullifier: &str,
) -> Result<(), ProtocolError> {
    let normalized = normalize_felt_hex(nullifier)?;
    if normalized == "0x0" {
        return Err(ProtocolError::Crypto("nullifier cannot be zero".into()));
    }
    let key = nullifier_key_bits(&normalized)?;
    if entries.contains_key(&key) {
        return Err(ProtocolError::Crypto(
            "duplicate sparse nullifier key".into(),
        ));
    }
    let leaf = nullifier_sparse_leaf(felt_from_hex_str(&normalized)?)?;
    entries.insert(key, leaf);
    Ok(())
}

pub fn nullifier_sparse_update_witnesses_for_nullifiers(
    prior_nullifiers: &[Nullifier],
    current_nullifiers: &[Nullifier],
) -> Result<(String, String, Vec<NullifierSparseUpdateWitness>), ProtocolError> {
    let mut entries = BTreeMap::<Vec<bool>, Felt>::new();
    for nullifier in prior_nullifiers {
        insert_nullifier_sparse_entry(&mut entries, &normalize_felt_hex(&nullifier.0)?)?;
    }
    let prior_root = sparse_nullifier_root(&entries)?;
    let mut witnesses = Vec::with_capacity(current_nullifiers.len());

    for nullifier in current_nullifiers {
        let normalized = normalize_felt_hex(&nullifier.0)?;
        let key = nullifier_key_bits(&normalized)?;
        if entries.contains_key(&key) {
            return Err(ProtocolError::Crypto(
                "nullifier already exists in sparse nullifier set".into(),
            ));
        }
        let (key_low, key_high) = nullifier_key_low_high(&normalized)?;
        let (merkle_path, merkle_directions) = if entries.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let levels = sparse_nullifier_levels(&entries)?;
            let mut merkle_path = Vec::with_capacity(NULLIFIER_SPARSE_TREE_DEPTH);
            let mut merkle_directions = Vec::with_capacity(NULLIFIER_SPARSE_TREE_DEPTH);
            for level in 0..NULLIFIER_SPARSE_TREE_DEPTH {
                let mut sibling_key = key[level..].to_vec();
                sibling_key[0] = !sibling_key[0];
                let sibling = levels[level]
                    .get(&sibling_key)
                    .copied()
                    .unwrap_or(Felt::ZERO);
                merkle_path.push(felt_hex(&sibling));
                merkle_directions.push(if key[level] {
                    "0x1".into()
                } else {
                    "0x0".into()
                });
            }
            (merkle_path, merkle_directions)
        };
        witnesses.push(NullifierSparseUpdateWitness {
            key_low: felt_hex(&Felt::from(key_low)),
            key_high: felt_hex(&Felt::from(key_high)),
            merkle_path,
            merkle_directions,
        });
        insert_nullifier_sparse_entry(&mut entries, &normalized)?;
    }

    let new_root = sparse_nullifier_root(&entries)?;
    Ok((prior_root, new_root, witnesses))
}

pub fn nullifier_sparse_update_witnesses_for_consumed_inputs(
    prior_consumed_inputs: &[ConsumedInput],
    current_consumed_inputs: &[ConsumedInput],
) -> Result<(String, String, Vec<NullifierSparseUpdateWitness>), ProtocolError> {
    let prior_nullifiers = prior_consumed_inputs
        .iter()
        .map(|input| input.nullifier.clone())
        .collect::<Vec<_>>();
    let current_nullifiers = current_consumed_inputs
        .iter()
        .map(|input| input.nullifier.clone())
        .collect::<Vec<_>>();
    nullifier_sparse_update_witnesses_for_nullifiers(&prior_nullifiers, &current_nullifiers)
}

fn renewal_sparse_leaf(entry: Felt) -> Result<Felt, ProtocolError> {
    let leaf_domain = felt_from_hex_str(NULLIFIER_SPARSE_LEAF_DOMAIN_HEX)?;
    Ok(poseidon_hash(leaf_domain, entry))
}

fn renewal_sparse_node(left: Felt, right: Felt) -> Result<Felt, ProtocolError> {
    let node_domain = felt_from_hex_str(NULLIFIER_SPARSE_NODE_DOMAIN_HEX)?;
    if left == Felt::ZERO {
        return Ok(right);
    }
    if right == Felt::ZERO {
        return Ok(left);
    }
    let mut state = [node_domain, left, right];
    poseidon_permute_comp(&mut state);
    Ok(state[0])
}

fn renewal_sparse_levels(
    entries: &BTreeMap<Vec<bool>, Felt>,
) -> Result<Vec<BTreeMap<Vec<bool>, Felt>>, ProtocolError> {
    let mut levels = Vec::with_capacity(RENEWAL_SPARSE_TREE_DEPTH + 1);
    levels.push(entries.clone());
    for _ in 0..RENEWAL_SPARSE_TREE_DEPTH {
        let current = levels
            .last()
            .expect("sparse tree always has a current level");
        let mut next = BTreeMap::new();
        for (key, value) in current {
            if key.is_empty() {
                return Err(ProtocolError::Crypto(
                    "renewal sparse tree level underflow".into(),
                ));
            }
            let parent_key = key[1..].to_vec();
            let sibling_key = {
                let mut sibling = key.clone();
                sibling[0] = !sibling[0];
                sibling
            };
            let sibling = current.get(&sibling_key).copied().unwrap_or(Felt::ZERO);
            let node = if key[0] {
                renewal_sparse_node(sibling, *value)?
            } else {
                renewal_sparse_node(*value, sibling)?
            };
            next.entry(parent_key).or_insert(node);
        }
        levels.push(next);
    }
    Ok(levels)
}

fn renewal_sparse_root(entries: &BTreeMap<Vec<bool>, Felt>) -> Result<String, ProtocolError> {
    let levels = renewal_sparse_levels(entries)?;
    let root = levels
        .last()
        .and_then(|level| level.get(&Vec::<bool>::new()).copied())
        .unwrap_or(Felt::ZERO);
    Ok(felt_hex(&root))
}

fn insert_renewal_sparse_entry(
    entries: &mut BTreeMap<Vec<bool>, Felt>,
    entry: &str,
) -> Result<(), ProtocolError> {
    let normalized = normalize_felt_hex(entry)?;
    if normalized == "0x0" {
        return Err(ProtocolError::Crypto(
            "renewal sparse entry cannot be zero".into(),
        ));
    }
    let key = renewal_key_bits(&normalized)?;
    if entries.contains_key(&key) {
        return Err(ProtocolError::Crypto("duplicate sparse renewal key".into()));
    }
    let leaf = renewal_sparse_leaf(felt_from_hex_str(&normalized)?)?;
    entries.insert(key, leaf);
    Ok(())
}

fn renewal_sparse_witness_for_entry(
    entries: &BTreeMap<Vec<bool>, Felt>,
    entry: &str,
) -> Result<NullifierSparseUpdateWitness, ProtocolError> {
    let normalized = normalize_felt_hex(entry)?;
    let key = renewal_key_bits(&normalized)?;
    if entries.contains_key(&key) {
        return Err(ProtocolError::Crypto(
            "renewal sparse entry already exists".into(),
        ));
    }
    let (key_low, key_high) = nullifier_key_low_high(&normalized)?;
    let (merkle_path, merkle_directions) = if entries.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let levels = renewal_sparse_levels(entries)?;
        let mut merkle_path = Vec::with_capacity(RENEWAL_SPARSE_TREE_DEPTH);
        let mut merkle_directions = Vec::with_capacity(RENEWAL_SPARSE_TREE_DEPTH);
        for level in 0..RENEWAL_SPARSE_TREE_DEPTH {
            let mut sibling_key = key[level..].to_vec();
            sibling_key[0] = !sibling_key[0];
            let sibling = levels[level]
                .get(&sibling_key)
                .copied()
                .unwrap_or(Felt::ZERO);
            merkle_path.push(felt_hex(&sibling));
            merkle_directions.push(if key[level] {
                "0x1".into()
            } else {
                "0x0".into()
            });
        }
        (merkle_path, merkle_directions)
    };

    Ok(NullifierSparseUpdateWitness {
        key_low: felt_hex(&Felt::from(key_low)),
        key_high: felt_hex(&Felt::from(key_high)),
        merkle_path,
        merkle_directions,
    })
}

fn expand_renewal_history(
    history: &[RenewalStateHistoryBatch],
) -> Result<Vec<String>, ProtocolError> {
    let mut entries = Vec::new();
    for batch in history {
        if batch.repeat_count == 0 {
            return Err(ProtocolError::Crypto(
                "renewal history repeat_count must be non-zero".into(),
            ));
        }
        if !batch.entries.is_empty() && batch.repeat_count != 1 {
            return Err(ProtocolError::Crypto(
                "non-empty renewal history batches cannot be repeated".into(),
            ));
        }
        entries.extend(batch.entries.iter().cloned());
    }
    Ok(entries)
}

fn renewal_sparse_entries_from_child_uses(child_uses: &[RenewalChildUse]) -> Vec<String> {
    child_uses
        .iter()
        .map(|entry| entry.child_nullifier.clone())
        .collect()
}

fn renewal_cancel_markers_from_matched_witnesses(
    matched_order_witnesses: &[MatchedOrderWitness],
) -> Result<Vec<String>, ProtocolError> {
    matched_order_witnesses
        .iter()
        .filter(|entry| {
            normalize_felt_hex(&entry.parent_order_commitment)
                .map(|value| value != "0x0")
                .unwrap_or(true)
        })
        .map(|entry| {
            renewal_parent_cancel_marker(
                &entry.parent_secret_commitment,
                &entry.parent_cancel_authority,
            )
        })
        .collect()
}

pub fn renewal_sparse_witnesses_for_child_uses(
    prior_entries: &[String],
    child_uses: &[RenewalChildUse],
    matched_order_witnesses: &[MatchedOrderWitness],
) -> Result<
    (
        String,
        String,
        Vec<NullifierSparseUpdateWitness>,
        Vec<NullifierSparseUpdateWitness>,
    ),
    ProtocolError,
> {
    let child_entries = renewal_sparse_entries_from_child_uses(child_uses);
    let cancel_markers = renewal_cancel_markers_from_matched_witnesses(matched_order_witnesses)?;
    if child_entries.len() != cancel_markers.len() {
        return Err(ProtocolError::Crypto(
            "renewal child and cancellation marker counts diverge".into(),
        ));
    }

    let mut entries = BTreeMap::<Vec<bool>, Felt>::new();
    for entry in prior_entries {
        insert_renewal_sparse_entry(&mut entries, entry)?;
    }
    let prior_root = renewal_sparse_root(&entries)?;
    let mut child_witnesses = Vec::with_capacity(child_entries.len());
    let mut cancel_witnesses = Vec::with_capacity(cancel_markers.len());

    for (child_entry, cancel_marker) in child_entries.iter().zip(cancel_markers.iter()) {
        let cancel_witness = renewal_sparse_witness_for_entry(&entries, cancel_marker)?;
        cancel_witnesses.push(cancel_witness);
        let child_witness = renewal_sparse_witness_for_entry(&entries, child_entry)?;
        child_witnesses.push(child_witness);
        insert_renewal_sparse_entry(&mut entries, child_entry)?;
    }

    let new_root = renewal_sparse_root(&entries)?;
    Ok((prior_root, new_root, child_witnesses, cancel_witnesses))
}

pub fn deposit_note_membership_witnesses_for_chain(
    initial_root: &str,
    activation_note_commitments: &[String],
    consumed_note_commitments: &[String],
) -> Result<(String, Vec<NoteMembershipWitness>), ProtocolError> {
    let consumed_note_commitments = consumed_note_commitments
        .iter()
        .map(|note_commitment| normalize_felt_hex(note_commitment))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let consumed_set = consumed_note_commitments
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let activation_note_commitments = activation_note_commitments
        .iter()
        .map(|note_commitment| normalize_felt_hex(note_commitment))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let deposit_roots = activation_note_commitments
        .iter()
        .map(|note_commitment| deposit_note_root(note_commitment))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let mut prefix_roots = Vec::with_capacity(deposit_roots.len());
    let mut root = normalize_felt_hex(initial_root)?;
    for deposit_root in &deposit_roots {
        prefix_roots.push(root.clone());
        root = settlement_state_transition_root(&root, deposit_root)?;
    }

    let mut witnesses_by_commitment = BTreeMap::<String, NoteMembershipWitness>::new();
    for (index, (note_commitment, batch_root)) in activation_note_commitments
        .iter()
        .zip(deposit_roots.iter())
        .enumerate()
    {
        if !consumed_set.contains(note_commitment) {
            continue;
        }
        if witnesses_by_commitment
            .insert(
                note_commitment.clone(),
                NoteMembershipWitness {
                    kind: NoteMembershipKind::Deposit,
                    prefix_root: prefix_roots[index].clone(),
                    batch_root: batch_root.clone(),
                    merkle_path: Vec::new(),
                    merkle_directions: Vec::new(),
                    suffix_batch_roots: deposit_roots[index + 1..].to_vec(),
                },
            )
            .is_some()
        {
            return Err(ProtocolError::Crypto(
                "duplicate deposit note commitment in activation chain".into(),
            ));
        }
    }

    let mut witnesses = Vec::with_capacity(consumed_note_commitments.len());
    for note_commitment in consumed_note_commitments {
        let witness = witnesses_by_commitment
            .get(&note_commitment)
            .cloned()
            .ok_or_else(|| {
                ProtocolError::Crypto(format!(
                    "consumed note {note_commitment} is missing from deposit activation chain"
                ))
            })?;
        witnesses.push(witness);
    }

    Ok((root, witnesses))
}

fn deposit_chain_membership_witnesses(
    note_commitments: &[String],
) -> Result<Vec<NoteMembershipWitness>, ProtocolError> {
    let (_root, witnesses) =
        deposit_note_membership_witnesses_for_chain("0x0", note_commitments, note_commitments)?;
    Ok(witnesses)
}

fn default_note_membership_witnesses(
    witness: &SettlementWitness,
) -> Result<Vec<NoteMembershipWitness>, ProtocolError> {
    if witness.consumed_inputs.is_empty() {
        return Ok(Vec::new());
    }
    let consumed_note_commitments = witness
        .consumed_inputs
        .iter()
        .map(|input| normalize_felt_hex(&input.note_commitment.0))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let deposit_chain_root = settlement_note_root_after_deposit_chain(&consumed_note_commitments)?;
    if normalize_felt_hex(&witness.prior_note_root)? == deposit_chain_root {
        return deposit_chain_membership_witnesses(&consumed_note_commitments);
    }
    Err(ProtocolError::Crypto(
        "settlement witness missing consumed-note membership witnesses for prior_note_root".into(),
    ))
}

fn note_membership_witnesses_for_serialization(
    witness: &SettlementWitness,
) -> Result<Vec<NoteMembershipWitness>, ProtocolError> {
    if witness.note_membership_witnesses.is_empty() {
        return default_note_membership_witnesses(witness);
    }
    if witness.note_membership_witnesses.len() != witness.consumed_inputs.len() {
        return Err(ProtocolError::Crypto(
            "note membership witness count does not match consumed input count".into(),
        ));
    }
    for membership in &witness.note_membership_witnesses {
        if membership.merkle_path.len() != membership.merkle_directions.len() {
            return Err(ProtocolError::Crypto(
                "note membership merkle path/direction length mismatch".into(),
            ));
        }
    }
    Ok(witness.note_membership_witnesses.clone())
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
    let roots = root_only_settlement_commitments(transcript)?;
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
        price_base_scale: encode_u128(transcript.price_base_scale),
        taker_fee_bps: encode_u64(u64::from(transcript.taker_fee_bps)),
        maker_fee_bps: encode_u64(u64::from(transcript.maker_fee_bps)),
        protocol_fee_recipient: encode_fee_recipient(&transcript.protocol_fee_recipient),
        output_bundle_ref: encode_output_bundle_ref(&transcript.output_ciphertext_bundle_ref)?,
        prior_note_root: roots.prior_note_root,
        prior_nullifier_root: roots.prior_nullifier_root,
        prior_renewal_root: roots.prior_renewal_root,
        prior_fee_root: roots.prior_fee_root,
        consumed_note_root: roots.consumed_note_root,
        consumed_nullifier_root: roots.consumed_nullifier_root,
        renewal_child_root: roots.renewal_child_root,
        output_note_root: roots.output_note_root,
        fee_root: roots.fee_root,
        new_note_root: roots.new_note_root,
        new_nullifier_root: roots.new_nullifier_root,
        new_renewal_root: roots.new_renewal_root,
        new_fee_root: roots.new_fee_root,
        fee_asset_ids: transcript
            .fees
            .iter()
            .map(|fee| encode_asset_id(&fee.asset_id.0))
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
    settlement_proof_message_hash_for_program(
        auction_verifier_address,
        auction_verifier_address,
        transcript_commitment,
    )
}

pub fn settlement_proof_message_hash_for_program(
    proof_program_address: &str,
    auction_verifier_address: &str,
    transcript_commitment: &str,
) -> Result<String, ProtocolError> {
    let statement_message_hash =
        native_settlement_message_hash(auction_verifier_address, transcript_commitment)?;
    settlement_proof_message_hash_from_statement(proof_program_address, &statement_message_hash)
}

pub fn settlement_proof_message_hash_from_statement(
    proof_program_address: &str,
    statement_message_hash: &str,
) -> Result<String, ProtocolError> {
    let fields = [
        felt_from_hex_str(proof_program_address)?,
        Felt::ZERO,
        Felt::from(2_u64),
        felt_from_hex_str(SETTLEMENT_PROOF_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(statement_message_hash)?,
    ];
    Ok(crate::hash::poseidon_hash_hex(&fields))
}

pub fn native_renewal_message_hash(
    auction_verifier_address: &str,
    transcript_commitment: &str,
    prior_renewal_root: &str,
    renewal_child_root: &str,
    new_renewal_root: &str,
) -> Result<String, ProtocolError> {
    let mut state = poseidon_hash(
        felt_from_hex_str(RENEWAL_PROOF_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(&normalize_felt_hex(auction_verifier_address)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(transcript_commitment)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(prior_renewal_root)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(renewal_child_root)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(new_renewal_root)?)?,
    );
    Ok(felt_hex(&state))
}

pub fn renewal_proof_message_hash_for_program(
    proof_program_address: &str,
    auction_verifier_address: &str,
    transcript_commitment: &str,
    prior_renewal_root: &str,
    renewal_child_root: &str,
    new_renewal_root: &str,
) -> Result<String, ProtocolError> {
    let statement_message_hash = native_renewal_message_hash(
        auction_verifier_address,
        transcript_commitment,
        prior_renewal_root,
        renewal_child_root,
        new_renewal_root,
    )?;
    renewal_proof_message_hash_from_statement(proof_program_address, &statement_message_hash)
}

pub fn renewal_proof_message_hash_from_statement(
    proof_program_address: &str,
    statement_message_hash: &str,
) -> Result<String, ProtocolError> {
    let fields = [
        felt_from_hex_str(proof_program_address)?,
        Felt::ZERO,
        Felt::from(2_u64),
        felt_from_hex_str(RENEWAL_PROOF_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(statement_message_hash)?,
    ];
    Ok(crate::hash::poseidon_hash_hex(&fields))
}

pub fn native_auction_result_message_hash(
    auction_verifier_address: &str,
    batch_id: &str,
    order_commitment_root: &str,
    admission_root: &str,
    transcript_commitment: &str,
) -> Result<String, ProtocolError> {
    let mut state = poseidon_hash(
        felt_from_hex_str(AUCTION_RESULT_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(&normalize_felt_hex(auction_verifier_address)?)?,
    );
    state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(batch_id)?)?);
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(order_commitment_root)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(admission_root)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(transcript_commitment)?)?,
    );
    Ok(felt_hex(&state))
}

pub fn auction_result_proof_message_hash_for_program(
    proof_program_address: &str,
    auction_verifier_address: &str,
    batch_id: &str,
    order_commitment_root: &str,
    admission_root: &str,
    transcript_commitment: &str,
) -> Result<String, ProtocolError> {
    let statement_message_hash = native_auction_result_message_hash(
        auction_verifier_address,
        batch_id,
        order_commitment_root,
        admission_root,
        transcript_commitment,
    )?;
    auction_result_proof_message_hash_from_statement(proof_program_address, &statement_message_hash)
}

pub fn auction_result_proof_message_hash_from_statement(
    proof_program_address: &str,
    statement_message_hash: &str,
) -> Result<String, ProtocolError> {
    let fields = [
        felt_from_hex_str(proof_program_address)?,
        Felt::ZERO,
        Felt::from(2_u64),
        felt_from_hex_str(AUCTION_RESULT_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(statement_message_hash)?,
    ];
    Ok(crate::hash::poseidon_hash_hex(&fields))
}

pub fn native_admission_message_hash(
    auction_verifier_address: &str,
    batch_id: &str,
    order_commitment_root: &str,
    admission_root: &str,
) -> Result<String, ProtocolError> {
    let mut state = poseidon_hash(
        felt_from_hex_str(ADMISSION_PROOF_MESSAGE_DOMAIN_HEX)?,
        felt_from_hex_str(&normalize_felt_hex(auction_verifier_address)?)?,
    );
    state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(batch_id)?)?);
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(order_commitment_root)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(admission_root)?)?,
    );
    Ok(felt_hex(&state))
}

pub fn admission_proof_message_hash_for_program(
    proof_program_address: &str,
    auction_verifier_address: &str,
    batch_id: &str,
    order_commitment_root: &str,
    admission_root: &str,
) -> Result<String, ProtocolError> {
    let statement_message_hash = native_admission_message_hash(
        auction_verifier_address,
        batch_id,
        order_commitment_root,
        admission_root,
    )?;
    admission_proof_message_hash_from_statement(proof_program_address, &statement_message_hash)
}

pub fn admission_proof_message_hash_from_statement(
    proof_program_address: &str,
    statement_message_hash: &str,
) -> Result<String, ProtocolError> {
    let fields = [
        felt_from_hex_str(proof_program_address)?,
        Felt::ZERO,
        Felt::from(2_u64),
        felt_from_hex_str(ADMISSION_PROOF_MESSAGE_DOMAIN_HEX)?,
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
    if transcript.price_base_scale == 0 {
        return Err(ProtocolError::Crypto(
            "settlement transcript price_base_scale must be non-zero".into(),
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
        prior_note_root: normalize_felt_hex(&transcript.prior_note_root)?,
        prior_nullifier_root: normalize_felt_hex(&transcript.prior_nullifier_root)?,
        prior_renewal_root: normalize_felt_hex(&transcript.prior_renewal_root)?,
        prior_fee_root: normalize_felt_hex(&transcript.prior_fee_root)?,
        new_nullifier_root: normalize_felt_hex(&transcript.new_nullifier_root)?,
        new_renewal_root: normalize_felt_hex(&transcript.new_renewal_root)?,
        clearing_price: transcript.clearing_price,
        price_base_scale: transcript.price_base_scale,
        taker_fee_bps: transcript.taker_fee_bps,
        maker_fee_bps: transcript.maker_fee_bps,
        protocol_fee_recipient: transcript.protocol_fee_recipient.clone(),
        base_asset_id,
        quote_asset_id,
        matched_orders: transcript.matched_orders.clone(),
        matched_order_witnesses,
        consumed_inputs: transcript.consumed_inputs.clone(),
        note_membership_witnesses: Vec::new(),
        nullifier_history: Vec::new(),
        nullifier_sparse_witnesses: Vec::new(),
        renewal_history: Vec::new(),
        renewal_child_sparse_witnesses: Vec::new(),
        renewal_cancel_sparse_witnesses: Vec::new(),
        privacy_gate: Default::default(),
        renewal_child_uses,
        fees: transcript.fees.clone(),
        output_notes: transcript.output_notes.clone(),
        output_note_preimages: transcript.output_note_preimages.clone(),
        output_recovery_records: transcript.output_recovery_records.clone(),
        output_recovery_dummy_commitments: transcript.output_recovery_dummy_commitments.clone(),
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
    for entry in &witness.matched_order_witnesses {
        let funding_notes = entry.effective_funding_notes();
        if funding_notes.is_empty() || funding_notes.len() > MAX_ORDER_FUNDING_INPUTS {
            return Err(ProtocolError::Crypto(
                "matched order funding input count is invalid".into(),
            ));
        }
        let mut commitments = Vec::with_capacity(funding_notes.len());
        let mut nullifiers = Vec::with_capacity(funding_notes.len());
        let first_spend_authority = funding_notes[0].spend_authority.clone();
        let first_owner_public_key = funding_notes[0].owner_public_key.clone();
        for note in funding_notes {
            if note.spend_authority != first_spend_authority {
                return Err(ProtocolError::Crypto(
                    "matched order funding inputs must share spend authority".into(),
                ));
            }
            if note.owner_public_key != first_owner_public_key {
                return Err(ProtocolError::Crypto(
                    "matched order funding inputs must share note owner".into(),
                ));
            }
            let commitment = note.commitment()?;
            let nullifier = nullifier_from_note_secret(&commitment, &note.blinding)?;
            commitments.push(commitment);
            nullifiers.push(nullifier);
        }
        if funding_input_set_commitment(&commitments)? != entry.funding_note_ref {
            return Err(ProtocolError::Crypto(
                "matched order funding input set commitment mismatch".into(),
            ));
        }
        if funding_nullifier_set_commitment(&nullifiers)? != entry.funding_nullifier {
            return Err(ProtocolError::Crypto(
                "matched order funding nullifier set commitment mismatch".into(),
            ));
        }
    }
    let note_membership_witnesses = note_membership_witnesses_for_serialization(witness)?;
    let consumed_nullifier_root = settlement_consumed_nullifier_root(&witness.consumed_inputs)?;
    let current_nullifiers = witness
        .consumed_inputs
        .iter()
        .map(|input| input.nullifier.clone())
        .collect::<Vec<_>>();
    let mut history_nullifiers = Vec::new();
    for batch in &witness.nullifier_history {
        if batch.repeat_count == 0 {
            return Err(ProtocolError::Crypto(
                "nullifier history repeat_count must be non-zero".into(),
            ));
        }
        if !batch.nullifiers.is_empty() && batch.repeat_count != 1 {
            return Err(ProtocolError::Crypto(
                "non-empty nullifier history batches cannot be repeated".into(),
            ));
        }
        history_nullifiers.extend(batch.nullifiers.iter().cloned());
    }
    let nullifier_sparse_witnesses = if current_nullifiers.is_empty() {
        Vec::new()
    } else if !history_nullifiers.is_empty() || witness.nullifier_sparse_witnesses.is_empty() {
        let (computed_prior_root, computed_new_root, generated_witnesses) =
            nullifier_sparse_update_witnesses_for_nullifiers(
                &history_nullifiers,
                &current_nullifiers,
            )?;
        if computed_prior_root != normalize_felt_hex(&witness.prior_nullifier_root)? {
            return Err(ProtocolError::Crypto(
                "nullifier history does not reconstruct prior_nullifier_root".into(),
            ));
        }
        if computed_new_root != normalize_felt_hex(&witness.new_nullifier_root)? {
            return Err(ProtocolError::Crypto(
                "sparse nullifier witness does not reconstruct new_nullifier_root".into(),
            ));
        }
        generated_witnesses
    } else {
        witness.nullifier_sparse_witnesses.clone()
    };
    if nullifier_sparse_witnesses.len() != witness.consumed_inputs.len() {
        return Err(ProtocolError::Crypto(
            "sparse nullifier witness count does not match consumed inputs".into(),
        ));
    }
    let renewal_history_entries = expand_renewal_history(&witness.renewal_history)?;
    let renewal_child_entries = renewal_sparse_entries_from_child_uses(&witness.renewal_child_uses);
    let renewal_cancel_markers =
        renewal_cancel_markers_from_matched_witnesses(&witness.matched_order_witnesses)?;
    let (renewal_child_sparse_witnesses, renewal_cancel_sparse_witnesses) =
        if renewal_child_entries.is_empty() {
            (Vec::new(), Vec::new())
        } else if !renewal_history_entries.is_empty()
            || witness.renewal_child_sparse_witnesses.is_empty()
            || witness.renewal_cancel_sparse_witnesses.is_empty()
        {
            let (
                computed_prior_renewal_root,
                computed_new_renewal_root,
                generated_child_witnesses,
                generated_cancel_witnesses,
            ) = renewal_sparse_witnesses_for_child_uses(
                &renewal_history_entries,
                &witness.renewal_child_uses,
                &witness.matched_order_witnesses,
            )?;
            if computed_prior_renewal_root != normalize_felt_hex(&witness.prior_renewal_root)? {
                return Err(ProtocolError::Crypto(
                    "renewal history does not reconstruct prior_renewal_root".into(),
                ));
            }
            if computed_new_renewal_root != normalize_felt_hex(&witness.new_renewal_root)? {
                return Err(ProtocolError::Crypto(
                    "sparse renewal witness does not reconstruct new_renewal_root".into(),
                ));
            }
            (generated_child_witnesses, generated_cancel_witnesses)
        } else {
            (
                witness.renewal_child_sparse_witnesses.clone(),
                witness.renewal_cancel_sparse_witnesses.clone(),
            )
        };
    if renewal_child_sparse_witnesses.len() != renewal_child_entries.len() {
        return Err(ProtocolError::Crypto(
            "renewal child sparse witness count does not match renewal children".into(),
        ));
    }
    if renewal_cancel_sparse_witnesses.len() != renewal_cancel_markers.len() {
        return Err(ProtocolError::Crypto(
            "renewal cancel sparse witness count does not match renewal children".into(),
        ));
    }
    validate_output_recovery_witness(witness)?;
    let _ = consumed_nullifier_root;

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
    let mut matched_funding_input_counts =
        Vec::with_capacity(witness.matched_order_witnesses.len());
    let mut matched_funding_note_commitments = Vec::new();
    let mut matched_funding_note_asset_ids = Vec::new();
    let mut matched_funding_input_amounts = Vec::new();
    let mut matched_funding_input_owner_keys = Vec::new();
    let mut matched_funding_note_spend_authorities = Vec::new();
    let mut matched_funding_note_withdraw_authorities = Vec::new();
    let mut matched_funding_note_blindings = Vec::new();
    let mut matched_funding_note_nonces = Vec::new();
    let mut matched_funding_note_metadata_commitments = Vec::new();
    let mut matched_funding_note_amounts =
        Vec::with_capacity(witness.matched_order_witnesses.len());
    let mut matched_funding_note_owner_keys =
        Vec::with_capacity(witness.matched_order_witnesses.len());
    for entry in &witness.matched_order_witnesses {
        let funding_notes = entry.effective_funding_notes();
        if funding_notes.is_empty() || funding_notes.len() > MAX_ORDER_FUNDING_INPUTS {
            return Err(ProtocolError::Crypto(
                "matched order funding input count is invalid".into(),
            ));
        }
        matched_funding_input_counts.push(encode_usize(funding_notes.len()));
        let mut total_amount = 0u128;
        for note in &funding_notes {
            total_amount = total_amount.checked_add(note.amount).ok_or_else(|| {
                ProtocolError::Crypto("matched order funding amount overflow".into())
            })?;
            matched_funding_note_commitments.push(note.commitment()?.0);
            matched_funding_note_asset_ids.push(encode_asset_id(&note.asset_id.0));
            matched_funding_input_amounts.push(encode_u128(note.amount));
            matched_funding_input_owner_keys.push(encode_owner_public_key(&note.owner_public_key));
            matched_funding_note_spend_authorities.push(normalize_felt_hex(&note.spend_authority)?);
            matched_funding_note_withdraw_authorities
                .push(normalize_felt_hex(&note.withdraw_authority)?);
            matched_funding_note_blindings.push(note.blinding.clone());
            matched_funding_note_nonces.push(encode_u64(note.nonce));
            matched_funding_note_metadata_commitments.push(note.metadata_commitment.clone());
        }
        matched_funding_note_amounts.push(encode_u128(total_amount));
        matched_funding_note_owner_keys
            .push(encode_owner_public_key(&funding_notes[0].owner_public_key));
    }
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
        encode_u128(witness.price_base_scale),
        encode_u64(u64::from(witness.taker_fee_bps)),
        encode_u64(u64::from(witness.maker_fee_bps)),
        encode_fee_recipient(&witness.protocol_fee_recipient),
        encode_u64(witness.matched_orders.len() as u64),
        encode_output_bundle_ref(&witness.output_ciphertext_bundle_ref)?,
        normalize_felt_hex(&witness.prior_note_root)?,
        normalize_felt_hex(&witness.prior_nullifier_root)?,
        normalize_felt_hex(&witness.prior_renewal_root)?,
        normalize_felt_hex(&witness.prior_fee_root)?,
        domain_felt_hex("zylith/root/consumed-notes-v1"),
        domain_felt_hex("zylith/root/consumed-nullifiers-v1"),
        domain_felt_hex("zylith/root/renewal-children-v1"),
        domain_felt_hex("zylith/root/output-notes-v1"),
        domain_felt_hex("zylith/root/fees-v1"),
        ROOT_ONLY_STATE_TRANSITION_DOMAIN_HEX.into(),
        NULLIFIER_SPARSE_LEAF_DOMAIN_HEX.into(),
        NULLIFIER_SPARSE_NODE_DOMAIN_HEX.into(),
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
    push_span(&mut payload, &matched_funding_input_counts);
    push_span(&mut payload, &matched_funding_note_commitments);
    push_span(&mut payload, &matched_funding_note_asset_ids);
    push_span(&mut payload, &matched_funding_input_amounts);
    push_span(&mut payload, &matched_funding_input_owner_keys);
    push_span(&mut payload, &matched_funding_note_spend_authorities);
    push_span(&mut payload, &matched_funding_note_withdraw_authorities);
    push_span(&mut payload, &matched_funding_note_blindings);
    push_span(&mut payload, &matched_funding_note_nonces);
    push_span(&mut payload, &matched_funding_note_metadata_commitments);
    push_span(&mut payload, &matched_funding_note_amounts);
    push_span(&mut payload, &matched_funding_note_owner_keys);
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
        &nullifier_sparse_witnesses
            .iter()
            .map(|update| normalize_felt_hex(&update.key_low))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &nullifier_sparse_witnesses
            .iter()
            .map(|update| normalize_felt_hex(&update.key_high))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &nullifier_sparse_witnesses
            .iter()
            .map(|update| encode_usize(update.merkle_path.len()))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &nullifier_sparse_witnesses
            .iter()
            .flat_map(|update| update.merkle_path.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &nullifier_sparse_witnesses
            .iter()
            .flat_map(|update| update.merkle_directions.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .map(|membership| match &membership.kind {
                NoteMembershipKind::Deposit => "0x0".to_string(),
                NoteMembershipKind::SettlementOutput => "0x1".to_string(),
            })
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .map(|membership| normalize_felt_hex(&membership.prefix_root))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .map(|membership| normalize_felt_hex(&membership.batch_root))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .map(|membership| encode_usize(membership.merkle_path.len()))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .flat_map(|membership| membership.merkle_path.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .flat_map(|membership| membership.merkle_directions.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .map(|membership| encode_usize(membership.suffix_batch_roots.len()))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &note_membership_witnesses
            .iter()
            .flat_map(|membership| membership.suffix_batch_roots.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
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
        &renewal_child_sparse_witnesses
            .iter()
            .map(|update| normalize_felt_hex(&update.key_low))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_child_sparse_witnesses
            .iter()
            .map(|update| normalize_felt_hex(&update.key_high))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_child_sparse_witnesses
            .iter()
            .map(|update| encode_usize(update.merkle_path.len()))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &renewal_child_sparse_witnesses
            .iter()
            .flat_map(|update| update.merkle_path.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_child_sparse_witnesses
            .iter()
            .flat_map(|update| update.merkle_directions.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_cancel_sparse_witnesses
            .iter()
            .map(|update| normalize_felt_hex(&update.key_low))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_cancel_sparse_witnesses
            .iter()
            .map(|update| normalize_felt_hex(&update.key_high))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_cancel_sparse_witnesses
            .iter()
            .map(|update| encode_usize(update.merkle_path.len()))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &renewal_cancel_sparse_witnesses
            .iter()
            .flat_map(|update| update.merkle_path.iter())
            .map(|value| normalize_felt_hex(value))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &renewal_cancel_sparse_witnesses
            .iter()
            .flat_map(|update| update.merkle_directions.iter())
            .map(|value| normalize_felt_hex(value))
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
            .output_note_preimages
            .iter()
            .map(|note| encode_owner_public_key(&note.owner_public_key))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .output_note_preimages
            .iter()
            .map(|note| normalize_felt_hex(&note.spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .output_note_preimages
            .iter()
            .map(|note| normalize_felt_hex(&note.blinding))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .output_note_preimages
            .iter()
            .map(|note| encode_u64(note.nonce))
            .collect::<Vec<_>>(),
    );
    push_span(
        &mut payload,
        &witness
            .output_note_preimages
            .iter()
            .map(|note| normalize_felt_hex(&note.metadata_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .output_recovery_records
            .iter()
            .map(|record| normalize_felt_hex(&record.key_tag))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .output_recovery_records
            .iter()
            .map(|record| normalize_felt_hex(&record.auth_tag))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .output_recovery_records
            .iter()
            .flat_map(|record| record.ciphertext_fields.iter())
            .map(|field| normalize_felt_hex(field))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_span(
        &mut payload,
        &witness
            .output_recovery_dummy_commitments
            .iter()
            .map(|commitment| normalize_felt_hex(commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    let claimed_new_renewal_root = {
        let normalized_new_root = normalize_felt_hex(&witness.new_renewal_root)?;
        if witness.renewal_child_uses.is_empty() && normalized_new_root == "0x0" {
            normalize_felt_hex(&witness.prior_renewal_root)?
        } else {
            normalized_new_root
        }
    };
    payload.push(claimed_new_renewal_root);
    let mut serialized = vec![encode_usize(payload.len())];
    serialized.extend(payload);
    Ok(serialized)
}

fn validate_output_recovery_witness(witness: &SettlementWitness) -> Result<(), ProtocolError> {
    if witness.output_notes.len() != witness.output_note_preimages.len() {
        return Err(ProtocolError::Crypto(
            "output recovery preimage count does not match output notes".into(),
        ));
    }
    if witness.output_notes.len() != witness.output_recovery_records.len() {
        return Err(ProtocolError::Crypto(
            "output recovery record count does not match output notes".into(),
        ));
    }

    let mut recovery_commitments = Vec::with_capacity(
        witness.output_recovery_records.len() + witness.output_recovery_dummy_commitments.len(),
    );
    for (output_index, ((output_note, note), record)) in witness
        .output_notes
        .iter()
        .zip(witness.output_note_preimages.iter())
        .zip(witness.output_recovery_records.iter())
        .enumerate()
    {
        if note.commitment()? != output_note.note_commitment {
            return Err(ProtocolError::Crypto(
                "output recovery note preimage does not match output commitment".into(),
            ));
        }
        if note.asset_id != output_note.asset_id
            || note.amount != output_note.amount
            || normalize_felt_hex(&note.withdraw_authority)?
                != normalize_felt_hex(&output_note.withdraw_authority)?
        {
            return Err(ProtocolError::Crypto(
                "output recovery note preimage does not match output record".into(),
            ));
        }
        let proof = output_note_merkle_proof(&witness.output_notes, &output_note.note_commitment)?;
        let expected = encrypt_output_recovery_record(
            &witness.batch_id.0,
            output_index,
            note,
            output_note,
            &proof,
        )?;
        if expected != *record {
            return Err(ProtocolError::Crypto(
                "output recovery record is not bound to output note preimage/proof".into(),
            ));
        }
        recovery_commitments.push(normalize_felt_hex(&record.commitment)?);
    }
    for commitment in &witness.output_recovery_dummy_commitments {
        let normalized = normalize_felt_hex(commitment)?;
        if felt_from_hex_str(&normalized)? == Felt::ZERO {
            return Err(ProtocolError::Crypto(
                "output recovery dummy commitment must be non-zero".into(),
            ));
        }
        recovery_commitments.push(normalized);
    }
    let expected_bundle_root = output_recovery_bundle_root(&recovery_commitments)?;
    if felt_from_hex_str(&expected_bundle_root)?
        != felt_from_hex_str(&encode_output_bundle_ref(
            &witness.output_ciphertext_bundle_ref,
        )?)?
    {
        return Err(ProtocolError::Crypto(
            "output recovery bundle root does not match settlement output bundle ref".into(),
        ));
    }

    Ok(())
}

fn auction_proof_vectors(
    witness: &SettlementWitness,
    all_orders: &[AuctionOrderWitness],
) -> Result<AuctionProofVectors, ProtocolError> {
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
        let funding_notes = entry.effective_funding_notes();
        if funding_notes.is_empty() || funding_notes.len() > MAX_ORDER_FUNDING_INPUTS {
            return Err(ProtocolError::Crypto(
                "auction order funding input count is invalid".into(),
            ));
        }
        let first_spend_authority = funding_notes[0].spend_authority.clone();
        let first_owner_public_key = funding_notes[0].owner_public_key.clone();
        let mut funding_note_commitments = Vec::with_capacity(funding_notes.len());
        let mut funding_nullifiers = Vec::with_capacity(funding_notes.len());
        for note in funding_notes {
            if note.spend_authority != first_spend_authority {
                return Err(ProtocolError::Crypto(
                    "auction order funding inputs must share spend authority".into(),
                ));
            }
            if note.owner_public_key != first_owner_public_key {
                return Err(ProtocolError::Crypto(
                    "auction order funding inputs must share note owner".into(),
                ));
            }
            let commitment = note.commitment()?;
            funding_nullifiers.push(nullifier_from_note_secret(&commitment, &note.blinding)?);
            funding_note_commitments.push(commitment);
        }
        if funding_input_set_commitment(&funding_note_commitments)? != entry.order.funding_note_ref
        {
            return Err(ProtocolError::Crypto(
                "auction order funding input set does not match funding_note_ref".into(),
            ));
        }
        if funding_nullifier_set_commitment(&funding_nullifiers)? != entry.order.funding_nullifier {
            return Err(ProtocolError::Crypto(
                "auction order funding nullifier set does not match funding_nullifier".into(),
            ));
        }
        let public_key = felt_from_hex_str(&first_spend_authority)?;
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
    let mut funding_input_counts = Vec::with_capacity(all_orders.len());
    let mut funding_note_commitments = Vec::new();
    let mut funding_note_asset_ids = Vec::new();
    let mut funding_input_amounts = Vec::new();
    let mut funding_input_owner_keys = Vec::new();
    let mut funding_note_spend_authorities = Vec::new();
    let mut funding_note_withdraw_authorities = Vec::new();
    let mut funding_note_blindings = Vec::new();
    let mut funding_note_nonces = Vec::new();
    let mut funding_note_metadata_commitments = Vec::new();
    let mut funding_note_amounts = Vec::with_capacity(all_orders.len());
    let mut funding_note_owner_keys = Vec::with_capacity(all_orders.len());
    for entry in all_orders {
        let funding_notes = entry.effective_funding_notes();
        if funding_notes.is_empty() || funding_notes.len() > MAX_ORDER_FUNDING_INPUTS {
            return Err(ProtocolError::Crypto(
                "auction order funding input count is invalid".into(),
            ));
        }
        funding_input_counts.push(encode_usize(funding_notes.len()));
        let mut total_amount = 0u128;
        for note in &funding_notes {
            total_amount = total_amount.checked_add(note.amount).ok_or_else(|| {
                ProtocolError::Crypto("auction order funding amount overflow".into())
            })?;
            funding_note_commitments.push(note.commitment()?.0);
            funding_note_asset_ids.push(encode_asset_id(&note.asset_id.0));
            funding_input_amounts.push(encode_u128(note.amount));
            funding_input_owner_keys.push(encode_owner_public_key(&note.owner_public_key));
            funding_note_spend_authorities.push(normalize_felt_hex(&note.spend_authority)?);
            funding_note_withdraw_authorities.push(normalize_felt_hex(&note.withdraw_authority)?);
            funding_note_blindings.push(note.blinding.clone());
            funding_note_nonces.push(encode_u64(note.nonce));
            funding_note_metadata_commitments.push(note.metadata_commitment.clone());
        }
        funding_note_amounts.push(encode_u128(total_amount));
        funding_note_owner_keys.push(encode_owner_public_key(&funding_notes[0].owner_public_key));
    }

    Ok(AuctionProofVectors {
        settlement_payload: settlement_payload.to_vec(),
        order_commitments: all_orders
            .iter()
            .map(|entry| entry.order_commitment.0.clone())
            .collect(),
        sides: all_orders
            .iter()
            .map(|entry| encode_order_side(&entry.order.side))
            .collect(),
        order_types: all_orders
            .iter()
            .map(|entry| encode_order_type(&entry.order.order_type))
            .collect(),
        maker_curve_commitments,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices: all_orders
            .iter()
            .map(|entry| encode_u128(entry.order.limit_price))
            .collect(),
        order_amounts: all_orders
            .iter()
            .map(|entry| encode_u128(entry.order.amount))
            .collect(),
        min_fills: all_orders
            .iter()
            .map(|entry| encode_u128(entry.order.min_fill))
            .collect(),
        time_in_force: all_orders
            .iter()
            .map(|entry| encode_time_in_force(&entry.order.time_in_force))
            .collect(),
        expiry_epochs: all_orders
            .iter()
            .map(|entry| encode_u64(entry.order.expiry_epoch))
            .collect(),
        order_nonces: all_orders
            .iter()
            .map(|entry| encode_u64(entry.order.order_nonce))
            .collect(),
        parent_order_commitments: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_order_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        parent_child_indexes: all_orders
            .iter()
            .map(|entry| encode_u64(entry.order.parent_child_index))
            .collect(),
        parent_secret_commitments: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_secret_commitment))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        parent_cancel_authorities: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_cancel_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        parent_authorization_secrets: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.parent_authorization_secret))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        auditor_flags: all_orders
            .iter()
            .map(|entry| {
                if entry.order.auditor_view_allowed {
                    "0x1".into()
                } else {
                    "0x0".into()
                }
            })
            .collect(),
        funding_note_refs: all_orders
            .iter()
            .map(|entry| entry.order.funding_note_ref.0.clone())
            .collect(),
        funding_input_counts,
        funding_note_commitments,
        funding_note_asset_ids,
        funding_input_amounts,
        funding_input_owner_keys,
        funding_note_spend_authorities,
        funding_note_withdraw_authorities,
        funding_note_blindings,
        funding_note_nonces,
        funding_note_metadata_commitments,
        funding_note_amounts,
        funding_note_owner_keys,
        funding_authorization_rs: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_authorization.signature_r))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        funding_authorization_ss: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.funding_authorization.signature_s))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        funding_nullifiers: all_orders
            .iter()
            .map(|entry| entry.order.funding_nullifier.0.clone())
            .collect(),
        recipient_owner_keys: all_orders
            .iter()
            .map(|entry| encode_owner_public_key(&entry.order.recipient_owner_public_key))
            .collect(),
        recipient_spend_authorities: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.recipient_spend_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        recipient_withdraw_authorities: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.recipient_withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        recipient_residual_withdraw_authorities: all_orders
            .iter()
            .map(|entry| normalize_felt_hex(&entry.order.recipient_residual_withdraw_authority))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        allocation_fill_amounts,
        privacy_gate_fields: vec![
            if witness.privacy_gate.enforced {
                "0x1".into()
            } else {
                "0x0".into()
            },
            encode_u128(witness.privacy_gate.min_batch_base_liquidity),
            encode_u64(witness.privacy_gate.min_batch_participants),
            encode_u64(witness.privacy_gate.min_eligible_orders),
            encode_u64(witness.privacy_gate.max_single_order_fill_bps),
            encode_u64(witness.privacy_gate.max_single_owner_fill_bps),
            encode_u64(witness.privacy_gate.min_maker_participants),
            encode_u64(witness.privacy_gate.max_maker_fill_bps),
        ],
    })
}

#[derive(Clone, Debug)]
struct AuctionProofVectors {
    settlement_payload: Vec<String>,
    order_commitments: Vec<String>,
    sides: Vec<String>,
    order_types: Vec<String>,
    maker_curve_commitments: Vec<String>,
    maker_curve_point_counts: Vec<String>,
    maker_curve_prices: Vec<String>,
    maker_curve_base_amounts: Vec<String>,
    limit_prices: Vec<String>,
    order_amounts: Vec<String>,
    min_fills: Vec<String>,
    time_in_force: Vec<String>,
    expiry_epochs: Vec<String>,
    order_nonces: Vec<String>,
    parent_order_commitments: Vec<String>,
    parent_child_indexes: Vec<String>,
    parent_secret_commitments: Vec<String>,
    parent_cancel_authorities: Vec<String>,
    parent_authorization_secrets: Vec<String>,
    auditor_flags: Vec<String>,
    funding_note_refs: Vec<String>,
    funding_input_counts: Vec<String>,
    funding_note_commitments: Vec<String>,
    funding_note_asset_ids: Vec<String>,
    funding_input_amounts: Vec<String>,
    funding_input_owner_keys: Vec<String>,
    funding_note_spend_authorities: Vec<String>,
    funding_note_withdraw_authorities: Vec<String>,
    funding_note_blindings: Vec<String>,
    funding_note_nonces: Vec<String>,
    funding_note_metadata_commitments: Vec<String>,
    funding_note_amounts: Vec<String>,
    funding_note_owner_keys: Vec<String>,
    funding_authorization_rs: Vec<String>,
    funding_authorization_ss: Vec<String>,
    funding_nullifiers: Vec<String>,
    recipient_owner_keys: Vec<String>,
    recipient_spend_authorities: Vec<String>,
    recipient_withdraw_authorities: Vec<String>,
    recipient_residual_withdraw_authorities: Vec<String>,
    allocation_fill_amounts: Vec<String>,
    privacy_gate_fields: Vec<String>,
}

pub fn auction_admission_root(
    witness: &SettlementWitness,
    all_orders: &[AuctionOrderWitness],
) -> Result<String, ProtocolError> {
    let vectors = auction_proof_vectors(witness, all_orders)?;
    admission_root_from_vectors(&vectors)
}

pub fn build_admission_serialized_input(
    witness: &SettlementWitness,
    all_orders: &[AuctionOrderWitness],
) -> Result<Vec<String>, ProtocolError> {
    let vectors = auction_proof_vectors(witness, all_orders)?;
    let mut payload = vec![encode_u64(ADMISSION_STATEMENT_TYPE_TAG)];
    push_span(&mut payload, &vectors.settlement_payload);
    push_admission_order_vectors(&mut payload, &vectors);
    let mut serialized = vec![encode_usize(payload.len())];
    serialized.extend(payload);
    Ok(serialized)
}

pub fn build_auction_result_serialized_input(
    witness: &SettlementWitness,
    all_orders: &[AuctionOrderWitness],
) -> Result<Vec<String>, ProtocolError> {
    let vectors = auction_proof_vectors(witness, all_orders)?;
    let admission_root = admission_root_from_vectors(&vectors)?;
    let mut payload = vec![encode_u64(AUCTION_RESULT_STATEMENT_TYPE_TAG)];
    push_span(&mut payload, &vectors.settlement_payload);
    payload.push(admission_root);
    push_span(&mut payload, &vectors.order_commitments);
    push_span(&mut payload, &vectors.sides);
    push_span(&mut payload, &vectors.order_types);
    push_span(&mut payload, &vectors.maker_curve_commitments);
    push_span(&mut payload, &vectors.maker_curve_point_counts);
    push_span(&mut payload, &vectors.maker_curve_prices);
    push_span(&mut payload, &vectors.maker_curve_base_amounts);
    push_span(&mut payload, &vectors.limit_prices);
    push_span(&mut payload, &vectors.order_amounts);
    push_span(&mut payload, &vectors.min_fills);
    push_span(&mut payload, &vectors.time_in_force);
    push_span(&mut payload, &vectors.funding_note_amounts);
    push_span(&mut payload, &vectors.funding_note_owner_keys);
    push_span(&mut payload, &vectors.allocation_fill_amounts);
    payload.extend(vectors.privacy_gate_fields);
    let mut serialized = vec![encode_usize(payload.len())];
    serialized.extend(payload);
    Ok(serialized)
}

fn push_admission_order_vectors(payload: &mut Vec<String>, vectors: &AuctionProofVectors) {
    push_span(payload, &vectors.order_commitments);
    push_span(payload, &vectors.sides);
    push_span(payload, &vectors.order_types);
    push_span(payload, &vectors.maker_curve_commitments);
    push_span(payload, &vectors.maker_curve_point_counts);
    push_span(payload, &vectors.maker_curve_prices);
    push_span(payload, &vectors.maker_curve_base_amounts);
    push_span(payload, &vectors.limit_prices);
    push_span(payload, &vectors.order_amounts);
    push_span(payload, &vectors.min_fills);
    push_span(payload, &vectors.time_in_force);
    push_span(payload, &vectors.expiry_epochs);
    push_span(payload, &vectors.order_nonces);
    push_span(payload, &vectors.parent_order_commitments);
    push_span(payload, &vectors.parent_child_indexes);
    push_span(payload, &vectors.parent_secret_commitments);
    push_span(payload, &vectors.parent_cancel_authorities);
    push_span(payload, &vectors.parent_authorization_secrets);
    push_span(payload, &vectors.auditor_flags);
    push_span(payload, &vectors.funding_note_refs);
    push_span(payload, &vectors.funding_input_counts);
    push_span(payload, &vectors.funding_note_commitments);
    push_span(payload, &vectors.funding_note_asset_ids);
    push_span(payload, &vectors.funding_input_amounts);
    push_span(payload, &vectors.funding_input_owner_keys);
    push_span(payload, &vectors.funding_note_spend_authorities);
    push_span(payload, &vectors.funding_note_withdraw_authorities);
    push_span(payload, &vectors.funding_note_blindings);
    push_span(payload, &vectors.funding_note_nonces);
    push_span(payload, &vectors.funding_note_metadata_commitments);
    push_span(payload, &vectors.funding_note_amounts);
    push_span(payload, &vectors.funding_note_owner_keys);
    push_span(payload, &vectors.funding_authorization_rs);
    push_span(payload, &vectors.funding_authorization_ss);
    push_span(payload, &vectors.funding_nullifiers);
    push_span(payload, &vectors.recipient_owner_keys);
    push_span(payload, &vectors.recipient_spend_authorities);
    push_span(payload, &vectors.recipient_withdraw_authorities);
    push_span(payload, &vectors.recipient_residual_withdraw_authorities);
}

fn admission_root_from_vectors(vectors: &AuctionProofVectors) -> Result<String, ProtocolError> {
    let order_count = vectors.order_commitments.len();
    let same_len_vectors = [
        vectors.sides.len(),
        vectors.order_types.len(),
        vectors.maker_curve_commitments.len(),
        vectors.limit_prices.len(),
        vectors.order_amounts.len(),
        vectors.min_fills.len(),
        vectors.time_in_force.len(),
        vectors.funding_note_amounts.len(),
        vectors.funding_note_owner_keys.len(),
    ];
    if same_len_vectors.iter().any(|len| *len != order_count) {
        return Err(ProtocolError::Crypto(
            "admission root vectors have inconsistent lengths".into(),
        ));
    }

    let mut leaves = Vec::with_capacity(order_count);
    for index in 0..order_count {
        let leaf_inputs = [
            vectors.order_commitments[index].as_str(),
            vectors.sides[index].as_str(),
            vectors.order_types[index].as_str(),
            vectors.maker_curve_commitments[index].as_str(),
            vectors.limit_prices[index].as_str(),
            vectors.order_amounts[index].as_str(),
            vectors.min_fills[index].as_str(),
            vectors.time_in_force[index].as_str(),
            vectors.funding_note_amounts[index].as_str(),
            vectors.funding_note_owner_keys[index].as_str(),
        ];
        leaves.push(poseidon_chain_hex_from_hexes(
            ADMISSION_LEAF_DOMAIN_HEX,
            &leaf_inputs,
        )?);
    }
    let mut root_inputs = Vec::with_capacity(leaves.len() + 1);
    root_inputs.push(encode_usize(order_count));
    root_inputs.extend(leaves);
    let root_input_refs = root_inputs.iter().map(String::as_str).collect::<Vec<_>>();
    poseidon_chain_hex_from_hexes(ADMISSION_ROOT_DOMAIN_HEX, &root_input_refs)
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
        OrderType::HeartbeatCover => "0x2".into(),
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

fn encode_fee_recipient(recipient: &str) -> String {
    encode_starknet_felt("fee-recipient", recipient)
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
        recovery: None,
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

fn parse_note_recognition_public_key(owner_key_hex: &str) -> Result<PublicKey, ProtocolError> {
    let normalized = owner_key_hex.trim_start_matches("0x");
    if normalized.len() == 64 {
        return Err(ProtocolError::Crypto(
            "recipient owner key must be a note-recognition public key, not a raw local key".into(),
        ));
    }
    parse_public_key(normalized)
}

fn note_recognition_secret_from_raw_key_hex(raw_key_hex: &str) -> Result<SecretKey, ProtocolError> {
    let raw_key = hex::decode(raw_key_hex.trim_start_matches("0x"))?;
    if raw_key.len() != 32 {
        return Err(ProtocolError::Crypto(format!(
            "note recognition key must be 32 bytes, got {}",
            raw_key.len()
        )));
    }

    for counter in 0_u16..=255 {
        let mut material = Vec::with_capacity(raw_key.len() + 2);
        material.extend_from_slice(&raw_key);
        material.extend_from_slice(&counter.to_be_bytes());
        let candidate = tagged_sha256_bytes("zylith/note-recognition-p256-secret-v1", &material);
        if let Ok(secret) = SecretKey::from_slice(&candidate) {
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

fn derive_output_note_key(
    shared_secret: &[u8],
    key_id: &str,
    ephemeral_public_key_hex: &str,
) -> Result<[u8; 32], ProtocolError> {
    hkdf_expand(
        shared_secret,
        OUTPUT_NOTE_HKDF_SALT,
        format!("zylith/output-note-aes-key:{key_id}:{ephemeral_public_key_hex}").as_bytes(),
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

fn output_note_blob_aad(
    algorithm: &str,
    key_id: &str,
    ephemeral_public_key: &str,
    nonce: &str,
) -> Vec<u8> {
    format!("zylith-output-note-blob:{algorithm}:{key_id}:{ephemeral_public_key}:{nonce}")
        .into_bytes()
}

fn padded_output_note_plaintext(
    payload: &OwnedOutputNotePayload,
) -> Result<Vec<u8>, ProtocolError> {
    let payload_json = serde_json::to_vec(payload)?;
    let payload_len = u32::try_from(payload_json.len())
        .map_err(|_| ProtocolError::Crypto("output note plaintext exceeds u32 length".into()))?;
    if payload_json.len() + 4 > OUTPUT_NOTE_PLAINTEXT_PADDED_LEN {
        return Err(ProtocolError::Crypto(format!(
            "output note plaintext must fit {} bytes, got {}",
            OUTPUT_NOTE_PLAINTEXT_PADDED_LEN,
            payload_json.len() + 4
        )));
    }

    let mut plaintext = vec![0_u8; OUTPUT_NOTE_PLAINTEXT_PADDED_LEN];
    plaintext[..4].copy_from_slice(&payload_len.to_be_bytes());
    plaintext[4..4 + payload_json.len()].copy_from_slice(&payload_json);
    OsRng.fill_bytes(&mut plaintext[4 + payload_json.len()..]);
    Ok(plaintext)
}

fn parse_padded_output_note_plaintext(
    plaintext: &[u8],
) -> Result<OwnedOutputNotePayload, ProtocolError> {
    if plaintext.len() != OUTPUT_NOTE_PLAINTEXT_PADDED_LEN {
        return Err(ProtocolError::Crypto(format!(
            "output note plaintext must be {} bytes, got {}",
            OUTPUT_NOTE_PLAINTEXT_PADDED_LEN,
            plaintext.len()
        )));
    }
    let len_bytes: [u8; 4] = plaintext[..4]
        .try_into()
        .map_err(|_| ProtocolError::Crypto("missing output note length prefix".into()))?;
    let payload_len = u32::from_be_bytes(len_bytes) as usize;
    if payload_len == 0 || payload_len + 4 > plaintext.len() {
        return Err(ProtocolError::Crypto(
            "invalid output note length prefix".into(),
        ));
    }
    let payload: OwnedOutputNotePayload = serde_json::from_slice(&plaintext[4..4 + payload_len])?;
    if payload.version != 1 {
        return Err(ProtocolError::Crypto(
            "unsupported output note payload version".into(),
        ));
    }
    Ok(payload)
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

fn flatten_settlement_call_arguments(args: &SettlementCallArguments) -> Vec<String> {
    let mut calldata = vec![
        args.batch_id.clone(),
        args.order_commitment_root.clone(),
        args.encrypted_order_set_commitment.clone(),
        args.transcript_commitment.clone(),
        args.proof_artifact_commitment.clone(),
    ];
    calldata.push(args.clearing_price.clone());
    calldata.push(args.price_base_scale.clone());
    calldata.push(args.taker_fee_bps.clone());
    calldata.push(args.maker_fee_bps.clone());
    calldata.push(args.protocol_fee_recipient.clone());
    calldata.push(args.output_bundle_ref.clone());
    calldata.push(args.prior_note_root.clone());
    calldata.push(args.prior_nullifier_root.clone());
    calldata.push(args.prior_renewal_root.clone());
    calldata.push(args.prior_fee_root.clone());
    calldata.push(args.consumed_note_root.clone());
    calldata.push(args.consumed_nullifier_root.clone());
    calldata.push(args.renewal_child_root.clone());
    calldata.push(args.output_note_root.clone());
    calldata.push(args.fee_root.clone());
    calldata.push(args.new_note_root.clone());
    calldata.push(args.new_nullifier_root.clone());
    calldata.push(args.new_renewal_root.clone());
    calldata.push(args.new_fee_root.clone());
    push_span(&mut calldata, &args.fee_asset_ids);
    push_span(&mut calldata, &args.fee_amounts);
    calldata
}

fn flatten_settlement_output_withdrawal_call_arguments(
    args: &SettlementOutputWithdrawalCallArguments,
) -> Vec<String> {
    let mut calldata = vec![
        args.batch_id.clone(),
        args.note_commitment.clone(),
        args.asset_id.clone(),
        args.amount.clone(),
        args.withdraw_authority.clone(),
    ];
    push_span(&mut calldata, &args.merkle_path);
    push_span(&mut calldata, &args.merkle_directions);
    calldata.push(args.withdraw_authorization_r.clone());
    calldata.push(args.withdraw_authorization_s.clone());
    calldata.push(args.recipient.clone());
    calldata
}

fn flatten_renewal_parent_cancel_call_arguments(
    args: &RenewalParentCancelCallArguments,
) -> Vec<String> {
    let mut calldata = vec![
        args.cancel_marker.clone(),
        args.cancel_authority.clone(),
        args.sparse_key_low.clone(),
        args.sparse_key_high.clone(),
    ];
    push_span(&mut calldata, &args.merkle_path);
    push_span(&mut calldata, &args.merkle_directions);
    calldata.push(args.signature_r.clone());
    calldata.push(args.signature_s.clone());
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
        SettlementOutputWithdrawalMessage, SettlementOutputWithdrawalPlanRequest,
        auction_admission_root, build_admission_serialized_input,
        build_auction_result_serialized_input, build_deposit_note, build_deposit_submission_plan,
        build_order_submission, build_output_note, build_renewal_parent_cancel_submission_plan,
        build_settlement_output_withdrawal_submission_plan, build_settlement_submission_plan,
        build_settlement_witness, build_stwo_serialized_input, build_withdrawal_submission_plan,
        create_order_ingress_receipt, create_recovery_artifact, decrypt_note_for_owner,
        decrypt_order_bundle, decrypt_order_share, decrypt_output_recovery_record,
        decrypt_recovery_artifact_payload, derive_account_id, derive_order_cancellation_secret,
        derive_order_cancellation_tag, derive_user_keys, encrypt_note_for_owner,
        encrypt_output_recovery_record, note_recognition_public_key_from_raw_key_hex,
        output_note_merkle_proof, output_note_merkle_root,
        private_execution_key_registry_fingerprint, proof_artifact_commitment,
        reconstruct_order_from_shares, renewal_child_nullifier, root_only_settlement_commitments,
        sanitize_order_submission_for_coordinator, settlement_note_root_after_deposit_chain,
        settlement_nullifier_root_after_history, settlement_output_withdrawal_message_hash,
        settlement_transcript_commitment, sign_order_authorization,
        validate_order_ingress_receipt_for_manifest,
        validate_order_ingress_receipt_for_manifest_with_secrets,
        validate_private_execution_key_registry_pin, verify_order_ingress_receipt,
        verify_order_ingress_receipt_with_secrets, verify_output_note_membership,
        withdrawal_message_hash,
    };
    use crate::types::{output_bundle_bucket_size, output_recovery_bundle_root};
    use crate::{AuctionPrivacyGateWitness, RenewalParentCancelPlanRequest};

    fn with_deposit_prior_note_root(mut transcript: SettlementTranscript) -> SettlementTranscript {
        if !transcript.consumed_inputs.is_empty() {
            let commitments = transcript
                .consumed_inputs
                .iter()
                .map(|input| input.note_commitment.0.clone())
                .collect::<Vec<_>>();
            transcript.prior_note_root =
                settlement_note_root_after_deposit_chain(&commitments).expect("deposit note root");
        }
        if transcript.new_nullifier_root == "0x0" {
            if transcript.consumed_inputs.is_empty() {
                transcript.new_nullifier_root = transcript.prior_nullifier_root.clone();
            } else {
                transcript.new_nullifier_root =
                    super::nullifier_sparse_update_witnesses_for_consumed_inputs(
                        &[],
                        &transcript.consumed_inputs,
                    )
                    .expect("sparse nullifier roots")
                    .1;
            }
        }
        transcript
    }

    fn with_proof_bound_output_recovery(
        mut transcript: SettlementTranscript,
        output_note_preimages: Vec<Note>,
    ) -> SettlementTranscript {
        assert_eq!(transcript.output_notes.len(), output_note_preimages.len());
        let mut recovery_records = Vec::with_capacity(output_note_preimages.len());
        let mut recovery_commitments = Vec::new();
        for (output_index, (note, output_note)) in output_note_preimages
            .iter()
            .zip(transcript.output_notes.iter())
            .enumerate()
        {
            let proof =
                output_note_merkle_proof(&transcript.output_notes, &output_note.note_commitment)
                    .expect("output proof");
            let record = encrypt_output_recovery_record(
                &transcript.batch_id.0,
                output_index,
                note,
                output_note,
                &proof,
            )
            .expect("output recovery record");
            recovery_commitments.push(record.commitment.clone());
            recovery_records.push(record);
        }
        let required_dummy_count = output_bundle_bucket_size(transcript.output_notes.len())
            .saturating_sub(transcript.output_notes.len());
        let dummy_bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            transcript.batch_id.clone(),
            "test-da",
            vec![],
        )
        .expect("dummy output bundle");
        let recovery_dummy_commitments = dummy_bundle
            .ciphertexts
            .iter()
            .take(required_dummy_count)
            .map(|ciphertext| {
                ciphertext
                    .recovery
                    .as_ref()
                    .expect("dummy recovery")
                    .commitment
                    .clone()
            })
            .collect::<Vec<_>>();
        recovery_commitments.extend(recovery_dummy_commitments.iter().cloned());
        transcript.output_note_preimages = output_note_preimages;
        transcript.output_recovery_records = recovery_records;
        transcript.output_recovery_dummy_commitments = recovery_dummy_commitments;
        transcript.output_ciphertext_bundle_ref =
            output_recovery_bundle_root(&recovery_commitments)
                .expect("output recovery bundle root");
        transcript
    }

    fn sample_single_match_witness(
        batch_id: &str,
        funding_note: Note,
        funding_nullifier: Nullifier,
        output_note: Note,
    ) -> SettlementWitness {
        let order_commitment = OrderCommitment("0xabc123".into());
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: BatchId(batch_id.into()),
                pair_id: PairId("STRK/USDC".into()),
                batch_epoch: 12,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 321,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
                matched_orders: vec![crate::MatchedOrder {
                    order_commitment: order_commitment.clone(),
                    filled_amount: 111,
                }],
                consumed_inputs: vec![ConsumedInput {
                    note_commitment: funding_note.commitment().expect("funding note commitment"),
                    nullifier: funding_nullifier.clone(),
                }],
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes: vec![OutputNoteRecord {
                    note_commitment: output_note.commitment().expect("output note commitment"),
                    asset_id: AssetId("STRK".into()),
                    amount: 104,
                    withdraw_authority: output_note.withdraw_authority.clone(),
                }],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: format!("{batch_id}-bundle"),
            }),
            vec![output_note.clone()],
        );
        build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment,
                funding_note,
                funding_notes: vec![],
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier,
                funding_nullifiers: vec![],
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
                recipient_withdraw_authority: output_note.withdraw_authority.clone(),
                recipient_residual_withdraw_authority: "0xccd".into(),
                filled_amount: 111,
                output_note,
                residual_note: None,
            }],
        )
        .expect("single match witness")
    }
    use crate::{
        AssetId, AuctionOrderWitness, BatchId, ConsumedInput, DepositIntent, FeeEntry,
        MatchedOrderWitness, Note, NoteCommitment, Nullifier, NullifierHistoryBatch,
        OrderCommitment, OrderIntent, OrderSide, OutputNoteRecord, PairId,
        PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
        PrivateExecutionKeyRegistry, PrivateOrderPayload, ProtocolError, RecoveryArtifactKind,
        RecoverySeed, SettlementTranscript, SettlementWitness,
        hash::{encode_starknet_felt, ordered_felt_list_commitment},
        nullifier_from_note_secret, spend_auth_key_felt_from_raw_key_hex,
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
    fn order_submission_rejects_mismatched_funding_nullifier() {
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
        let mut payload = sample_private_order();
        payload.order.funding_nullifier = Nullifier("0xdead".into());
        payload.funding_authorization = sample_authorization_for_order(&payload.order);

        let error = build_order_submission(&payload, &registry, &"11".repeat(32))
            .expect_err("bad nullifier rejected");
        assert!(
            matches!(error, ProtocolError::Crypto(message) if message.contains("funding nullifier"))
        );
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
        let seed = RecoverySeed([42_u8; 32]);
        let keys = derive_user_keys(&seed);
        let note_recognition_key = hex::encode(keys.note_recognition_key);
        let owner_public_key = note_recognition_public_key_from_raw_key_hex(&note_recognition_key)
            .expect("owner public key");
        let payload = sample_private_order();
        let mut order = payload.order;
        order.recipient_owner_public_key = owner_public_key.clone();
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
        let expected_metadata = super::output_note_metadata_commitment(
            "batch-1",
            &order.commitment().expect("commitment"),
            &order.funding_note_ref,
            &order.pair_id,
            &order.recipient_spend_authority,
            &order.recipient_withdraw_authority,
        )
        .expect("metadata commitment");
        assert_eq!(note.metadata_commitment, expected_metadata);
        let blob = encrypt_note_for_owner("batch-1", 0, &note, &order.recipient_owner_public_key)
            .expect("encrypted note");

        assert_ne!(blob.key_id, order.recipient_owner_public_key);
        assert!(!blob.ephemeral_public_key.is_empty());
        assert_eq!(hex::decode(&blob.nonce).expect("nonce").len(), 12);
        assert_eq!(
            hex::decode(&blob.ciphertext).expect("ciphertext").len(),
            crate::types::OUTPUT_NOTE_CIPHERTEXT_LEN
        );

        let decrypted = decrypt_note_for_owner(&note_recognition_key, &blob)
            .expect("decrypt")
            .expect("matching owner");

        assert_eq!(decrypted, note);
        assert!(
            decrypt_note_for_owner(&"01".repeat(32), &blob)
                .expect("wrong-owner decrypt")
                .is_none()
        );
        assert!(
            decrypt_note_for_owner(&blob.key_id, &blob)
                .expect("public key id decrypt")
                .is_none(),
            "public envelope key_id must not be sufficient to decrypt output notes"
        );
    }

    #[test]
    fn output_recovery_record_is_decryptable_and_tamper_bound() {
        let note = sample_note("STRK", 500, 77);
        let output_note = OutputNoteRecord {
            note_commitment: note.commitment().expect("note commitment"),
            asset_id: note.asset_id.clone(),
            amount: note.amount,
            withdraw_authority: note.withdraw_authority.clone(),
        };
        let proof = crate::OutputNoteMerkleProof {
            merkle_path: vec![],
            merkle_directions: vec![],
        };
        let record =
            encrypt_output_recovery_record("batch-recovery", 0, &note, &output_note, &proof)
                .expect("recovery record");

        let payload = decrypt_output_recovery_record(
            &note.spend_authority,
            &note.owner_public_key,
            &BatchId("batch-recovery".into()),
            0,
            &record,
        )
        .expect("recovery decrypt")
        .expect("matching recovery key");
        assert_eq!(payload.note, note);
        assert_eq!(payload.output_note, output_note);

        let mut tampered = record;
        tampered.ciphertext_fields[5] = "0x0".into();
        assert!(
            decrypt_output_recovery_record(
                &note.spend_authority,
                &note.owner_public_key,
                &BatchId("batch-recovery".into()),
                0,
                &tampered,
            )
            .expect("tampered decrypt")
            .is_none()
        );
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
    fn settlement_output_withdrawal_plan_targets_verifier_and_includes_merkle_path() {
        let withdraw_key = "11".repeat(32);
        let withdraw_auth_key_felt = crate::withdraw_auth_key_felt_from_raw_key_hex(&withdraw_key);
        let withdraw_authority =
            crate::withdraw_authority_from_raw_key_hex(&withdraw_key).expect("withdraw authority");
        let outputs = vec![
            OutputNoteRecord {
                note_commitment: NoteCommitment("0x101".into()),
                asset_id: AssetId("USDC".into()),
                amount: 100,
                withdraw_authority: withdraw_authority.clone(),
            },
            OutputNoteRecord {
                note_commitment: NoteCommitment("0x202".into()),
                asset_id: AssetId("USDC".into()),
                amount: 200,
                withdraw_authority: withdraw_authority.clone(),
            },
        ];
        let proof =
            output_note_merkle_proof(&outputs, &outputs[1].note_commitment).expect("output proof");
        assert_eq!(proof.merkle_path.len(), 1);
        assert_eq!(proof.merkle_directions, vec!["0x1"]);
        let output_root = output_note_merkle_root(&outputs, "bundle").expect("output root");
        verify_output_note_membership(&outputs[1], &proof, &output_root).expect("valid membership");
        let wrong_root = output_note_merkle_root(&outputs[..1], "bundle").expect("wrong root");
        verify_output_note_membership(&outputs[1], &proof, &wrong_root)
            .expect_err("wrong output root must fail");

        let batch_id = BatchId("batch-strk-usdc-7".into());
        let plan = build_settlement_output_withdrawal_submission_plan(
            SettlementOutputWithdrawalPlanRequest {
                batch_id: &batch_id,
                output_note: &outputs[1],
                output_proof: &proof,
                withdraw_auth_key_felt: &withdraw_auth_key_felt,
                recipient: "0x444",
                auction_verifier_address: "0x123",
                shielded_asset_adapter_address: "0x456",
                chain_id: "0x534e5f5345504f4c4941",
            },
        )
        .expect("settlement output withdrawal plan");

        assert_eq!(
            plan.starknet_call.entrypoint,
            "withdraw_settlement_output_to_l2"
        );
        assert_eq!(plan.starknet_call.contract_address, "0x123");
        assert_eq!(plan.encoded_args.note_commitment, "0x202");
        assert_eq!(plan.encoded_args.amount, "0xc8");
        assert_eq!(plan.encoded_args.merkle_path.len(), 1);
        assert_eq!(plan.encoded_args.merkle_directions, vec!["0x1"]);
        assert_eq!(plan.starknet_call.calldata.len(), 12);
    }

    #[test]
    fn settlement_output_withdrawal_hash_is_chain_verifier_and_adapter_bound() {
        let base = settlement_output_withdrawal_message_hash(SettlementOutputWithdrawalMessage {
            auction_verifier_address: "0x123",
            shielded_asset_adapter_address: "0x456",
            chain_id: "0x534e5f5345504f4c4941",
            batch_id: "0x777",
            note_commitment: "0x888",
            asset_id: "0x999",
            amount: "0x64",
            recipient: "0xabc",
        })
        .expect("base hash");
        let other_verifier =
            settlement_output_withdrawal_message_hash(SettlementOutputWithdrawalMessage {
                auction_verifier_address: "0x124",
                shielded_asset_adapter_address: "0x456",
                chain_id: "0x534e5f5345504f4c4941",
                batch_id: "0x777",
                note_commitment: "0x888",
                asset_id: "0x999",
                amount: "0x64",
                recipient: "0xabc",
            })
            .expect("verifier hash");
        let other_adapter =
            settlement_output_withdrawal_message_hash(SettlementOutputWithdrawalMessage {
                auction_verifier_address: "0x123",
                shielded_asset_adapter_address: "0x457",
                chain_id: "0x534e5f5345504f4c4941",
                batch_id: "0x777",
                note_commitment: "0x888",
                asset_id: "0x999",
                amount: "0x64",
                recipient: "0xabc",
            })
            .expect("adapter hash");
        assert_ne!(base, other_verifier);
        assert_ne!(base, other_adapter);
    }

    #[test]
    fn settlement_submission_plan_flattens_proof_facts_call_arguments() {
        let transcript = with_deposit_prior_note_root(SettlementTranscript {
            batch_id: crate::BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 145,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "fee-recipient".into(),
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
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle-1".into(),
        });

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
        assert_ne!(plan.encoded_args.consumed_note_root, "0x0");
        assert_ne!(plan.encoded_args.output_note_root, "0x0");
        assert_eq!(
            plan.settlement_call.calldata.len(),
            26 + transcript.fees.len() * 2
        );
    }

    #[test]
    fn settlement_submission_plan_targets_native_proof_facts_entrypoint() {
        let transcript = with_deposit_prior_note_root(SettlementTranscript {
            batch_id: crate::BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 145,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-fee".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle-1".into(),
        });

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
        assert_eq!(
            plan.settlement_call.calldata[6],
            plan.encoded_args.price_base_scale
        );
    }

    #[test]
    fn settlement_transcript_commitment_matches_cairo_contract_formula() {
        let transcript = with_deposit_prior_note_root(SettlementTranscript {
            batch_id: crate::BatchId("batch-strk-usdc-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 300,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-fee".into(),
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
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref:
                "a9bfa0d37d7a84cc26c1fec3e7dd0e00d463a93f886e6e62ada07470b1a4ea4a".into(),
        });

        let commitment =
            settlement_transcript_commitment(&transcript).expect("transcript commitment");
        let plan = build_settlement_submission_plan(&transcript, "0x123", "0x456").expect("plan");
        assert_eq!(commitment, plan.encoded_args.transcript_commitment);
        assert_eq!(
            plan.settlement_call.calldata.len(),
            26 + transcript.fees.len() * 2
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
        let transcript = with_deposit_prior_note_root(SettlementTranscript {
            batch_id: crate::BatchId("batch-2".into()),
            pair_id: PairId("STRK/ETH".into()),
            batch_epoch: 9,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 200,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-treasury".into(),
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
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle-2".into(),
        });

        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/ETH".into()),
            "0x456",
            AssetId("STRK".into()),
            AssetId("ETH".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-2".into()),
                funding_note,
                funding_notes: vec![],
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier,
                funding_nullifiers: vec![],
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
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: crate::BatchId("batch-3".into()),
                pair_id: PairId("STRK/USDC".into()),
                batch_epoch: 12,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 321,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "recipient-3".into(),
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
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "bundle-3".into(),
            }),
            vec![output_note.clone()],
        );

        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-3".into()),
                funding_note,
                funding_notes: vec![],
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier,
                funding_nullifiers: vec![],
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
    fn stwo_serialized_input_binds_multiple_funding_inputs() {
        let funding_note_a = sample_note("USDC", 80_000, 54);
        let funding_note_b = sample_note("USDC", 120_000, 55);
        let output_note = sample_note("STRK", 997, 56);
        let residual_note = sample_note("USDC", 55_000, 57);
        let funding_commitment_a = funding_note_a
            .commitment()
            .expect("funding note commitment a");
        let funding_commitment_b = funding_note_b
            .commitment()
            .expect("funding note commitment b");
        let funding_nullifier_a = sample_nullifier(&funding_note_a);
        let funding_nullifier_b = sample_nullifier(&funding_note_b);
        let funding_note_ref = crate::funding_input_set_commitment(&[
            funding_commitment_a.clone(),
            funding_commitment_b.clone(),
        ])
        .expect("funding input set");
        let funding_nullifier = crate::funding_nullifier_set_commitment(&[
            funding_nullifier_a.clone(),
            funding_nullifier_b.clone(),
        ])
        .expect("funding nullifier set");
        let order_commitment = crate::OrderCommitment("order-multi-input".into());
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: crate::BatchId("batch-multi-input".into()),
                pair_id: PairId("STRK/USDC".into()),
                batch_epoch: 12,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "recipient-asset-owner".into(),
                matched_orders: vec![crate::MatchedOrder {
                    order_commitment: order_commitment.clone(),
                    filled_amount: 1000,
                }],
                consumed_inputs: vec![
                    ConsumedInput {
                        note_commitment: funding_commitment_a.clone(),
                        nullifier: funding_nullifier_a.clone(),
                    },
                    ConsumedInput {
                        note_commitment: funding_commitment_b.clone(),
                        nullifier: funding_nullifier_b.clone(),
                    },
                ],
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes: vec![
                    OutputNoteRecord {
                        note_commitment: output_note.commitment().expect("output note commitment"),
                        asset_id: AssetId("STRK".into()),
                        amount: 997,
                        withdraw_authority: output_note.withdraw_authority.clone(),
                    },
                    OutputNoteRecord {
                        note_commitment: residual_note
                            .commitment()
                            .expect("residual note commitment"),
                        asset_id: AssetId("USDC".into()),
                        amount: 55_000,
                        withdraw_authority: residual_note.withdraw_authority.clone(),
                    },
                ],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "bundle-multi-input".into(),
            }),
            vec![output_note.clone(), residual_note.clone()],
        );
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment,
                funding_note: funding_note_a.clone(),
                funding_notes: vec![funding_note_a, funding_note_b],
                funding_note_ref: funding_note_ref.clone(),
                funding_nullifier: funding_nullifier.clone(),
                funding_nullifiers: vec![funding_nullifier_a, funding_nullifier_b],
                funding_authorization: sample_authorization_unchecked(),
                side: OrderSide::Buy,
                order_type: crate::OrderType::LimitBatch,
                maker_curve: None,
                limit_price: 145,
                order_amount: 1000,
                min_fill: 1000,
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
                recipient_withdraw_authority: output_note.withdraw_authority.clone(),
                recipient_residual_withdraw_authority: residual_note.withdraw_authority.clone(),
                filled_amount: 1000,
                output_note,
                residual_note: Some(residual_note),
            }],
        )
        .expect("multi-input witness");

        let serialized = build_stwo_serialized_input(&witness).expect("serialized input");
        let mut index = 1 + 34;
        let _matched_order_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_fill_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_sides = read_serialized_span(&serialized, &mut index);
        let _matched_order_types = read_serialized_span(&serialized, &mut index);
        let _matched_maker_curve_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_maker_curve_point_counts = read_serialized_span(&serialized, &mut index);
        let _matched_maker_curve_prices = read_serialized_span(&serialized, &mut index);
        let _matched_maker_curve_base_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_limit_prices = read_serialized_span(&serialized, &mut index);
        let _matched_order_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_min_fills = read_serialized_span(&serialized, &mut index);
        let _matched_time_in_force = read_serialized_span(&serialized, &mut index);
        let _matched_expiry_epochs = read_serialized_span(&serialized, &mut index);
        let _matched_order_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_parent_order_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_parent_child_indexes = read_serialized_span(&serialized, &mut index);
        let _matched_parent_secret_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_parent_cancel_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_parent_authorization_secrets = read_serialized_span(&serialized, &mut index);
        let _matched_auditor_flags = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_refs = read_serialized_span(&serialized, &mut index);
        let matched_funding_input_counts = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_commitments = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let matched_funding_input_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_funding_input_owner_keys = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_blindings = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let matched_funding_note_amounts = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let _matched_funding_authorization_rs = read_serialized_span(&serialized, &mut index);
        let _matched_funding_authorization_ss = read_serialized_span(&serialized, &mut index);
        let matched_funding_nullifiers = read_serialized_span(&serialized, &mut index);

        assert_eq!(matched_funding_note_refs, vec![funding_note_ref.0]);
        assert_eq!(matched_funding_input_counts, vec!["0x2".to_string()]);
        assert_eq!(
            matched_funding_note_commitments,
            vec![funding_commitment_a.0, funding_commitment_b.0]
        );
        assert_eq!(
            matched_funding_input_amounts,
            vec!["0x13880".to_string(), "0x1d4c0".to_string()]
        );
        assert_eq!(matched_funding_note_amounts, vec!["0x30d40".to_string()]);
        assert_eq!(matched_funding_nullifiers, vec![funding_nullifier.0]);
        assert_eq!(witness.consumed_inputs.len(), 2);
    }

    #[test]
    fn stwo_serialized_input_rejects_mismatched_witness_count() {
        let output_note = sample_note("STRK", 104, 5);
        let transcript = with_deposit_prior_note_root(SettlementTranscript {
            batch_id: crate::BatchId("batch-mismatched-witnesses".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 321,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-treasury".into(),
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
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle-ref-mismatch".into(),
        });
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
    fn stwo_serialized_input_rejects_consumed_note_without_prior_root_membership() {
        let funding_note = sample_note("USDC", 44_400, 44);
        let output_note = sample_note("STRK", 104, 45);
        let funding_nullifier = sample_nullifier(&funding_note);
        let mut transcript = SettlementTranscript {
            batch_id: crate::BatchId("batch-missing-membership".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 12,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x123".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 321,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-treasury".into(),
            matched_orders: vec![crate::MatchedOrder {
                order_commitment: crate::OrderCommitment("order-missing-membership".into()),
                filled_amount: 111,
            }],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: funding_note.commitment().expect("funding note commitment"),
                nullifier: funding_nullifier.clone(),
            }],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: output_note.commitment().expect("output note commitment"),
                asset_id: AssetId("STRK".into()),
                amount: 104,
                withdraw_authority: output_note.withdraw_authority.clone(),
            }],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle-missing-membership".into(),
        };
        transcript.new_nullifier_root =
            super::nullifier_sparse_update_witnesses_for_consumed_inputs(
                &[],
                &transcript.consumed_inputs,
            )
            .expect("sparse nullifier root")
            .1;
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-missing-membership".into()),
                funding_note,
                funding_notes: vec![],
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier,
                funding_nullifiers: vec![],
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

        let error = build_stwo_serialized_input(&witness).expect_err("membership required");
        assert!(matches!(error, ProtocolError::Crypto(message) if message.contains("membership")));
    }

    #[test]
    fn stwo_serialized_input_rejects_prior_nullifier_root_without_sparse_witness() {
        let funding_note = sample_note("USDC", 44_400, 46);
        let output_note = sample_note("STRK", 104, 47);
        let funding_nullifier = sample_nullifier(&funding_note);
        let mut witness = sample_single_match_witness(
            "batch-root-only-nullifier-history",
            funding_note,
            funding_nullifier,
            output_note,
        );
        witness.prior_nullifier_root = "0x123".into();
        witness.new_nullifier_root = "0x456".into();

        let error = build_stwo_serialized_input(&witness).expect_err("sparse witness required");
        assert!(
            matches!(error, ProtocolError::Crypto(message) if message.contains("prior_nullifier_root"))
        );
    }

    #[test]
    fn stwo_serialized_input_rejects_replayed_sparse_nullifier_history() {
        let funding_note = sample_note("USDC", 44_400, 48);
        let output_note = sample_note("STRK", 104, 49);
        let funding_nullifier = sample_nullifier(&funding_note);
        let mut witness = sample_single_match_witness(
            "batch-nullifier-replay-history",
            funding_note,
            funding_nullifier.clone(),
            output_note,
        );
        witness.nullifier_history = vec![NullifierHistoryBatch {
            repeat_count: 1,
            nullifiers: vec![funding_nullifier],
        }];
        witness.prior_nullifier_root =
            settlement_nullifier_root_after_history(&witness.nullifier_history)
                .expect("history root");

        let error = build_stwo_serialized_input(&witness).expect_err("spent history rejected");
        assert!(
            matches!(error, ProtocolError::Crypto(message) if message.contains("already exists"))
        );
    }

    #[test]
    fn stwo_serialized_input_accepts_sparse_nullifier_history() {
        let funding_note = sample_note("USDC", 44_400, 50);
        let output_note = sample_note("STRK", 104, 51);
        let funding_nullifier = sample_nullifier(&funding_note);
        let historical_note = sample_note("USDC", 1_000, 52);
        let mut witness = sample_single_match_witness(
            "batch-valid-nullifier-history",
            funding_note,
            funding_nullifier,
            output_note,
        );
        witness.nullifier_history = vec![NullifierHistoryBatch {
            repeat_count: 1,
            nullifiers: vec![sample_nullifier(&historical_note)],
        }];
        witness.prior_nullifier_root =
            settlement_nullifier_root_after_history(&witness.nullifier_history)
                .expect("history root");
        let mut history_after_batch = witness.nullifier_history.clone();
        history_after_batch.push(NullifierHistoryBatch {
            repeat_count: 1,
            nullifiers: witness
                .consumed_inputs
                .iter()
                .map(|input| input.nullifier.clone())
                .collect(),
        });
        witness.new_nullifier_root =
            settlement_nullifier_root_after_history(&history_after_batch).expect("new root");

        build_stwo_serialized_input(&witness).expect("sparse history accepted");
    }

    #[test]
    fn sparse_nullifier_witness_uses_empty_path_for_empty_root_only() {
        let first = sample_nullifier(&sample_note("USDC", 1_000, 500));
        let second = sample_nullifier(&sample_note("STRK", 2_000, 501));
        let current = vec![first, second];

        let (prior_root, new_root, witnesses) =
            super::nullifier_sparse_update_witnesses_for_nullifiers(&[], &current)
                .expect("sparse witnesses");
        let expected_root = settlement_nullifier_root_after_history(&[NullifierHistoryBatch {
            repeat_count: 1,
            nullifiers: current,
        }])
        .expect("history root");

        assert_eq!(prior_root, "0x0");
        assert_eq!(new_root, expected_root);
        assert_eq!(witnesses.len(), 2);
        assert!(witnesses[0].merkle_path.is_empty());
        assert!(witnesses[0].merkle_directions.is_empty());
        assert_eq!(
            witnesses[1].merkle_path.len(),
            super::NULLIFIER_SPARSE_TREE_DEPTH
        );
        assert_eq!(
            witnesses[1].merkle_directions.len(),
            super::NULLIFIER_SPARSE_TREE_DEPTH
        );
    }

    #[test]
    fn compressed_empty_nullifier_history_matches_expanded_history() {
        let expanded = vec![
            NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: vec![],
            },
            NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: vec![],
            },
            NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: vec![Nullifier("0x123".into())],
            },
        ];
        let compressed = vec![
            NullifierHistoryBatch {
                repeat_count: 2,
                nullifiers: vec![],
            },
            NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: vec![Nullifier("0x123".into())],
            },
        ];

        assert_eq!(
            settlement_nullifier_root_after_history(&compressed).expect("compressed"),
            settlement_nullifier_root_after_history(&expanded).expect("expanded"),
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
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: crate::BatchId("batch-asset-owner".into()),
                pair_id: PairId("STRK/USDC".into()),
                batch_epoch: 22,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 321,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "recipient-asset-owner".into(),
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
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "bundle-asset-owner".into(),
            }),
            vec![output_note.clone()],
        );

        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: crate::OrderCommitment("order-asset-owner".into()),
                funding_note,
                funding_notes: vec![],
                funding_note_ref: transcript.consumed_inputs[0].note_commitment.clone(),
                funding_nullifier,
                funding_nullifiers: vec![],
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
        index += 34;

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
        let matched_funding_input_counts = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_commitments = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _matched_funding_input_amounts = read_serialized_span(&serialized, &mut index);
        let matched_funding_input_owner_keys = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_withdraw_authorities =
            read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_blindings = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_nonces = read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_metadata_commitments =
            read_serialized_span(&serialized, &mut index);
        let _matched_funding_note_amounts = read_serialized_span(&serialized, &mut index);
        let matched_funding_note_owner_keys = read_serialized_span(&serialized, &mut index);
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
        let _nullifier_sparse_key_lows = read_serialized_span(&serialized, &mut index);
        let _nullifier_sparse_key_highs = read_serialized_span(&serialized, &mut index);
        let _nullifier_sparse_path_counts = read_serialized_span(&serialized, &mut index);
        let _nullifier_sparse_path_values = read_serialized_span(&serialized, &mut index);
        let _nullifier_sparse_path_directions = read_serialized_span(&serialized, &mut index);
        let note_membership_kinds = read_serialized_span(&serialized, &mut index);
        let _note_membership_prefix_roots = read_serialized_span(&serialized, &mut index);
        let note_membership_batch_roots = read_serialized_span(&serialized, &mut index);
        let note_membership_path_counts = read_serialized_span(&serialized, &mut index);
        let note_membership_path_values = read_serialized_span(&serialized, &mut index);
        let note_membership_path_directions = read_serialized_span(&serialized, &mut index);
        let note_membership_suffix_counts = read_serialized_span(&serialized, &mut index);
        let _note_membership_suffix_roots = read_serialized_span(&serialized, &mut index);
        let renewal_parent_order_commitments = read_serialized_span(&serialized, &mut index);
        let renewal_child_nullifiers = read_serialized_span(&serialized, &mut index);
        let _renewal_child_sparse_key_lows = read_serialized_span(&serialized, &mut index);
        let _renewal_child_sparse_key_highs = read_serialized_span(&serialized, &mut index);
        let _renewal_child_sparse_path_counts = read_serialized_span(&serialized, &mut index);
        let _renewal_child_sparse_path_values = read_serialized_span(&serialized, &mut index);
        let _renewal_child_sparse_path_directions = read_serialized_span(&serialized, &mut index);
        let _renewal_cancel_sparse_key_lows = read_serialized_span(&serialized, &mut index);
        let _renewal_cancel_sparse_key_highs = read_serialized_span(&serialized, &mut index);
        let _renewal_cancel_sparse_path_counts = read_serialized_span(&serialized, &mut index);
        let _renewal_cancel_sparse_path_values = read_serialized_span(&serialized, &mut index);
        let _renewal_cancel_sparse_path_directions = read_serialized_span(&serialized, &mut index);
        let _output_note_commitments = read_serialized_span(&serialized, &mut index);
        let output_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let _output_note_amounts = read_serialized_span(&serialized, &mut index);
        let _output_note_withdraw_authorities = read_serialized_span(&serialized, &mut index);

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
        assert_eq!(matched_funding_input_counts, vec!["0x1".to_string()]);
        assert_eq!(note_membership_kinds, vec!["0x0".to_string()]);
        assert_eq!(note_membership_batch_roots.len(), 1);
        assert_eq!(note_membership_path_counts, vec!["0x0".to_string()]);
        assert!(note_membership_path_values.is_empty());
        assert!(note_membership_path_directions.is_empty());
        assert_eq!(note_membership_suffix_counts, vec!["0x0".to_string()]);
        assert_eq!(matched_funding_note_asset_ids, vec![quote_asset.clone()]);
        assert_eq!(matched_output_note_asset_ids, vec![base_asset.clone()]);
        assert_eq!(output_note_asset_ids, vec![base_asset.clone()]);
        assert_eq!(matched_funding_input_owner_keys, vec![owner_key.clone()]);
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
    fn admission_serialized_input_binds_full_order_preimages() {
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
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: crate::BatchId("batch-auction-bind".into()),
                pair_id: private_order.order.pair_id.clone(),
                batch_epoch: private_order.order.expiry_epoch,
                order_commitment_root: order_root,
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
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
                    recipient: "zylith-protocol-treasury".into(),
                }],
                output_notes: vec![OutputNoteRecord {
                    note_commitment: output_note.commitment().expect("output note commitment"),
                    asset_id: AssetId("STRK".into()),
                    amount: 997,
                    withdraw_authority: output_note.withdraw_authority.clone(),
                }],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "bundle-auction-bind".into(),
            }),
            vec![output_note.clone()],
        );
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: order_commitment.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_notes: vec![],
                funding_note_ref: funding_note_commitment.clone(),
                funding_nullifier: private_order.order.funding_nullifier.clone(),
                funding_nullifiers: vec![],
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
        let serialized = build_admission_serialized_input(
            &witness,
            &[AuctionOrderWitness {
                order_commitment: order_commitment.clone(),
                order: private_order.order.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_notes: vec![],
                funding_authorization: private_order.funding_authorization.clone(),
            }],
        )
        .expect("admission serialized input");

        let mut index = 1;
        assert_eq!(serialized[index], "0x3");
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
        let funding_input_counts = read_serialized_span(&serialized, &mut index);
        let funding_note_commitments = read_serialized_span(&serialized, &mut index);
        let funding_note_asset_ids = read_serialized_span(&serialized, &mut index);
        let funding_input_amounts = read_serialized_span(&serialized, &mut index);
        let funding_input_owner_keys = read_serialized_span(&serialized, &mut index);
        let funding_note_spend_authorities = read_serialized_span(&serialized, &mut index);
        let funding_note_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let funding_note_blindings = read_serialized_span(&serialized, &mut index);
        let funding_note_nonces = read_serialized_span(&serialized, &mut index);
        let funding_note_metadata_commitments = read_serialized_span(&serialized, &mut index);
        let funding_note_amounts = read_serialized_span(&serialized, &mut index);
        let funding_note_owner_keys = read_serialized_span(&serialized, &mut index);
        let funding_authorization_rs = read_serialized_span(&serialized, &mut index);
        let funding_authorization_ss = read_serialized_span(&serialized, &mut index);
        let funding_nullifiers = read_serialized_span(&serialized, &mut index);
        let recipient_owner_keys = read_serialized_span(&serialized, &mut index);
        let recipient_spend_authorities = read_serialized_span(&serialized, &mut index);
        let recipient_withdraw_authorities = read_serialized_span(&serialized, &mut index);
        let recipient_residual_withdraw_authorities = read_serialized_span(&serialized, &mut index);

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
        assert_eq!(funding_input_counts, vec!["0x1".to_string()]);
        assert_eq!(funding_note_commitments, vec![funding_note_commitment.0]);
        assert_eq!(
            funding_note_asset_ids,
            vec![encode_starknet_felt("asset-id", "USDC")]
        );
        assert_eq!(funding_input_amounts, vec!["0x30d40".to_string()]);
        assert_eq!(
            funding_input_owner_keys,
            vec![encode_starknet_felt("owner-public-key", &"ab".repeat(32))]
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
        assert_eq!(index, serialized.len());
    }

    #[test]
    fn split_auction_inputs_bind_admission_and_result_roots() {
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
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: crate::BatchId("batch-auction-bind".into()),
                pair_id: private_order.order.pair_id.clone(),
                batch_epoch: private_order.order.expiry_epoch,
                order_commitment_root: order_root,
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
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
                    recipient: "zylith-protocol-treasury".into(),
                }],
                output_notes: vec![OutputNoteRecord {
                    note_commitment: output_note.commitment().expect("output note commitment"),
                    asset_id: AssetId("STRK".into()),
                    amount: 997,
                    withdraw_authority: output_note.withdraw_authority.clone(),
                }],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "bundle-auction-bind".into(),
            }),
            vec![output_note.clone()],
        );
        let mut witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: order_commitment.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_notes: vec![],
                funding_note_ref: funding_note_commitment,
                funding_nullifier: private_order.order.funding_nullifier.clone(),
                funding_nullifiers: vec![],
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
        witness.privacy_gate = AuctionPrivacyGateWitness {
            enforced: true,
            min_batch_base_liquidity: 100,
            min_batch_participants: 1,
            min_eligible_orders: 1,
            max_single_order_fill_bps: 10_000,
            max_single_owner_fill_bps: 10_000,
            min_maker_participants: 0,
            max_maker_fill_bps: 0,
        };
        let orders = [AuctionOrderWitness {
            order_commitment,
            order: private_order.order,
            funding_note: private_order.funding_note,
            funding_notes: vec![],
            funding_authorization: private_order.funding_authorization,
        }];
        let admission_root = auction_admission_root(&witness, &orders).expect("admission root");
        let admission =
            build_admission_serialized_input(&witness, &orders).expect("admission input");
        let result =
            build_auction_result_serialized_input(&witness, &orders).expect("result input");

        let mut admission_index = 1;
        assert_eq!(admission[admission_index], "0x3");
        admission_index += 1;
        let _admission_settlement_payload = read_serialized_span(&admission, &mut admission_index);
        let admitted_order_commitments = read_serialized_span(&admission, &mut admission_index);
        assert_eq!(
            admitted_order_commitments,
            vec![orders[0].order_commitment.0.clone()]
        );

        let mut result_index = 1;
        assert_eq!(result[result_index], "0x4");
        result_index += 1;
        let _result_settlement_payload = read_serialized_span(&result, &mut result_index);
        assert_eq!(result[result_index], admission_root);
        assert_eq!(result[result.len() - 8], "0x1");
        assert_eq!(result[result.len() - 7], "0x64");
        assert_eq!(result[result.len() - 6], "0x1");
        assert_eq!(result[result.len() - 5], "0x1");
    }

    #[test]
    fn admission_serialized_input_allows_empty_noop_batch() {
        let order_root =
            ordered_felt_list_commitment("zylith/batch-order-root", &[]).expect("empty root");
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: BatchId("batch-strk-usdc-empty".into()),
                pair_id: PairId("STRK/USDC".into()),
                batch_epoch: 42,
                order_commitment_root: order_root,
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 0,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
                matched_orders: vec![],
                consumed_inputs: vec![],
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes: vec![],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "noop-output-bundle".into(),
            }),
            vec![],
        );
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![],
        )
        .expect("empty witness");

        let serialized =
            build_admission_serialized_input(&witness, &[]).expect("empty admission input");

        let mut index = 1;
        assert_eq!(serialized[index], "0x3");
        index += 1;
        let settlement_payload = read_serialized_span(&serialized, &mut index);
        assert_eq!(settlement_payload[0], "0x1");
        assert_eq!(settlement_payload[15], "0x0");
        assert_eq!(settlement_payload[16], "0x1");
        assert_eq!(settlement_payload[20], "0x0");

        let mut admission_vector_count = 0;
        while index < serialized.len() {
            let values = read_serialized_span(&serialized, &mut index);
            assert!(values.is_empty());
            admission_vector_count += 1;
        }
        assert!(admission_vector_count > 0);
    }

    #[test]
    fn empty_output_note_root_is_nonzero_and_bundle_bound() {
        let base = SettlementTranscript {
            batch_id: BatchId("batch-empty-root".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 42,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 0,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-treasury".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "noop-output-bundle-a".into(),
        };
        let roots_a = root_only_settlement_commitments(&base).expect("roots a");
        let mut other = base;
        other.output_ciphertext_bundle_ref = "noop-output-bundle-b".into();
        let roots_b = root_only_settlement_commitments(&other).expect("roots b");

        assert_ne!(roots_a.output_note_root, "0x0");
        assert_ne!(roots_a.output_note_root, roots_b.output_note_root);
    }

    #[test]
    fn admission_serialized_input_rejects_wrong_order_batch_domain() {
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
        let transcript = with_proof_bound_output_recovery(
            with_deposit_prior_note_root(SettlementTranscript {
                batch_id: crate::BatchId("batch-auction-bind".into()),
                pair_id: private_order.order.pair_id.clone(),
                batch_epoch: private_order.order.expiry_epoch,
                order_commitment_root: order_root,
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
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
                    recipient: "zylith-protocol-treasury".into(),
                }],
                output_notes: vec![OutputNoteRecord {
                    note_commitment: output_note.commitment().expect("output note commitment"),
                    asset_id: AssetId("STRK".into()),
                    amount: 997,
                    withdraw_authority: output_note.withdraw_authority.clone(),
                }],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: vec![],
                output_ciphertext_bundle_ref: "bundle-auction-bind".into(),
            }),
            vec![output_note.clone()],
        );
        let witness = build_settlement_witness(
            &transcript,
            PairId("STRK/USDC".into()),
            "0x999",
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            vec![MatchedOrderWitness {
                order_commitment: order_commitment.clone(),
                funding_note: private_order.funding_note.clone(),
                funding_notes: vec![],
                funding_note_ref: funding_note_commitment,
                funding_nullifier: private_order.order.funding_nullifier.clone(),
                funding_nullifiers: vec![],
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
        let error = build_admission_serialized_input(
            &witness,
            &[AuctionOrderWitness {
                order_commitment,
                order: private_order.order,
                funding_note: private_order.funding_note,
                funding_notes: vec![],
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
            funding_notes: Vec::new(),
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
        nullifier_from_note_secret(&note.commitment().expect("note commitment"), &note.blinding)
            .expect("sample nullifier")
    }

    #[test]
    fn renewal_parent_cancel_submission_plan_builds_signed_contract_call() {
        let order_cancel_key_hex = "44".repeat(32);
        let parent_authorization_secret = "0x12345";
        let parent_secret_commitment =
            crate::renewal_parent_secret_commitment(parent_authorization_secret)
                .expect("parent secret commitment");
        let parent_cancel_authority =
            crate::renewal_cancel_authority_from_raw_key_hex(&order_cancel_key_hex)
                .expect("cancel authority");
        let renewal_cancel_auth_key =
            crate::renewal_cancel_auth_key_felt_from_raw_key_hex(&order_cancel_key_hex);

        let plan = build_renewal_parent_cancel_submission_plan(RenewalParentCancelPlanRequest {
            chain_id: "0x534e5f5345504f4c4941".into(),
            auction_verifier_address: "0x1234".into(),
            parent_secret_commitment,
            parent_cancel_authority: parent_cancel_authority.clone(),
            renewal_cancel_auth_key,
            prior_renewal_entries: vec![],
        })
        .expect("renewal parent cancel plan");

        assert_eq!(plan.starknet_call.contract_address, "0x1234");
        assert_eq!(
            plan.starknet_call.entrypoint,
            "cancel_renewal_parent_marker"
        );
        assert_eq!(
            plan.starknet_call.calldata[0],
            plan.encoded_args.cancel_marker
        );
        assert_eq!(plan.starknet_call.calldata[1], parent_cancel_authority);
        assert_eq!(
            plan.starknet_call.calldata[2],
            plan.encoded_args.sparse_key_low
        );
        assert_eq!(
            plan.starknet_call.calldata[3],
            plan.encoded_args.sparse_key_high
        );
        assert_eq!(plan.starknet_call.calldata[4], "0x0");
        assert_eq!(plan.starknet_call.calldata[5], "0x0");
        assert_ne!(plan.encoded_args.signature_r, "0x0");
        assert_ne!(plan.encoded_args.signature_s, "0x0");
    }

    #[test]
    fn renewal_parent_cancel_submission_plan_uses_sparse_non_empty_witnesses() {
        let order_cancel_key_hex = "45".repeat(32);
        let parent_secret_commitment =
            crate::renewal_parent_secret_commitment("0x98765").expect("parent secret commitment");
        let parent_cancel_authority =
            crate::renewal_cancel_authority_from_raw_key_hex(&order_cancel_key_hex)
                .expect("cancel authority");
        let prior_entry =
            renewal_child_nullifier("0xabc", 1, "0xdef").expect("prior renewal child nullifier");

        let plan = build_renewal_parent_cancel_submission_plan(RenewalParentCancelPlanRequest {
            chain_id: "0x534e5f5345504f4c4941".into(),
            auction_verifier_address: "0x1234".into(),
            parent_secret_commitment,
            parent_cancel_authority,
            renewal_cancel_auth_key: crate::renewal_cancel_auth_key_felt_from_raw_key_hex(
                &order_cancel_key_hex,
            ),
            prior_renewal_entries: vec![prior_entry],
        })
        .expect("renewal parent cancel plan");

        assert_eq!(
            plan.encoded_args.merkle_path.len(),
            super::RENEWAL_SPARSE_TREE_DEPTH
        );
        assert_eq!(
            plan.encoded_args.merkle_directions.len(),
            super::RENEWAL_SPARSE_TREE_DEPTH,
        );
        assert_eq!(plan.starknet_call.calldata[4], "0x80");
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

    #[test]
    fn renewal_proof_message_hash_binds_statement_roots() {
        let proof_program = "0x0123";
        let verifier = "0x030f8072f3c6a9261704b056875cc0983335f7e95540026bfd359c9ee5c1041d";
        let transcript = "0x34f779a519b7c0ffb1db2f00d7683befa23663c929cbce579c87d4fb0dbb89b";
        let prior_renewal_root = "0x45";
        let renewal_child_root = "0x67";
        let new_renewal_root = "0x89";

        let statement = crate::native_renewal_message_hash(
            verifier,
            transcript,
            prior_renewal_root,
            renewal_child_root,
            new_renewal_root,
        )
        .expect("native renewal statement message hash");
        let direct = crate::renewal_proof_message_hash_from_statement(proof_program, &statement)
            .expect("renewal proof message hash");
        let composed = crate::renewal_proof_message_hash_for_program(
            proof_program,
            verifier,
            transcript,
            prior_renewal_root,
            renewal_child_root,
            new_renewal_root,
        )
        .expect("renewal proof message hash for program");
        let settlement =
            crate::settlement_proof_message_hash_for_program(proof_program, verifier, transcript)
                .expect("settlement proof message hash");

        assert_eq!(direct, composed);
        assert_ne!(direct, settlement);
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
