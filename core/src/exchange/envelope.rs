//! private requests to the operator: a persistent order, a cancellation, a withdrawal or a status
//! lookup, sealed to every private execution key. the plaintext is split into xor shares, one per
//! key, and each share is encrypted with ecdh-p256, hkdf-sha256 and aes-gcm, so reading a request
//! takes every key. the operator must read orders to match them, so its process holds all the
//! keys: the envelope keeps requests from proxies, load balancers and logs, not from the operator.
//! the privacy zylith offers is against the chain and everyone outside the operator.
//!
//! the request's kind travels inside the plaintext, which is padded to one fixed size, so every
//! request looks alike from outside. the plaintext also carries a one-time response key: the
//! operator answers under it with aes-gcm, bound to the request's digest and padded to a size
//! class of its own, so a response shows neither what was asked nor what came back.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use starknet_crypto::Felt;
use zeroize::Zeroizing;

use super::model::*;
use super::transition::NewOrder;
use super::withdrawal::withdrawal_authorization_message;
use crate::ProtocolError;
use crate::crypto::{
    decrypt_encrypted_blob, encrypt_for_private_execution_key, split_into_xor_shares,
};
use crate::types::{EncryptedBlob, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyRegistry};

pub const ENVELOPE_VERSION: u32 = 2;

// the wire limits every party shares: the wallet (through this crate's wasm build) seals within
// them and chunks status lookups by them, and the operator refuses to start with a body limit
// below the largest sealed request.

/// every request plaintext pads to exactly this size; the largest order (four funding notes)
/// and the largest status lookup both fit with room to spare.
pub const REQUEST_PLAINTEXT_BYTES: usize = 4_096;
/// the most execution keys a request is split across.
pub const MAX_EXECUTION_KEYS: usize = 4;
/// the most order ids plus nullifiers one status request asks about; wallets send more as
/// several requests, chunked in order.
pub const MAX_STATUS_ITEMS: usize = 8;
/// the most events one status answer returns per order; a wallet further behind catches up over
/// the following lookups.
pub const MAX_STATUS_EVENTS_PER_ORDER: usize = 2;
/// an upper bound on a serialized sealed request with the most execution keys.
pub const MAX_SEALED_REQUEST_BYTES: usize = 96 * 1_024;
/// every private answer uses one wire size across request kinds and populated status lookups.
pub const RESPONSE_PLAINTEXT_BYTES: usize = 16_384;

/// what a sealed request asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum PrivateRequest {
    Order(OrderRequest),
    Cancel(CancelRequest),
    Withdraw(WithdrawRequest),
    Status(StatusRequest),
}

/// the state of the wallet's orders and withdrawals, asked for together so how many a wallet has
/// in flight stays inside the envelope, up to the status item limit per request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRequest {
    pub orders: Vec<OrderQuery>,
    #[serde(with = "felt_vec_hex_serde")]
    pub nullifiers: Vec<Felt>,
}

/// an order to report on, with the events the wallet already holds left out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderQuery {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    /// only events of later transitions are returned.
    #[serde(default)]
    pub after_seq: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeShare {
    pub key_id: String,
    pub ciphertext: EncryptedBlob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRequest {
    pub version: u32,
    /// sha-256 of the plaintext: binds the shares together, keys idempotent retries and binds
    /// the response.
    pub digest: String,
    pub shares: Vec<EnvelopeShare>,
}

/// the operator's answer, readable only with the request's response key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedResponse {
    pub nonce: String,
    pub ciphertext: String,
}

/// the one-time aes-256 key a request's answer is sealed under.
pub type ResponseKey = Zeroizing<[u8; 32]>;

#[derive(Serialize, Deserialize)]
struct RequestPlaintext {
    request: PrivateRequest,
    response_key: String,
}

/// an opened request and the key its answer is sealed under.
pub struct OpenedRequest {
    pub request: PrivateRequest,
    pub response_key: ResponseKey,
}

#[derive(Serialize, Deserialize)]
struct SharePlaintext {
    digest: String,
    share_index: usize,
    share_count: usize,
    share_hex: String,
}

fn digest_hex(plaintext: &[u8]) -> String {
    hex::encode(Sha256::digest(plaintext))
}

/// pads json with trailing spaces, which json ignores, to the smallest class that fits.
fn pad_json(mut json: Vec<u8>, classes: &[usize]) -> Result<Vec<u8>, ProtocolError> {
    let target = classes
        .iter()
        .copied()
        .find(|class| *class >= json.len())
        .ok_or_else(|| {
            ProtocolError::Crypto("the message exceeds the largest size class".into())
        })?;
    json.resize(target, b' ');
    Ok(json)
}

/// splits a wallet's lookups into status requests within the status item limit, orders first, in
/// the order given, so the same wallet state always yields the same requests.
pub fn chunk_status(status: StatusRequest) -> Vec<StatusRequest> {
    let items = status
        .orders
        .into_iter()
        .map(Ok)
        .chain(status.nullifiers.into_iter().map(Err))
        .collect::<Vec<Result<OrderQuery, Felt>>>();
    if items.is_empty() {
        return vec![];
    }
    items
        .chunks(MAX_STATUS_ITEMS)
        .map(|chunk| StatusRequest {
            orders: chunk.iter().filter_map(|item| item.clone().ok()).collect(),
            nullifiers: chunk.iter().filter_map(|item| item.clone().err()).collect(),
        })
        .collect()
}

pub fn seal_request(
    registry: &PrivateExecutionKeyRegistry,
    request: &PrivateRequest,
) -> Result<(SealedRequest, ResponseKey), ProtocolError> {
    if registry.keys.is_empty() || registry.keys.len() > MAX_EXECUTION_KEYS {
        return Err(ProtocolError::Crypto(format!(
            "the execution key registry must hold 1..={MAX_EXECUTION_KEYS} keys"
        )));
    }
    if let PrivateRequest::Status(status) = request
        && status.orders.len() + status.nullifiers.len() > MAX_STATUS_ITEMS
    {
        return Err(ProtocolError::Crypto(format!(
            "a status request asks about at most {MAX_STATUS_ITEMS} items"
        )));
    }
    let mut response_key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(response_key.as_mut_slice());
    let plaintext = Zeroizing::new(pad_json(
        serde_json::to_vec(&RequestPlaintext {
            request: request.clone(),
            response_key: hex::encode(response_key.as_slice()),
        })?,
        &[REQUEST_PLAINTEXT_BYTES],
    )?);
    let digest = digest_hex(&plaintext);
    let shares = Zeroizing::new(split_into_xor_shares(&plaintext, registry.keys.len()));
    let shares = registry
        .keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let share = Zeroizing::new(serde_json::to_vec(&SharePlaintext {
                digest: digest.clone(),
                share_index: index,
                share_count: registry.keys.len(),
                share_hex: hex::encode(&shares[index]),
            })?);
            Ok(EnvelopeShare {
                key_id: key.key_id.clone(),
                ciphertext: encrypt_for_private_execution_key(
                    &key.key_id,
                    &key.public_key,
                    &share,
                )?,
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    Ok((
        SealedRequest {
            version: ENVELOPE_VERSION,
            digest,
            shares,
        },
        response_key,
    ))
}

pub fn open_request(
    sealed: &SealedRequest,
    keys: &[PrivateExecutionKeyPrivateConfig],
) -> Result<OpenedRequest, ProtocolError> {
    if sealed.version != ENVELOPE_VERSION
        || keys.is_empty()
        || keys.len() > MAX_EXECUTION_KEYS
        || sealed.shares.len() != keys.len()
    {
        return Err(ProtocolError::Crypto(
            "sealed request does not match the execution keys".into(),
        ));
    }
    let mut combined: Option<Zeroizing<Vec<u8>>> = None;
    for key in keys {
        let share = sealed
            .shares
            .iter()
            .find(|share| share.key_id == key.key_id)
            .ok_or_else(|| ProtocolError::Crypto("sealed request is missing a key share".into()))?;
        let plaintext =
            Zeroizing::new(decrypt_encrypted_blob(&key.private_key, &share.ciphertext)?);
        let share: SharePlaintext = serde_json::from_slice(&plaintext)?;
        if share.digest != sealed.digest || share.share_count != keys.len() {
            return Err(ProtocolError::Crypto(
                "sealed request shares disagree".into(),
            ));
        }
        let bytes = Zeroizing::new(hex::decode(&share.share_hex)?);
        combined = Some(match combined {
            None => bytes,
            Some(mut accumulated) => {
                if accumulated.len() != bytes.len() {
                    return Err(ProtocolError::Crypto(
                        "sealed request shares differ in length".into(),
                    ));
                }
                for (left, right) in accumulated.iter_mut().zip(bytes.iter()) {
                    *left ^= right;
                }
                accumulated
            }
        });
    }
    let plaintext = combined.expect("at least one key");
    if plaintext.len() != REQUEST_PLAINTEXT_BYTES || digest_hex(&plaintext) != sealed.digest {
        return Err(ProtocolError::Crypto(
            "sealed request digest mismatch".into(),
        ));
    }
    let opened: RequestPlaintext = serde_json::from_slice(&plaintext)?;
    let key_bytes = Zeroizing::new(hex::decode(&opened.response_key)?);
    let response_key = Zeroizing::new(
        <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| ProtocolError::Crypto("the response key is not 32 bytes".into()))?,
    );
    Ok(OpenedRequest {
        request: opened.request,
        response_key,
    })
}

/// seals the operator's json answer under the request's response key, bound to its digest.
pub fn seal_response(
    response_key: &[u8; 32],
    request_digest: &str,
    response: &serde_json::Value,
) -> Result<SealedResponse, ProtocolError> {
    let plaintext = pad_json(serde_json::to_vec(response)?, &[RESPONSE_PLAINTEXT_BYTES])?;
    let cipher = Aes256Gcm::new_from_slice(response_key)
        .map_err(|_| ProtocolError::Crypto("bad response key".into()))?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: request_digest.as_bytes(),
            },
        )
        .map_err(|_| ProtocolError::Crypto("response encryption failed".into()))?;
    Ok(SealedResponse {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn open_response(
    response_key: &[u8; 32],
    request_digest: &str,
    sealed: &SealedResponse,
) -> Result<serde_json::Value, ProtocolError> {
    let nonce = hex::decode(&sealed.nonce)?;
    if nonce.len() != 12 {
        return Err(ProtocolError::Crypto("bad response nonce".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(response_key)
        .map_err(|_| ProtocolError::Crypto("bad response key".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &hex::decode(&sealed.ciphertext)?,
                aad: request_digest.as_bytes(),
            },
        )
        .map_err(|_| ProtocolError::Crypto("the response does not open".into()))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// a persistent order as the wallet sends it: its terms, the notes that fund it and the spend
/// key's authorization. the operator adds the notes' membership paths at admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderRequest {
    pub terms: OrderTerms,
    pub funding: Vec<NoteFields>,
    pub authorization: Signature,
}

impl OrderRequest {
    pub fn order_id(&self) -> Felt {
        self.terms.order_id()
    }

    pub fn authorization_message(&self, chain_context: Felt) -> Felt {
        let commitments = self
            .funding
            .iter()
            .map(NoteFields::commitment)
            .collect::<Vec<_>>();
        order_authorization_message(
            chain_context,
            self.order_id(),
            funding_set_commitment(&commitments),
        )
    }

    /// the checks the operator can make without the chain: terms, the pair's minimum size,
    /// funding shape and signature. order sizes stay private to the proof, so the minimum is
    /// enforced here, where every order enters the book.
    pub fn validate(
        &self,
        chain_context: Felt,
        input_asset: Felt,
        min_order_amount: u128,
    ) -> Result<(), ProtocolError> {
        self.terms.validate()?;
        if self.terms.amount < min_order_amount.max(1) {
            return Err(invalid("the order is below the pair's minimum size"));
        }
        if self.funding.is_empty() || self.funding.len() > MAX_FUNDING_NOTES {
            return Err(invalid("an order is funded by 1..=4 notes"));
        }
        let spend_authority = self.funding[0].spend_authority;
        let mut total = 0_u128;
        for note in &self.funding {
            if note.asset_id != input_asset || note.spend_authority != spend_authority {
                return Err(invalid(
                    "funding notes must be the input asset under one spend key",
                ));
            }
            if note.amount == 0 || note.nonce == 0 || note.blinding == Felt::ZERO {
                return Err(invalid("a funding note is malformed"));
            }
            total = total
                .checked_add(note.amount)
                .ok_or_else(|| invalid("funding overflows"))?;
        }
        if total > super::MAX_ORDER_AMOUNT || (self.terms.sell && total < self.terms.amount) {
            return Err(invalid("order funding is out of range"));
        }
        if !verify_message(
            &spend_authority,
            &self.authorization_message(chain_context),
            &self.authorization,
        ) {
            return Err(invalid("order authorization signature is invalid"));
        }
        Ok(())
    }

    /// the admission the transition proves, once the operator attaches membership paths.
    pub fn into_new_order(self, memberships: Vec<NoteMembership>) -> NewOrder {
        NewOrder {
            funding: self
                .funding
                .into_iter()
                .zip(memberships)
                .map(|(note, membership)| super::transition::FundingNote { note, membership })
                .collect(),
            terms: self.terms,
            authorization: self.authorization,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelRequest {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub signature: Signature,
}

/// a withdrawal as the wallet sends it: the note, its exit and the note's withdraw key's
/// authorization. the operator adds the membership path and proves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub note: NoteFields,
    #[serde(with = "felt_hex_serde")]
    pub exit_commitment: Felt,
    #[serde(with = "felt_hex_serde")]
    pub exit_authority: Felt,
    pub authorization: Signature,
}

impl WithdrawRequest {
    pub fn validate(&self, chain_context: Felt) -> Result<(), ProtocolError> {
        let message = withdrawal_authorization_message(
            chain_context,
            self.note.nullifier(),
            self.exit_commitment,
            self.exit_authority,
        );
        if self.exit_commitment == Felt::ZERO
            || self.exit_authority == Felt::ZERO
            || !verify_message(&self.note.withdraw_authority, &message, &self.authorization)
        {
            return Err(ProtocolError::InvalidWithdrawal(
                "withdrawal authorization is invalid".into(),
            ));
        }
        Ok(())
    }
}
