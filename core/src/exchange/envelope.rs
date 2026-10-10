//! private requests to the operator: a persistent order, a cancellation, a withdrawal or a status
//! lookup, sealed to one active x25519 execution key with the pinned hpke profile. the envelope
//! keeps requests from proxies, load balancers and logs, not from the operator. the privacy
//! zylith offers is against the chain and everyone outside the operator.
//!
//! the request's kind travels inside the plaintext, which is padded to one fixed size, so every
//! request looks alike from outside. the plaintext also carries a response root: every operator
//! answer derives a fresh aes-gcm subkey from it and a random salt, binds the request digest, and
//! pads to a size class of its own, so a response shows neither what was asked nor what came back.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::ToPrimitive;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use starknet_crypto::Felt;
use zeroize::Zeroizing;

use super::model::*;
use super::transition::NewOrder;
use super::withdrawal::withdrawal_authorization_message;
use crate::ProtocolError;
use crate::private_envelope::{
    HPKE_ENVELOPE_VERSION, HPKE_PROFILE_ID, PrivateEnvelopeContext, open_hpke, seal_hpke,
};
use crate::types::{PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyRegistry};

pub const ENVELOPE_VERSION: u32 = HPKE_ENVELOPE_VERSION as u32;

// the wire limits every party shares: the wallet (through this crate's wasm build) seals within
// them and chunks status lookups by them, and the operator refuses to start with a body limit
// below the largest sealed request.

/// every request plaintext pads to exactly this size; the largest order (four funding notes)
/// and the largest status lookup both fit with room to spare.
pub const REQUEST_PLAINTEXT_BYTES: usize = 4_096;
/// the private keyring holds at most active and next execution keys during rotation.
pub const MAX_EXECUTION_KEYS: usize = 2;
/// the most order ids plus nullifiers one status request asks about; wallets send more as
/// several requests, chunked in order.
pub const MAX_STATUS_ITEMS: usize = 8;
/// the most events one status answer returns per order; a wallet further behind catches up over
/// the following lookups.
pub const MAX_STATUS_EVENTS_PER_ORDER: usize = 2;
/// an upper bound on a serialized sealed request with one fixed-size ciphertext.
pub const MAX_SEALED_REQUEST_BYTES: usize = 9 * 1_024;
/// every private answer uses one wire size across request kinds and populated status lookups.
pub const RESPONSE_PLAINTEXT_BYTES: usize = 16_384;
const RESPONSE_ENVELOPE_VERSION: u32 = 3;
const RESPONSE_KEY_INFO_DOMAIN: &[u8] = b"zylith-response-key-hkdf-sha256-v3";
const RESPONSE_AAD_DOMAIN: &[u8] = b"zylith-response-aad-v3";
const RESPONSE_CIPHERTEXT_BYTES: usize = RESPONSE_PLAINTEXT_BYTES + 16;
const WITHDRAWAL_STATUS_DOMAIN: &str = "zylith_withdraw_status_v1";
const REQUEST_INFO_DOMAIN: &[u8] = b"zylith-request-hpke-info-v3";
const REQUEST_AAD_DOMAIN: &[u8] = b"zylith-request-hpke-aad-v3";
const REQUEST_CIPHERTEXT_BYTES: usize = REQUEST_PLAINTEXT_BYTES + 16;

/// what a sealed request asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PrivateRequest {
    Order(OrderRequest),
    Cancel(CancelRequest),
    Withdraw(WithdrawRequest),
    Status(StatusRequest),
}

/// the state of the wallet's orders and withdrawals, asked for together so how many a wallet has
/// in flight stays inside the envelope, up to the status item limit per request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub orders: Vec<OrderQuery>,
    pub withdrawals: Vec<WithdrawalQuery>,
}

/// an order to report on, with the events the wallet already holds left out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderQuery {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    /// only events of later transitions are returned.
    #[serde(default)]
    pub after_seq: u32,
}

/// a private withdrawal lookup authenticated by the note's withdrawal authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalQuery {
    #[serde(with = "felt_hex_serde")]
    pub nullifier: Felt,
    pub authorization: Signature,
}

pub fn withdrawal_status_message(chain_context: Felt, nullifier: Felt) -> Felt {
    sponge(&[
        short_string(WITHDRAWAL_STATUS_DOMAIN),
        chain_context,
        nullifier,
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRequest {
    #[serde(deserialize_with = "deserialize_envelope_version")]
    pub version: u32,
    #[serde(deserialize_with = "deserialize_key_id")]
    pub key_id: String,
    /// sha-256 of the exact padded plaintext; binds the response and supports request idempotency.
    #[serde(deserialize_with = "deserialize_digest")]
    pub digest: String,
    #[serde(deserialize_with = "deserialize_encapsulated_key")]
    pub encapsulated_key: String,
    #[serde(deserialize_with = "deserialize_request_ciphertext")]
    pub ciphertext: String,
}

/// The operator's answer, readable only with a key derived from the request's response root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedResponse {
    #[serde(deserialize_with = "deserialize_response_version")]
    pub version: u32,
    #[serde(deserialize_with = "deserialize_response_salt")]
    pub salt: String,
    #[serde(deserialize_with = "deserialize_response_nonce")]
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_response_ciphertext")]
    pub ciphertext: String,
}

/// the response root embedded in a request. each answer derives a fresh aes-256 key from it.
pub type ResponseKey = Zeroizing<[u8; 32]>;

#[derive(Serialize)]
struct RequestPlaintext<'a> {
    request: &'a PrivateRequest,
    response_key: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenedPlaintext {
    request: PrivateRequest,
    response_key: String,
}

/// an opened request and the root from which each answer derives a fresh sealing key.
pub struct OpenedRequest {
    pub request: PrivateRequest,
    pub response_key: ResponseKey,
}

fn digest_hex(plaintext: &[u8]) -> String {
    hex::encode(Sha256::digest(plaintext))
}

fn canonical_hex(value: &str, bytes: usize, field: &str) -> Result<Vec<u8>, ProtocolError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::Crypto(format!(
            "{field} must be {bytes} bytes of lowercase hex"
        )));
    }
    Ok(hex::decode(value)?)
}

fn private_key_bytes(value: &str) -> Result<Zeroizing<[u8; 32]>, ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::Crypto(
            "execution private key must be 32 bytes of lowercase hex".into(),
        ));
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(value, bytes.as_mut())?;
    Ok(bytes)
}

fn deserialize_hex<'de, D>(deserializer: D, bytes: usize, field: &str) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    canonical_hex(&value, bytes, field).map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_digest<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_hex(deserializer, 32, "request digest")
}

fn deserialize_envelope_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != ENVELOPE_VERSION {
        return Err(serde::de::Error::custom(
            "unsupported sealed request version",
        ));
    }
    Ok(version)
}

fn deserialize_key_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let key_id = String::deserialize(deserializer)?;
    crate::types::validate_execution_key_id(&key_id).map_err(serde::de::Error::custom)?;
    Ok(key_id)
}

fn deserialize_encapsulated_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_hex(deserializer, 32, "encapsulated key")
}

fn deserialize_request_ciphertext<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_hex(deserializer, REQUEST_CIPHERTEXT_BYTES, "request ciphertext")
}

fn deserialize_response_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != RESPONSE_ENVELOPE_VERSION {
        return Err(serde::de::Error::custom(
            "unsupported sealed response version",
        ));
    }
    Ok(version)
}

fn deserialize_response_salt<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_hex(deserializer, 32, "response salt")
}

fn deserialize_response_nonce<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_hex(deserializer, 12, "response nonce")
}

fn deserialize_response_ciphertext<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_hex(
        deserializer,
        RESPONSE_CIPHERTEXT_BYTES,
        "response ciphertext",
    )
}

fn validate_context(context: PrivateEnvelopeContext) -> Result<(), ProtocolError> {
    if context.chain_id == Felt::ZERO || context.deployment_id == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "private envelope chain and deployment ids must be nonzero".into(),
        ));
    }
    Ok(())
}

/// encodes byte parts as a big-endian count followed by big-endian lengths and exact bytes.
fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut encoded =
        Vec::with_capacity(4 + parts.iter().map(|part| 4 + part.len()).sum::<usize>());
    encoded.extend_from_slice(&(parts.len() as u32).to_be_bytes());
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u32).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    encoded
}

fn request_info(key_id: &str, context: PrivateEnvelopeContext) -> Vec<u8> {
    let version = ENVELOPE_VERSION.to_be_bytes();
    let size = (REQUEST_PLAINTEXT_BYTES as u32).to_be_bytes();
    let chain_id = context.chain_id.to_bytes_be();
    let deployment_id = context.deployment_id.to_bytes_be();
    frame(&[
        REQUEST_INFO_DOMAIN,
        &version,
        HPKE_PROFILE_ID.as_bytes(),
        key_id.as_bytes(),
        &size,
        &chain_id,
        &deployment_id,
    ])
}

fn request_aad(digest: &[u8]) -> Vec<u8> {
    frame(&[REQUEST_AAD_DOMAIN, digest])
}

fn response_key_info(digest: &[u8; 32]) -> Vec<u8> {
    let version = RESPONSE_ENVELOPE_VERSION.to_be_bytes();
    let size = (RESPONSE_PLAINTEXT_BYTES as u32).to_be_bytes();
    frame(&[RESPONSE_KEY_INFO_DOMAIN, &version, &size, digest])
}

fn response_aad(digest: &[u8; 32], salt: &[u8; 32]) -> Vec<u8> {
    let version = RESPONSE_ENVELOPE_VERSION.to_be_bytes();
    let size = (RESPONSE_PLAINTEXT_BYTES as u32).to_be_bytes();
    frame(&[RESPONSE_AAD_DOMAIN, &version, &size, digest, salt])
}

fn derive_response_key(
    response_root: &[u8; 32],
    salt: &[u8; 32],
    digest: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ProtocolError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), response_root)
        .expand(&response_key_info(digest), key.as_mut_slice())
        .map_err(|_| ProtocolError::Crypto("response key derivation failed".into()))?;
    Ok(key)
}

/// pads json with trailing spaces, which json ignores, to the smallest class that fits.
fn pad_json(
    mut json: Zeroizing<Vec<u8>>,
    classes: &[usize],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
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
        .chain(status.withdrawals.into_iter().map(Err))
        .collect::<Vec<Result<OrderQuery, WithdrawalQuery>>>();
    if items.is_empty() {
        return vec![];
    }
    items
        .chunks(MAX_STATUS_ITEMS)
        .map(|chunk| StatusRequest {
            orders: chunk.iter().filter_map(|item| item.clone().ok()).collect(),
            withdrawals: chunk.iter().filter_map(|item| item.clone().err()).collect(),
        })
        .collect()
}

pub fn seal_request(
    registry: &PrivateExecutionKeyRegistry,
    context: PrivateEnvelopeContext,
    request: &PrivateRequest,
) -> Result<(SealedRequest, ResponseKey), ProtocolError> {
    validate_context(context)?;
    registry.fingerprint()?;
    if let PrivateRequest::Status(status) = request
        && status.orders.len() + status.withdrawals.len() > MAX_STATUS_ITEMS
    {
        return Err(ProtocolError::Crypto(format!(
            "a status request asks about at most {MAX_STATUS_ITEMS} items"
        )));
    }
    let mut response_key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(response_key.as_mut_slice());
    let response_key_hex = Zeroizing::new(hex::encode(response_key.as_slice()));
    let plaintext = pad_json(
        Zeroizing::new(serde_json::to_vec(&RequestPlaintext {
            request,
            response_key: &response_key_hex,
        })?),
        &[REQUEST_PLAINTEXT_BYTES],
    )?;
    let digest = digest_hex(&plaintext);
    let key = &registry.keys[0];
    let recipient = canonical_hex(&key.public_key, 32, "execution public key")?;
    let digest_bytes = canonical_hex(&digest, 32, "request digest")?;
    let mut rng = rand::rng();
    let (encapsulated_key, ciphertext) = seal_hpke(
        &recipient,
        &request_info(&key.key_id, context),
        &request_aad(&digest_bytes),
        &plaintext,
        &mut rng,
    )?;
    Ok((
        SealedRequest {
            version: ENVELOPE_VERSION,
            key_id: key.key_id.clone(),
            digest,
            encapsulated_key: hex::encode(encapsulated_key),
            ciphertext: hex::encode(ciphertext),
        },
        response_key,
    ))
}

/// opens the same bytes repeatedly; application request-id idempotency handles retries.
pub fn open_request(
    sealed: &SealedRequest,
    context: PrivateEnvelopeContext,
    keys: &[PrivateExecutionKeyPrivateConfig],
) -> Result<OpenedRequest, ProtocolError> {
    validate_context(context)?;
    if sealed.version != ENVELOPE_VERSION || keys.is_empty() || keys.len() > MAX_EXECUTION_KEYS {
        return Err(ProtocolError::Crypto(
            "sealed request does not match the execution keys".into(),
        ));
    }
    let matching = keys
        .iter()
        .filter(|key| key.key_id == sealed.key_id)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(ProtocolError::Crypto(
            "sealed request key id is not configured".into(),
        ));
    }
    let key = matching[0];
    key.canonical_public_key()?;
    let digest = canonical_hex(&sealed.digest, 32, "request digest")?;
    let encapsulated_key = canonical_hex(&sealed.encapsulated_key, 32, "encapsulated key")?;
    let ciphertext = canonical_hex(
        &sealed.ciphertext,
        REQUEST_CIPHERTEXT_BYTES,
        "request ciphertext",
    )?;
    let private_key = private_key_bytes(&key.private_key)?;
    let plaintext = Zeroizing::new(open_hpke(
        private_key.as_slice(),
        &request_info(&sealed.key_id, context),
        &request_aad(&digest),
        &encapsulated_key,
        &ciphertext,
    )?);
    if plaintext.len() != REQUEST_PLAINTEXT_BYTES || digest_hex(&plaintext) != sealed.digest {
        return Err(ProtocolError::Crypto(
            "sealed request digest mismatch".into(),
        ));
    }
    let opened: OpenedPlaintext = serde_json::from_slice(&plaintext)?;
    let response_key_hex = Zeroizing::new(opened.response_key);
    let key_bytes = Zeroizing::new(canonical_hex(&response_key_hex, 32, "response key")?);
    let response_key = Zeroizing::new(
        <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| ProtocolError::Crypto("the response key is not 32 bytes".into()))?,
    );
    Ok(OpenedRequest {
        request: opened.request,
        response_key,
    })
}

/// seals the operator's json answer under a fresh subkey of the request's response root.
pub fn seal_response(
    response_root: &[u8; 32],
    request_digest: &str,
    response: &serde_json::Value,
) -> Result<SealedResponse, ProtocolError> {
    let digest: [u8; 32] = canonical_hex(request_digest, 32, "request digest")?
        .try_into()
        .map_err(|_| ProtocolError::Crypto("request digest is not 32 bytes".into()))?;
    let plaintext = pad_json(
        Zeroizing::new(serde_json::to_vec(response)?),
        &[RESPONSE_PLAINTEXT_BYTES],
    )?;
    let mut salt = [0_u8; 32];
    OsRng.fill_bytes(&mut salt);
    let response_key = derive_response_key(response_root, &salt, &digest)?;
    let cipher = Aes256Gcm::new_from_slice(response_key.as_slice())
        .map_err(|_| ProtocolError::Crypto("bad response key".into()))?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &response_aad(&digest, &salt),
            },
        )
        .map_err(|_| ProtocolError::Crypto("response encryption failed".into()))?;
    Ok(SealedResponse {
        version: RESPONSE_ENVELOPE_VERSION,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn open_response(
    response_root: &[u8; 32],
    request_digest: &str,
    sealed: &SealedResponse,
) -> Result<serde_json::Value, ProtocolError> {
    if sealed.version != RESPONSE_ENVELOPE_VERSION {
        return Err(ProtocolError::Crypto(
            "unsupported sealed response version".into(),
        ));
    }
    let digest: [u8; 32] = canonical_hex(request_digest, 32, "request digest")?
        .try_into()
        .map_err(|_| ProtocolError::Crypto("request digest is not 32 bytes".into()))?;
    let salt: [u8; 32] = canonical_hex(&sealed.salt, 32, "response salt")?
        .try_into()
        .map_err(|_| ProtocolError::Crypto("response salt is not 32 bytes".into()))?;
    let nonce: [u8; 12] = canonical_hex(&sealed.nonce, 12, "response nonce")?
        .try_into()
        .map_err(|_| ProtocolError::Crypto("response nonce is not 12 bytes".into()))?;
    let ciphertext = canonical_hex(
        &sealed.ciphertext,
        RESPONSE_CIPHERTEXT_BYTES,
        "response ciphertext",
    )?;
    let response_key = derive_response_key(response_root, &salt, &digest)?;
    let cipher = Aes256Gcm::new_from_slice(response_key.as_slice())
        .map_err(|_| ProtocolError::Crypto("bad response key".into()))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &response_aad(&digest, &salt),
                },
            )
            .map_err(|_| ProtocolError::Crypto("the response does not open".into()))?,
    );
    if plaintext.len() != RESPONSE_PLAINTEXT_BYTES {
        return Err(ProtocolError::Crypto("the response does not open".into()));
    }
    serde_json::from_slice(&plaintext)
        .map_err(|_| ProtocolError::Crypto("the response plaintext is invalid".into()))
}

#[cfg(test)]
mod sealed_request_frame_tests {
    use super::*;
    use crate::types::{PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry};

    fn decode_parts(bytes: &[u8]) -> Vec<&[u8]> {
        let mut offset = 0;
        let mut next = |length: usize| {
            let start = offset;
            offset += length;
            &bytes[start..offset]
        };
        let count = u32::from_be_bytes(next(4).try_into().unwrap());
        let parts = (0..count)
            .map(|_| {
                let length = u32::from_be_bytes(next(4).try_into().unwrap()) as usize;
                next(length)
            })
            .collect::<Vec<_>>();
        assert_eq!(offset, bytes.len());
        parts
    }

    #[test]
    fn sealed_request_v3_framing_binds_each_binary_field_in_order() {
        let context = PrivateEnvelopeContext {
            chain_id: Felt::ONE,
            deployment_id: Felt::from(2_u8),
        };
        let info = request_info("active", context);
        let parts = decode_parts(&info);
        assert_eq!(parts.len(), 7);
        assert_eq!(parts[0], b"zylith-request-hpke-info-v3");
        assert_eq!(parts[1], [0, 0, 0, 3]);
        assert_eq!(
            parts[2],
            b"DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305/base"
        );
        assert_eq!(parts[3], b"active");
        assert_eq!(parts[4], [0, 0, 16, 0]);
        assert_eq!(parts[5], Felt::ONE.to_bytes_be());
        assert_eq!(parts[6], Felt::from(2_u8).to_bytes_be());
        let digest = [0xa5; 32];
        let aad = request_aad(&digest);
        let parts = decode_parts(&aad);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], b"zylith-request-hpke-aad-v3");
        assert_eq!(parts[1], digest);
    }

    #[test]
    fn sealed_response_v3_key_schedule_and_aad_have_frozen_vectors() {
        let root = [0xab; 32];
        let digest = [0xd1; 32];
        let salt: [u8; 32] =
            hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            hex::encode(
                derive_response_key(&root, &salt, &digest)
                    .unwrap()
                    .as_slice()
            ),
            "ea8e968545afac9bc818918aa846b762c1bd3993270c3433be2c0500647d6c1a"
        );
        let aad = response_aad(&digest, &salt);
        assert_eq!(aad.len(), 118);
        assert_eq!(
            hex::encode(Sha256::digest(aad)),
            "a30c16572c02911878dbaf83891deef37391361916baebb587c15a8c6e54a61f"
        );
    }

    #[test]
    fn decrypted_request_v3_rejects_unknown_fields_at_every_current_schema_layer() {
        let note = NoteFields {
            asset_id: Felt::ONE,
            amount: 1,
            owner_public_key: Felt::ONE,
            spend_authority: Felt::ONE,
            withdraw_authority: Felt::ONE,
            blinding: Felt::ONE,
            nonce: 1,
            metadata_commitment: Felt::ONE,
        };
        let signature = Signature {
            r: Felt::ONE,
            s: Felt::ONE,
        };
        let order = PrivateRequest::Order(OrderRequest {
            terms: OrderTerms {
                pair_id: Felt::ONE,
                sell: true,
                external: false,
                amount: 1,
                limit: 1,
                expiry_ms: 1,
                owner: OrderOwner {
                    owner_public_key: Felt::ONE,
                    spend_authority: Felt::ONE,
                    withdraw_authority: Felt::ONE,
                    cancel_authority: Felt::ONE,
                    nonce: Felt::ONE,
                },
            },
            funding: vec![note.clone()],
            authorization: signature,
        });
        let cancel = PrivateRequest::Cancel(CancelRequest {
            order_id: Felt::ONE,
            signature,
        });
        let withdraw = PrivateRequest::Withdraw(WithdrawRequest {
            note,
            exit_commitment: Felt::ONE,
            exit_authority: Felt::ONE,
            authorization: signature,
        });
        let status = PrivateRequest::Status(StatusRequest {
            orders: vec![OrderQuery {
                order_id: Felt::ONE,
                after_seq: 0,
            }],
            withdrawals: vec![WithdrawalQuery {
                nullifier: Felt::ONE,
                authorization: signature,
            }],
        });
        let wrapper = |request: &PrivateRequest| {
            serde_json::json!({
                "request": request,
                "response_key": "00".repeat(32),
            })
        };
        let reject = |mut value: serde_json::Value, path: &[&str]| {
            let mut current = &mut value;
            for field in path {
                current = if let Ok(index) = field.parse::<usize>() {
                    &mut current[index]
                } else {
                    &mut current[*field]
                };
            }
            current["unexpected"] = serde_json::json!(true);
            assert!(serde_json::from_value::<OpenedPlaintext>(value).is_err());
        };

        reject(wrapper(&status), &[]);
        reject(wrapper(&status), &["request"]);
        reject(wrapper(&status), &["request", "body"]);
        reject(wrapper(&status), &["request", "body", "orders", "0"]);
        reject(wrapper(&status), &["request", "body", "withdrawals", "0"]);
        reject(wrapper(&order), &["request", "body"]);
        reject(wrapper(&order), &["request", "body", "terms"]);
        reject(wrapper(&order), &["request", "body", "terms", "owner"]);
        reject(wrapper(&order), &["request", "body", "funding", "0"]);
        reject(wrapper(&order), &["request", "body", "authorization"]);
        reject(wrapper(&cancel), &["request", "body"]);
        reject(wrapper(&cancel), &["request", "body", "signature"]);
        reject(wrapper(&withdraw), &["request", "body"]);
        reject(wrapper(&withdraw), &["request", "body", "note"]);
        reject(wrapper(&withdraw), &["request", "body", "authorization"]);

        let escaped_unknown = serde_json::to_string(&wrapper(&status))
            .unwrap()
            .replace("\"orders\":", "\"un\\u006bnown\":true,\"orders\":");
        assert!(serde_json::from_str::<OpenedPlaintext>(&escaped_unknown).is_err());
        let duplicate = serde_json::to_string(&wrapper(&status)).unwrap().replace(
            "\"response_key\":",
            "\"respon\\u0073e_key\":\"00\",\"response_key\":",
        );
        assert!(serde_json::from_str::<OpenedPlaintext>(&duplicate).is_err());
    }

    #[test]
    fn sealed_response_v3_never_returns_decrypted_plaintext_in_parse_errors() {
        let response_root = [0xab; 32];
        let digest = [0xd1; 32];
        let salt = [0xef; 32];
        let nonce = [0x42; 12];
        let marker = "private-response-marker";
        let mut plaintext = Zeroizing::new(marker.as_bytes().to_vec());
        plaintext.resize(RESPONSE_PLAINTEXT_BYTES, b' ');
        let response_key = derive_response_key(&response_root, &salt, &digest).unwrap();
        let cipher = Aes256Gcm::new_from_slice(response_key.as_slice()).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &response_aad(&digest, &salt),
                },
            )
            .unwrap();
        let sealed = SealedResponse {
            version: RESPONSE_ENVELOPE_VERSION,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let error = open_response(&response_root, &hex::encode(digest), &sealed)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "protocol cryptography error: the response plaintext is invalid"
        );
        assert!(!error.contains(marker));
    }

    #[test]
    fn sealed_request_v3_rejects_false_digest_after_successful_hpke_open() {
        let private = PrivateExecutionKeyPrivateConfig {
            key_id: "active".into(),
            algorithm: HPKE_PROFILE_ID.into(),
            private_key: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb".into(),
            public_key: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a".into(),
        };
        let registry = PrivateExecutionKeyRegistry {
            keys: vec![PrivateExecutionKeyPublicConfig {
                key_id: private.key_id.clone(),
                algorithm: private.algorithm.clone(),
                public_key: private.public_key.clone(),
            }],
        };
        let context = PrivateEnvelopeContext {
            chain_id: Felt::ONE,
            deployment_id: Felt::from(2_u8),
        };
        let request = PrivateRequest::Status(StatusRequest::default());
        let (sealed, _) = seal_request(&registry, context, &request).unwrap();
        let private_bytes = Zeroizing::new(hex::decode(&private.private_key).unwrap());
        let public_bytes = hex::decode(&private.public_key).unwrap();
        let original_digest = hex::decode(&sealed.digest).unwrap();
        let info = request_info(&sealed.key_id, context);
        let plaintext = Zeroizing::new(
            open_hpke(
                &private_bytes,
                &info,
                &request_aad(&original_digest),
                &hex::decode(&sealed.encapsulated_key).unwrap(),
                &hex::decode(&sealed.ciphertext).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(plaintext.len(), REQUEST_PLAINTEXT_BYTES);
        assert_eq!(digest_hex(&plaintext), sealed.digest);

        let mut false_digest = original_digest;
        false_digest[0] ^= 1;
        let (encapsulated_key, ciphertext) = seal_hpke(
            &public_bytes,
            &info,
            &request_aad(&false_digest),
            &plaintext,
            &mut rand::rng(),
        )
        .unwrap();
        let forged = SealedRequest {
            digest: hex::encode(&false_digest),
            encapsulated_key: hex::encode(&encapsulated_key),
            ciphertext: hex::encode(&ciphertext),
            ..sealed
        };
        assert_eq!(
            open_hpke(
                &private_bytes,
                &info,
                &request_aad(&false_digest),
                &encapsulated_key,
                &ciphertext,
            )
            .unwrap(),
            *plaintext,
        );
        let error = match open_request(&forged, context, &[private]) {
            Ok(_) => panic!("false digest was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("sealed request digest mismatch"));
    }
}

/// a persistent order as the wallet sends it: its terms, the notes that fund it and the spend
/// key's authorization. the operator adds the notes' membership paths at admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        min_order_quote_amount: u128,
        price_base_scale: u128,
    ) -> Result<(), ProtocolError> {
        self.terms.validate()?;
        if self.terms.amount < min_order_amount.max(1) {
            return Err(invalid("the order is below the pair's minimum size"));
        }
        if price_base_scale == 0 || min_order_quote_amount == 0 {
            return Err(invalid("the pair's order-value policy is invalid"));
        }
        if self.funding.is_empty() || self.funding.len() > MAX_FUNDING_NOTES {
            return Err(invalid("an order is funded by 1..=4 notes"));
        }
        let spend_authority = self.funding[0].spend_authority;
        let mut total = 0_u128;
        let mut commitments = std::collections::BTreeSet::new();
        let mut nullifiers = std::collections::BTreeSet::new();
        for note in &self.funding {
            if note.asset_id != input_asset || note.spend_authority != spend_authority {
                return Err(invalid(
                    "funding notes must be the input asset under one spend key",
                ));
            }
            if note.amount == 0 || note.nonce == 0 || note.blinding == Felt::ZERO {
                return Err(invalid("a funding note is malformed"));
            }
            if !commitments.insert(note.commitment().to_bytes_be())
                || !nullifiers.insert(note.nullifier().to_bytes_be())
            {
                return Err(invalid("an order cannot use the same funding note twice"));
            }
            total = total
                .checked_add(note.amount)
                .ok_or_else(|| invalid("funding overflows"))?;
        }
        let quote_value = (BigUint::from(self.terms.amount) * BigUint::from(self.terms.limit))
            .div_ceil(&BigUint::from(price_base_scale))
            .to_u128()
            .ok_or_else(|| invalid("the order value is out of range"))?;
        let required_funding = if self.terms.sell {
            self.terms.amount
        } else {
            quote_value
        };
        if total > super::MAX_ORDER_AMOUNT
            || total < required_funding
            || quote_value < min_order_quote_amount
        {
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
    pub fn try_into_new_order(
        self,
        memberships: Vec<NoteMembership>,
    ) -> Result<NewOrder, ProtocolError> {
        if self.funding.len() != memberships.len() {
            return Err(invalid(
                "funding notes and memberships must have equal cardinality",
            ));
        }
        Ok(NewOrder {
            funding: self
                .funding
                .into_iter()
                .zip(memberships)
                .map(|(note, membership)| super::transition::FundingNote { note, membership })
                .collect(),
            terms: self.terms,
            authorization: self.authorization,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub signature: Signature,
}

/// a withdrawal as the wallet sends it: the note, its exit and the note's withdraw key's
/// authorization. the operator adds the membership path and proves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
