use std::str::FromStr;

use serde::Serialize;
use sha2::{Digest, Sha256};
use starknet_crypto::{Felt, poseidon_hash, poseidon_hash_many};

use crate::ProtocolError;

pub fn tagged_commitment_sha256<T: Serialize>(
    tag: &str,
    value: &T,
) -> Result<String, ProtocolError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(tagged_sha256_hex(tag, &encoded))
}

pub fn tagged_field_hex<T: Serialize>(tag: &str, value: &T) -> Result<String, ProtocolError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(field_hex_from_bytes(tagged_sha256_bytes(tag, &encoded)))
}

pub fn domain_felt(tag: &str) -> Felt {
    let bytes = tagged_sha256_bytes("zylith/poseidon-domain", tag.as_bytes());
    felt_from_bytes(bytes)
}

pub fn domain_felt_hex(tag: &str) -> String {
    felt_hex(&domain_felt(tag))
}

pub fn encode_starknet_felt(kind: &str, value: &str) -> String {
    field_hex_from_bytes(tagged_sha256_bytes(
        "zylith/starknet-felt",
        format!("{kind}:{value}").as_bytes(),
    ))
}

pub fn normalize_felt_hex(value: &str) -> Result<String, ProtocolError> {
    felt_from_hex_str(value).map(|felt| felt_hex(&felt))
}

pub fn felt_from_hex_str(value: &str) -> Result<Felt, ProtocolError> {
    let normalized = if value.starts_with("0x") {
        value.to_string()
    } else {
        format!("0x{value}")
    };

    Felt::from_str(&normalized)
        .map_err(|err| ProtocolError::Crypto(format!("invalid felt hex {normalized}: {err}")))
}

pub fn field_from_u64(value: u64) -> Felt {
    Felt::from(value)
}

pub fn field_from_u128(value: u128) -> Felt {
    Felt::from(value)
}

pub fn field_from_bool(value: bool) -> Felt {
    if value { Felt::ONE } else { Felt::ZERO }
}

pub fn poseidon_hash_hex(inputs: &[Felt]) -> String {
    felt_hex(&poseidon_hash_many(inputs))
}

pub fn poseidon_chain_hex(seed: Felt, inputs: &[Felt]) -> String {
    let mut state = seed;
    for input in inputs {
        state = poseidon_hash(state, *input);
    }
    felt_hex(&state)
}

pub fn ordered_felt_list_commitment(
    domain_tag: &str,
    values: &[String],
) -> Result<String, ProtocolError> {
    let mut state = domain_felt(domain_tag);
    state = poseidon_hash(state, Felt::from(values.len() as u64));
    for value in values {
        state = poseidon_hash(state, felt_from_hex_str(&normalize_felt_hex(value)?)?);
    }
    Ok(felt_hex(&state))
}

pub fn felt_hex(value: &Felt) -> String {
    format!("{value:#x}")
}

pub fn tagged_sha256_hex(tag: &str, data: &[u8]) -> String {
    hex::encode(tagged_sha256_bytes(tag, data))
}

pub fn tagged_sha256_bytes(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

fn field_hex_from_bytes(mut bytes: [u8; 32]) -> String {
    bytes[0] &= 0x03;
    felt_hex(&felt_from_bytes(bytes))
}

fn felt_from_bytes(bytes: [u8; 32]) -> Felt {
    Felt::from_bytes_be(&bytes)
}
