use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::wallet_crypto::{
    WALLET_KEY_SCHEDULE_ID, WALLET_KEY_SCHEDULE_VERSION, WalletKeyScheduleV2,
    deserialize_wallet_key_schedule_version, encode_context,
};
use crate::{ProtocolError, RecoverySeed, WalletDataError, deserialize_unique_wallet_json};

pub const MAX_WALLET_STATE_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WALLET_STATE_REQUEST_BYTES: usize = MAX_WALLET_STATE_CIPHERTEXT_BYTES - 16 + 256;
const MAX_WALLET_STATE_RECORD_BYTES: usize =
    MAX_WALLET_STATE_CIPHERTEXT_BYTES.div_ceil(3) * 4 + 512;
const ALGORITHM: &str = "AES-256-GCM";
const PURPOSE: &str = "wallet-state";
const AAD_PROTOCOL: &[u8] = b"zylith/local-wallet-state/aad/v2";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletStateRecord {
    #[serde(deserialize_with = "deserialize_wallet_key_schedule_version")]
    pub version: u16,
    #[serde(deserialize_with = "deserialize_wallet_key_schedule_version")]
    pub key_schedule_version: u16,
    pub kdf: String,
    pub algorithm: String,
    pub account_id: String,
    pub purpose: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn migration_required() -> ProtocolError {
    ProtocolError::Crypto("wallet migration required".into())
}

fn invalid_state() -> ProtocolError {
    ProtocolError::Crypto("invalid local wallet state".into())
}

fn too_large() -> ProtocolError {
    ProtocolError::Crypto("local wallet state is too large".into())
}

fn wallet_state_record_size_is_valid(length: usize) -> bool {
    length <= MAX_WALLET_STATE_RECORD_BYTES
}

fn wallet_state_plaintext_size_is_valid(length: usize) -> bool {
    length <= MAX_WALLET_STATE_CIPHERTEXT_BYTES - 16
}

fn unique_state_json(source: &str) -> Result<Value, ProtocolError> {
    let mut decoder = serde_json::Deserializer::from_str(source);
    let value = deserialize_unique_wallet_json(&mut decoder).map_err(|_| invalid_state())?;
    decoder.end().map_err(|_| invalid_state())?;
    Ok(value)
}

fn authenticated_state_json(source: &str) -> Result<Value, WalletDataError> {
    match unique_state_json(source) {
        Ok(value) => Ok(value),
        Err(_) if serde_json::from_str::<Value>(source).is_ok() => {
            Err(WalletDataError::MigrationRequired)
        }
        Err(_) => Err(WalletDataError::DataInvalid),
    }
}

fn decode_base64(value: &str, min: usize, max: usize) -> Result<Vec<u8>, ProtocolError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(too_large());
    }
    let bytes = STANDARD.decode(value).map_err(|_| invalid_state())?;
    if bytes.len() < min || bytes.len() > max || STANDARD.encode(&bytes) != value {
        return Err(invalid_state());
    }
    Ok(bytes)
}

fn validate_metadata(record: &WalletStateRecord) -> Result<(), ProtocolError> {
    if record.version != 2
        || record.key_schedule_version != WALLET_KEY_SCHEDULE_VERSION
        || record.kdf != WALLET_KEY_SCHEDULE_ID
        || record.algorithm != ALGORITHM
        || record.purpose != PURPOSE
        || record.account_id.len() != 64
        || !record
            .account_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(migration_required());
    }
    Ok(())
}

fn wallet_state_aad(record: &WalletStateRecord) -> Result<Vec<u8>, ProtocolError> {
    validate_metadata(record)?;
    let account = hex::decode(&record.account_id).map_err(|_| invalid_state())?;
    encode_context(&[
        AAD_PROTOCOL,
        &record.version.to_be_bytes(),
        &record.key_schedule_version.to_be_bytes(),
        record.kdf.as_bytes(),
        record.algorithm.as_bytes(),
        &account,
        record.purpose.as_bytes(),
    ])
}

/// encrypts strict json with a fresh nonce and a key that stays within the wallet module.
pub fn encrypt_wallet_state(
    seed: &RecoverySeed,
    value_json: &str,
) -> Result<WalletStateRecord, ProtocolError> {
    encrypt_wallet_state_with_nonce(seed, value_json, rand::random())
}

fn encrypt_wallet_state_with_nonce(
    seed: &RecoverySeed,
    value_json: &str,
    nonce: [u8; 12],
) -> Result<WalletStateRecord, ProtocolError> {
    if !wallet_state_plaintext_size_is_valid(value_json.len()) {
        return Err(too_large());
    }
    unique_state_json(value_json)?;
    let schedule = WalletKeyScheduleV2::from_seed(seed);
    let mut record = WalletStateRecord {
        version: 2,
        key_schedule_version: WALLET_KEY_SCHEDULE_VERSION,
        kdf: WALLET_KEY_SCHEDULE_ID.into(),
        algorithm: ALGORITHM.into(),
        account_id: schedule.account_id(),
        purpose: PURPOSE.into(),
        nonce: STANDARD.encode(nonce),
        ciphertext: String::new(),
    };
    let aad = wallet_state_aad(&record)?;
    let key = schedule.wallet_state_key();
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| invalid_state())?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: value_json.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| invalid_state())?;
    record.ciphertext = STANDARD.encode(ciphertext);
    Ok(record)
}

/// decrypts only exact v2 records, rejecting ambiguity before authentication or json return.
pub fn decrypt_wallet_state(
    seed: &RecoverySeed,
    record_json: &str,
) -> Result<Value, ProtocolError> {
    decrypt_wallet_state_classified(seed, record_json).map_err(ProtocolError::from)
}

/// classifies only authenticated, publicly visible format incompatibility as migration.
pub fn decrypt_wallet_state_classified(
    seed: &RecoverySeed,
    record_json: &str,
) -> Result<Value, WalletDataError> {
    if !wallet_state_record_size_is_valid(record_json.len()) {
        return Err(WalletDataError::DataInvalid);
    }
    let value = unique_state_json(record_json).map_err(|_| WalletDataError::DataInvalid)?;
    classify_state_record_shape(&value)?;
    let record: WalletStateRecord =
        serde_json::from_value(value).map_err(|_| WalletDataError::DataInvalid)?;
    let nonce: [u8; 12] = decode_base64(&record.nonce, 12, 12)
        .map_err(|_| WalletDataError::DataInvalid)?
        .try_into()
        .map_err(|_| WalletDataError::DataInvalid)?;
    let ciphertext = decode_base64(&record.ciphertext, 16, MAX_WALLET_STATE_CIPHERTEXT_BYTES)
        .map_err(|_| WalletDataError::DataInvalid)?;
    let schedule = WalletKeyScheduleV2::from_seed(seed);
    if record.account_id != schedule.account_id() {
        return Err(WalletDataError::DataInvalid);
    }
    let aad = wallet_state_aad(&record).map_err(|_| WalletDataError::DataInvalid)?;
    let key = schedule.wallet_state_key();
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| WalletDataError::DataInvalid)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| WalletDataError::DataInvalid)?,
    );
    authenticated_state_json(
        std::str::from_utf8(&plaintext).map_err(|_| WalletDataError::DataInvalid)?,
    )
}

fn classify_state_record_shape(value: &Value) -> Result<(), WalletDataError> {
    const FIELDS: [&str; 8] = [
        "version",
        "key_schedule_version",
        "kdf",
        "algorithm",
        "account_id",
        "purpose",
        "nonce",
        "ciphertext",
    ];
    let object = value.as_object().ok_or(WalletDataError::DataInvalid)?;
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(WalletDataError::MigrationRequired);
    }
    if object.get("version").and_then(Value::as_u64) != Some(2)
        || object.get("key_schedule_version").and_then(Value::as_u64)
            != Some(u64::from(WALLET_KEY_SCHEDULE_VERSION))
        || object.get("kdf").and_then(Value::as_str) != Some(WALLET_KEY_SCHEDULE_ID)
        || object.get("algorithm").and_then(Value::as_str) != Some(ALGORITHM)
        || object.get("purpose").and_then(Value::as_str) != Some(PURPOSE)
    {
        return Err(WalletDataError::MigrationRequired);
    }
    let account = object
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or(WalletDataError::DataInvalid)?;
    if account.len() != 64
        || !account
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WalletDataError::DataInvalid);
    }
    if object.get("nonce").and_then(Value::as_str).is_none()
        || object.get("ciphertext").and_then(Value::as_str).is_none()
    {
        return Err(WalletDataError::DataInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &str = "00000007000000207a796c6974682f6c6f63616c2d77616c6c65742d73746174652f6161642f76320000000200020000000200020000001c7a796c6974682d77616c6c65742d686b64662d7368613235362d76320000000b4145532d3235362d47434d00000020572a6b66c69d65e185bb78512b704b47be6d75b2595df4aeea988bffaa9889be0000000c77616c6c65742d7374617465";

    fn fixture(ciphertext: &str) -> String {
        serde_json::json!({
            "version": 2, "key_schedule_version": 2,
            "kdf": "zylith-wallet-hkdf-sha256-v2", "algorithm": "AES-256-GCM",
            "account_id": "572a6b66c69d65e185bb78512b704b47be6d75b2595df4aeea988bffaa9889be",
            "purpose": "wallet-state", "nonce": "AAECAwQFBgcICQoL", "ciphertext": ciphertext,
        })
        .to_string()
    }

    fn fixture_record() -> WalletStateRecord {
        serde_json::from_str(&fixture(
            "0ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw==",
        ))
        .unwrap()
    }

    #[test]
    fn wallet_state_json_and_base64_preconditions_are_exact() {
        assert_eq!(
            unique_state_json("{} trailing").unwrap_err().to_string(),
            invalid_state().to_string()
        );
        assert_eq!(
            decode_base64("AAECAwQFBgcICQoL", 12, 12).unwrap(),
            (0_u8..12).collect::<Vec<_>>()
        );
        assert_eq!(
            decode_base64("AA==", 12, 12).unwrap_err().to_string(),
            invalid_state().to_string()
        );

        let thirteen = STANDARD.encode((0_u8..13).collect::<Vec<_>>());
        assert_eq!(
            decode_base64(&thirteen, 12, 12).unwrap_err().to_string(),
            too_large().to_string()
        );
        assert_eq!(
            decode_base64(&"!".repeat(17), 12, 12)
                .unwrap_err()
                .to_string(),
            too_large().to_string()
        );
    }

    #[test]
    fn wallet_state_metadata_validation_rejects_every_field_and_boundary() {
        let valid = fixture_record();
        validate_metadata(&valid).unwrap();

        for version in [1, 3] {
            let mut record = fixture_record();
            record.version = version;
            assert_eq!(
                validate_metadata(&record).unwrap_err().to_string(),
                migration_required().to_string()
            );
        }
        for version in [1, 3] {
            let mut record = fixture_record();
            record.key_schedule_version = version;
            assert_eq!(
                validate_metadata(&record).unwrap_err().to_string(),
                migration_required().to_string()
            );
        }
        for (field, values) in [
            ("kdf", ["a", "z"]),
            ("algorithm", ["A", "Z"]),
            ("purpose", ["a", "z"]),
        ] {
            for value in values {
                let mut record = fixture_record();
                match field {
                    "kdf" => record.kdf = value.into(),
                    "algorithm" => record.algorithm = value.into(),
                    "purpose" => record.purpose = value.into(),
                    _ => unreachable!(),
                }
                assert_eq!(
                    validate_metadata(&record).unwrap_err().to_string(),
                    migration_required().to_string()
                );
                assert_eq!(
                    wallet_state_aad(&record).unwrap_err().to_string(),
                    migration_required().to_string()
                );
            }
        }
        for account in [
            "a".repeat(63),
            "a".repeat(65),
            format!("{}G", "a".repeat(63)),
        ] {
            let mut record = fixture_record();
            record.account_id = account;
            assert_eq!(
                validate_metadata(&record).unwrap_err().to_string(),
                migration_required().to_string()
            );
            assert_eq!(
                wallet_state_aad(&record).unwrap_err().to_string(),
                migration_required().to_string()
            );
        }
    }

    #[test]
    fn wallet_state_serialized_record_size_boundary_is_exact() {
        assert!(wallet_state_record_size_is_valid(
            MAX_WALLET_STATE_RECORD_BYTES
        ));
        assert!(!wallet_state_record_size_is_valid(
            MAX_WALLET_STATE_RECORD_BYTES + 1
        ));
    }

    #[test]
    fn wallet_state_plaintext_size_boundary_is_exact() {
        assert!(wallet_state_plaintext_size_is_valid(
            MAX_WALLET_STATE_CIPHERTEXT_BYTES - 16
        ));
        assert!(!wallet_state_plaintext_size_is_valid(
            MAX_WALLET_STATE_CIPHERTEXT_BYTES - 15
        ));
    }

    #[test]
    fn wallet_state_shape_classifier_is_closed_and_typed() {
        let valid = serde_json::to_value(fixture_record()).unwrap();
        classify_state_record_shape(&valid).unwrap();

        for (field, values) in [
            ("version", vec![serde_json::json!(1), serde_json::json!(3)]),
            (
                "key_schedule_version",
                vec![serde_json::json!(1), serde_json::json!(3)],
            ),
            ("kdf", vec![serde_json::json!("a"), serde_json::json!("z")]),
            (
                "algorithm",
                vec![serde_json::json!("A"), serde_json::json!("Z")],
            ),
            (
                "purpose",
                vec![serde_json::json!("a"), serde_json::json!("z")],
            ),
        ] {
            for value in values {
                let mut changed = valid.clone();
                changed[field] = value;
                assert_eq!(
                    classify_state_record_shape(&changed).unwrap_err(),
                    WalletDataError::MigrationRequired
                );
            }
        }
        for account in [
            "a".repeat(63),
            "a".repeat(65),
            format!("{}G", "a".repeat(63)),
        ] {
            let mut changed = valid.clone();
            changed["account_id"] = serde_json::json!(account);
            assert_eq!(
                classify_state_record_shape(&changed).unwrap_err(),
                WalletDataError::DataInvalid
            );
        }
        for field in ["nonce", "ciphertext"] {
            let mut changed = valid.clone();
            changed[field] = serde_json::json!(null);
            assert_eq!(
                classify_state_record_shape(&changed).unwrap_err(),
                WalletDataError::DataInvalid
            );
        }
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("nonce");
        assert_eq!(
            classify_state_record_shape(&missing).unwrap_err(),
            WalletDataError::MigrationRequired
        );
        let mut extra = valid;
        extra["extra"] = serde_json::json!(1);
        assert_eq!(
            classify_state_record_shape(&extra).unwrap_err(),
            WalletDataError::MigrationRequired
        );
    }

    #[test]
    fn wallet_state_rejects_an_authenticated_record_for_a_different_account() {
        let seed = RecoverySeed([0; 32]);
        let schedule = WalletKeyScheduleV2::from_seed(&seed);
        let nonce = [0_u8; 12];
        let mut record = fixture_record();
        record.account_id = "11".repeat(32);
        record.nonce = STANDARD.encode(nonce);
        let aad = wallet_state_aad(&record).unwrap();
        let key = schedule.wallet_state_key();
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        record.ciphertext = STANDARD.encode(
            cipher
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: b"{}",
                        aad: &aad,
                    },
                )
                .unwrap(),
        );

        assert_eq!(
            decrypt_wallet_state_classified(&seed, &serde_json::to_string(&record).unwrap())
                .unwrap_err(),
            WalletDataError::DataInvalid
        );

        record.account_id = "ff".repeat(32);
        let aad = wallet_state_aad(&record).unwrap();
        record.ciphertext = STANDARD.encode(
            cipher
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: b"{}",
                        aad: &aad,
                    },
                )
                .unwrap(),
        );
        assert_eq!(
            decrypt_wallet_state_classified(&seed, &serde_json::to_string(&record).unwrap())
                .unwrap_err(),
            WalletDataError::DataInvalid
        );
    }

    #[test]
    fn wallet_state_fixed_nonce_key_aad_ciphertext_known_answer() {
        let seed = RecoverySeed([0; 32]);
        let record = encrypt_wallet_state_with_nonce(
            &seed,
            r#"{"count":1,"orders":["0xabc"]}"#,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        )
        .unwrap();
        assert_eq!(hex::encode(wallet_state_aad(&record).unwrap()), AAD);
        assert_eq!(
            record.ciphertext,
            "0ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw=="
        );
        assert_eq!(record.nonce, "AAECAwQFBgcICQoL");
        assert_eq!(
            decrypt_wallet_state(&seed, &serde_json::to_string(&record).unwrap()).unwrap(),
            serde_json::json!({"count": 1, "orders": ["0xabc"]})
        );
        let second = encrypt_wallet_state_with_nonce(
            &RecoverySeed([1; 32]),
            r#"{"count":1,"orders":["0xabc"]}"#,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        )
        .unwrap();
        assert_eq!(
            hex::encode(wallet_state_aad(&second).unwrap()),
            "00000007000000207a796c6974682f6c6f63616c2d77616c6c65742d73746174652f6161642f76320000000200020000000200020000001c7a796c6974682d77616c6c65742d686b64662d7368613235362d76320000000b4145532d3235362d47434d000000203142846eff7f5cd3bea9c020fcf9eb1e07554647daa520b0d065a0ac86292bc00000000c77616c6c65742d7374617465"
        );
        assert_eq!(
            second.ciphertext,
            "0Fea+jQNpAfQDi/FLCgrc6enXUkatdiE/dlhf4ZnVCNVm2zsDRX1t3iXpoadIQ=="
        );
    }

    #[test]
    fn wallet_state_rejects_every_metadata_tamper_and_a_different_seed() {
        let seed = RecoverySeed([0; 32]);
        let original: serde_json::Value = serde_json::from_str(&fixture(
            "0ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw==",
        ))
        .unwrap();
        for (field, value) in [
            ("version", serde_json::json!(1)),
            ("key_schedule_version", serde_json::json!(3)),
            ("kdf", serde_json::json!("other")),
            ("algorithm", serde_json::json!("AES-GCM")),
            ("purpose", serde_json::json!("orders")),
            ("account_id", serde_json::json!("11".repeat(32))),
            ("nonce", serde_json::json!("AAAAAAAAAAAAAAAA")),
        ] {
            let mut record = original.clone();
            record[field] = value;
            assert!(
                decrypt_wallet_state(&seed, &record.to_string()).is_err(),
                "{field}"
            );
        }
        assert!(decrypt_wallet_state(&RecoverySeed([1; 32]), &original.to_string()).is_err());
    }

    #[test]
    fn wallet_state_rejects_missing_extra_legacy_future_and_duplicate_fields() {
        let seed = RecoverySeed([0; 32]);
        let original = fixture("0ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw==");
        let value: serde_json::Value = serde_json::from_str(&original).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut record = value.clone();
            record.as_object_mut().unwrap().remove(field);
            assert!(
                decrypt_wallet_state(&seed, &record.to_string()).is_err(),
                "missing {field}"
            );
        }
        for raw in [
            original.replace("{", r#"{"extra":1,"#),
            original.replace("{", r#"{"version":2,"#),
            original.replace("{", r#"{"key_schedule_\u0076ersion":2,"#),
        ] {
            assert!(decrypt_wallet_state(&seed, &raw).is_err());
        }
        for version in [
            serde_json::Value::Null,
            serde_json::json!(1),
            serde_json::json!(3),
            serde_json::json!("2"),
            serde_json::json!(2.0),
        ] {
            let mut record = value.clone();
            record["version"] = version;
            assert!(
                decrypt_wallet_state(&seed, &record.to_string())
                    .unwrap_err()
                    .to_string()
                    .contains("migration required")
            );
        }
    }

    #[test]
    fn wallet_state_rejects_recursive_plain_and_escaped_duplicates_before_encrypt_and_after_decrypt()
     {
        let seed = RecoverySeed([0; 32]);
        for raw in [
            r#"{"outer":{"a":1,"a":2}}"#,
            r#"[{"outer":{"a":1,"\u0061":2}}]"#,
        ] {
            assert!(encrypt_wallet_state(&seed, raw).is_err());
        }
        for ciphertext in [
            "0ejCSerYBn0UhfjWldBjuuX36wDYhRywfgCG3upu9IFkRx5YHPTH",
            "0ejCSerYBn0UhfjWldBjuuXKvArazlC9Y8qJHFRVg+e8098WxDTmNkzpkXw=",
        ] {
            assert!(decrypt_wallet_state(&seed, &fixture(ciphertext)).is_err());
        }
    }

    #[test]
    fn wallet_state_checks_canonical_base64_tag_only_and_zero_length_edges() {
        let seed = RecoverySeed([0; 32]);
        assert_eq!(
            decrypt_wallet_state(&seed, &fixture("xL/BUBX4xxFLJaJBtQTqZqB5V00=")).unwrap(),
            serde_json::Value::Null
        );
        for ciphertext in [
            "",
            "AA==",
            "!!!!",
            "wmEkrYjYFaD3gVPguPb7Xg==",
            "xL/BUBX4xxFLJaJBtQTqZqB5V00",
            "xL/BUBX4xxFLJaJBtQTqZqB5V01=",
            " xL/BUBX4xxFLJaJBtQTqZqB5V00=",
        ] {
            assert!(
                decrypt_wallet_state(&seed, &fixture(ciphertext)).is_err(),
                "{ciphertext}"
            );
        }
    }

    #[test]
    fn wallet_state_rejects_oversized_json_and_ciphertext_before_decode() {
        let seed = RecoverySeed([0; 32]);
        let maximum = format!("\"{}\"", "a".repeat(MAX_WALLET_STATE_CIPHERTEXT_BYTES - 18));
        let record = encrypt_wallet_state(&seed, &maximum).unwrap();
        assert_eq!(
            decrypt_wallet_state(&seed, &serde_json::to_string(&record).unwrap()).unwrap(),
            serde_json::json!("a".repeat(MAX_WALLET_STATE_CIPHERTEXT_BYTES - 18))
        );
        assert!(
            encrypt_wallet_state(
                &seed,
                &format!("\"{}\"", "a".repeat(MAX_WALLET_STATE_CIPHERTEXT_BYTES - 17))
            )
            .is_err()
        );
        assert!(
            decrypt_wallet_state(
                &seed,
                &fixture(&"A".repeat(MAX_WALLET_STATE_CIPHERTEXT_BYTES * 2))
            )
            .is_err()
        );
        let valid_record = serde_json::to_string(&record).unwrap();
        let oversized_but_otherwise_valid = format!(
            "{}{}",
            " ".repeat(MAX_WALLET_STATE_RECORD_BYTES + 1 - valid_record.len()),
            valid_record
        );
        assert_eq!(
            oversized_but_otherwise_valid.len(),
            MAX_WALLET_STATE_RECORD_BYTES + 1
        );
        assert!(decrypt_wallet_state(&seed, &oversized_but_otherwise_valid).is_err());
        let unicode_maximum = format!(
            "\"{}\"",
            "é".repeat((MAX_WALLET_STATE_CIPHERTEXT_BYTES - 18) / 2)
        );
        let record = encrypt_wallet_state(&seed, &unicode_maximum).unwrap();
        assert_eq!(
            STANDARD.decode(&record.ciphertext).unwrap().len(),
            MAX_WALLET_STATE_CIPHERTEXT_BYTES
        );
        let unicode_oversized =
            format!("\"{}\"", "é".repeat(MAX_WALLET_STATE_CIPHERTEXT_BYTES / 2));
        assert!(encrypt_wallet_state(&seed, &unicode_oversized).is_err());
    }

    #[test]
    fn wallet_state_fresh_nonces_and_authentication_failure() {
        let seed = RecoverySeed([0; 32]);
        let first = encrypt_wallet_state(&seed, "{}").unwrap();
        let second = encrypt_wallet_state(&seed, "{}").unwrap();
        assert_ne!(first.nonce, second.nonce);
        let mut damaged: serde_json::Value = serde_json::from_str(&fixture(
            "0ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw==",
        ))
        .unwrap();
        damaged["ciphertext"] =
            serde_json::json!("1ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw==");
        assert!(decrypt_wallet_state(&seed, &damaged.to_string()).is_err());
    }

    #[test]
    fn wallet_state_classification_distinguishes_incompatibility_from_invalid_data() {
        let seed = RecoverySeed([0; 32]);
        let original = fixture("0ejOU+vTAH0Uz/aV2Jg287Xl6wCx2lHnOJqXQ+2AQhbkByXGLlXYbcUE+qj8Iw==");
        let mut incompatible: Value = serde_json::from_str(&original).unwrap();
        incompatible["version"] = serde_json::json!(1);
        assert_eq!(
            decrypt_wallet_state_classified(&seed, &incompatible.to_string()).unwrap_err(),
            crate::WalletDataError::MigrationRequired
        );
        incompatible = serde_json::from_str(&original).unwrap();
        incompatible["kdf"] = serde_json::json!("zylith-wallet-hkdf-sha256-v1");
        assert_eq!(
            decrypt_wallet_state_classified(&seed, &incompatible.to_string()).unwrap_err(),
            crate::WalletDataError::MigrationRequired
        );

        for invalid in [
            "{".to_owned(),
            "null".to_owned(),
            original.replace("{", r#"{"version":2,"#),
            original.replace("AAECAwQFBgcICQoL", "not-base64"),
        ] {
            assert_eq!(
                decrypt_wallet_state_classified(&seed, &invalid).unwrap_err(),
                crate::WalletDataError::DataInvalid
            );
        }
        assert_eq!(
            decrypt_wallet_state_classified(&RecoverySeed([1; 32]), &original).unwrap_err(),
            crate::WalletDataError::DataInvalid
        );
    }
}
