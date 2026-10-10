use zylith_core::{
    RecoverySeed, WalletDataError, decrypt_wallet_state_classified, encrypt_wallet_state,
};

#[test]
fn future_wallet_state_versions_and_kdfs_are_classified_as_migration_required() {
    let seed = RecoverySeed::from_hex(&"5a".repeat(32)).unwrap();
    let record = encrypt_wallet_state(&seed, r#"{"orders":[]}"#).unwrap();
    let encoded = serde_json::to_value(record).unwrap();

    for (field, future_value) in [
        ("version", serde_json::json!(3)),
        ("kdf", serde_json::json!("zylith-wallet-hkdf-sha256-v3")),
    ] {
        let mut future = encoded.clone();
        future[field] = future_value;
        assert_eq!(
            decrypt_wallet_state_classified(&seed, &future.to_string()).unwrap_err(),
            WalletDataError::MigrationRequired,
            "{field}"
        );
    }
}
