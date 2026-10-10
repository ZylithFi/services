use crate::{
    PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry,
};
use hpke::{Deserializable, Kem, Serializable};
use starknet_crypto::Felt;

fn envelope_context() -> crate::private_envelope::PrivateEnvelopeContext {
    crate::private_envelope::PrivateEnvelopeContext {
        chain_id: Felt::from(0x534e5f5345504f4c4941_u128),
        deployment_id: Felt::from(0x123_u32),
    }
}

use super::fixtures::*;
use super::*;

#[test]
fn sealed_request_v3_uses_one_x25519_recipient() {
    let private = PrivateExecutionKeyPrivateConfig {
        key_id: "active".into(),
        algorithm: crate::private_envelope::HPKE_PROFILE_ID.into(),
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
    let request = PrivateRequest::Status(StatusRequest::default());
    let (sealed, _) = seal_request(&registry, envelope_context(), &request).unwrap();
    assert_eq!(sealed.version, 3);
    assert_eq!(sealed.key_id, "active");
    assert_eq!(sealed.encapsulated_key.len(), 64);
    assert_eq!(sealed.ciphertext.len(), 2 * (REQUEST_PLAINTEXT_BYTES + 16));
    assert_eq!(
        open_request(&sealed, envelope_context(), &[private])
            .unwrap()
            .request,
        request
    );
}

#[test]
fn sealed_request_v3_all_four_variants_round_trip() {
    let registry = registry_of(1);
    let key = sealed_test_key("execution-key-0", 1);
    let owner = user(3);
    let note = deposit(&owner, BASE, 40, 17);
    let mut notes = Notes::default();
    notes.add_deposit(&note);
    let new = new_order(
        &notes,
        &owner,
        true,
        true,
        40,
        95,
        std::slice::from_ref(&note),
    );
    let order = PrivateRequest::Order(OrderRequest {
        terms: new.terms,
        funding: vec![note.clone()],
        authorization: new.authorization,
    });
    let cancel = PrivateRequest::Cancel(CancelRequest {
        order_id: Felt::from(9_u8),
        signature: Signature {
            r: Felt::ONE,
            s: Felt::ONE,
        },
    });
    let exit = Felt::from(87_u8);
    let exit_authority = public_key(&Felt::from(43_u8));
    let withdraw = PrivateRequest::Withdraw(WithdrawRequest {
        authorization: sign_message(
            &owner.withdraw_key,
            &withdrawal_authorization_message(
                Felt::from(CHAIN),
                note.nullifier(),
                exit,
                exit_authority,
            ),
        )
        .unwrap(),
        note,
        exit_commitment: exit,
        exit_authority,
    });
    let status = PrivateRequest::Status(StatusRequest {
        orders: vec![OrderQuery {
            order_id: Felt::ONE,
            after_seq: 2,
        }],
        withdrawals: vec![],
    });
    for request in [order, cancel, withdraw, status] {
        let (sealed, response_key) = seal_request(&registry, envelope_context(), &request).unwrap();
        assert_eq!(sealed.encapsulated_key.len(), 64);
        assert_eq!(sealed.ciphertext.len(), 2 * (REQUEST_PLAINTEXT_BYTES + 16));
        let opened = open_request(&sealed, envelope_context(), std::slice::from_ref(&key)).unwrap();
        assert_eq!(opened.request, request);
        assert_eq!(*opened.response_key, *response_key);
    }
}

#[test]
fn sealed_request_v3_rejects_every_authenticated_field_change() {
    let registry = registry_of(1);
    let key = sealed_test_key("execution-key-0", 1);
    let next = sealed_test_key("next", 2);
    let request = PrivateRequest::Status(StatusRequest::default());
    let (sealed, _) = seal_request(&registry, envelope_context(), &request).unwrap();
    let mut changed = sealed.clone();
    changed.version = 2;
    assert!(open_request(&changed, envelope_context(), &[key.clone(), next.clone()]).is_err());
    changed = sealed.clone();
    changed.key_id = next.key_id.clone();
    assert!(open_request(&changed, envelope_context(), &[key.clone(), next.clone()]).is_err());
    changed = sealed.clone();
    changed.digest.replace_range(0..2, "00");
    if changed.digest == sealed.digest {
        changed.digest.replace_range(0..2, "01");
    }
    assert!(open_request(&changed, envelope_context(), std::slice::from_ref(&key)).is_err());
    changed = sealed.clone();
    changed.encapsulated_key.replace_range(0..2, "00");
    if changed.encapsulated_key == sealed.encapsulated_key {
        changed.encapsulated_key.replace_range(0..2, "01");
    }
    assert!(open_request(&changed, envelope_context(), std::slice::from_ref(&key)).is_err());
    changed = sealed.clone();
    changed.ciphertext.replace_range(0..2, "00");
    if changed.ciphertext == sealed.ciphertext {
        changed.ciphertext.replace_range(0..2, "01");
    }
    assert!(open_request(&changed, envelope_context(), std::slice::from_ref(&key)).is_err());

    let mut context = envelope_context();
    context.chain_id += Felt::ONE;
    assert!(open_request(&sealed, context, std::slice::from_ref(&key)).is_err());
    context = envelope_context();
    context.deployment_id += Felt::ONE;
    assert!(open_request(&sealed, context, std::slice::from_ref(&key)).is_err());
    context = envelope_context();
    std::mem::swap(&mut context.chain_id, &mut context.deployment_id);
    assert!(open_request(&sealed, context, std::slice::from_ref(&key)).is_err());
    context = envelope_context();
    context.chain_id = Felt::ZERO;
    assert!(seal_request(&registry, context, &request).is_err());
    assert!(open_request(&sealed, context, std::slice::from_ref(&key)).is_err());
    context = envelope_context();
    context.deployment_id = Felt::ZERO;
    assert!(seal_request(&registry, context, &request).is_err());
    assert!(open_request(&sealed, context, std::slice::from_ref(&key)).is_err());
}

#[test]
fn sealed_request_v3_only_opens_with_matching_configured_key_and_allows_retry() {
    let registry = registry_of(1);
    let key = sealed_test_key("execution-key-0", 1);
    let other = sealed_test_key("other", 2);
    let request = PrivateRequest::Status(StatusRequest::default());
    let (sealed, _) = seal_request(&registry, envelope_context(), &request).unwrap();
    assert!(open_request(&sealed, envelope_context(), std::slice::from_ref(&other)).is_err());
    let mut wrong = other.clone();
    wrong.key_id = key.key_id.clone();
    assert!(open_request(&sealed, envelope_context(), &[wrong]).is_err());
    assert!(open_request(&sealed, envelope_context(), &[key.clone(), key.clone()]).is_err());
    assert_eq!(
        open_request(&sealed, envelope_context(), &[other, key.clone()])
            .unwrap()
            .request,
        request
    );
    assert_eq!(
        open_request(&sealed, envelope_context(), std::slice::from_ref(&key))
            .unwrap()
            .request,
        request
    );
    assert_eq!(
        open_request(&sealed, envelope_context(), std::slice::from_ref(&key))
            .unwrap()
            .request,
        request
    );
}

#[test]
fn rotation_overlap_opens_both_key_ids_then_retirement_rejects_old_id() {
    let old = sealed_test_key("old", 1);
    let new = sealed_test_key("new", 2);
    let request = PrivateRequest::Status(StatusRequest::default());
    let old_registry = PrivateExecutionKeyRegistry {
        keys: vec![PrivateExecutionKeyPublicConfig {
            key_id: old.key_id.clone(),
            algorithm: old.algorithm.clone(),
            public_key: old.public_key.clone(),
        }],
    };
    let new_registry = PrivateExecutionKeyRegistry {
        keys: vec![PrivateExecutionKeyPublicConfig {
            key_id: new.key_id.clone(),
            algorithm: new.algorithm.clone(),
            public_key: new.public_key.clone(),
        }],
    };
    let (old_sealed, _) = seal_request(&old_registry, envelope_context(), &request).unwrap();
    let (new_sealed, _) = seal_request(&new_registry, envelope_context(), &request).unwrap();
    let overlap = [old.clone(), new.clone()];
    assert_eq!(
        open_request(&old_sealed, envelope_context(), &overlap)
            .unwrap()
            .request,
        request
    );
    assert_eq!(
        open_request(&new_sealed, envelope_context(), &overlap)
            .unwrap()
            .request,
        request
    );
    assert!(open_request(&old_sealed, envelope_context(), &[new]).is_err());
}

#[test]
fn sealed_request_v3_rejects_noncanonical_wire_and_unknown_fields() {
    let registry = registry_of(1);
    let key = sealed_test_key("execution-key-0", 1);
    let (sealed, _) = seal_request(
        &registry,
        envelope_context(),
        &PrivateRequest::Status(StatusRequest::default()),
    )
    .unwrap();
    let original = serde_json::to_value(&sealed).unwrap();
    for (field, value) in [
        ("digest", serde_json::json!("AA".repeat(32))),
        ("digest", serde_json::json!("00")),
        ("encapsulated_key", serde_json::json!("FF".repeat(32))),
        ("encapsulated_key", serde_json::json!("00")),
        (
            "ciphertext",
            serde_json::json!("AA".repeat(REQUEST_PLAINTEXT_BYTES + 16)),
        ),
        ("ciphertext", serde_json::json!("00")),
    ] {
        let mut wire = original.clone();
        wire[field] = value;
        assert!(serde_json::from_value::<SealedRequest>(wire).is_err());
    }
    let mut wire = original.clone();
    wire["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SealedRequest>(wire).is_err());
    let mut wire = original.clone();
    wire["version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<SealedRequest>(wire).is_err());
    let mut wire = original.clone();
    wire["key_id"] = serde_json::json!("Not-Canonical");
    assert!(serde_json::from_value::<SealedRequest>(wire).is_err());
    let mut malformed = sealed.clone();
    malformed.ciphertext = "gg".repeat(REQUEST_PLAINTEXT_BYTES + 16);
    assert!(open_request(&malformed, envelope_context(), &[key]).is_err());
}

#[test]
fn sealed_request_v3_open_does_not_authorize_an_invalid_order() {
    let owner = user(4);
    let note = deposit(&owner, BASE, 40, 17);
    let mut notes = Notes::default();
    notes.add_deposit(&note);
    let new = new_order(
        &notes,
        &owner,
        true,
        true,
        40,
        95,
        std::slice::from_ref(&note),
    );
    let mut order = OrderRequest {
        terms: new.terms,
        funding: vec![note],
        authorization: new.authorization,
    };
    order
        .validate(Felt::from(CHAIN), Felt::from(BASE), 1, 1, 1)
        .unwrap();
    order.authorization = Signature {
        r: Felt::ONE,
        s: Felt::ONE,
    };
    let (sealed, _) = seal_request(
        &registry_of(1),
        envelope_context(),
        &PrivateRequest::Order(order),
    )
    .unwrap();
    let opened = open_request(
        &sealed,
        envelope_context(),
        &[sealed_test_key("execution-key-0", 1)],
    )
    .unwrap();
    let PrivateRequest::Order(opened) = opened.request else {
        panic!("expected order");
    };
    assert!(
        opened
            .validate(Felt::from(CHAIN), Felt::from(BASE), 1, 1, 1)
            .is_err()
    );
}

#[test]
fn sealed_request_v3_max_status_fits_and_opens() {
    let full = Felt::from_hex(&format!("0x7{}", "f".repeat(62))).unwrap();
    let request = PrivateRequest::Status(StatusRequest {
        orders: vec![
            OrderQuery {
                order_id: full,
                after_seq: u32::MAX
            };
            MAX_STATUS_ITEMS / 2
        ],
        withdrawals: vec![
            WithdrawalQuery {
                nullifier: full,
                authorization: Signature { r: full, s: full },
            };
            MAX_STATUS_ITEMS / 2
        ],
    });
    let (sealed, _) = seal_request(&registry_of(1), envelope_context(), &request).unwrap();
    assert_eq!(sealed.ciphertext.len(), 2 * (REQUEST_PLAINTEXT_BYTES + 16));
    assert!(serde_json::to_vec(&sealed).unwrap().len() <= MAX_SEALED_REQUEST_BYTES);
    assert_eq!(
        open_request(
            &sealed,
            envelope_context(),
            &[sealed_test_key("execution-key-0", 1)]
        )
        .unwrap()
        .request,
        request
    );
}

#[test]
fn wallet_owner_tag_is_stable_and_ownership_checks_all_authorities() {
    let seed = crate::RecoverySeed([1; 32]);
    let keys = WalletKeys::from_seed(&seed).unwrap();
    let restored = WalletKeys::from_seed(&seed).unwrap();
    let other = WalletKeys::from_seed(&crate::RecoverySeed([2; 32])).unwrap();
    let owner = keys.owner(Felt::from(42_u8));
    assert_eq!(
        hex::encode(owner.owner_public_key.to_bytes_be()),
        "028204bd403e2e99dbbbc654d2cc20f3a0ec2a15d43f58235b8a5dfb02f6c0d1"
    );
    assert_eq!(
        owner.owner_public_key,
        crate::wallet_crypto::WalletKeyScheduleV2::from_seed(&seed)
            .owner_tag()
            .unwrap()
    );
    assert_eq!(owner.owner_public_key, restored.owner_public_key);
    assert_eq!(
        owner.owner_public_key,
        keys.owner(Felt::from(43_u8)).owner_public_key
    );
    assert_ne!(owner.owner_public_key, other.owner_public_key);
    let note = NoteFields {
        asset_id: Felt::from(BASE),
        amount: 10,
        owner_public_key: owner.owner_public_key,
        spend_authority: owner.spend_authority,
        withdraw_authority: owner.withdraw_authority,
        blinding: Felt::from(19_u8),
        nonce: 42,
        metadata_commitment: Felt::from(23_u8),
    };
    assert!(keys.owns(&note));
    assert!(restored.owns(&note));
    assert!(!other.owns(&note));
    for altered in [
        NoteFields {
            owner_public_key: other.owner_public_key,
            ..note.clone()
        },
        NoteFields {
            spend_authority: public_key(&other.spend_key),
            ..note.clone()
        },
        NoteFields {
            withdraw_authority: public_key(&other.withdraw_key),
            ..note.clone()
        },
    ] {
        assert!(!keys.owns(&altered));
    }
}

#[test]
fn wallet_keys_v2_stark_scalars_match_known_answers_and_public_keys() {
    let keys = WalletKeys::from_seed(&crate::RecoverySeed([1; 32])).unwrap();
    let owner = keys.owner(Felt::from(42_u8));
    for (private_key, authority, expected) in [
        (
            keys.spend_key,
            owner.spend_authority,
            "03a0495ece379aff389ec6c398b7528fa912ce95dad3d26a91588bfd35594422",
        ),
        (
            keys.withdraw_key,
            owner.withdraw_authority,
            "06ad8b419bab84618ed6dd0534ef1bbeed054c698924850c5b444a4ec73c91f6",
        ),
        (
            keys.cancel_key,
            owner.cancel_authority,
            "0662ca3e99a67df8f7f57d7640a1c3df8054e4c0fb916a9b84ed7434c16dd90a",
        ),
    ] {
        assert_eq!(hex::encode(private_key.to_bytes_be()), expected);
        assert_eq!(authority, starknet_crypto::get_public_key(&private_key));
    }
}

#[test]
fn wallet_keys_v2_authorizations_keep_existing_semantics() {
    let keys = WalletKeys::from_seed(&crate::RecoverySeed([1; 32])).unwrap();
    let other = WalletKeys::from_seed(&crate::RecoverySeed([2; 32])).unwrap();
    let owner = keys.owner(Felt::from(42_u8));
    let note = NoteFields {
        asset_id: Felt::from(BASE),
        amount: 10,
        owner_public_key: owner.owner_public_key,
        spend_authority: owner.spend_authority,
        withdraw_authority: owner.withdraw_authority,
        blinding: Felt::from(19_u8),
        nonce: 42,
        metadata_commitment: Felt::from(23_u8),
    };
    assert!(keys.owns(&note));
    assert!(!other.owns(&note));
    let chain = Felt::from(CHAIN);
    let order = keys
        .order(
            chain,
            Felt::from(PAIR),
            true,
            false,
            10,
            95,
            1_000_000,
            vec![note.clone()],
        )
        .unwrap();
    order.validate(chain, Felt::from(BASE), 1, 1, 1).unwrap();
    let mut wrong_order = order.clone();
    wrong_order.authorization =
        sign_message(&keys.cancel_key, &order.authorization_message(chain)).unwrap();
    assert!(
        wrong_order
            .validate(chain, Felt::from(BASE), 1, 1, 1)
            .is_err()
    );
    let cancel = keys.cancel(chain, order.order_id()).unwrap();
    let cancel_message = cancel_message(chain, cancel.order_id);
    assert!(verify_message(
        &owner.cancel_authority,
        &cancel_message,
        &cancel.signature
    ));
    assert!(!verify_message(
        &owner.spend_authority,
        &cancel_message,
        &cancel.signature
    ));
    let withdrawal = keys
        .withdraw(chain, note.clone(), Felt::from(43_u8))
        .unwrap();
    withdrawal.validate(chain).unwrap();
    let mut wrong_withdrawal = withdrawal.clone();
    wrong_withdrawal.authorization = sign_message(
        &keys.spend_key,
        &withdrawal_authorization_message(
            chain,
            note.nullifier(),
            withdrawal.exit_commitment,
            withdrawal.exit_authority,
        ),
    )
    .unwrap();
    assert!(wrong_withdrawal.validate(chain).is_err());
    assert!(other.withdraw(chain, note, Felt::from(43_u8)).is_err());
}

fn outputs_total(result: &TransitionResult, asset: u64) -> u128 {
    result
        .outputs
        .iter()
        .filter(|output| output.note.asset_id == Felt::from(asset))
        .map(|output| output.note.amount)
        .sum()
}

#[test]
fn per_order_bounds_keep_full_book_aggregates_in_range() {
    let mut owner = user(99).owner;
    owner.nonce = Felt::from(1_u8);
    let terms = |amount| OrderTerms {
        pair_id: Felt::from(PAIR),
        sell: true,
        external: false,
        amount,
        limit: 1,
        expiry_ms: 1_000,
        owner: owner.clone(),
    };
    assert!(terms(MAX_ORDER_AMOUNT).validate().is_ok());
    assert!(terms(MAX_ORDER_AMOUNT + 1).validate().is_err());
    assert!(
        MAX_ORDER_AMOUNT
            .checked_mul(MAX_BOOK_ORDERS as u128)
            .unwrap()
            < AMOUNT_BOUND
    );
}

#[test]
fn an_order_cannot_reuse_a_funding_note() {
    let mut notes = Notes::default();
    let owner = user(100);
    let funding = deposit(&owner, BASE, 10, 100);
    notes.add_deposit(&funding);
    let admitted = new_order(
        &notes,
        &owner,
        true,
        false,
        10,
        1,
        std::slice::from_ref(&funding),
    );
    let mut request = OrderRequest {
        terms: admitted.terms,
        funding: vec![funding.clone(), funding],
        authorization: Signature {
            r: Felt::ZERO,
            s: Felt::ZERO,
        },
    };
    request.authorization = sign_message(
        &owner.spend_key,
        &request.authorization_message(Felt::from(CHAIN)),
    )
    .unwrap();
    assert!(
        request
            .validate(Felt::from(CHAIN), Felt::from(BASE), 1, 1, 1)
            .is_err()
    );
}

#[test]
fn order_admission_requires_exact_note_membership_cardinality() {
    let mut notes = Notes::default();
    let owner = user(101);
    let funding = deposit(&owner, BASE, 10, 101);
    notes.add_deposit(&funding);
    let admitted = new_order(
        &notes,
        &owner,
        true,
        false,
        10,
        1,
        std::slice::from_ref(&funding),
    );
    let request = OrderRequest {
        terms: admitted.terms,
        funding: vec![funding.clone()],
        authorization: admitted.authorization,
    };
    let membership = notes.membership(&funding);
    assert!(
        request
            .clone()
            .try_into_new_order(vec![membership.clone()])
            .is_ok()
    );
    assert!(request.clone().try_into_new_order(vec![]).is_err());
    assert!(
        request
            .try_into_new_order(vec![membership.clone(), membership])
            .is_err()
    );
}

#[test]
fn buy_orders_require_the_full_rounded_quote_value_and_the_market_minimum() {
    fn request(owner: &User, funding: NoteFields, amount: u128, limit: u128) -> OrderRequest {
        let mut notes = Notes::default();
        notes.add_deposit(&funding);
        let admitted = new_order(
            &notes,
            owner,
            false,
            false,
            amount,
            limit,
            std::slice::from_ref(&funding),
        );
        OrderRequest {
            terms: admitted.terms,
            funding: vec![funding],
            authorization: admitted.authorization,
        }
    }

    let underfunded_owner = user(103);
    let underfunded = request(
        &underfunded_owner,
        deposit(&underfunded_owner, QUOTE, 10, 103),
        10,
        105,
    );
    assert!(
        underfunded
            .validate(Felt::from(CHAIN), Felt::from(QUOTE), 1, 1, 100)
            .is_err()
    );

    let dust_owner = user(104);
    let dust = request(&dust_owner, deposit(&dust_owner, QUOTE, 1, 104), 10, 1);
    assert!(
        dust.validate(Felt::from(CHAIN), Felt::from(QUOTE), 1, 2, 100)
            .is_err()
    );

    let exact_owner = user(105);
    let exact = request(&exact_owner, deposit(&exact_owner, QUOTE, 11, 105), 10, 105);
    exact
        .validate(Felt::from(CHAIN), Felt::from(QUOTE), 1, 11, 100)
        .unwrap();
}

#[test]
fn canonical_books_reject_duplicate_order_ids() {
    let mut notes = Notes::default();
    let owner = user(101);
    let funding = deposit(&owner, BASE, 10, 101);
    notes.add_deposit(&funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &owner, true, false, 10, 1, &[funding])],
        notes.root(),
        100,
    ))
    .unwrap();
    let duplicate = vec![
        admitted.new_book[0].order.clone(),
        admitted.new_book[0].order.clone(),
    ];
    assert!(assert_canonical_book(&duplicate).is_err());
}

#[test]
fn admission_rejects_an_order_beyond_the_protocol_lifetime() {
    let mut notes = Notes::default();
    let owner = user(102);
    let funding = deposit(&owner, BASE, 10, 102);
    notes.add_deposit(&funding);
    let mut order = new_order(&notes, &owner, true, false, 10, 1, &[funding]);
    let transition = input(1, vec![], vec![], Felt::ZERO, 100);
    order.terms.expiry_ms = transition.close_time_ms + MAX_ORDER_LIFETIME_MS + 1;
    order.authorization = sign_message(
        &owner.spend_key,
        &order.authorization_message(transition.chain_context),
    )
    .unwrap();
    let mut transition = transition;
    transition.note_root = notes.root();
    transition.new_orders = vec![order];

    assert!(build_transition(&transition).is_err());
}

fn book_funding(book: &[BookEntry], sell: bool) -> u128 {
    book.iter()
        .filter(|entry| entry.order.sell == sell)
        .map(|entry| entry.order.funding)
        .sum()
}

#[test]
fn a_cross_settles_both_sides_and_empties_the_book() {
    let mut notes = Notes::default();
    let (seller, buyer) = (user(1), user(2));
    let base_note = deposit(&seller, BASE, 10, 1);
    let quote_note = deposit(&buyer, QUOTE, 2_000, 2);
    notes.add_deposit(&base_note);
    notes.add_deposit(&quote_note);
    let orders = vec![
        new_order(&notes, &seller, true, false, 10, 95, &[base_note]),
        new_order(&notes, &buyer, false, false, 10, 105, &[quote_note]),
    ];
    let ids = orders
        .iter()
        .map(|order| order.terms.order_id())
        .collect::<Vec<_>>();
    let result = build_transition(&input(1, vec![], orders, notes.root(), 100)).unwrap();
    let (sell, buy) = (report(&result, ids[0]), report(&result, ids[1]));
    assert_eq!(sell.fill_base, 10);
    assert_eq!(buy.fill_base, 10);
    assert_eq!(buy.fill_quote, 1_000);
    assert!(result.new_book.is_empty());
    // the seller receives 1000 quote less 0.3%, the buyer 10 base less 0.3% and 1000 quote back.
    assert_eq!(sell.proceeds, 1_000 - 3);
    assert_eq!(buy.proceeds, 10 - 1);
    assert_eq!(buy.refund, 1_000);
    // every unit that entered leaves as a note.
    assert_eq!(outputs_total(&result, BASE), 10);
    assert_eq!(outputs_total(&result, QUOTE), 2_000);
    assert_eq!(result.public.nullifiers.len(), MIN_NULLIFIER_BUCKET);
    assert_eq!(result.public.output_records.len(), MIN_OUTPUT_BUCKET);
    assert_eq!(
        result.public.commitment,
        result.public.transition_commitment()
    );
}

#[test]
fn an_unfilled_order_persists_and_its_book_reopens() {
    let mut notes = Notes::default();
    let buyer = user(3);
    let quote_note = deposit(&buyer, QUOTE, 900, 3);
    notes.add_deposit(&quote_note);
    let orders = vec![new_order(
        &notes,
        &buyer,
        false,
        false,
        10,
        90,
        &[quote_note],
    )];
    let first = build_transition(&input(1, vec![], orders, notes.root(), 100)).unwrap();
    assert_eq!(first.new_book.len(), 1);
    assert_eq!(first.new_book[0].order.funding, 900);
    assert_eq!(first.residual_outputs.len(), 1);
    let first_residual = &first.residual_outputs[0];
    assert_eq!(first_residual.order_id, first.new_book[0].order.order_id);
    assert_eq!(first_residual.note.funding, 900);
    assert_eq!(
        first.new_book[0].order.residual_commitment,
        first_residual.note.commitment()
    );
    let second =
        build_transition(&input(2, first.new_book.clone(), vec![], Felt::ZERO, 100)).unwrap();
    assert_eq!(second.public.prior_book_root, first.public.new_book_root);
    assert_eq!(second.public.new_book_root, first.public.new_book_root);
    assert!(second.residual_outputs.is_empty());
    assert!(
        !second
            .public
            .nullifiers
            .contains(&first_residual.note.nullifier())
    );
}

#[test]
fn a_partial_fill_replaces_exactly_one_residual_generation() {
    let mut notes = Notes::default();
    let (seller, buyer) = (user(31), user(32));
    let base = deposit(&seller, BASE, 20, 31);
    notes.add_deposit(&base);
    let first = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &seller, true, false, 20, 95, &[base])],
        notes.root(),
        100,
    ))
    .unwrap();
    let old = first.residual_outputs[0].note.clone();
    notes.add_outputs(&first.public);

    let quote = deposit(&buyer, QUOTE, 525, 32);
    notes.add_deposit(&quote);
    let second = build_transition(&input(
        2,
        first.new_book,
        vec![new_order(&notes, &buyer, false, false, 5, 105, &[quote])],
        notes.root(),
        100,
    ))
    .unwrap();
    assert!(second.public.nullifiers.contains(&old.nullifier()));
    assert_eq!(second.residual_outputs.len(), 1);
    let replacement = &second.residual_outputs[0].note;
    assert_eq!(replacement.generation, 2);
    assert_eq!(replacement.remaining, 15);
    assert_eq!(replacement.funding, 15);
    assert_ne!(replacement.commitment(), old.commitment());
    assert_eq!(
        second.new_book[0].order.residual_commitment,
        replacement.commitment()
    );
}

#[test]
fn a_full_fill_consumes_the_residual_authority_without_replacing_it() {
    let mut notes = Notes::default();
    let (seller, buyer) = (user(37), user(38));
    let base = deposit(&seller, BASE, 10, 37);
    notes.add_deposit(&base);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &seller, true, false, 10, 95, &[base])],
        notes.root(),
        100,
    ))
    .unwrap();
    let authority = admitted.residual_outputs[0].note.clone();
    let order_id = authority.order_id;
    notes.add_outputs(&admitted.public);
    let quote = deposit(&buyer, QUOTE, 1_050, 38);
    notes.add_deposit(&quote);
    let filled = build_transition(&input(
        2,
        admitted.new_book,
        vec![new_order(&notes, &buyer, false, false, 10, 105, &[quote])],
        notes.root(),
        100,
    ))
    .unwrap();
    assert!(filled.new_book.is_empty());
    assert!(filled.residual_outputs.is_empty());
    assert!(filled.public.nullifiers.contains(&authority.nullifier()));
    assert_eq!(report(&filled, order_id).removal, Some(Removal::Completed));
}

#[test]
fn repeated_partial_fills_replace_only_the_latest_residual_authority() {
    let mut notes = Notes::default();
    let (seller, first_buyer, second_buyer) = (user(41), user(42), user(43));
    let base = deposit(&seller, BASE, 20, 41);
    notes.add_deposit(&base);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &seller, true, false, 20, 95, &[base])],
        notes.root(),
        100,
    ))
    .unwrap();
    let first_authority = admitted.residual_outputs[0].note.clone();
    notes.add_outputs(&admitted.public);

    let first_quote = deposit(&first_buyer, QUOTE, 525, 42);
    notes.add_deposit(&first_quote);
    let first_fill = build_transition(&input(
        2,
        admitted.new_book,
        vec![new_order(
            &notes,
            &first_buyer,
            false,
            false,
            5,
            105,
            &[first_quote],
        )],
        notes.root(),
        100,
    ))
    .unwrap();
    let second_authority = first_fill.residual_outputs[0].note.clone();
    assert!(
        first_fill
            .public
            .nullifiers
            .contains(&first_authority.nullifier())
    );
    notes.add_outputs(&first_fill.public);

    let second_quote = deposit(&second_buyer, QUOTE, 525, 43);
    notes.add_deposit(&second_quote);
    let second_fill = build_transition(&input(
        3,
        first_fill.new_book,
        vec![new_order(
            &notes,
            &second_buyer,
            false,
            false,
            5,
            105,
            &[second_quote],
        )],
        notes.root(),
        100,
    ))
    .unwrap();
    let latest = second_fill.residual_outputs[0].note.clone();
    assert!(
        second_fill
            .public
            .nullifiers
            .contains(&second_authority.nullifier())
    );
    assert!(
        !second_fill
            .public
            .nullifiers
            .contains(&first_authority.nullifier())
    );
    assert_eq!(
        (latest.generation, latest.remaining, latest.funding),
        (3, 10, 10)
    );
    assert_ne!(latest.nullifier(), second_authority.nullifier());
}

#[test]
fn many_zero_fill_epochs_do_not_churn_the_residual_authority() {
    let mut notes = Notes::default();
    let owner = user(44);
    let funding = deposit(&owner, BASE, 10, 44);
    notes.add_deposit(&funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &owner, true, false, 10, 110, &[funding])],
        notes.root(),
        100,
    ))
    .unwrap();
    let authority = admitted.residual_outputs[0].note.clone();
    let mut book = admitted.new_book;
    for seq in 2..=32 {
        let unchanged = build_transition(&input(seq, book, vec![], Felt::ZERO, 100)).unwrap();
        assert_eq!(
            unchanged.public.prior_book_root,
            unchanged.public.new_book_root
        );
        assert!(unchanged.residual_outputs.is_empty());
        assert!(!unchanged.public.nullifiers.contains(&authority.nullifier()));
        assert_eq!(
            unchanged.new_book[0].order.residual_commitment,
            authority.commitment()
        );
        assert_eq!(unchanged.new_book[0].order.residual_generation, 1);
        book = unchanged.new_book;
    }
}

#[test]
fn malformed_residual_recovery_preimages_fail_membership() {
    let mut notes = Notes::default();
    let owner = user(45);
    let funding = deposit(&owner, BASE, 10, 45);
    notes.add_deposit(&funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &owner, true, false, 10, 110, &[funding])],
        notes.root(),
        100,
    ))
    .unwrap();
    notes.add_outputs(&admitted.public);
    let note = admitted.residual_outputs[0].note.clone();
    let base = ResidualRecoveryInput {
        note_root: notes.root(),
        membership: notes.membership_leaf(note.output_leaf()),
        note,
        output_asset_id: Felt::from(QUOTE),
        fee_bps: 30,
        capacity: RecoveryCapacity::default(),
        input_exit: RecoveryExit {
            commitment: Felt::from(900_u64),
            authority: Felt::from(901_u64),
        },
        output_exit: RecoveryExit::default(),
        authorization: Signature {
            r: Felt::ZERO,
            s: Felt::ZERO,
        },
    };
    let mut wrong_owner = base.clone();
    wrong_owner.note.owner = user(46).owner;
    assert!(preview_residual_recovery(&wrong_owner).is_err());
    let mut wrong_market = base;
    wrong_market.note.pair_id = Felt::from(999_u64);
    assert!(preview_residual_recovery(&wrong_market).is_err());
}

#[test]
fn permissionless_recovery_matches_the_external_average_allocation() {
    let mut notes = Notes::default();
    let owner = user(77);
    let funding = deposit(&owner, BASE, 10, 77);
    notes.add_deposit(&funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &owner, true, true, 10, 95, &[funding])],
        notes.root(),
        100,
    ))
    .unwrap();
    notes.add_outputs(&admitted.public);
    let residual = admitted.residual_outputs[0].note.clone();
    let capacity = RecoveryCapacity {
        generation: 2,
        status: CAPACITY_STATUS_FROZEN,
        total: 10,
        consumed_base: 6,
        pool_quote: 606,
        scale: 1,
    };
    assert_eq!(
        residual_recovery_amounts(&residual, capacity, 30).unwrap(),
        (4, 604, 2)
    );
    let mut recovery = ResidualRecoveryInput {
        note_root: notes.root(),
        note: residual.clone(),
        membership: notes.membership_leaf(residual.output_leaf()),
        output_asset_id: Felt::from(QUOTE),
        fee_bps: 30,
        capacity,
        input_exit: RecoveryExit {
            commitment: Felt::from(701_u64),
            authority: public_key(&Felt::from(702_u64)),
        },
        output_exit: RecoveryExit {
            commitment: Felt::from(703_u64),
            authority: public_key(&Felt::from(704_u64)),
        },
        authorization: Signature {
            r: Felt::ZERO,
            s: Felt::ZERO,
        },
    };
    let preview = preview_residual_recovery(&recovery).unwrap();
    recovery.authorization = sign_message(
        &owner.withdraw_key,
        &residual_recovery_authorization_message(preview.commitment),
    )
    .unwrap();
    let (public, _) = build_residual_recovery(&recovery).unwrap();
    assert_eq!(
        (public.input_amount, public.output_amount, public.fee_amount),
        (4, 604, 2)
    );

    let mut next = input(2, admitted.new_book, vec![], Felt::ZERO, 100);
    next.outcomes = vec![Outcome::from_capacity(
        1,
        Felt::from(PAIR),
        true,
        6,
        606,
        95,
        1,
    )];
    let applied = build_transition(&next).unwrap();
    assert_eq!(applied.reports[0].external_base, 6);
    assert_eq!(applied.reports[0].proceeds, 604);
}

#[test]
fn retiring_an_externally_recovered_order_does_not_issue_its_value_or_fee_twice() {
    let mut notes = Notes::default();
    let owner = user(81);
    let funding = deposit(&owner, BASE, 10, 81);
    notes.add_deposit(&funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &owner, true, true, 10, 95, &[funding])],
        notes.root(),
        100,
    ))
    .unwrap();
    let residual = admitted.residual_outputs[0].note.clone();
    let mut retire = input(2, admitted.new_book, vec![], Felt::ZERO, 100);
    retire.outcomes = vec![Outcome::from_capacity(
        1,
        Felt::from(PAIR),
        true,
        10,
        1_010,
        95,
        1,
    )];
    retire.recovered_order_ids = vec![residual.order_id];
    let retired = build_transition(&retire).unwrap();

    assert!(retired.new_book.is_empty());
    assert_eq!(
        retired.public.retired_nullifiers,
        vec![residual.nullifier()]
    );
    assert!(retired.outputs.is_empty());
    assert_eq!(retired.reports[0].external_base, 10);
    assert_eq!(retired.reports[0].proceeds, 0);
    assert_eq!(retired.reports[0].fee, 0);
}

#[test]
fn residual_recovery_uses_the_capacitys_canonical_multi_order_offset() {
    let mut notes = Notes::default();
    let (first, second) = (user(79), user(80));
    let first_funding = deposit(&first, BASE, 10, 79);
    let second_funding = deposit(&second, BASE, 10, 80);
    notes.add_deposit(&first_funding);
    notes.add_deposit(&second_funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &first, true, true, 10, 95, &[first_funding]),
            new_order(&notes, &second, true, true, 10, 95, &[second_funding]),
        ],
        notes.root(),
        100,
    ))
    .unwrap();
    let mut residuals = admitted
        .residual_outputs
        .iter()
        .map(|output| output.note.clone())
        .collect::<Vec<_>>();
    residuals.sort_by_key(|note| note.reserved_offset);
    assert_eq!(residuals[0].reserved_offset, 0);
    assert_eq!(residuals[1].reserved_offset, 10);
    let capacity = RecoveryCapacity {
        generation: 2,
        status: CAPACITY_STATUS_FROZEN,
        total: 20,
        consumed_base: 15,
        pool_quote: 1515,
        scale: 1,
    };
    assert_eq!(
        residual_recovery_amounts(&residuals[0], capacity, 30).unwrap(),
        (0, 1006, 4)
    );
    assert_eq!(
        residual_recovery_amounts(&residuals[1], capacity, 30).unwrap(),
        (5, 503, 2)
    );
}

#[test]
fn a_finalized_recovery_retires_only_the_authenticated_residual() {
    let mut notes = Notes::default();
    let owner = user(78);
    let funding = deposit(&owner, BASE, 10, 78);
    notes.add_deposit(&funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(&notes, &owner, true, false, 10, 110, &[funding])],
        notes.root(),
        100,
    ))
    .unwrap();
    let old = admitted.residual_outputs[0].note.clone();
    let mut retire = input(2, admitted.new_book, vec![], Felt::ZERO, 100);
    retire.recovered_order_ids = vec![old.order_id];
    let retired = build_transition(&retire).unwrap();
    assert!(retired.new_book.is_empty());
    assert_eq!(retired.public.retired_nullifiers, vec![old.nullifier()]);
    assert!(!retired.public.nullifiers.contains(&old.nullifier()));
    assert!(
        retired
            .outputs
            .iter()
            .all(|output| output.order_id != old.order_id)
    );

    let mut unknown = input(2, retired.new_book, vec![], Felt::ZERO, 100);
    unknown.recovered_order_ids = vec![old.order_id];
    assert!(build_transition(&unknown).is_err());
}

#[test]
fn an_external_residual_is_reserved_then_its_outcome_settles() {
    let mut notes = Notes::default();
    let seller = user(4);
    let base_note = deposit(&seller, BASE, 10, 4);
    notes.add_deposit(&base_note);
    let orders = vec![new_order(&notes, &seller, true, true, 10, 95, &[base_note])];
    let first = build_transition(&input(1, vec![], orders, notes.root(), 100)).unwrap();
    assert_eq!(
        first.public.capacities,
        vec![Capacity {
            pair_id: Felt::from(PAIR),
            sell: true,
            bound: 95,
            total: 10
        }]
    );
    assert_eq!(first.new_book[0].order.reserved, 10);
    // the searcher took 6 base at m1 = 101 and the pool received 606 quote.
    let mut second_input = input(2, first.new_book.clone(), vec![], Felt::ZERO, 100);
    second_input.outcomes = vec![Outcome {
        seq: 1,
        pair_id: Felt::from(PAIR),
        sell: true,
        consumed_base: 6,
        pool_quote: 606,
        m1: 101,
        m1_scale: 1,
    }];
    let second = build_transition(&second_input).unwrap();
    assert_eq!(second.reports[0].external_base, 6);
    assert_eq!(second.reports[0].external_quote, 606);
    assert_eq!(second.reports[0].proceeds, 606 - 2);
    // the unconsumed 4 base is reserved again at the same bound.
    assert_eq!(second.new_book[0].order.remaining, 4);
    assert_eq!(second.new_book[0].order.reserved, 4);
    assert_eq!(second.new_book[0].order.reserved_seq, 2);
    assert_eq!(outputs_total(&second, QUOTE), 606);
}

#[test]
fn cancellation_and_expiry_refund_the_locked_funding() {
    let mut notes = Notes::default();
    let (first_user, second_user) = (user(5), user(6));
    let first_note = deposit(&first_user, QUOTE, 500, 5);
    let second_note = deposit(&second_user, QUOTE, 700, 6);
    notes.add_deposit(&first_note);
    notes.add_deposit(&second_note);
    let mut expiring = new_order(&notes, &second_user, false, false, 5, 90, &[second_note]);
    expiring.terms.expiry_ms = 10_005;
    expiring.authorization = sign_message(
        &second_user.spend_key,
        &expiring.authorization_message(Felt::from(CHAIN)),
    )
    .unwrap();
    let orders = vec![
        new_order(&notes, &first_user, false, false, 5, 90, &[first_note]),
        expiring,
    ];
    let first = build_transition(&input(1, vec![], orders, notes.root(), 100)).unwrap();
    assert_eq!(first.new_book.len(), 2);
    let cancelled = first.new_book[0].order.order_id;
    let mut later = input(9, first.new_book.clone(), vec![], Felt::ZERO, 100);
    later.cancellations = vec![Cancellation {
        order_id: cancelled,
        signature: sign_message(
            &first_user.cancel_key,
            &cancel_message(Felt::from(CHAIN), cancelled),
        )
        .unwrap(),
    }];
    let result = build_transition(&later).unwrap();
    assert!(result.new_book.is_empty());
    assert_eq!(result.reports[0].removal, Some(Removal::Cancelled));
    assert_eq!(result.reports[1].removal, Some(Removal::Expired));
    assert_eq!(outputs_total(&result, QUOTE), 1_200);
}

#[test]
fn a_forged_authorization_or_cancel_is_rejected() {
    let mut notes = Notes::default();
    let (owner, thief) = (user(7), user(8));
    let note = deposit(&owner, BASE, 10, 7);
    notes.add_deposit(&note);
    let mut order = new_order(&notes, &owner, true, false, 10, 95, &[note]);
    order.authorization = sign_message(
        &thief.spend_key,
        &order.authorization_message(Felt::from(CHAIN)),
    )
    .unwrap();
    assert!(build_transition(&input(1, vec![], vec![order], notes.root(), 100)).is_err());
}

#[test]
fn conservation_holds_across_partial_fills() {
    let mut notes = Notes::default();
    let (seller, buyer_a, buyer_b) = (user(9), user(10), user(11));
    let base_note = deposit(&seller, BASE, 25, 9);
    let quote_a = deposit(&buyer_a, QUOTE, 1_050, 10);
    let quote_b = deposit(&buyer_b, QUOTE, 3_000, 11);
    for note in [&base_note, &quote_a, &quote_b] {
        notes.add_deposit(note);
    }
    let orders = vec![
        new_order(&notes, &seller, true, false, 25, 99, &[base_note]),
        new_order(&notes, &buyer_a, false, false, 10, 101, &[quote_a]),
        new_order(&notes, &buyer_b, false, false, 30, 100, &[quote_b]),
    ];
    let seller_id = orders[0].terms.order_id();
    let result = build_transition(&input(1, vec![], orders, notes.root(), 100)).unwrap();
    let bought = result
        .reports
        .iter()
        .filter(|report| report.order_id != seller_id)
        .map(|report| report.fill_base)
        .sum::<u128>();
    assert_eq!(bought, 25);
    assert_eq!(report(&result, seller_id).fill_base, 25);
    assert_eq!(
        outputs_total(&result, BASE) + book_funding(&result.new_book, true),
        25
    );
    assert_eq!(
        outputs_total(&result, QUOTE) + book_funding(&result.new_book, false),
        4_050
    );
}

pub(crate) fn report(result: &TransitionResult, order_id: Felt) -> &OrderReport {
    result
        .reports
        .iter()
        .find(|report| report.order_id == order_id)
        .expect("order is reported")
}

#[test]
fn withdrawal_proves_membership_and_signs_privately() {
    let mut notes = Notes::default();
    let owner = user(12);
    let note = deposit(&owner, BASE, 42, 12);
    notes.add_deposit(&note);
    let nullifier = note.nullifier();
    let exit = Felt::from(0xe417_u64);
    let exit_authority = public_key(&Felt::from(0xe41a_u64));
    let input = WithdrawalInput {
        chain_context: Felt::from(CHAIN),
        note_root: notes.root(),
        exit_commitment: exit,
        exit_authority,
        membership: notes.membership(&note),
        authorization: sign_message(
            &owner.withdraw_key,
            &withdrawal_authorization_message(Felt::from(CHAIN), nullifier, exit, exit_authority),
        )
        .unwrap(),
        note,
    };
    let (public, witness) = build_withdrawal(&input).unwrap();
    assert_eq!(public.nullifier, nullifier);
    assert_eq!(public.amount, 42);
    assert_eq!(witness.len(), 14 + 64 + 2);
    let mut forged = input.clone();
    forged.exit_commitment = Felt::from(0xbad_u64);
    assert!(build_withdrawal(&forged).is_err());
}

#[test]
fn sealed_request_v3_response_key_round_trips_and_hides_request_kind() {
    let keys = vec![sealed_test_key("execution-key-0", 1)];
    let registry = registry_of(1);
    let status = PrivateRequest::Status(StatusRequest {
        orders: vec![OrderQuery {
            order_id: Felt::from(7_u8),
            after_seq: 0,
        }],
        withdrawals: vec![],
    });
    let (sealed, response_key) = seal_request(&registry, envelope_context(), &status).unwrap();
    let opened = open_request(&sealed, envelope_context(), &keys).unwrap();
    assert_eq!(opened.request, status);
    assert_eq!(*opened.response_key, *response_key);
    assert!(open_request(&sealed, envelope_context(), &[]).is_err());
    let mut tampered = sealed.clone();
    tampered.digest = "00".repeat(32);
    assert!(open_request(&tampered, envelope_context(), &keys).is_err());

    // the kind is inside and the plaintext is padded: a status looks like a cancellation.
    let cancel = PrivateRequest::Cancel(CancelRequest {
        order_id: Felt::from(7_u8),
        signature: Signature {
            r: Felt::ONE,
            s: Felt::ONE,
        },
    });
    let (other, _) = seal_request(&registry, envelope_context(), &cancel).unwrap();
    let body = |sealed: &SealedRequest| serde_json::to_string(sealed).unwrap();
    assert!(!body(&sealed).contains("status") && !body(&other).contains("cancel"));
    assert_eq!(body(&sealed).len(), body(&other).len());

    // Every answer derives a fresh subkey from its response root. Both answers open, but their
    // salts and nonces are independently fresh and the wire is closed and exact-sized.
    let answer = serde_json::json!({ "ok": true, "orders": [] });
    let response = seal_response(&opened.response_key, &sealed.digest, &answer).unwrap();
    let retried_response = seal_response(&opened.response_key, &sealed.digest, &answer).unwrap();
    assert_eq!(response.version, 3);
    assert_eq!(response.salt.len(), 64);
    assert_eq!(response.nonce.len(), 24);
    assert_eq!(
        response.ciphertext.len(),
        2 * (RESPONSE_PLAINTEXT_BYTES + 16)
    );
    assert_eq!(
        open_response(&response_key, &sealed.digest, &response).unwrap(),
        answer
    );
    assert_eq!(
        open_response(&response_key, &sealed.digest, &retried_response).unwrap(),
        answer
    );
    assert_ne!(response.salt, retried_response.salt);
    assert_ne!(response.nonce, retried_response.nonce);
    assert!(open_response(&response_key, &other.digest, &response).is_err());
    assert!(open_response(&[0; 32], &sealed.digest, &response).is_err());

    let mut tampered = response.clone();
    tampered.version = 2;
    assert!(open_response(&response_key, &sealed.digest, &tampered).is_err());
    let mut tampered = response.clone();
    tampered.salt.replace_range(..2, "00");
    assert!(open_response(&response_key, &sealed.digest, &tampered).is_err());
    let mut tampered = response.clone();
    tampered.nonce.replace_range(..2, "00");
    assert!(open_response(&response_key, &sealed.digest, &tampered).is_err());
    let mut tampered = response.clone();
    tampered.ciphertext.replace_range(..2, "00");
    assert!(open_response(&response_key, &sealed.digest, &tampered).is_err());
}

#[test]
fn sealed_response_v3_json_schema_rejects_legacy_unknown_and_noncanonical_values() {
    let valid = serde_json::json!({
        "version": 3,
        "salt": "ab".repeat(32),
        "nonce": "cd".repeat(12),
        "ciphertext": "ef".repeat(RESPONSE_PLAINTEXT_BYTES + 16),
    });
    serde_json::from_value::<SealedResponse>(valid.clone()).unwrap();

    let mut cases = vec![
        serde_json::json!({
            "nonce": "cd".repeat(12),
            "ciphertext": "ef".repeat(RESPONSE_PLAINTEXT_BYTES + 16),
        }),
        serde_json::json!({
            "version": 2,
            "salt": "ab".repeat(32),
            "nonce": "cd".repeat(12),
            "ciphertext": "ef".repeat(RESPONSE_PLAINTEXT_BYTES + 16),
        }),
    ];
    for (field, value) in [
        ("salt", "AB".repeat(32)),
        ("salt", "ab".repeat(31)),
        ("nonce", "CD".repeat(12)),
        ("nonce", "cd".repeat(11)),
        ("ciphertext", "ef".repeat(RESPONSE_PLAINTEXT_BYTES + 15)),
    ] {
        let mut changed = valid.clone();
        changed[field] = serde_json::json!(value);
        cases.push(changed);
    }
    let mut extra = valid;
    extra["extra"] = serde_json::json!(true);
    cases.push(extra);
    for case in cases {
        assert!(serde_json::from_value::<SealedResponse>(case).is_err());
    }

    let answer = serde_json::json!({"ok": true});
    assert!(seal_response(&[0; 32], "not-a-digest", &answer).is_err());
    assert!(seal_response(&[0; 32], &"D1".repeat(32), &answer).is_err());
}

#[test]
fn an_attestor_signed_price_verifies_as_the_exchange_checks_it() {
    use crate::{
        AssetId, PairId, ReferencePriceDerivation, ReferencePriceEnvelope,
        sign_reference_price_attestation,
    };
    let envelope = ReferencePriceEnvelope {
        pair_id: PairId("STRK/USDC".into()),
        base_asset_id: AssetId("STRK".into()),
        quote_asset_id: AssetId("USDC".into()),
        midpoint_price: 1_000,
        lower_price: 999,
        upper_price: 1_001,
        price_base_scale: 1_000_000,
        source_count: 3,
        observed_at_unix_ms: 9_000,
        derivation: ReferencePriceDerivation::DirectBbo {
            bid_price: 999,
            ask_price: 1_001,
        },
    };
    let signed =
        sign_reference_price_attestation("0x5167", "0x5eed", envelope, "0x5e7", 11_000, 4).unwrap();
    let attestation = MarketAttestation::from_reference(&signed).unwrap();
    assert!(attestation.verify(Felt::from(CHAIN)));
    assert!(!attestation.verify(Felt::from(CHAIN + 1)));
}

#[test]
fn transition_calldata_rejects_a_price_batch_field_changed_after_signing() {
    let result = build_transition(&input(1, vec![], vec![], Felt::ZERO, 100)).unwrap();
    let mut prices = attestations(&result.public);
    sign_price_batch(Felt::from(CHAIN), &mut prices, &Felt::from(0x5167_u64)).unwrap();
    assert!(transition_calldata(&result.public, &prices).is_ok());

    prices[0].lower_price -= 1;
    assert!(transition_calldata(&result.public, &prices).is_err());
}

/// strk-like base (18 decimals) against usdc-like quote (6 decimals) at about 0.04 usdc: the
/// value of one base atom is near 2^-45 of a quote atom, which the certificate must still cover.
#[test]
fn mainnet_scale_prices_cross_and_reserve() {
    const SCALE: u128 = 1_000_000_000_000_000_000;
    let strk = |whole: u128| whole * SCALE;
    let market_at = |midpoint| Market {
        midpoint,
        scale: SCALE,
        ..market(midpoint)
    };
    let mut notes = Notes::default();
    let (seller, buyer, resting) = (user(11), user(12), user(13));
    let base = deposit(&seller, BASE, strk(1_500), 11);
    let quote = deposit(&buyer, QUOTE, 50_000_000, 12);
    let reserved = deposit(&resting, BASE, strk(700), 13);
    for note in [&base, &quote, &reserved] {
        notes.add_deposit(note);
    }
    let orders = vec![
        new_order(&notes, &seller, true, false, strk(1_500), 40_000, &[base]),
        new_order(&notes, &buyer, false, false, strk(1_000), 42_000, &[quote]),
        new_order(&notes, &resting, true, true, strk(700), 40_500, &[reserved]),
    ];
    let ids = orders
        .iter()
        .map(|order| order.terms.order_id())
        .collect::<Vec<_>>();
    let mut transition = input(1, vec![], orders, notes.root(), 41_000);
    transition.markets = vec![market_at(41_000)];
    let result = build_transition(&transition).unwrap();
    // the buyer's 1000 strk cross against the sellers; the external remainder is reserved.
    assert_eq!(report(&result, ids[1]).fill_base, strk(1_000));
    let sold = report(&result, ids[0]).fill_base + report(&result, ids[2]).fill_base;
    assert_eq!(sold, strk(1_000));
    assert_eq!(report(&result, ids[1]).fill_quote, 41_000_000);
    // whatever of the external order did not cross is reserved for the searcher.
    let external = report(&result, ids[2]);
    assert_eq!(external.reserved + external.fill_base, strk(700));
}

#[test]
fn every_value_output_blinds_unused_residual_lanes_and_fee_amounts() {
    let result = crossed();
    for output in &result.outputs {
        let record = result.public.output_records[output.index];
        assert_ne!(record.enc_remaining, Felt::ZERO);
        assert_ne!(record.enc_reserved, Felt::ZERO);
        assert_ne!(record.enc_reserved_offset, Felt::ZERO);
    }
    let fees = result
        .outputs
        .iter()
        .filter(|output| output.kind == OUTPUT_KIND_FEE)
        .collect::<Vec<_>>();
    assert!(!fees.is_empty());
    for fee in fees {
        let record = result.public.output_records[fee.index];
        assert_ne!(record.enc, felt_u128(fee.note.amount));
        let blinding = output_blinding(
            Felt::from(FEE_KEY),
            result.public.seq,
            OutputKind::Fee,
            fee.note.asset_id,
        );
        assert_eq!(record.enc - blinding, felt_u128(fee.note.amount));
        assert_eq!(record.leaf, fee.note.output_leaf());
    }
    let mut keyless = input(1, vec![], vec![], Felt::ZERO, 100);
    keyless.fee_key = Felt::ZERO;
    assert!(build_transition(&keyless).is_err());
}

#[test]
fn padding_and_auxiliary_streams_are_domain_and_position_separated() {
    let seed = Felt::from(0x5a17_u64);
    let first = output_padding_record(seed, 7);
    assert_eq!(
        first,
        [
            Felt::from_hex("0x38d63a22d32a333bd5f69bc2736d98a5543406ac7471e7c7330cab014ab8534")
                .unwrap(),
            Felt::from_hex("0x269836ee9da9baee712ff61a48ff880f00fa607a4ecb646b358d5b85815a7d5")
                .unwrap(),
            Felt::from_hex("0x5cd8336af3c364e3fc6bb5359d4d2bbf128f38649889713b0d9187d896bf1c9")
                .unwrap(),
            Felt::from_hex("0x4a30e81307e5f8f2c9540cfe1a8a349621bc4221dbe7104277b27a1e7cf8962")
                .unwrap(),
            Felt::from_hex("0x7472c276275ac5253e6d6e6365a8c64ab14cb5b6d95b62f6c6b70b3c511fbb6")
                .unwrap(),
        ]
    );
    assert_eq!(
        output_aux_blindings(seed),
        [
            Felt::from_hex("0x22ee2763316052c532ad3dab4020166d638d3000678b1fe5f4fe808677c12dd")
                .unwrap(),
            Felt::from_hex("0x1b2919e1441904ee00dc376333786cf783efa67e47945499301db3be4a43f08")
                .unwrap(),
            Felt::from_hex("0x43cf5f4ee18207f9b08c7fdbe5bd6550d7af0662e90c71d8a1e4659abcd094d")
                .unwrap(),
        ]
    );
    assert_eq!(
        order_output_blindings(seed, 7),
        [
            Felt::from_hex("0x38111f0c2200112b0c987deca5a2b2e07810ab2b2e0aa9b79e844796ce4adc")
                .unwrap(),
            Felt::from_hex("0x1604f6032d9c5697bc35f6e6e259b1c830c3c69a7fa95ce068c9c8d95db700e")
                .unwrap(),
            Felt::from_hex("0x479fd5fd0c3cef943888ddee24f45f507a70c0f6c1572868117d35d0c4251f6")
                .unwrap(),
        ]
    );
    assert_eq!(
        nullifier_padding_value(seed, 7),
        Felt::from_hex("0x2fd5b28dd91b254115daaa068bf0fb2aa8d6e3618aeec770fa495756dec85ba")
            .unwrap(),
    );
    let repeated = output_padding_record(seed, 7);
    let next = output_padding_record(seed, 8);
    assert_eq!(first, repeated);
    assert_ne!(first, next);

    let values = first
        .into_iter()
        .chain(next)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(values.len(), 10);

    let aux = output_aux_blindings(seed);
    assert_eq!(
        aux.into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert_ne!(aux[0], first[0]);
    assert_ne!(
        nullifier_padding_value(seed, 7),
        nullifier_padding_value(seed, 8),
    );
}

#[test]
fn every_prg_domain_lane_and_fee_asset_is_separated() {
    assert_eq!(ORDER_OUTPUT_BLINDING_DOMAIN, "zylith_order_blind_prg_v1");
    assert_eq!(OUTPUT_AUX_BLINDING_DOMAIN, "zylith_out_aux_prg_v1");
    assert_eq!(OUTPUT_PADDING_DOMAIN, "zylith_out_pad_v1");
    assert_eq!(NULLIFIER_PADDING_DOMAIN, "zylith_null_pad_v1");

    let key = Felt::from(0x5a17_u64);
    let mut values = Vec::new();
    values.extend(order_output_blindings(key, 7));
    values.extend(output_aux_blindings(key));
    values.extend(output_padding_record(key, 7));
    values.push(nullifier_padding_value(key, 7));
    assert_eq!(
        values
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        values.len(),
        "the frozen cross-domain vector must not reuse a field element"
    );

    let fee_key = Felt::from(FEE_KEY);
    let first_asset = Felt::from(0x111_u64);
    let second_asset = Felt::from(0x222_u64);
    let first = output_blinding(fee_key, 7, OutputKind::Fee, first_asset);
    let second = output_blinding(fee_key, 7, OutputKind::Fee, second_asset);
    assert_ne!(first, second);
    assert_eq!(
        first,
        output_blinding(fee_key, 7, OutputKind::Fee, first_asset)
    );
}

#[test]
fn unknown_output_kinds_fail_closed_before_derivation() {
    for kind in [0, 5, u64::MAX] {
        assert_eq!(
            OutputKind::try_from(kind).unwrap_err().to_string(),
            "invalid order: unknown output kind"
        );
    }
}

#[test]
fn the_step_budget_caps_the_book_so_a_full_cross_still_proves() {
    let cap = StepShape::max_book_orders(700_000);
    assert!((400..MAX_BOOK_ORDERS).contains(&cap), "cap {cap}");
    let full = |orders: usize| StepShape {
        markets: MAX_MARKETS as u64,
        resting: orders as u64,
        crossing: orders as u64,
        nullifiers: 8,
        outputs: padded_len(2 * orders + MAX_ASSETS, 16) as u64,
        ..Default::default()
    };
    assert!(full(cap).estimated_steps() <= 700_000);
    assert!(full(cap + 1).estimated_steps() > 700_000);
    assert!(StepShape::max_book_orders(10_000_000) == MAX_BOOK_ORDERS);
    assert_eq!(StepShape::max_book_orders(0), 0);
}

#[test]
fn the_step_estimate_accounts_for_multi_note_membership_paths() {
    let four_note_admissions = |orders: u64| StepShape {
        markets: 1,
        admissions: orders,
        nullifiers: 4 * orders,
        outputs: 16,
        funding_notes: 4 * orders,
        // four notes, each with a one-level output subtree and the 32-level accumulator path.
        membership_path_elements: 4 * orders * 33,
        ..Default::default()
    };
    assert!(four_note_admissions(64).estimated_steps() >= 398_290);
    assert!(four_note_admissions(128).estimated_steps() >= 790_340);
    let cap = StepShape::max_admissions(700_000);
    assert!((80..128).contains(&cap), "admission cap {cap}");
    assert!(four_note_admissions(cap as u64).estimated_steps() <= 700_000);
}

/// the widest json a value of this shape can take: every felt at full width, every amount and
/// counter at its maximum.
fn widened<T: serde::Serialize>(value: &T) -> serde_json::Value {
    fn widen(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(text) if text.starts_with("0x") => {
                *text = format!("0x7{}", "f".repeat(62))
            }
            serde_json::Value::String(text) if text.chars().all(|c| c.is_ascii_digit()) => {
                *text = u128::MAX.to_string()
            }
            serde_json::Value::Number(_) => *value = serde_json::json!(u64::MAX),
            serde_json::Value::Array(items) => items.iter_mut().for_each(widen),
            serde_json::Value::Object(fields) => {
                for (name, field) in fields {
                    if name == "nonce" && field.is_string() {
                        *field = serde_json::Value::String(u64::MAX.to_string());
                    } else {
                        widen(field);
                    }
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).unwrap();
    widen(&mut value);
    value
}

fn sealed_test_key(key_id: &str, scalar: u8) -> PrivateExecutionKeyPrivateConfig {
    let bytes = [scalar; 32];
    let secret = <hpke::kem::X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&bytes).unwrap();
    PrivateExecutionKeyPrivateConfig {
        key_id: key_id.into(),
        algorithm: crate::private_envelope::HPKE_PROFILE_ID.into(),
        private_key: hex::encode(bytes),
        public_key: hex::encode(hpke::kem::X25519HkdfSha256::sk_to_pk(&secret).to_bytes()),
    }
}

fn registry_of(count: usize) -> PrivateExecutionKeyRegistry {
    PrivateExecutionKeyRegistry {
        keys: (0..count)
            .map(|index| {
                let key = sealed_test_key(&format!("execution-key-{index}"), (index + 1) as u8);
                PrivateExecutionKeyPublicConfig {
                    key_id: key.key_id.clone(),
                    algorithm: key.algorithm.clone(),
                    public_key: key.public_key.clone(),
                }
            })
            .collect(),
    }
}

#[test]
fn every_request_seals_to_one_size_within_the_wire_limits() {
    // the widest order: four funding notes, every field at full width.
    let mut notes = Notes::default();
    let trader = user(3);
    let funding = (0..MAX_FUNDING_NOTES as u64)
        .map(|salt| deposit(&trader, BASE, 10, 10 + salt))
        .collect::<Vec<_>>();
    for note in &funding {
        notes.add_deposit(note);
    }
    let order = new_order(&notes, &trader, true, true, 40, 95, &funding);
    let order: PrivateRequest =
        serde_json::from_value(widened(&PrivateRequest::Order(OrderRequest {
            terms: order.terms,
            funding,
            authorization: order.authorization,
        })))
        .unwrap();
    let full = Felt::from_hex(&format!("0x7{}", "f".repeat(62))).unwrap();
    let status = PrivateRequest::Status(StatusRequest {
        orders: vec![
            OrderQuery {
                order_id: full,
                after_seq: u32::MAX,
            };
            MAX_STATUS_ITEMS / 2
        ],
        withdrawals: vec![
            WithdrawalQuery {
                nullifier: full,
                authorization: Signature { r: full, s: full },
            };
            MAX_STATUS_ITEMS / 2
        ],
    });
    let cancel = PrivateRequest::Cancel(CancelRequest {
        order_id: Felt::ONE,
        signature: Signature {
            r: Felt::ONE,
            s: Felt::ONE,
        },
    });
    let registry = registry_of(1);
    let sizes = [order, status, cancel]
        .iter()
        .map(|request| {
            serde_json::to_vec(
                &seal_request(&registry, envelope_context(), request)
                    .unwrap()
                    .0,
            )
            .unwrap()
            .len()
        })
        .collect::<Vec<_>>();
    assert!(sizes.iter().all(|size| *size == sizes[0]), "{sizes:?}");
    assert!(sizes[0] <= MAX_SEALED_REQUEST_BYTES, "{sizes:?}");

    // past the limits nothing seals.
    let too_many = PrivateRequest::Status(StatusRequest {
        orders: vec![],
        withdrawals: vec![
            WithdrawalQuery {
                nullifier: Felt::ONE,
                authorization: Signature {
                    r: Felt::ONE,
                    s: Felt::ONE
                },
            };
            MAX_STATUS_ITEMS + 1
        ],
    });
    assert!(seal_request(&registry, envelope_context(), &too_many).is_err());
    let empty = PrivateRequest::Status(StatusRequest::default());
    assert!(
        seal_request(
            &registry_of(MAX_EXECUTION_KEYS + 1),
            envelope_context(),
            &empty
        )
        .is_err()
    );
}

#[test]
fn status_lookups_chunk_in_order_within_the_limit() {
    let orders = (1..=40_u32)
        .map(|index| OrderQuery {
            order_id: Felt::from(index),
            after_seq: index,
        })
        .collect::<Vec<_>>();
    let withdrawals = (100..130_u32)
        .map(|index| WithdrawalQuery {
            nullifier: Felt::from(index),
            authorization: Signature {
                r: Felt::ONE,
                s: Felt::ONE,
            },
        })
        .collect::<Vec<_>>();
    let chunks = chunk_status(StatusRequest {
        orders: orders.clone(),
        withdrawals: withdrawals.clone(),
    });
    let sizes = chunks
        .iter()
        .map(|chunk| chunk.orders.len() + chunk.withdrawals.len())
        .collect::<Vec<_>>();
    assert_eq!(sizes, vec![8, 8, 8, 8, 8, 8, 8, 8, 6]);
    let rejoined_orders = chunks.iter().flat_map(|chunk| chunk.orders.clone());
    assert_eq!(rejoined_orders.collect::<Vec<_>>(), orders);
    let rejoined_withdrawals = chunks.iter().flat_map(|chunk| chunk.withdrawals.clone());
    assert_eq!(rejoined_withdrawals.collect::<Vec<_>>(), withdrawals);
    assert!(chunk_status(StatusRequest::default()).is_empty());
}

#[test]
fn the_widest_status_answer_fits_the_fixed_response() {
    let event = serde_json::json!({
        "seq": u32::MAX,
        "close_time_ms": u64::MAX,
        "report": widened(&OrderReport {
            order_id: Felt::ONE,
            admitted: true,
            external_base: 1,
            external_quote: 1,
            fill_base: 1,
            fill_quote: 1,
            fee: 1,
            proceeds: 1,
            refund: 1,
            reserved: 1,
            removal: Some(Removal::Completed),
        }),
    });
    let order = serde_json::json!({
        "order_id": format!("0x7{}", "f".repeat(62)),
        "status": "unknown",
        "cancel_requested": false,
        "more_events": true,
        "events": vec![event; MAX_STATUS_EVENTS_PER_ORDER],
    });
    let answer = serde_json::json!({
        "ok": true,
        "orders": vec![order; MAX_STATUS_ITEMS],
        "withdrawals": [],
    });
    let response = seal_response(&[1; 32], &"d1".repeat(32), &answer).unwrap();
    assert_eq!(
        response.ciphertext.len(),
        2 * (RESPONSE_PLAINTEXT_BYTES + 16)
    );
}
