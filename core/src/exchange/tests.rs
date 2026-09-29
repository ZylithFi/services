use starknet_crypto::Felt;

use super::fixtures::*;
use super::*;

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

    let quote = deposit(&buyer, QUOTE, 500, 32);
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
    let quote = deposit(&buyer, QUOTE, 1_000, 38);
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

    let first_quote = deposit(&first_buyer, QUOTE, 500, 42);
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

    let second_quote = deposit(&second_buyer, QUOTE, 500, 43);
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
fn a_sealed_request_opens_only_with_every_execution_key() {
    use crate::types::{
        PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
        PrivateExecutionKeyRegistry,
    };
    let keys = (1..=2)
        .map(|index| {
            let private_key = format!("{index:064x}");
            let secret = p256::SecretKey::from_slice(&hex::decode(&private_key).unwrap()).unwrap();
            let public_key = hex::encode(p256::EncodedPoint::from(secret.public_key()).as_bytes());
            PrivateExecutionKeyPrivateConfig {
                key_id: format!("k{index}"),
                private_key,
                public_key,
            }
        })
        .collect::<Vec<_>>();
    let registry = PrivateExecutionKeyRegistry {
        keys: keys
            .iter()
            .map(|key| PrivateExecutionKeyPublicConfig {
                key_id: key.key_id.clone(),
                public_key: key.public_key.clone(),
            })
            .collect(),
    };
    let status = PrivateRequest::Status(StatusRequest {
        orders: vec![OrderQuery {
            order_id: Felt::from(7_u8),
            after_seq: 0,
        }],
        nullifiers: vec![],
    });
    let (sealed, response_key) = seal_request(&registry, &status).unwrap();
    let opened = open_request(&sealed, &keys).unwrap();
    assert_eq!(opened.request, status);
    assert_eq!(*opened.response_key, *response_key);
    assert!(open_request(&sealed, &keys[..1]).is_err());
    let mut tampered = sealed.clone();
    tampered.digest = "00".repeat(32);
    assert!(open_request(&tampered, &keys).is_err());

    // the kind is inside and the plaintext is padded: a status looks like a cancellation.
    let cancel = PrivateRequest::Cancel(CancelRequest {
        order_id: Felt::from(7_u8),
        signature: Signature {
            r: Felt::ONE,
            s: Felt::ONE,
        },
    });
    let (other, _) = seal_request(&registry, &cancel).unwrap();
    let body = |sealed: &SealedRequest| serde_json::to_string(sealed).unwrap();
    assert!(!body(&sealed).contains("status") && !body(&other).contains("cancel"));
    assert_eq!(body(&sealed).len(), body(&other).len());

    // the answer opens only with the request's key and digest, and pads to a class.
    let answer = serde_json::json!({ "ok": true, "orders": [] });
    let response = seal_response(&opened.response_key, &sealed.digest, &answer).unwrap();
    assert_eq!(
        response.ciphertext.len(),
        2 * (RESPONSE_PLAINTEXT_BYTES + 16)
    );
    assert_eq!(
        open_response(&response_key, &sealed.digest, &response).unwrap(),
        answer
    );
    assert!(open_response(&response_key, &other.digest, &response).is_err());
    assert!(open_response(&[0; 32], &sealed.digest, &response).is_err());
}

#[test]
fn an_attestor_signed_price_verifies_as_the_exchange_checks_it() {
    use crate::{AssetId, PairId, ReferencePriceEnvelope, sign_reference_price_attestation};
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
            OUTPUT_KIND_FEE,
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
            serde_json::Value::Object(fields) => fields.values_mut().for_each(widen),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).unwrap();
    widen(&mut value);
    value
}

fn registry_of(count: usize) -> crate::PrivateExecutionKeyRegistry {
    crate::PrivateExecutionKeyRegistry {
        keys: (0..count)
            .map(|index| {
                let secret = p256::SecretKey::from_slice(
                    &hex::decode(format!("{:064x}", index + 1)).unwrap(),
                )
                .unwrap();
                crate::PrivateExecutionKeyPublicConfig {
                    key_id: format!("execution-key-{index}"),
                    public_key: hex::encode(
                        p256::EncodedPoint::from(secret.public_key()).as_bytes(),
                    ),
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
        nullifiers: vec![full; MAX_STATUS_ITEMS / 2],
    });
    let cancel = PrivateRequest::Cancel(CancelRequest {
        order_id: Felt::ONE,
        signature: Signature {
            r: Felt::ONE,
            s: Felt::ONE,
        },
    });
    let registry = registry_of(MAX_EXECUTION_KEYS);
    let sizes = [order, status, cancel]
        .iter()
        .map(|request| {
            serde_json::to_vec(&seal_request(&registry, request).unwrap().0)
                .unwrap()
                .len()
        })
        .collect::<Vec<_>>();
    assert!(sizes.iter().all(|size| *size == sizes[0]), "{sizes:?}");
    assert!(sizes[0] <= MAX_SEALED_REQUEST_BYTES, "{sizes:?}");

    // past the limits nothing seals.
    let too_many = PrivateRequest::Status(StatusRequest {
        orders: vec![],
        nullifiers: vec![Felt::ONE; MAX_STATUS_ITEMS + 1],
    });
    assert!(seal_request(&registry, &too_many).is_err());
    let empty = PrivateRequest::Status(StatusRequest::default());
    assert!(seal_request(&registry_of(MAX_EXECUTION_KEYS + 1), &empty).is_err());
}

#[test]
fn status_lookups_chunk_in_order_within_the_limit() {
    let orders = (1..=40_u32)
        .map(|index| OrderQuery {
            order_id: Felt::from(index),
            after_seq: index,
        })
        .collect::<Vec<_>>();
    let nullifiers = (100..130_u32).map(Felt::from).collect::<Vec<_>>();
    let chunks = chunk_status(StatusRequest {
        orders: orders.clone(),
        nullifiers: nullifiers.clone(),
    });
    let sizes = chunks
        .iter()
        .map(|chunk| chunk.orders.len() + chunk.nullifiers.len())
        .collect::<Vec<_>>();
    assert_eq!(sizes, vec![8, 8, 8, 8, 8, 8, 8, 8, 6]);
    let rejoined_orders = chunks.iter().flat_map(|chunk| chunk.orders.clone());
    assert_eq!(rejoined_orders.collect::<Vec<_>>(), orders);
    let rejoined_nullifiers = chunks.iter().flat_map(|chunk| chunk.nullifiers.clone());
    assert_eq!(rejoined_nullifiers.collect::<Vec<_>>(), nullifiers);
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
    let response = seal_response(&[1; 32], "digest", &answer).unwrap();
    assert_eq!(
        response.ciphertext.len(),
        2 * (RESPONSE_PLAINTEXT_BYTES + 16)
    );
}
