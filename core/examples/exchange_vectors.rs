//! differential vectors for the exchange statements: every scenario is built by the rust reference
//! (`zylith_core::exchange`) and written as the cairo statement's input with the commitment the
//! statement must output; tampered variants must be rejected.
//!
//! `cargo run -p zylith-core --example exchange_vectors -- <dir>` writes `<name>.json` inputs and
//! `expectations.json` for `scripts/exchange_vectors.sh`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use starknet_crypto::Felt;
use zylith_core::exchange::fixtures::*;
use zylith_core::exchange::*;

const RESIDUAL_RECOVERY_FUNDING_INDEX: usize = 21;

struct Vectors {
    dir: String,
    expectations: BTreeMap<String, Value>,
}

impl Vectors {
    fn write(
        &mut self,
        name: &str,
        witness: &[Felt],
        expected: Option<Felt>,
    ) -> Result<(), Box<dyn Error>> {
        self.write_for("transition", name, witness, expected)
    }

    fn write_for(
        &mut self,
        executable: &str,
        name: &str,
        witness: &[Felt],
        expected: Option<Felt>,
    ) -> Result<(), Box<dyn Error>> {
        let mut values = vec![format!("{:#x}", witness.len())];
        values.extend(witness.iter().map(|felt| format!("{felt:#x}")));
        fs::write(
            Path::new(&self.dir).join(format!("{name}.json")),
            serde_json::to_vec(&values)?,
        )?;
        let expectation = match expected {
            Some(commitment) => {
                json!({ "expect": "accept", "commitment": format!("{commitment:#x}"), "executable": executable })
            }
            None => json!({ "expect": "reject", "executable": executable }),
        };
        self.expectations.insert(name.into(), expectation);
        Ok(())
    }

    fn accept(&mut self, name: &str, result: &TransitionResult) -> Result<(), Box<dyn Error>> {
        self.write(name, &result.witness, Some(result.public.commitment))?;
        // the runner fails when cairo measures more steps than the operator's estimate.
        let shape = StepShape::of(result);
        let expectation = self.expectations.get_mut(name).expect("just written");
        expectation["max_steps"] = json!(shape.estimated_steps());
        expectation["shape"] = serde_json::to_value(shape)?;
        Ok(())
    }

    fn tamper(
        &mut self,
        name: &str,
        result: &TransitionResult,
        edit: impl FnOnce(&mut Vec<Felt>, &WitnessLayout),
    ) -> Result<(), Box<dyn Error>> {
        let mut witness = result.witness.clone();
        edit(&mut witness, &result.layout);
        self.write(name, &witness, None)
    }
}

/// admits `count` orders at `midpoint`, alternating buys at `buy_limit` and sells at
/// `sell_limit`, none of which can fill.
fn scaled_book(
    count: usize,
    sell_limit: u128,
    buy_limit: u128,
    midpoint: u128,
) -> Result<((TransitionResult,), Notes), Box<dyn Error>> {
    let mut notes = Notes::default();
    let mut funding = Vec::new();
    for index in 0..count {
        let owner = user(1_000 + index as u64);
        let sell = index % 2 == 1;
        let note = if sell {
            deposit(&owner, BASE, 10, 1_000 + index as u64)
        } else {
            deposit(&owner, QUOTE, 1_100, 1_000 + index as u64)
        };
        notes.add_deposit(&note);
        funding.push((owner, note, sell));
    }
    let orders = funding
        .iter()
        .map(|(owner, note, sell)| {
            new_order(
                &notes,
                owner,
                *sell,
                false,
                10,
                if *sell { sell_limit } else { buy_limit },
                std::slice::from_ref(note),
            )
        })
        .collect::<Vec<_>>();
    let admitted = build_transition(&input(1, vec![], orders, notes.root(), midpoint))?;
    assert_eq!(admitted.new_book.len(), count);
    notes.add_outputs(&admitted.public);
    Ok(((admitted,), notes))
}

fn order_layout(layout: &WitnessLayout, existing: bool, index: usize) -> &OrderLayout {
    layout
        .orders
        .iter()
        .filter(|order| order.existing == existing)
        .nth(index)
        .expect("order layout")
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: exchange_vectors <dir>")?;
    fs::create_dir_all(&dir)?;
    let mut vectors = Vectors {
        dir,
        expectations: BTreeMap::new(),
    };

    // a two-sided cross between new orders.
    let mut notes = Notes::default();
    let (seller, buyer) = (user(1), user(2));
    let (base_note, quote_note) = (
        deposit(&seller, BASE, 10, 1),
        deposit(&buyer, QUOTE, 2_000, 2),
    );
    notes.add_deposit(&base_note);
    notes.add_deposit(&quote_note);
    let cross = build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &seller, true, false, 10, 95, &[base_note]),
            new_order(&notes, &buyer, false, false, 10, 105, &[quote_note]),
        ],
        notes.root(),
        100,
    ))?;
    vectors.accept("cross", &cross)?;

    // mainnet magnitudes: an 18-decimal base near 0.041 of a 6-decimal quote, a cross and an
    // external residual, which the certificate's weights must span.
    const STRK_SCALE: u128 = 1_000_000_000_000_000_000;
    let mut notes = Notes::default();
    let (mainnet_seller, mainnet_buyer, mainnet_external) = (user(21), user(22), user(23));
    let mainnet_notes = [
        deposit(&mainnet_seller, BASE, 1_500 * STRK_SCALE, 21),
        deposit(&mainnet_buyer, QUOTE, 50_000_000, 22),
        deposit(&mainnet_external, BASE, 700 * STRK_SCALE, 23),
    ];
    for note in &mainnet_notes {
        notes.add_deposit(note);
    }
    let mut mainnet = input(
        1,
        vec![],
        vec![
            new_order(
                &notes,
                &mainnet_seller,
                true,
                false,
                1_500 * STRK_SCALE,
                40_000,
                &[mainnet_notes[0].clone()],
            ),
            new_order(
                &notes,
                &mainnet_buyer,
                false,
                false,
                1_000 * STRK_SCALE,
                42_000,
                &[mainnet_notes[1].clone()],
            ),
            new_order(
                &notes,
                &mainnet_external,
                true,
                true,
                700 * STRK_SCALE,
                40_500,
                &[mainnet_notes[2].clone()],
            ),
        ],
        notes.root(),
        41_000,
    );
    mainnet.markets = vec![Market {
        scale: STRK_SCALE,
        ..market(41_000)
    }];
    vectors.accept("mainnet_scale", &build_transition(&mainnet)?)?;
    vectors.tamper("reject_fill_inflated", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).allocation] += Felt::ONE;
    })?;
    vectors.tamper("reject_quote_short", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).allocation + 1] -= Felt::ONE;
    })?;
    vectors.tamper("reject_capacity_changed", &cross, |witness, layout| {
        witness[order_layout(layout, false, 1).allocation + 2] -= Felt::ONE;
    })?;
    vectors.tamper("reject_forged_authorization", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).authorization.unwrap()] += Felt::ONE;
    })?;
    vectors.tamper("reject_amount_changed", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).start + 1] -= Felt::ONE;
    })?;
    vectors.tamper("reject_hidden_market", &cross, |witness, layout| {
        witness[layout.groups[0] + 2] = Felt::ZERO;
    })?;
    vectors.tamper("reject_truncated", &cross, |witness, _| {
        witness.pop();
    })?;

    // a resting order persists, then fills against a later order.
    let mut notes = Notes::default();
    let (resting, taker) = (user(3), user(4));
    let resting_note = deposit(&resting, QUOTE, 2_000, 3);
    notes.add_deposit(&resting_note);
    let first = build_transition(&input(
        1,
        vec![],
        vec![new_order(
            &notes,
            &resting,
            false,
            false,
            10,
            105,
            &[resting_note],
        )],
        notes.root(),
        110,
    ))?;
    notes.add_outputs(&first.public);
    let taker_note = deposit(&taker, BASE, 6, 4);
    notes.add_deposit(&taker_note);
    let persist = build_transition(&input(
        2,
        first.new_book.clone(),
        vec![new_order(&notes, &taker, true, false, 6, 95, &[taker_note])],
        notes.root(),
        100,
    ))?;
    vectors.accept("admit_resting", &first)?;
    vectors.accept("persist_cross", &persist)?;
    let mut retire_input = input(2, first.new_book.clone(), vec![], Felt::ZERO, 110);
    retire_input.recovered_order_ids = vec![first.new_book[0].order.order_id];
    let retire = build_transition(&retire_input)?;
    vectors.accept("retire_recovered", &retire)?;
    vectors.tamper("reject_book_forged", &persist, |witness, layout| {
        witness[order_layout(layout, true, 0).start + 1] += Felt::ONE;
    })?;

    // an external residual is reserved, then its outcome settles.
    let mut notes = Notes::default();
    let external = user(5);
    let external_note = deposit(&external, BASE, 10, 5);
    notes.add_deposit(&external_note);
    let reserve = build_transition(&input(
        1,
        vec![],
        vec![new_order(
            &notes,
            &external,
            true,
            true,
            10,
            95,
            &[external_note],
        )],
        notes.root(),
        100,
    ))?;
    vectors.accept("external_reserve", &reserve)?;
    let mut apply = input(2, reserve.new_book.clone(), vec![], Felt::ZERO, 100);
    apply.outcomes = vec![Outcome {
        seq: 1,
        pair_id: Felt::from(PAIR),
        sell: true,
        consumed_base: 6,
        pool_quote: 607,
        m1: 101,
        m1_scale: 1,
    }];
    let applied = build_transition(&apply)?;
    vectors.accept("outcome_apply", &applied)?;
    vectors.tamper("reject_outcome_skipped", &applied, |witness, layout| {
        witness[order_layout(layout, true, 0).outcome.unwrap()] = Felt::ZERO;
    })?;

    // two external sells share a capacity filled in parts at different m1s (6 at 101, then 5 at
    // 103, one base left): they share the totals at the average price, 1121 per 11, and the
    // rounding dust goes to the fee.
    let mut notes = Notes::default();
    let (first, second) = (user(8), user(9));
    let first_note = deposit(&first, BASE, 7, 8);
    let second_note = deposit(&second, BASE, 5, 9);
    notes.add_deposit(&first_note);
    notes.add_deposit(&second_note);
    let shared = build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &first, true, true, 7, 95, &[first_note]),
            new_order(&notes, &second, true, true, 5, 90, &[second_note]),
        ],
        notes.root(),
        100,
    ))?;
    let mut apply = input(2, shared.new_book.clone(), vec![], Felt::ZERO, 100);
    apply.outcomes = vec![Outcome::from_capacity(
        1,
        Felt::from(PAIR),
        true,
        11,
        6 * 101 + 5 * 103,
        shared.public.capacities[0].bound,
        apply.markets[0].scale,
    )];
    vectors.accept("outcome_apply_average", &build_transition(&apply)?)?;

    // cancellation and expiry.
    let mut notes = Notes::default();
    let (cancelling, expiring) = (user(6), user(7));
    let cancel_note = deposit(&cancelling, QUOTE, 500, 6);
    let expiry_note = deposit(&expiring, QUOTE, 700, 7);
    notes.add_deposit(&cancel_note);
    notes.add_deposit(&expiry_note);
    let mut short_lived = new_order(&notes, &expiring, false, false, 5, 90, &[expiry_note]);
    short_lived.terms.expiry_ms = 10_005;
    short_lived.authorization = sign_message(
        &expiring.spend_key,
        &short_lived.authorization_message(Felt::from(CHAIN)),
    )?;
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &cancelling, false, false, 5, 90, &[cancel_note]),
            short_lived,
        ],
        notes.root(),
        100,
    ))?;
    let cancelled_id = admitted.new_book[0].order.order_id;
    let mut removal = input(9, admitted.new_book.clone(), vec![], Felt::ZERO, 100);
    removal.cancellations = vec![Cancellation {
        order_id: cancelled_id,
        signature: sign_message(
            &cancelling.cancel_key,
            &cancel_message(Felt::from(CHAIN), cancelled_id),
        )?,
    }];
    let removed = build_transition(&removal)?;
    vectors.accept("cancel_expiry", &removed)?;
    vectors.tamper("reject_expired_kept", &removed, |witness, layout| {
        let expired = layout
            .orders
            .iter()
            .find(|order| order.order_id != cancelled_id)
            .unwrap();
        witness[expired.removal.unwrap()] = Felt::ZERO;
    })?;
    vectors.tamper("reject_forged_cancel", &removed, |witness, layout| {
        let cancel = layout
            .orders
            .iter()
            .find(|order| order.order_id == cancelled_id)
            .unwrap();
        witness[cancel.removal.unwrap() + 1] += Felt::ONE;
    })?;

    // two markets sharing a quote asset, and a resting order whose market is absent.
    let second_pair = Felt::from(0x9a2_u64);
    let second_base = Felt::from(0xba5e2_u64);
    let second_market = Market {
        pair_id: second_pair,
        base_asset_id: second_base,
        quote_asset_id: Felt::from(QUOTE),
        midpoint: 50,
        scale: 1,
        observed_at_ms: 9_000,
        valid_until_ms: 11_000,
        fee_bps: 10,
        reference_methodology: REFERENCE_METHOD_DIRECT_BBO,
        derivation_base_market_id: Felt::ZERO,
        derivation_quote_market_id: Felt::ZERO,
        derivation_base_bid: 50,
        derivation_base_ask: 50,
        derivation_quote_bid: 0,
        derivation_quote_ask: 0,
        max_leg_skew_ms: 0,
    };
    let mut notes = Notes::default();
    let users = (8..14).map(user).collect::<Vec<_>>();
    let notes_for = [
        deposit(&users[0], BASE, 10, 8),
        deposit(&users[1], QUOTE, 2_000, 9),
        NoteFields {
            asset_id: second_base,
            ..deposit(&users[2], BASE, 20, 10)
        },
        deposit(&users[3], QUOTE, 2_000, 11),
        NoteFields {
            asset_id: second_base,
            ..deposit(&users[4], BASE, 7, 12)
        },
    ];
    for note in &notes_for {
        notes.add_deposit(note);
    }
    let mut multi_input = input(
        1,
        vec![],
        vec![
            new_order(
                &notes,
                &users[0],
                true,
                false,
                10,
                95,
                &[notes_for[0].clone()],
            ),
            new_order(
                &notes,
                &users[1],
                false,
                true,
                12,
                105,
                &[notes_for[1].clone()],
            ),
            new_order_for(
                &notes,
                &users[2],
                second_pair,
                true,
                false,
                20,
                49,
                &[notes_for[2].clone()],
            ),
            new_order_for(
                &notes,
                &users[3],
                second_pair,
                false,
                false,
                15,
                51,
                &[notes_for[3].clone()],
            ),
        ],
        notes.root(),
        100,
    );
    multi_input.markets.push(second_market.clone());
    // the non-numeraire market is derived from the two direct numeraire bbo observations.
    multi_input.markets.push(Market {
        pair_id: Felt::from(0x9a3_u64),
        base_asset_id: Felt::from(BASE),
        quote_asset_id: second_base,
        midpoint: 2,
        scale: 1,
        observed_at_ms: 9_000,
        valid_until_ms: 11_000,
        fee_bps: 10,
        reference_methodology: REFERENCE_METHOD_SYNTHETIC_CROSS_BBO,
        derivation_base_market_id: Felt::from(PAIR),
        derivation_quote_market_id: second_pair,
        derivation_base_bid: 100,
        derivation_base_ask: 100,
        derivation_quote_bid: 50,
        derivation_quote_ask: 50,
        max_leg_skew_ms: 1_500,
    });
    let multi = build_transition(&multi_input)?;
    vectors.accept("multi_market", &multi)?;
    vectors.tamper("reject_synthetic_midpoint", &multi, |witness, _| {
        let market_start = 12 + 3 * 3;
        let synthetic_midpoint = market_start + 2 * 16 + 3;
        witness[synthetic_midpoint] += Felt::ONE;
    })?;
    notes.add_outputs(&multi.public);
    // only the first market this time: the second pair's resting orders pass through.
    let resting_input = input(2, multi.new_book.clone(), vec![], Felt::ZERO, 100);
    let pass = build_transition(&resting_input)?;
    vectors.accept("pass_through", &pass)?;

    // scale: a resting book of n orders with a small cross against it, and a book whose limits
    // all overlap the next midpoint so the whole book crosses.
    for count in [64_usize, 256, 1022] {
        let (resting_book, notes) = scaled_book(count, 101, 99, 100)?;
        vectors.accept(&format!("admit_{count}"), &resting_book.0)?;
        let mut notes = notes;
        let (taker_sell, taker_buy) = (user(900_001), user(900_002));
        let sell_note = deposit(&taker_sell, BASE, 10, 900_001);
        let buy_note = deposit(&taker_buy, QUOTE, 1_100, 900_002);
        notes.add_deposit(&sell_note);
        notes.add_deposit(&buy_note);
        let resting = build_transition(&input(
            2,
            resting_book.0.new_book.clone(),
            vec![
                new_order(&notes, &taker_sell, true, false, 10, 95, &[sell_note]),
                new_order(&notes, &taker_buy, false, false, 10, 105, &[buy_note]),
            ],
            notes.root(),
            100,
        ))?;
        vectors.accept(&format!("book_{count}"), &resting)?;
        let (crossing_book, _) = scaled_book(count, 95, 105, 200)?;
        let full = build_transition(&input(
            2,
            crossing_book.0.new_book.clone(),
            vec![],
            Felt::ZERO,
            100,
        ))?;
        assert!(full.new_book.is_empty());
        vectors.accept(&format!("cross_{count}"), &full)?;
    }

    // a withdrawal of a transition output: membership through its output subtree.
    let mut notes = Notes::default();
    let (seller, buyer) = (user(20), user(21));
    let (base_note, quote_note) = (
        deposit(&seller, BASE, 10, 20),
        deposit(&buyer, QUOTE, 2_000, 21),
    );
    notes.add_deposit(&base_note);
    notes.add_deposit(&quote_note);
    let settled = build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &seller, true, false, 10, 95, &[base_note]),
            new_order(&notes, &buyer, false, false, 10, 105, &[quote_note]),
        ],
        notes.root(),
        100,
    ))?;
    notes.add_outputs(&settled.public);
    let proceeds = settled
        .outputs
        .iter()
        .find(|output| output.note.owner_public_key == seller.owner.owner_public_key)
        .unwrap();
    let exit = Felt::from(0xe417_u64);
    let exit_authority = public_key(&Felt::from(0xe41a_u64));
    let withdrawal = WithdrawalInput {
        chain_context: Felt::from(CHAIN),
        note_root: notes.root(),
        exit_commitment: exit,
        exit_authority,
        membership: notes.membership(&proceeds.note),
        authorization: sign_message(
            &seller.withdraw_key,
            &withdrawal_authorization_message(
                Felt::from(CHAIN),
                proceeds.note.nullifier(),
                exit,
                exit_authority,
            ),
        )?,
        note: proceeds.note.clone(),
    };
    let (public, witness) = build_withdrawal(&withdrawal)?;
    vectors.write_for(
        "exchange_withdrawal",
        "withdraw_output",
        &witness,
        Some(public.commitment),
    )?;
    let mut swapped_exit = witness.clone();
    swapped_exit[4] = public_key(&Felt::from(0xbad_u64));
    vectors.write_for(
        "exchange_withdrawal",
        "reject_withdraw_exit_swapped",
        &swapped_exit,
        None,
    )?;
    let mut wrong_root = witness.clone();
    wrong_root[2] += Felt::ONE;
    vectors.write_for(
        "exchange_withdrawal",
        "reject_withdraw_wrong_root",
        &wrong_root,
        None,
    )?;

    // permissionless recovery of a resting residual authority.
    let mut residual_notes = Notes::default();
    let residual_user = user(30);
    let residual_funding = deposit(&residual_user, BASE, 10, 30);
    residual_notes.add_deposit(&residual_funding);
    let admitted = build_transition(&input(
        1,
        vec![],
        vec![new_order(
            &residual_notes,
            &residual_user,
            true,
            false,
            10,
            110,
            &[residual_funding],
        )],
        residual_notes.root(),
        100,
    ))?;
    residual_notes.add_outputs(&admitted.public);
    let residual = &admitted.residual_outputs[0].note;
    let mut recovery = ResidualRecoveryInput {
        note_root: residual_notes.root(),
        note: residual.clone(),
        membership: residual_notes.membership_leaf(residual.output_leaf()),
        output_asset_id: Felt::from(QUOTE),
        fee_bps: 30,
        capacity: RecoveryCapacity::default(),
        input_exit: RecoveryExit {
            commitment: Felt::from(0x301_u64),
            authority: public_key(&Felt::from(0x302_u64)),
        },
        output_exit: RecoveryExit::default(),
        authorization: Signature {
            r: Felt::ZERO,
            s: Felt::ZERO,
        },
    };
    let preview = preview_residual_recovery(&recovery)?;
    recovery.authorization = sign_message(
        &residual_user.withdraw_key,
        &residual_recovery_authorization_message(preview.commitment),
    )?;
    let (recovery_public, recovery_witness) = build_residual_recovery(&recovery)?;
    vectors.write_for(
        "residual_recovery",
        "recover_residual",
        &recovery_witness,
        Some(recovery_public.commitment),
    )?;
    let mut wrong_recovery_signature = recovery_witness.clone();
    let last = wrong_recovery_signature.len() - 1;
    wrong_recovery_signature[last] += Felt::ONE;
    vectors.write_for(
        "residual_recovery",
        "reject_recovery_signature",
        &wrong_recovery_signature,
        None,
    )?;
    let mut inflated_residual_funding = recovery_witness.clone();
    inflated_residual_funding[RESIDUAL_RECOVERY_FUNDING_INDEX] += Felt::ONE;
    vectors.write_for(
        "residual_recovery",
        "reject_residual_funding_inflated",
        &inflated_residual_funding,
        None,
    )?;

    // a finalized recovery owns the external proceeds and fee, so retirement authenticates the
    // capacity outcome without emitting those economic outputs a second time.
    let mut external_notes = Notes::default();
    let external_user = user(31);
    let external_funding = deposit(&external_user, BASE, 10, 31);
    external_notes.add_deposit(&external_funding);
    let reserved = build_transition(&input(
        1,
        vec![],
        vec![new_order(
            &external_notes,
            &external_user,
            true,
            true,
            10,
            95,
            &[external_funding],
        )],
        external_notes.root(),
        100,
    ))?;
    let recovered = reserved.residual_outputs[0].note.clone();
    let mut retire = input(2, reserved.new_book, vec![], Felt::ZERO, 100);
    retire.outcomes = vec![Outcome::from_capacity(
        1,
        Felt::from(PAIR),
        true,
        10,
        1_010,
        95,
        1,
    )];
    retire.recovered_order_ids = vec![recovered.order_id];
    let retired = build_transition(&retire)?;
    assert!(retired.outputs.is_empty());
    vectors.accept("retire_recovered_external", &retired)?;

    fs::write(
        Path::new(&vectors.dir).join("expectations.json"),
        serde_json::to_vec_pretty(&vectors.expectations)?,
    )?;
    Ok(())
}
