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
use zylith_core::ProtocolError;
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
        expectation["proof_shape"] = json!({
            "markets": shape.markets,
            "resting_orders": shape.resting,
            "admissions": shape.admissions,
            "crossings": shape.crossing,
            "outcomes": result.public.outcomes.len(),
            "nullifiers": shape.nullifiers,
            "retired_nullifiers": shape.retired_nullifiers,
            "outputs": shape.outputs,
            "funding_notes": shape.funding_notes,
            "membership_path_elements": shape.membership_path_elements,
        });
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

fn market_witness_start(witness: &[Felt]) -> usize {
    // type/header (including the claimed public output root), then the asset count and three
    // certificate fields per asset, then the objective numeraire and market count.
    let asset_count: usize = witness[10].try_into().expect("asset count");
    13 + 3 * asset_count
}

fn market_witness_end(witness: &[Felt]) -> usize {
    let mut cursor = market_witness_start(witness);
    let count: usize = witness[cursor - 1].try_into().expect("market count");
    for _ in 0..count {
        cursor += if witness[cursor + 9] == Felt::ZERO {
            12
        } else {
            17
        };
    }
    cursor
}

// these are jointly reachable small-runtime cases, not a replacement for measured capacity
// profiles. unlike a coordinate-wise maximum, every setup and tested transition obeys both caps.
fn accept_small_runtime(
    vectors: &mut Vectors,
    name: &str,
    result: &TransitionResult,
) -> Result<(), Box<dyn Error>> {
    let shape = StepShape::of(result);
    assert!(
        shape.resting + shape.admissions <= 2,
        "{name}: input book cap"
    );
    assert!(shape.admissions <= 1, "{name}: admission cap");
    assert_eq!(shape.markets, 3, "{name}: direct and synthetic registry");
    vectors.accept(name, result)?;
    vectors.expectations.get_mut(name).unwrap()["runtime_limits"] =
        json!({"max_book_orders": 2, "max_admissions_per_transition": 1});
    Ok(())
}

fn with_small_registry(mut transition: TransitionInput, midpoint: u128) -> TransitionInput {
    let mut second = market(50);
    second.pair_id = Felt::from(PAIR + 1);
    second.base_asset_id = Felt::from(BASE + 1);
    let mut synthetic = market(midpoint / 50);
    synthetic.pair_id = Felt::from(PAIR + 2);
    synthetic.quote_asset_id = Felt::from(BASE + 1);
    synthetic.reference_methodology = REFERENCE_METHOD_SYNTHETIC_CROSS_BBO;
    synthetic.derivation_base_market_id = Felt::from(PAIR);
    synthetic.derivation_quote_market_id = second.pair_id;
    synthetic.derivation_base_bid = midpoint;
    synthetic.derivation_base_ask = midpoint;
    synthetic.derivation_quote_bid = 50;
    synthetic.derivation_quote_ask = 50;
    synthetic.max_leg_skew_ms = 1_500;
    transition.markets = vec![market(midpoint), second, synthetic];
    transition
}

fn reachable_small_runtime_vectors(vectors: &mut Vectors) -> Result<(), Box<dyn Error>> {
    let mut notes = Notes::default();
    let (seller, buyer, second_seller) = (user(61_001), user(61_002), user(61_003));
    let seller_note = deposit(&seller, BASE, 5, 61_001);
    let second_note = deposit(&second_seller, BASE + 1, 5, 61_003);
    notes.add_deposit(&seller_note);
    notes.add_deposit(&second_note);

    // all four funding paths have the maximum subtree and accumulator depths. the notes share
    // one authenticated batch path while each output-subtree path is checked independently.
    let funding: Vec<_> = (0..MAX_FUNDING_NOTES)
        .map(|index| deposit(&buyer, QUOTE, 300, 62_000 + index as u64))
        .collect();
    let mut leaves: Vec<_> = funding.iter().map(NoteFields::output_leaf).collect();
    leaves.extend(
        (leaves.len()..(1 << MAX_OUTPUT_SUBTREE_DEPTH)).map(|i| Felt::from(0xd000_u64 + i as u64)),
    );
    notes.tree.append(output_tree_root(&leaves));
    for note in &funding {
        notes
            .located
            .push((note.output_leaf(), notes.tree.len() - 1, leaves.clone()));
    }
    let admission = new_order(&notes, &buyer, false, true, 5, 105, &funding);
    let admit = build_transition(&with_small_registry(
        input(1, vec![], vec![admission], notes.root(), 100),
        100,
    ))?;
    assert_eq!(StepShape::of(&admit).membership_path_elements, 4 * 48);
    accept_small_runtime(vectors, "reachable_admission_four_notes", &admit)?;
    vectors.tamper(
        "reject_duplicate_funding_nullifier",
        &admit,
        |witness, layout| {
            let first_note = order_layout(layout, false, 0).funding_starts[0];
            let second_note = order_layout(layout, false, 0).funding_starts[1];
            let width = second_note - first_note;
            let first = witness[first_note..first_note + width].to_vec();
            witness[second_note..second_note + width].copy_from_slice(&first);
        },
    )?;
    vectors
        .expectations
        .get_mut("reject_duplicate_funding_nullifier")
        .unwrap()["error"] = json!("EX_DUP_NULLIFIER");
    let first_reference = admit.layout.orders[0].batch_references[0];
    let second_reference = admit.layout.orders[0].batch_references[1];
    for (name, position, value, error) in [
        (
            "reject_first_batch_reference",
            first_reference,
            (1 << 21) + 16,
            "EX_BATCH_REFERENCE",
        ),
        (
            "reject_forward_batch_reference",
            second_reference,
            (2 << 21) + 16,
            "EX_BATCH_REFERENCE",
        ),
        (
            "reject_batch_reference_high_bits",
            second_reference,
            0x1_0000_0000_u64,
            "EX_BATCH_REFERENCE",
        ),
        ("reject_legacy_transition_type", 0, 14, "EX_TYPE"),
        (
            "reject_shared_path_position_high_bits",
            admit.layout.orders[0].batch_references[0],
            15 + (1 << 20),
            "EX_SUBTREE_POSITION",
        ),
    ] {
        vectors.tamper(name, &admit, |witness, _| {
            witness[position] = Felt::from(value)
        })?;
        vectors.expectations.get_mut(name).unwrap()["error"] = json!(error);
    }
    vectors.tamper("reject_shared_batch_root", &admit, |witness, _| {
        witness[admit.layout.orders[0].funding_starts[1] + 1] += Felt::ONE;
    })?;
    vectors
        .expectations
        .get_mut("reject_shared_batch_root")
        .unwrap()["error"] = json!("EX_BATCH_ROOT");
    for (name, position) in [
        (
            "reject_initial_shared_accumulator",
            admit.layout.funding_siblings,
        ),
        ("reject_shared_note_root", 7),
    ] {
        vectors.tamper(name, &admit, |witness, _| witness[position] += Felt::ONE)?;
        vectors.expectations.get_mut(name).unwrap()["error"] = json!("EX_FUNDING_MEMBERSHIP");
    }
    vectors.tamper("reject_shared_trailing_record", &admit, |witness, _| {
        witness.push(Felt::ZERO)
    })?;
    vectors
        .expectations
        .get_mut("reject_shared_trailing_record")
        .unwrap()["error"] = json!("EX_TRAILING");
    for (name, offset) in [
        ("header", 9),
        ("owner", admit.layout.orders[0].start + 6),
        ("funding", admit.layout.orders[0].funding_starts[0] + 2),
    ] {
        let name = format!("reject_short_{name}_record");
        vectors.write(&name, &admit.witness[..offset], None)?;
        vectors.expectations.get_mut(&name).unwrap()["error"] = json!("EX_SHORT");
    }
    vectors.tamper(
        "reject_funding_encoding_high_bits",
        &admit,
        |witness, layout| {
            witness[order_layout(layout, false, 0).funding_starts[0]] = Felt::TWO.pow(194_u128);
        },
    )?;
    vectors
        .expectations
        .get_mut("reject_funding_encoding_high_bits")
        .unwrap()["error"] = json!("EX_FUNDING_ENCODING");
    vectors.tamper(
        "reject_shared_funding_authority",
        &admit,
        |witness, layout| {
            witness[order_layout(layout, false, 0).start + 3] += Felt::ONE;
        },
    )?;
    vectors
        .expectations
        .get_mut("reject_shared_funding_authority")
        .unwrap()["error"] = json!("EX_BATCH_ROOT");

    let private_notes = Notes {
        tree: notes.tree.clone(),
        located: notes.located.clone(),
    };

    let reserved = build_transition(&with_small_registry(
        input(
            1,
            vec![],
            vec![new_order(
                &notes,
                &seller,
                true,
                true,
                5,
                95,
                std::slice::from_ref(&seller_note),
            )],
            notes.root(),
            100,
        ),
        100,
    ))?;
    accept_small_runtime(vectors, "reachable_reserve", &reserved)?;
    notes.add_outputs(&reserved.public);
    let admission = new_order(&notes, &buyer, false, true, 5, 105, &funding);
    let base = with_small_registry(
        input(
            2,
            reserved.new_book.clone(),
            vec![admission],
            notes.root(),
            100,
        ),
        100,
    );
    accept_small_runtime(
        vectors,
        "reachable_reserved_with_admission",
        &build_transition(&base)?,
    )?;
    for consumed in [0, 2, 5] {
        for recovered in [false, true] {
            let mut apply = base.clone();
            apply.outcomes = vec![Outcome::from_capacity(
                1,
                Felt::from(PAIR),
                true,
                consumed,
                consumed * 101,
                95,
                1,
            )];
            if recovered {
                apply.recovered_order_ids = vec![reserved.new_book[0].order.order_id];
            }
            let result = build_transition(&apply)?;
            let name = format!("reachable_outcome_{consumed}_recovered_{recovered}_admission");
            accept_small_runtime(vectors, &name, &result)?;
            if consumed == 2 && !recovered {
                assert_eq!(StepShape::of(&result).crossing, 2);
                vectors.tamper(
                    "reject_reachable_outcome_skipped",
                    &result,
                    |witness, layout| {
                        witness[order_layout(layout, true, 0).outcome.unwrap()] = Felt::ZERO;
                    },
                )?;
            }
            if consumed == 5 && !recovered {
                vectors.tamper(
                    "reject_unallocated_outcome_capacity",
                    &result,
                    |witness, _| {
                        let assets: usize = witness[10].try_into().unwrap();
                        let start = market_witness_end(witness) + 2 * (assets - 1) + 1;
                        witness[start + 3] = Felt::from(7_u64);
                        witness[start + 4] = Felt::from(707_u64);
                        witness[start + 5] = Felt::from(707_u64);
                        witness[start + 6] = Felt::from(7_u64);
                    },
                )?;
                vectors
                    .expectations
                    .get_mut("reject_unallocated_outcome_capacity")
                    .unwrap()["error"] = json!("EX_OUTCOME_UNALLOCATED");
            }
        }
    }

    // two reservations were admitted in separate transitions. no new order can enter this full
    // book; outcome allocation and cleanup are exercised without an impossible third input.
    let second = new_order_for(
        &notes,
        &second_seller,
        Felt::from(PAIR + 1),
        true,
        true,
        5,
        45,
        std::slice::from_ref(&second_note),
    );
    let full = build_transition(&with_small_registry(
        input(2, reserved.new_book, vec![second], notes.root(), 100),
        100,
    ))?;
    accept_small_runtime(vectors, "reachable_full_reserved_book", &full)?;
    for recovered in [false, true] {
        let mut apply = with_small_registry(
            input(3, full.new_book.clone(), vec![], Felt::ZERO, 100),
            100,
        );
        apply.outcomes = vec![
            Outcome::from_capacity(1, Felt::from(PAIR), true, 2, 202, 95, 1),
            Outcome::from_capacity(2, Felt::from(PAIR + 1), true, 5, 250, 45, 1),
        ];
        if recovered {
            apply.recovered_order_ids = full
                .new_book
                .iter()
                .map(|entry| entry.order.order_id)
                .collect();
        }
        accept_small_runtime(
            vectors,
            &format!("reachable_two_outcomes_recovered_{recovered}"),
            &build_transition(&apply)?,
        )?;
    }

    let first = build_transition(&with_small_registry(
        input(
            1,
            vec![],
            vec![new_order(
                &private_notes,
                &seller,
                true,
                false,
                5,
                95,
                &[seller_note],
            )],
            private_notes.root(),
            200,
        ),
        200,
    ))?;
    accept_small_runtime(vectors, "reachable_private_resting", &first)?;
    let second = new_order(&private_notes, &buyer, false, false, 5, 105, &funding);
    let full = build_transition(&with_small_registry(
        input(2, first.new_book, vec![second], private_notes.root(), 200),
        200,
    ))?;
    accept_small_runtime(vectors, "reachable_full_private_book", &full)?;
    let cross = build_transition(&with_small_registry(
        input(3, full.new_book.clone(), vec![], Felt::ZERO, 100),
        100,
    ))?;
    assert_eq!(StepShape::of(&cross).crossing, 2);
    accept_small_runtime(vectors, "reachable_full_book_cross", &cross)?;
    vectors.tamper("reject_duplicate_order_id", &cross, |witness, layout| {
        witness[order_layout(layout, true, 1).start + 9] = order_layout(layout, true, 0).order_id;
    })?;
    vectors
        .expectations
        .get_mut("reject_duplicate_order_id")
        .unwrap()["error"] = json!("EX_DUP_ORDER_ID");
    let mut cancel = with_small_registry(
        input(3, full.new_book.clone(), vec![], Felt::ZERO, 200),
        200,
    );
    cancel.cancellations = full
        .new_book
        .iter()
        .map(|entry| {
            let key = if entry.order.sell {
                &seller.cancel_key
            } else {
                &buyer.cancel_key
            };
            Ok(Cancellation {
                order_id: entry.order.order_id,
                signature: sign_message(
                    key,
                    &cancel_message(Felt::from(CHAIN), entry.order.order_id),
                )?,
            })
        })
        .collect::<Result<_, ProtocolError>>()?;
    accept_small_runtime(
        vectors,
        "reachable_full_book_cancel",
        &build_transition(&cancel)?,
    )?;
    let mut expire = with_small_registry(input(3, full.new_book, vec![], Felt::ZERO, 200), 200);
    expire.close_time_ms = 1_000_000;
    for market in &mut expire.markets {
        market.observed_at_ms = expire.close_time_ms - 1;
        market.valid_until_ms = expire.close_time_ms + 100;
    }
    accept_small_runtime(
        vectors,
        "reachable_full_book_expire",
        &build_transition(&expire)?,
    )?;
    Ok(())
}

fn shared_membership_vectors(vectors: &mut Vectors) -> Result<(), Box<dyn Error>> {
    for count in 1_usize..=MAX_FUNDING_NOTES {
        for batches in 1..=count {
            for depth in [0, 2, 5, MAX_OUTPUT_SUBTREE_DEPTH] {
                if (1_usize << depth) < count.div_ceil(batches) {
                    continue;
                }
                let owner = user(77_001);
                let funding: Vec<_> = (0..count)
                    .map(|i| deposit(&owner, QUOTE, 400, 77_100 + i as u64))
                    .collect();
                let mut notes = Notes::default();
                for batch in 0..batches {
                    let mut leaves: Vec<_> = funding
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| i % batches == batch)
                        .map(|(_, note)| note.output_leaf())
                        .collect();
                    leaves.extend(
                        (leaves.len()..(1 << depth))
                            .map(|i| Felt::from(0xe000_u64 + 100_000 * batch as u64 + i as u64)),
                    );
                    notes.tree.append(output_tree_root(&leaves));
                    for (i, note) in funding.iter().enumerate() {
                        if i % batches == batch {
                            notes.located.push((
                                note.output_leaf(),
                                notes.tree.len() - 1,
                                leaves.clone(),
                            ));
                        }
                    }
                }
                let result = build_transition(&input(
                    1,
                    vec![],
                    vec![new_order(&notes, &owner, false, true, 3, 105, &funding)],
                    notes.root(),
                    100,
                ))?;
                let name = format!("shared_{count}_notes_{batches}_batches_depth_{depth}");
                vectors.accept(&name, &result)?;
                if count == 4 && batches == 2 && depth == 5 {
                    let second_reference = result.layout.orders[0].batch_references[1];
                    let third_reference = result.layout.orders[0].batch_references[2];
                    for (name, position, value, error) in [
                        (
                            "reject_second_batch_uses_first",
                            second_reference,
                            5 + (1 << 5),
                            "EX_BATCH_ROOT",
                        ),
                        (
                            "reject_first_batch_uses_second",
                            third_reference,
                            (1 << 21) + 5 + (2 << 5),
                            "EX_BATCH_ROOT",
                        ),
                        (
                            "reject_shared_reference_out_of_range",
                            third_reference,
                            (3 << 21) + 5 + (2 << 5),
                            "EX_BATCH_REFERENCE",
                        ),
                        (
                            "reject_second_subtree_position_high_bits",
                            result.layout.orders[0].batch_references[1],
                            5 + (1 << 10),
                            "EX_SUBTREE_POSITION",
                        ),
                    ] {
                        vectors.tamper(name, &result, |witness, _| {
                            witness[position] = Felt::from(value)
                        })?;
                        vectors.expectations.get_mut(name).unwrap()["error"] = json!(error);
                    }
                    vectors.write(
                        "reject_truncated_shared_path",
                        &result.witness[..result.layout.funding_siblings + 20],
                        None,
                    )?;
                    vectors
                        .expectations
                        .get_mut("reject_truncated_shared_path")
                        .unwrap()["error"] = json!("EX_SHORT");
                    let mut second_owner = user(77_001);
                    second_owner.owner.nonce += Felt::ONE;
                    let split = build_transition(&input(
                        1,
                        vec![],
                        vec![
                            new_order(&notes, &owner, false, true, 3, 105, &funding[..2]),
                            new_order(&notes, &second_owner, false, true, 3, 105, &funding[2..]),
                        ],
                        notes.root(),
                        100,
                    ))?;
                    vectors.accept("shared_two_independent_admissions", &split)?;
                    vectors.tamper(
                        "reject_wrong_reference_across_admissions",
                        &split,
                        |witness, layout| {
                            let reference = order_layout(layout, false, 1).batch_references[0];
                            let descriptor =
                                u64::try_from(witness[reference]).unwrap() & ((1 << 21) - 1);
                            witness[reference] = Felt::from(descriptor | (1 << 21));
                        },
                    )?;
                    vectors
                        .expectations
                        .get_mut("reject_wrong_reference_across_admissions")
                        .unwrap()["error"] = json!("EX_BATCH_ROOT");
                    for (name, offset, value, error) in [
                        (
                            "reject_duplicate_batch_position",
                            1,
                            0_u128,
                            "EX_BATCH_ORDER",
                        ),
                        (
                            "reject_descending_batch_position",
                            1,
                            0x1_0000_0002,
                            "EX_BATCH_ORDER",
                        ),
                        (
                            "reject_batch_position_overflow",
                            1,
                            0x1_0000_0000_0000_0000_u128,
                            "EX_BATCH_ENCODING",
                        ),
                        ("reject_excess_batch_count", 0, 4097, "EX_BATCH_COUNT"),
                    ] {
                        vectors.tamper(name, &result, |witness, layout| {
                            witness[layout.funding_batches + offset] = Felt::from(value);
                        })?;
                        vectors.expectations.get_mut(name).unwrap()["error"] = json!(error);
                    }
                    vectors.tamper(
                        "reject_extra_frontier_sibling",
                        &result,
                        |witness, layout| {
                            let count = layout.funding_siblings - 1;
                            let length =
                                usize::try_from(u64::try_from(witness[count]).unwrap()).unwrap();
                            witness[count] += Felt::ONE;
                            witness.insert(layout.funding_siblings + length, Felt::ZERO);
                        },
                    )?;
                    vectors
                        .expectations
                        .get_mut("reject_extra_frontier_sibling")
                        .unwrap()["error"] = json!("EX_BATCH_TRAILING");
                }
            }
        }
    }
    Ok(())
}

/// equal note amounts share poseidon prefixes. cover distinct amounts too, while preserving
/// every order's total funding and clearing terms: shape counts alone do not capture dedup cost.
fn funding_entropy_vectors(vectors: &mut Vectors) -> Result<(), Box<dyn Error>> {
    for varied in [false, true] {
        let owners: Vec<_> = (0..80).map(|i| user(88_000 + i)).collect();
        let funding: Vec<Vec<_>> = owners
            .iter()
            .enumerate()
            .map(|(i, owner)| {
                let quarter = if i % 2 == 0 {
                    1_000_000 / 4
                } else {
                    105_000_000 / 4
                };
                let delta = 4_000 + i as u128 * 4;
                (0..4)
                    .map(|lane| {
                        let amount = if varied {
                            match lane {
                                0 => quarter - 3 * delta,
                                1 => quarter - delta,
                                2 => quarter + delta,
                                _ => quarter + 3 * delta,
                            }
                        } else {
                            quarter
                        };
                        deposit(
                            owner,
                            if i % 2 == 0 { BASE } else { QUOTE },
                            amount,
                            880_000 + i as u64 * 4 + lane,
                        )
                    })
                    .collect()
            })
            .collect();
        let mut notes = Notes::default();
        for note in funding.iter().flatten() {
            notes.add_deposit(note);
        }
        let orders = owners
            .iter()
            .enumerate()
            .map(|(i, owner)| {
                new_order(
                    &notes,
                    owner,
                    i % 2 == 0,
                    false,
                    1_000_000,
                    if i % 2 == 0 { 95 } else { 105 },
                    &funding[i],
                )
            })
            .collect();
        let result = build_transition(&with_small_registry(
            input(1, vec![], orders, notes.root(), 100),
            100,
        ))?;
        assert_eq!(StepShape::of(&result).funding_notes, 320);
        vectors.accept(
            if varied {
                "funding_80_four_notes_varied"
            } else {
                "funding_80_four_notes_uniform"
            },
            &result,
        )?;
    }
    Ok(())
}

fn recovery_fee_vectors(vectors: &mut Vectors) -> Result<(), Box<dyn Error>> {
    for sell in [false, true] {
        for amount in [10_u128, 10_000, MAX_ORDER_AMOUNT / 105] {
            let owner = user(63_001);
            let mut notes = Notes::default();
            let funding = deposit(
                &owner,
                if sell { BASE } else { QUOTE },
                if sell { amount } else { amount * 105 },
                63_001,
            );
            notes.add_deposit(&funding);
            let result = build_transition(&input(
                1,
                vec![],
                vec![new_order(
                    &notes,
                    &owner,
                    sell,
                    true,
                    amount,
                    if sell { 95 } else { 105 },
                    &[funding],
                )],
                notes.root(),
                100,
            ))?;
            notes.add_outputs(&result.public);
            let note = &result.residual_outputs[0].note;
            assert!(note.reserved != 0);
            for fee_bps in [0, 1, 100] {
                let capacity = RecoveryCapacity {
                    generation: 1,
                    status: CAPACITY_STATUS_FROZEN,
                    total: note.reserved,
                    consumed_base: note.reserved,
                    pool_quote: note.reserved * 100,
                    scale: 1,
                };
                let (input_amount, output_amount, fee) =
                    residual_recovery_amounts(note, capacity, fee_bps)?;
                let exit = |amount, commitment| {
                    if amount == 0 {
                        RecoveryExit::default()
                    } else {
                        RecoveryExit {
                            commitment: Felt::from(commitment),
                            authority: owner.owner.withdraw_authority,
                        }
                    }
                };
                let mut recovery = ResidualRecoveryInput {
                    note_root: notes.root(),
                    note: note.clone(),
                    membership: notes.membership_leaf(note.output_leaf()),
                    output_asset_id: Felt::from(if sell { QUOTE } else { BASE }),
                    fee_bps,
                    capacity,
                    input_exit: exit(input_amount, 0x63001_u64),
                    output_exit: exit(output_amount, 0x63002_u64),
                    authorization: Signature {
                        r: Felt::ZERO,
                        s: Felt::ZERO,
                    },
                };
                let preview = preview_residual_recovery(&recovery)?;
                recovery.authorization = sign_message(
                    &owner.withdraw_key,
                    &residual_recovery_authorization_message(preview.commitment),
                )?;
                let (public, witness) = build_residual_recovery(&recovery)?;
                assert_eq!(public.fee_amount, fee);
                let name = format!("recover_reserved_sell_{sell}_amount_{amount}_fee_{fee_bps}");
                vectors.write_for(
                    "residual_recovery",
                    &name,
                    &witness,
                    Some(public.commitment),
                )?;
                if fee_bps == 100 && amount == 10 {
                    let mut changed = witness;
                    changed[4] = Felt::from(101_u64);
                    let name = format!("reject_recovery_fee_sell_{sell}");
                    vectors.write_for("residual_recovery", &name, &changed, None)?;
                    vectors.expectations.get_mut(&name).unwrap()["error"] = json!("RR_FEE");
                }
            }
        }
    }
    Ok(())
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
    // Inheritance only omits an equal key; an explicit spelling of that same key is equivalent.
    let start = cross.layout.orders[0].start;
    let mut explicit = cross.witness.clone();
    explicit[start + 1] -= Felt::TWO.pow(52_u128);
    explicit.insert(start + 7, cross.witness[start + 3]);
    vectors.write(
        "explicit_equal_funding_authority",
        &explicit,
        Some(cross.public.commitment),
    )?;
    for (name, delta, error) in [
        (
            "reject_empty_packed_funding_count",
            -Felt::TWO.pow(49_u128),
            "EX_FUNDING_COUNT",
        ),
        (
            "reject_excess_packed_funding_count",
            Felt::from(4_u64) * Felt::TWO.pow(49_u128),
            "EX_FUNDING_COUNT",
        ),
        (
            "reject_admission_unused_high_bit",
            Felt::TWO.pow(53_u128),
            "EX_ADMISSION_ENCODING",
        ),
    ] {
        vectors.tamper(name, &cross, |witness, layout| {
            witness[order_layout(layout, false, 0).start + 1] += delta;
        })?;
        vectors.expectations.get_mut(name).unwrap()["error"] = json!(error);
    }
    for (name, delta, error) in [
        (
            "reject_zero_packed_order_amount",
            -Felt::from(10_u64),
            "EX_AMOUNT",
        ),
        (
            "reject_packed_order_amount_high_bit",
            Felt::TWO.pow(110_u128),
            "EX_AMOUNT",
        ),
        (
            "reject_packed_order_limit_high_bit",
            Felt::TWO.pow(248_u128),
            "EX_LIMIT",
        ),
        (
            "reject_zero_packed_order_limit",
            -Felt::from(105_u64) * Felt::TWO.pow(128_u128),
            "EX_LIMIT",
        ),
    ] {
        vectors.tamper(name, &cross, |witness, layout| {
            witness[order_layout(layout, false, 0).start] += delta;
        })?;
        vectors.expectations.get_mut(name).unwrap()["error"] = json!(error);
    }
    // A valid funding authority may differ from every authority of the receiving order owner.
    let mut delegated = new_order(
        &notes,
        &seller,
        true,
        false,
        10,
        95,
        &[deposit(&seller, BASE, 10, 1)],
    );
    delegated.terms.owner = buyer.owner.clone();
    delegated.authorization = sign_message(
        &seller.spend_key,
        &delegated.authorization_message(Felt::from(CHAIN)),
    )?;
    let delegated = build_transition(&input(1, vec![], vec![delegated], notes.root(), 100))?;
    vectors.accept("different_funding_and_order_authorities", &delegated)?;
    vectors.tamper(
        "reject_explicit_funding_authority_changed",
        &delegated,
        |witness, layout| {
            witness[layout.orders[0].start + 7] += Felt::ONE;
        },
    )?;
    vectors
        .expectations
        .get_mut("reject_explicit_funding_authority_changed")
        .unwrap()["error"] = json!("EX_BATCH_ROOT");
    vectors.tamper(
        "reject_admission_without_authenticated_batches",
        &cross,
        |witness, layout| {
            let sibling_count =
                usize::try_from(u64::try_from(witness[layout.funding_siblings - 1]).unwrap())
                    .unwrap();
            witness.splice(
                layout.funding_batches..layout.funding_siblings + sibling_count,
                [Felt::ZERO, Felt::ZERO],
            );
        },
    )?;
    vectors
        .expectations
        .get_mut("reject_admission_without_authenticated_batches")
        .unwrap()["error"] = json!("EX_FUNDING_MEMBERSHIP");

    // The canonical floor can be zero for an extreme but valid direct reference ratio; the
    // protocol clamps that asset's objective weight to one.
    let mut minimum_weight_notes = Notes::default();
    let minimum_weight_owner = user(20);
    let minimum_weight_note = deposit(&minimum_weight_owner, BASE, 1, 20);
    minimum_weight_notes.add_deposit(&minimum_weight_note);
    let maximum_reference = u128::from(u64::MAX);
    let mut minimum_weight_input = input(
        1,
        vec![],
        vec![new_order(
            &minimum_weight_notes,
            &minimum_weight_owner,
            true,
            false,
            1,
            maximum_reference,
            &[minimum_weight_note],
        )],
        minimum_weight_notes.root(),
        maximum_reference,
    );
    minimum_weight_input.markets[0].scale = 1;
    let minimum_weight = build_transition(&minimum_weight_input)?;
    // The second sorted asset is the quote numeraire, whose unclamped weight is zero here.
    assert_eq!(minimum_weight.witness[15], Felt::ONE);
    vectors.accept("minimum_weight", &minimum_weight)?;
    vectors.tamper(
        "reject_minimum_weight_changed",
        &minimum_weight,
        |witness, _| {
            witness[15] = Felt::TWO;
        },
    )?;

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
        witness[order_layout(layout, false, 0).allocation] += Felt::TWO.pow(128_u128);
    })?;
    vectors.tamper("reject_quote_short", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).allocation] -= Felt::ONE;
    })?;
    vectors.tamper("reject_capacity_changed", &cross, |witness, layout| {
        witness[order_layout(layout, false, 1).allocation + 1] -= Felt::ONE;
    })?;
    for (name, offset, delta, error) in [
        (
            "reject_packed_fill_high_bit",
            0,
            Felt::TWO.pow(238_u128),
            "EX_ALLOCATION_ENCODING",
        ),
        (
            "reject_packed_external_high_bit",
            1,
            Felt::TWO.pow(238_u128),
            "EX_ALLOCATION_ENCODING",
        ),
        (
            "reject_packed_capacity_high_bit",
            1,
            Felt::TWO.pow(110_u128),
            "EX_CAPACITY",
        ),
        (
            "reject_external_allocation_for_internal_order",
            1,
            Felt::TWO.pow(128_u128),
            "EX_EXTERNAL",
        ),
    ] {
        vectors.tamper(name, &cross, |witness, layout| {
            witness[order_layout(layout, false, 0).allocation + offset] += delta;
        })?;
        vectors.expectations.get_mut(name).unwrap()["error"] = json!(error);
    }
    vectors.tamper("reject_forged_authorization", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).authorization.unwrap()] += Felt::ONE;
    })?;
    vectors.tamper("reject_amount_changed", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).start] -= Felt::ONE;
    })?;
    vectors.tamper("reject_weight_changed", &cross, |witness, _| {
        // Type/header, asset count, then the first asset id and weight.
        witness[12] += Felt::ONE;
    })?;
    vectors.tamper("reject_order_value_dust", &cross, |witness, layout| {
        let market_start = market_witness_start(witness);
        witness[market_start + 8] = Felt::from(2_u64);
        // The first (buy) order originally requests 10 units at limit 105. Keep its flags/count.
        witness[order_layout(layout, false, 0).start] -=
            Felt::from(9_u64) + Felt::from(104_u64) * Felt::TWO.pow(128_u128);
    })?;
    let excessive_expiry = cross.public.close_time_ms + MAX_ORDER_LIFETIME_MS + 1;
    vectors.tamper("reject_long_expiry", &cross, |witness, layout| {
        witness[order_layout(layout, false, 0).start + 1] +=
            Felt::from(excessive_expiry) - Felt::from(1_000_000_u64);
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
        min_order_quote_amount: 1,
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
        min_order_quote_amount: 1,
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
        let market_start = market_witness_start(witness);
        let synthetic_midpoint = market_start + 2 * 12 + 3;
        witness[synthetic_midpoint] += Felt::ONE;
    })?;
    vectors
        .expectations
        .get_mut("reject_synthetic_midpoint")
        .unwrap()["error"] = json!("EX_SYNTH_MID");
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
    vectors.expectations.get_mut("withdraw_output").unwrap()["proof_shape"] = json!({
        "markets": 0,
        "resting_orders": 0,
        "admissions": 0,
        "crossings": 0,
        "outcomes": 0,
        "nullifiers": 1,
        "retired_nullifiers": 0,
        "outputs": 0,
        "funding_notes": 1,
        "membership_path_elements": withdrawal.membership.subtree_path.len()
            + withdrawal.membership.accumulator_path.len(),
    });
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
    vectors.expectations.get_mut("recover_residual").unwrap()["proof_shape"] = json!({
        "markets": 0,
        "resting_orders": 1,
        "admissions": 0,
        "crossings": 0,
        "outcomes": 1,
        "nullifiers": 1,
        "retired_nullifiers": 1,
        "outputs": 0,
        "funding_notes": 1,
        "membership_path_elements": recovery.membership.subtree_path.len()
            + recovery.membership.accumulator_path.len(),
    });
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

    reachable_small_runtime_vectors(&mut vectors)?;
    shared_membership_vectors(&mut vectors)?;
    funding_entropy_vectors(&mut vectors)?;
    recovery_fee_vectors(&mut vectors)?;

    fs::write(
        Path::new(&vectors.dir).join("expectations.json"),
        serde_json::to_vec_pretty(&vectors.expectations)?,
    )?;
    Ok(())
}
