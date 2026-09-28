//! fixtures for the exchange contract's tests: the rust reference builds each transition and
//! withdrawal, and the contract must accept the exact calldata, commitments and proof messages.
//!
//! `cargo run -p zylith-core --example exchange_contract_fixtures -- <dir>` writes one felt per
//! line, the format `snforge_std::fs::read_txt` reads.

use std::error::Error;
use std::fs;
use std::path::Path;

use starknet_crypto::Felt;
use zylith_core::exchange::fixtures::*;
use zylith_core::exchange::*;

const PROOF_PROGRAM: u64 = 0x9999;
const SIGNER_KEY: u64 = 0x5167;

fn attestation(market: &Market) -> Result<MarketAttestation, Box<dyn Error>> {
    Ok(MarketAttestation {
        pair_id: market.pair_id,
        base_asset_id: market.base_asset_id,
        quote_asset_id: market.quote_asset_id,
        midpoint: market.midpoint,
        lower_price: market.midpoint - 1,
        upper_price: market.midpoint + 1,
        scale: market.scale,
        source_count: 3,
        observed_at_ms: market.observed_at_ms,
        valid_until_ms: market.valid_until_ms,
        source_set_commitment: Felt::from(0x5e7_u64),
        nonce: 1,
        price_batch_commitment: Felt::ZERO,
        signer: Felt::ZERO,
        signature: Signature {
            r: Felt::ZERO,
            s: Felt::ZERO,
        },
    })
}

struct Fixture {
    lines: Vec<Felt>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            lines: vec![
                Felt::from(CHAIN),
                public_key(&Felt::from(SIGNER_KEY)),
                Felt::from(PROOF_PROGRAM),
            ],
        }
    }

    fn deposits(&mut self, notes: &[NoteFields]) {
        self.lines.push(Felt::from(notes.len() as u64));
        for note in notes {
            self.lines.extend_from_slice(&[
                sponge(&[short_string("zylith_fixture_funding"), note.commitment()]),
                note.output_leaf(),
                note.commitment(),
                note.asset_id,
                felt_u128(note.amount),
                note.withdraw_authority,
            ]);
        }
    }

    fn transition(&mut self, result: &TransitionResult) -> Result<(), Box<dyn Error>> {
        let public = &result.public;
        let mut attestations = public
            .markets
            .iter()
            .map(attestation)
            .collect::<Result<Vec<_>, _>>()?;
        sign_price_batch(
            Felt::from(CHAIN),
            &mut attestations,
            &Felt::from(SIGNER_KEY),
        )?;
        let message = proof_message_hash(
            Felt::from(PROOF_PROGRAM),
            TRANSITION_MESSAGE_DOMAIN,
            bound_statement_message(
                TRANSITION_MESSAGE_DOMAIN,
                public.chain_context,
                public.commitment,
            ),
        );
        let calldata = transition_calldata(public, &attestations)?;
        self.lines.push(public.commitment);
        self.lines.push(message);
        self.lines.push(Felt::from(calldata.len() as u64));
        self.lines.extend(calldata);
        Ok(())
    }

    fn withdrawal(&mut self, public: &WithdrawalPublic) {
        let message = proof_message_hash(
            Felt::from(PROOF_PROGRAM),
            WITHDRAWAL_MESSAGE_DOMAIN,
            bound_statement_message(
                WITHDRAWAL_MESSAGE_DOMAIN,
                public.chain_context,
                public.commitment,
            ),
        );
        self.lines.push(public.commitment);
        self.lines.push(message);
        self.lines.extend(withdrawal_calldata(public));
    }

    fn write(&self, dir: &str, name: &str) -> Result<(), Box<dyn Error>> {
        let text = self
            .lines
            .iter()
            .map(|felt| felt.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(Path::new(dir).join(format!("{name}.txt")), text + "\n")?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: exchange_contract_fixtures <dir> [<proof program dir>]")?;
    fs::create_dir_all(&dir)?;
    let program_dir = std::env::args().nth(2);

    // a cross between two new orders, then a withdrawal of the seller's proceeds.
    let mut notes = Notes::default();
    let (seller, buyer) = (user(1), user(2));
    let deposits = vec![
        deposit(&seller, BASE, 10, 1),
        deposit(&buyer, QUOTE, 2_000, 2),
    ];
    for note in &deposits {
        notes.add_deposit(note);
    }
    // the seller also asks to withdraw the note its order spends: the transition must win.
    let exit = Felt::from(0xe417_u64);
    let exit_authority = public_key(&Felt::from(0xe41a_u64));
    let (raced, _) = build_withdrawal(&WithdrawalInput {
        chain_context: Felt::from(CHAIN),
        note_root: notes.root(),
        exit_commitment: exit,
        exit_authority,
        membership: notes.membership(&deposits[0]),
        authorization: sign_message(
            &seller.withdraw_key,
            &withdrawal_authorization_message(
                Felt::from(CHAIN),
                deposits[0].nullifier(),
                exit,
                exit_authority,
            ),
        )?,
        note: deposits[0].clone(),
    })?;
    let cross = build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &seller, true, false, 10, 95, &[deposits[0].clone()]),
            new_order(
                &notes,
                &buyer,
                false,
                false,
                10,
                105,
                &[deposits[1].clone()],
            ),
        ],
        notes.root(),
        100,
    ))?;
    notes.add_outputs(&cross.public);
    let proceeds = cross
        .outputs
        .iter()
        .find(|output| output.note.owner_public_key == seller.owner.owner_public_key)
        .unwrap();
    let (withdrawal, _) = build_withdrawal(&WithdrawalInput {
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
    })?;
    let mut fixture = Fixture::new();
    fixture.deposits(&deposits);
    fixture.withdrawal(&raced);
    fixture.transition(&cross)?;
    fixture.withdrawal(&withdrawal);
    fixture.write(&dir, "exchange_cross")?;
    if let Some(program_dir) = &program_dir {
        // the proof program's inputs: its exchange, the expected commitment and the witness.
        fs::create_dir_all(program_dir)?;
        let (withdrawal_public, withdrawal_witness) = build_withdrawal(&WithdrawalInput {
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
        })?;
        for (name, commitment, witness) in [
            ("transition_cross", cross.public.commitment, &cross.witness),
            (
                "withdrawal_output",
                withdrawal_public.commitment,
                &withdrawal_witness,
            ),
        ] {
            let mut program = Fixture {
                lines: vec![
                    Felt::from(CHAIN),
                    commitment,
                    Felt::from(witness.len() as u64),
                ],
            };
            program.lines.extend_from_slice(witness);
            program.write(program_dir, name)?;
        }
    }

    // an external reservation, then its (unfilled) outcome is applied by the next transition.
    let mut notes = Notes::default();
    let external = user(5);
    let deposits = vec![deposit(&external, BASE, 10, 5)];
    notes.add_deposit(&deposits[0]);
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
            &[deposits[0].clone()],
        )],
        notes.root(),
        100,
    ))?;
    // the outcome as the contract records it: unfilled, or filled in parts (6 then 3 of the 10
    // at an m1 of 101, the last base left for the book) and shared at the average price.
    let capacity = &reserve.public.capacities[0];
    let apply_with = |consumed_base: u128, pool_quote: u128| {
        let mut apply_input = input(2, reserve.new_book.clone(), vec![], Felt::ZERO, 100);
        apply_input.outcomes = vec![Outcome::from_capacity(
            1,
            Felt::from(PAIR),
            true,
            consumed_base,
            pool_quote,
            capacity.bound,
            apply_input.markets[0].scale,
        )];
        build_transition(&apply_input)
    };
    let apply = apply_with(0, 0)?;
    let apply_parts = apply_with(9, 909)?;
    let apply_full = apply_with(10, 1010)?;
    let mut fixture = Fixture::new();
    fixture.deposits(&deposits);
    fixture.transition(&reserve)?;
    fixture.transition(&apply)?;
    // a fresh m1 above the sell capacity's bound, for the searcher's fill.
    let mut m1 = attestation(&Market {
        midpoint: 101,
        observed_at_ms: 10_000,
        valid_until_ms: 20_000,
        ..market(101)
    })?;
    m1.sign(Felt::from(CHAIN), &Felt::from(SIGNER_KEY))?;
    fixture.lines.extend(m1.calldata());
    fixture.write(&dir, "exchange_external")?;
    let mut fixture = Fixture::new();
    fixture.deposits(&deposits);
    fixture.transition(&reserve)?;
    fixture.transition(&apply_parts)?;
    fixture.lines.extend(m1.calldata());
    fixture.write(&dir, "exchange_external_parts")?;
    let mut fixture = Fixture::new();
    fixture.deposits(&deposits);
    fixture.transition(&reserve)?;
    fixture.transition(&apply_full)?;
    fixture.lines.extend(m1.calldata());
    fixture.write(&dir, "exchange_external_full")?;

    // mainnet-scale external fills for the ekubo fork tests, 1000 strk (18 decimals) against usdc
    // (6 decimals) with m0 at 0.041: a sell resting at a limit of 0.040 filled at an m1 of 0.0405
    // while the pool pays about 0.0412, and a buy resting at 0.042 filled at 0.0415 while the
    // pool asks about 0.04116.
    fork_fixture(&dir, "exchange_fork", true, 40_000, 40_500)?;
    fork_fixture(&dir, "exchange_fork_buy", false, 42_000, 41_500)?;
    Ok(())
}

fn fork_fixture(
    dir: &str,
    name: &str,
    sell: bool,
    limit: u128,
    m1_price: u128,
) -> Result<(), Box<dyn Error>> {
    const STRK_SCALE: u128 = 1_000_000_000_000_000_000;
    const SIZE: u128 = 1_000 * STRK_SCALE;
    let m0 = 41_000_u128;
    let fork_market = |midpoint| Market {
        midpoint,
        scale: STRK_SCALE,
        ..market(midpoint)
    };
    let mut notes = Notes::default();
    let trader = user(if sell { 6 } else { 7 });
    // a sell locks its base; a buy the quote its size costs at the limit.
    let deposits = if sell {
        vec![deposit(&trader, BASE, SIZE, 6)]
    } else {
        vec![deposit(&trader, QUOTE, SIZE * limit / STRK_SCALE, 7)]
    };
    notes.add_deposit(&deposits[0]);
    let mut reserve_input = input(
        1,
        vec![],
        vec![new_order(
            &notes,
            &trader,
            sell,
            true,
            SIZE,
            limit,
            &[deposits[0].clone()],
        )],
        notes.root(),
        m0,
    );
    reserve_input.markets = vec![fork_market(m0)];
    let reserve = build_transition(&reserve_input)?;
    let mut apply_input = input(2, reserve.new_book.clone(), vec![], Felt::ZERO, m0);
    apply_input.markets = vec![fork_market(m0)];
    let product = SIZE * m1_price;
    // the escrow's side rounds in the book's favour: down for what a sell receives, up for what
    // a buy pays. the fork tests fill it whole and in halves, which divide exactly, so both
    // record the same totals.
    let pool_quote = if sell {
        product / STRK_SCALE
    } else {
        product.div_ceil(STRK_SCALE)
    };
    apply_input.outcomes = vec![Outcome::from_capacity(
        1,
        Felt::from(PAIR),
        sell,
        SIZE,
        pool_quote,
        reserve.public.capacities[0].bound,
        STRK_SCALE,
    )];
    let apply = build_transition(&apply_input)?;
    let mut fixture = Fixture::new();
    fixture.deposits(&deposits);
    fixture.transition(&reserve)?;
    fixture.transition(&apply)?;
    let mut m1 = attestation(&Market {
        observed_at_ms: 10_000,
        valid_until_ms: 20_000,
        ..fork_market(m1_price)
    })?;
    m1.sign(Felt::from(CHAIN), &Felt::from(SIGNER_KEY))?;
    fixture.lines.extend(m1.calldata());
    fixture.write(dir, name)?;
    Ok(())
}
