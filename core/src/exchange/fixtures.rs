//! deterministic users, notes and orders for the exchange's tests and differential vectors.

use starknet_crypto::Felt;

use super::*;

pub const CHAIN: u64 = 0x5eed;
pub const FEE_RECIPIENT: u64 = 0xfee;
pub const FEE_KEY: u64 = 0xfee5ec;
pub const BASE: u64 = 0xba5e;
pub const QUOTE: u64 = 0x9a07e;
pub const PAIR: u64 = 0x9a1;

pub struct User {
    pub spend_key: Felt,
    pub cancel_key: Felt,
    pub withdraw_key: Felt,
    pub owner: OrderOwner,
}

pub fn user(seed: u64) -> User {
    let spend_key = Felt::from(seed * 1000 + 1);
    let cancel_key = Felt::from(seed * 1000 + 2);
    let withdraw_key = Felt::from(seed * 1000 + 3);
    User {
        spend_key,
        cancel_key,
        withdraw_key,
        owner: OrderOwner {
            owner_public_key: Felt::from(seed * 1000 + 4),
            spend_authority: public_key(&spend_key),
            withdraw_authority: public_key(&withdraw_key),
            cancel_authority: public_key(&cancel_key),
            nonce: Felt::from(seed * 1000 + 5),
        },
    }
}

pub fn deposit(user: &User, asset: u64, amount: u128, salt: u64) -> NoteFields {
    NoteFields {
        asset_id: Felt::from(asset),
        amount,
        owner_public_key: user.owner.owner_public_key,
        spend_authority: user.owner.spend_authority,
        withdraw_authority: user.owner.withdraw_authority,
        blinding: Felt::from(salt * 7 + 11),
        nonce: salt,
        metadata_commitment: Felt::from(salt * 13 + 17),
    }
}

/// the chain's note accumulator: deposits and transition output subtrees, as batch roots.
#[derive(Default)]
pub struct Notes {
    pub tree: NoteAccumulator,
    /// leaf -> (batch index, subtree leaves)
    pub located: Vec<(Felt, usize, Vec<Felt>)>,
}

impl Notes {
    pub fn add_deposit(&mut self, note: &NoteFields) {
        let leaf = note.output_leaf();
        self.tree.append(leaf);
        self.located.push((leaf, self.tree.len() - 1, vec![leaf]));
    }

    pub fn add_outputs(&mut self, public: &TransitionPublic) {
        let leaves = public
            .output_records
            .iter()
            .map(|record| record.leaf)
            .collect::<Vec<_>>();
        self.tree.append(public.output_root);
        for leaf in &leaves {
            self.located
                .push((*leaf, self.tree.len() - 1, leaves.clone()));
        }
    }

    pub fn root(&self) -> Felt {
        self.tree.root()
    }

    pub fn membership(&self, note: &NoteFields) -> NoteMembership {
        self.membership_leaf(note.output_leaf())
    }

    pub fn membership_leaf(&self, leaf: Felt) -> NoteMembership {
        let (_, batch, leaves) = self
            .located
            .iter()
            .find(|(candidate, _, _)| *candidate == leaf)
            .expect("note is known");
        let leaf_index = leaves
            .iter()
            .position(|candidate| *candidate == leaf)
            .expect("leaf is in its batch");
        self.tree
            .membership(*batch, leaves, leaf_index)
            .expect("batch is appended")
    }
}

pub fn market(midpoint: u128) -> Market {
    Market {
        pair_id: Felt::from(PAIR),
        base_asset_id: Felt::from(BASE),
        quote_asset_id: Felt::from(QUOTE),
        midpoint,
        scale: 1,
        observed_at_ms: 9_000,
        valid_until_ms: 11_000,
        fee_bps: 30,
    }
}

pub fn new_order(
    notes: &Notes,
    user: &User,
    sell: bool,
    external: bool,
    amount: u128,
    limit: u128,
    funding: &[NoteFields],
) -> NewOrder {
    new_order_for(
        notes,
        user,
        Felt::from(PAIR),
        sell,
        external,
        amount,
        limit,
        funding,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn new_order_for(
    notes: &Notes,
    user: &User,
    pair_id: Felt,
    sell: bool,
    external: bool,
    amount: u128,
    limit: u128,
    funding: &[NoteFields],
) -> NewOrder {
    let terms = OrderTerms {
        pair_id,
        sell,
        external,
        amount,
        limit,
        expiry_ms: 1_000_000,
        owner: user.owner.clone(),
    };
    let funding = funding
        .iter()
        .map(|note| FundingNote {
            note: note.clone(),
            membership: notes.membership(note),
        })
        .collect::<Vec<_>>();
    let mut order = NewOrder {
        terms,
        funding,
        authorization: Signature {
            r: Felt::ZERO,
            s: Felt::ZERO,
        },
    };
    order.authorization = sign_message(
        &user.spend_key,
        &order.authorization_message(Felt::from(CHAIN)),
    )
    .unwrap();
    order
}

pub fn input(
    seq: u32,
    book: Vec<BookEntry>,
    new_orders: Vec<NewOrder>,
    note_root: Felt,
    midpoint: u128,
) -> TransitionInput {
    TransitionInput {
        chain_context: Felt::from(CHAIN),
        seq,
        close_time_ms: 10_000 + u64::from(seq),
        fee_recipient: Felt::from(FEE_RECIPIENT),
        fee_key: Felt::from(FEE_KEY),
        note_root: if new_orders.is_empty() {
            Felt::ZERO
        } else {
            note_root
        },
        objective_numeraire_asset_id: Felt::from(QUOTE),
        markets: vec![market(midpoint)],
        book,
        new_orders,
        cancellations: vec![],
        recovered_order_ids: vec![],
        outcomes: vec![],
        padding_seed: Felt::from(0x5a17_u64 + u64::from(seq)),
    }
}

/// an unsigned attestation of each market, for exercising calldata layouts.
pub fn attestations(public: &TransitionPublic) -> Vec<MarketAttestation> {
    public
        .markets
        .iter()
        .map(|market| MarketAttestation {
            pair_id: market.pair_id,
            base_asset_id: market.base_asset_id,
            quote_asset_id: market.quote_asset_id,
            midpoint: market.midpoint,
            lower_price: market.midpoint,
            upper_price: market.midpoint,
            scale: market.scale,
            source_count: 3,
            observed_at_ms: market.observed_at_ms,
            valid_until_ms: market.valid_until_ms,
            source_set_commitment: Felt::ONE,
            nonce: 1,
            price_batch_commitment: Felt::ZERO,
            signer: Felt::ONE,
            signature: Signature {
                r: Felt::ONE,
                s: Felt::ONE,
            },
        })
        .collect()
}

/// a transition crossing one seller against one buyer.
pub fn crossed() -> TransitionResult {
    let mut notes = Notes::default();
    let (seller, buyer) = (user(1), user(2));
    let (base, quote) = (
        deposit(&seller, BASE, 10, 1),
        deposit(&buyer, QUOTE, 2_000, 2),
    );
    notes.add_deposit(&base);
    notes.add_deposit(&quote);
    build_transition(&input(
        1,
        vec![],
        vec![
            new_order(&notes, &seller, true, false, 10, 95, &[base]),
            new_order(&notes, &buyer, false, false, 10, 105, &[quote]),
        ],
        notes.root(),
        100,
    ))
    .expect("the fixture transition builds")
}
