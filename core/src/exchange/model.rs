//! persistent orders, the book and the hashing every layer shares.
//!
//! the cairo statements (`stwo_statement/src/exchange`) and the exchange contract recompute
//! exactly these encodings; every domain is a cairo short string so the three agree without a
//! derived constant table.

use serde::{Deserialize, Serialize};
use starknet_crypto::{
    Felt, get_public_key, poseidon_hash, poseidon_hash_many, poseidon_permute_comp,
    rfc6979_generate_k, sign, verify,
};

use crate::ProtocolError;

/// every order amount, limit and funding total stays below this bound, so the statements can
/// multiply two of them in the field and check a remainder with one u128 range check.
pub const AMOUNT_BOUND: u128 = 1 << 120;
pub const EXPIRY_BOUND_MS: u64 = 1 << 48;
pub const MAX_BOOK_ORDERS: usize = 1024;
/// per-order base/funding bound chosen so every full-book aggregate stays below `amount_bound`.
pub const MAX_ORDER_AMOUNT: u128 = (AMOUNT_BOUND - 1) / MAX_BOOK_ORDERS as u128;
pub const MAX_MARKETS: usize = 8;
pub const MAX_ASSETS: usize = 8;
pub const MAX_FUNDING_NOTES: usize = 4;
pub const MAX_FEE_BPS: u128 = 100;
pub const FEE_BPS_DENOMINATOR: u128 = 10_000;
pub const MIN_OUTPUT_BUCKET: usize = 16;
pub const MIN_NULLIFIER_BUCKET: usize = 8;
pub const NOTE_ACCUMULATOR_DEPTH: usize = 32;

pub const OUTPUT_KIND_PROCEEDS: u64 = 1;
pub const OUTPUT_KIND_REFUND: u64 = 2;
pub const OUTPUT_KIND_FEE: u64 = 3;

/// the existing note, nullifier and output-note domains (sha-derived; see `hash::domain_felt`).
pub const NOTE_COMMITMENT_DOMAIN_HEX: &str =
    "0x43aeae569e031a74671a28c60a017d2a53bbb5ffa6f6a7711c076348fb186c";
pub const NULLIFIER_DOMAIN_HEX: &str =
    "0x6cd79aee4dd094aadf944f50e83fad66ce717a58d59d73a92df351aac6d14e3";
pub const OUTPUT_NOTE_LEAF_DOMAIN_HEX: &str =
    "0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3";
pub const OUTPUT_NOTE_NODE_DOMAIN_HEX: &str =
    "0x03c6998f476a618431be1c1764a6724f13c0739be395bab4c1217bc0a65b2ee7";
pub const NOTE_ACCUMULATOR_LEAF_DOMAIN_HEX: &str =
    "0x7a796c6974685f6e6f74655f6163635f6c6561665f7631";
pub const NOTE_ACCUMULATOR_NODE_DOMAIN_HEX: &str =
    "0x7a796c6974685f6e6f74655f6163635f6e6f64655f7631";

pub const OWNER_DOMAIN: &str = "zylith_owner_v1";
pub const ORDER_ID_DOMAIN: &str = "zylith_order_v2";
pub const FUNDING_SET_DOMAIN: &str = "zylith_funding_v1";
pub const ORDER_AUTH_DOMAIN: &str = "zylith_order_auth_v1";
pub const CANCEL_DOMAIN: &str = "zylith_cancel_v1";
pub const BOOK_DOMAIN: &str = "zylith_book_v1";
pub const M0_DOMAIN: &str = "zylith_m0_v1";
pub const OUTCOMES_DOMAIN: &str = "zylith_outcomes_v1";
pub const CAPACITY_DOMAIN: &str = "zylith_capacity_v1";
pub const NULLIFIERS_DOMAIN: &str = "zylith_nullifiers_v1";
pub const OUTPUTS_DOMAIN: &str = "zylith_outputs_v1";
pub const OUTPUT_BLINDING_DOMAIN: &str = "zylith_out_blind_v1";
pub const TRANSITION_DOMAIN: &str = "zylith_transition_v1";
pub const PADDING_DOMAIN: &str = "zylith_pad_v1";
pub const WITHDRAW_AUTH_DOMAIN: &str = "zylith_withdraw_v2";
pub const WITHDRAWAL_DOMAIN: &str = "zylith_withdrawal_v2";

/// a cairo short string: its ascii bytes read big-endian.
pub fn short_string(value: &str) -> Felt {
    assert!(
        value.len() <= 31 && value.is_ascii(),
        "short string {value} is not a felt"
    );
    Felt::from_bytes_be_slice(value.as_bytes())
}

pub(crate) fn domain_hex(hex: &str) -> Felt {
    Felt::from_hex(hex).expect("domain constants are valid felts")
}

/// `poseidon_hash_span` over the sequence: the sponge every commitment uses.
pub fn sponge(values: &[Felt]) -> Felt {
    poseidon_hash_many(values)
}

pub fn felt_u128(value: u128) -> Felt {
    Felt::from(value)
}

pub fn felt_u64(value: u64) -> Felt {
    Felt::from(value)
}

pub fn felt_bool(value: bool) -> Felt {
    if value { Felt::ONE } else { Felt::ZERO }
}

pub(crate) fn two_pow(exponent: u32) -> Felt {
    Felt::TWO.pow(exponent as u128)
}

pub(crate) fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidOrder(message.into())
}

pub(crate) fn felt_to_u256_bytes(value: &Felt) -> [u8; 32] {
    value.to_bytes_be()
}

/// felts ordered as integers, as the statements compare them.
pub(crate) fn felt_lt(left: &Felt, right: &Felt) -> bool {
    felt_to_u256_bytes(left) < felt_to_u256_bytes(right)
}

pub mod felt_hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use starknet_crypto::Felt;

    pub fn serialize<S: Serializer>(value: &Felt, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Felt, D::Error> {
        let value = String::deserialize(deserializer)?;
        let normalized = if value.starts_with("0x") {
            value
        } else {
            format!("0x{value}")
        };
        Felt::from_hex(&normalized).map_err(serde::de::Error::custom)
    }
}

pub mod felt_vec_hex_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use starknet_crypto::Felt;

    pub fn serialize<S: Serializer>(values: &[Felt], serializer: S) -> Result<S::Ok, S::Error> {
        values
            .iter()
            .map(|value| format!("{value:#x}"))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Felt>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| {
                let normalized = if value.starts_with("0x") {
                    value
                } else {
                    format!("0x{value}")
                };
                Felt::from_hex(&normalized).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

pub mod u128_decimal_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// ecdsa over the stark curve, the scheme `check_ecdsa_signature` verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(with = "felt_hex_serde")]
    pub r: Felt,
    #[serde(with = "felt_hex_serde")]
    pub s: Felt,
}

pub fn sign_message(private_key: &Felt, message: &Felt) -> Result<Signature, ProtocolError> {
    if *private_key == Felt::ZERO {
        return Err(ProtocolError::Crypto("signing key cannot be zero".into()));
    }
    let k = rfc6979_generate_k(message, private_key, None);
    let signature = sign(private_key, message, &k)
        .map_err(|error| ProtocolError::Crypto(format!("ecdsa signing failed: {error}")))?;
    Ok(Signature {
        r: signature.r,
        s: signature.s,
    })
}

pub fn verify_message(public_key: &Felt, message: &Felt, signature: &Signature) -> bool {
    verify(public_key, message, &signature.r, &signature.s).unwrap_or(false)
}

pub fn public_key(private_key: &Felt) -> Felt {
    get_public_key(private_key)
}

/// who receives an order's outputs and who may cancel it. `nonce` is the order's random secret:
/// it makes the order id unique and keys the encryption of its output amounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderOwner {
    #[serde(with = "felt_hex_serde")]
    pub owner_public_key: Felt,
    #[serde(with = "felt_hex_serde")]
    pub spend_authority: Felt,
    #[serde(with = "felt_hex_serde")]
    pub withdraw_authority: Felt,
    #[serde(with = "felt_hex_serde")]
    pub cancel_authority: Felt,
    #[serde(with = "felt_hex_serde")]
    pub nonce: Felt,
}

impl OrderOwner {
    pub fn digest(&self) -> Felt {
        sponge(&[
            short_string(OWNER_DOMAIN),
            self.owner_public_key,
            self.spend_authority,
            self.withdraw_authority,
            self.cancel_authority,
            self.nonce,
        ])
    }

    pub fn fields(&self) -> [Felt; 5] {
        [
            self.owner_public_key,
            self.spend_authority,
            self.withdraw_authority,
            self.cancel_authority,
            self.nonce,
        ]
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.fields().contains(&Felt::ZERO) {
            return Err(invalid("order owner fields must be nonzero"));
        }
        Ok(())
    }
}

/// what the user signs: the immutable terms of a persistent order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderTerms {
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    pub sell: bool,
    pub external: bool,
    #[serde(with = "u128_decimal_serde")]
    pub amount: u128,
    #[serde(with = "u128_decimal_serde")]
    pub limit: u128,
    pub expiry_ms: u64,
    pub owner: OrderOwner,
}

impl OrderTerms {
    pub fn flags(&self) -> u64 {
        u64::from(self.sell) + 2 * u64::from(self.external)
    }

    pub fn order_id(&self) -> Felt {
        sponge(&[
            short_string(ORDER_ID_DOMAIN),
            self.pair_id,
            felt_u64(self.flags()),
            felt_u128(self.amount),
            felt_u128(self.limit),
            felt_u64(self.expiry_ms),
            self.owner.digest(),
        ])
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.pair_id == Felt::ZERO {
            return Err(invalid("order pair is zero"));
        }
        if self.amount == 0 || self.amount > MAX_ORDER_AMOUNT {
            return Err(invalid("order amount is out of range"));
        }
        if self.limit == 0 || self.limit >= AMOUNT_BOUND {
            return Err(invalid("order limit is out of range"));
        }
        if self.expiry_ms == 0 || self.expiry_ms >= EXPIRY_BOUND_MS {
            return Err(invalid("order expiry is out of range"));
        }
        self.owner.validate()
    }
}

/// the message the funding notes' spend key signs to lock them into an order.
pub fn order_authorization_message(chain_context: Felt, order_id: Felt, funding_set: Felt) -> Felt {
    sponge(&[
        short_string(ORDER_AUTH_DOMAIN),
        chain_context,
        order_id,
        funding_set,
    ])
}

pub fn funding_set_commitment(note_commitments: &[Felt]) -> Felt {
    let mut values = Vec::with_capacity(note_commitments.len() + 2);
    values.push(short_string(FUNDING_SET_DOMAIN));
    values.extend_from_slice(note_commitments);
    values.push(felt_u64(note_commitments.len() as u64));
    sponge(&values)
}

/// the message the order's cancel key signs to remove it from the book.
pub fn cancel_message(chain_context: Felt, order_id: Felt) -> Felt {
    sponge(&[short_string(CANCEL_DOMAIN), chain_context, order_id])
}

/// a persistent order as the book holds it between transitions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookOrder {
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    pub sell: bool,
    pub external: bool,
    /// remaining base amount.
    #[serde(with = "u128_decimal_serde")]
    pub remaining: u128,
    #[serde(with = "u128_decimal_serde")]
    pub limit: u128,
    /// locked input asset: base for a sell, quote for a buy.
    #[serde(with = "u128_decimal_serde")]
    pub funding: u128,
    /// base amount reserved for the external leg of transition `reserved_seq`.
    #[serde(with = "u128_decimal_serde")]
    pub reserved: u128,
    pub reserved_seq: u32,
    pub expiry_ms: u64,
    #[serde(with = "felt_hex_serde")]
    pub owner_digest: Felt,
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
}

impl BookOrder {
    pub fn admitted(terms: &OrderTerms, funding: u128) -> Self {
        Self {
            pair_id: terms.pair_id,
            sell: terms.sell,
            external: terms.external,
            remaining: terms.amount,
            limit: terms.limit,
            funding,
            reserved: 0,
            reserved_seq: 0,
            expiry_ms: terms.expiry_ms,
            owner_digest: terms.owner.digest(),
            order_id: terms.order_id(),
        }
    }

    /// `(pair_id, p1, p2, p3, d, order_id)`, the six felts the book sponge absorbs.
    pub fn leaf_fields(&self) -> [Felt; 6] {
        let flags = felt_u64(u64::from(self.sell) + 2 * u64::from(self.external));
        [
            self.pair_id,
            felt_u128(self.remaining) + flags * two_pow(128),
            felt_u128(self.limit) + felt_u128(self.funding) * two_pow(128),
            felt_u128(self.reserved)
                + felt_u64(u64::from(self.reserved_seq)) * two_pow(128)
                + felt_u64(self.expiry_ms) * two_pow(160),
            self.owner_digest,
            self.order_id,
        ]
    }

    pub fn group(&self) -> (Felt, bool) {
        (self.pair_id, self.sell)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.remaining > MAX_ORDER_AMOUNT || self.limit == 0 || self.limit >= AMOUNT_BOUND {
            return Err(invalid("book order amount or limit is out of range"));
        }
        if self.funding > MAX_ORDER_AMOUNT || self.reserved > self.remaining {
            return Err(invalid("book order funding or reservation is out of range"));
        }
        if self.expiry_ms == 0 || self.expiry_ms >= EXPIRY_BOUND_MS {
            return Err(invalid("book order expiry is out of range"));
        }
        if (self.reserved == 0) != (self.reserved_seq == 0) {
            return Err(invalid("book order reservation tag is inconsistent"));
        }
        Ok(())
    }
}

/// the operator's record of a live order: the book leaf and the owner preimage its outputs and
/// cancellation need.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookEntry {
    pub order: BookOrder,
    pub owner: OrderOwner,
}

pub fn book_root(chain_context: Felt, orders: &[BookOrder]) -> Felt {
    let mut values = Vec::with_capacity(orders.len() * 6 + 3);
    values.push(short_string(BOOK_DOMAIN));
    values.push(chain_context);
    for order in orders {
        values.extend_from_slice(&order.leaf_fields());
    }
    values.push(felt_u64(orders.len() as u64));
    sponge(&values)
}

/// books are grouped by `(pair_id, side)`, strictly increasing by pair and then side.
pub fn assert_canonical_book(orders: &[BookOrder]) -> Result<(), ProtocolError> {
    let mut previous: Option<(Felt, bool)> = None;
    for order in orders {
        order.validate()?;
        let group = order.group();
        if let Some(last) = previous
            && last != group
            && !group_lt(&last, &group)
        {
            return Err(invalid("book groups are not strictly increasing"));
        }
        previous = Some(group);
    }
    Ok(())
}

pub(crate) fn group_lt(left: &(Felt, bool), right: &(Felt, bool)) -> bool {
    felt_lt(&left.0, &right.0) || (left.0 == right.0 && !left.1 && right.1)
}

/// a zylith note as its commitment sees it: the felts after asset and owner encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteFields {
    #[serde(with = "felt_hex_serde")]
    pub asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub amount: u128,
    #[serde(with = "felt_hex_serde")]
    pub owner_public_key: Felt,
    #[serde(with = "felt_hex_serde")]
    pub spend_authority: Felt,
    #[serde(with = "felt_hex_serde")]
    pub withdraw_authority: Felt,
    #[serde(with = "felt_hex_serde")]
    pub blinding: Felt,
    pub nonce: u64,
    #[serde(with = "felt_hex_serde")]
    pub metadata_commitment: Felt,
}

impl NoteFields {
    pub fn commitment(&self) -> Felt {
        let mut state = domain_hex(NOTE_COMMITMENT_DOMAIN_HEX);
        for value in [
            self.asset_id,
            felt_u128(self.amount),
            self.owner_public_key,
            self.spend_authority,
            self.withdraw_authority,
            self.blinding,
            felt_u64(self.nonce),
            self.metadata_commitment,
        ] {
            state = poseidon_hash(state, value);
        }
        state
    }

    pub fn nullifier(&self) -> Felt {
        poseidon_hash(
            poseidon_hash(domain_hex(NULLIFIER_DOMAIN_HEX), self.commitment()),
            self.blinding,
        )
    }

    pub fn output_leaf(&self) -> Felt {
        output_note_leaf(
            self.commitment(),
            self.asset_id,
            self.amount,
            self.withdraw_authority,
        )
    }

    pub fn from_note(note: &crate::Note) -> Result<Self, ProtocolError> {
        use crate::hash::{encode_starknet_felt, felt_from_hex_str};
        Ok(Self {
            asset_id: felt_from_hex_str(&encode_starknet_felt("asset-id", &note.asset_id.0))?,
            amount: note.amount,
            owner_public_key: felt_from_hex_str(&encode_starknet_felt(
                "owner-public-key",
                &note.owner_public_key,
            ))?,
            spend_authority: felt_from_hex_str(&note.spend_authority)?,
            withdraw_authority: felt_from_hex_str(&note.withdraw_authority)?,
            blinding: felt_from_hex_str(&note.blinding)?,
            nonce: note.nonce,
            metadata_commitment: felt_from_hex_str(&note.metadata_commitment)?,
        })
    }
}

pub fn output_note_leaf(
    commitment: Felt,
    asset_id: Felt,
    amount: u128,
    withdraw_authority: Felt,
) -> Felt {
    let mut state = poseidon_hash(domain_hex(OUTPUT_NOTE_LEAF_DOMAIN_HEX), commitment);
    state = poseidon_hash(state, asset_id);
    state = poseidon_hash(state, felt_u128(amount));
    poseidon_hash(state, withdraw_authority)
}

/// one permutation whose capacity element carries the domain: `hades(left, right, tag)[0]`.
pub fn tagged_hash(left: Felt, right: Felt, tag: Felt) -> Felt {
    let mut state = [left, right, tag];
    poseidon_permute_comp(&mut state);
    state[0]
}

pub fn output_note_node(left: Felt, right: Felt) -> Felt {
    tagged_hash(left, right, domain_hex(OUTPUT_NOTE_NODE_DOMAIN_HEX))
}

/// the merkle root over a power-of-two list of output leaves.
pub fn output_tree_root(leaves: &[Felt]) -> Felt {
    assert!(
        leaves.len().is_power_of_two(),
        "output trees are padded to a power of two"
    );
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| output_note_node(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

pub fn output_tree_path(leaves: &[Felt], index: usize) -> (Vec<Felt>, Vec<bool>) {
    assert!(leaves.len().is_power_of_two() && index < leaves.len());
    let mut level = leaves.to_vec();
    let mut index = index;
    let mut path = Vec::new();
    let mut directions = Vec::new();
    while level.len() > 1 {
        path.push(level[index ^ 1]);
        directions.push(index & 1 == 1);
        level = level
            .chunks(2)
            .map(|pair| output_note_node(pair[0], pair[1]))
            .collect();
        index >>= 1;
    }
    (path, directions)
}

/// the accumulator node for `level`, zero over two empty children.
pub fn note_accumulator_node(left: Felt, right: Felt, level: usize) -> Felt {
    if left == Felt::ZERO && right == Felt::ZERO {
        return Felt::ZERO;
    }
    tagged_hash(
        left,
        right,
        domain_hex(NOTE_ACCUMULATOR_NODE_DOMAIN_HEX) + felt_u64(level as u64),
    )
}

pub fn note_accumulator_leaf(batch_root: Felt) -> Felt {
    poseidon_hash(domain_hex(NOTE_ACCUMULATOR_LEAF_DOMAIN_HEX), batch_root)
}

/// the chain's note accumulator: an append-only tree of depth 32 over deposit and transition
/// batch roots, as the exchange contract keeps it.
#[derive(Clone, Debug, Default)]
pub struct NoteAccumulator {
    levels: Vec<Vec<Felt>>,
}

impl NoteAccumulator {
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn root(&self) -> Felt {
        self.levels
            .get(NOTE_ACCUMULATOR_DEPTH)
            .and_then(|level| level.first())
            .copied()
            .unwrap_or(Felt::ZERO)
    }

    /// appends a batch root and returns the new accumulator root.
    pub fn append(&mut self, batch_root: Felt) -> Felt {
        if self.levels.is_empty() {
            self.levels = vec![Vec::new(); NOTE_ACCUMULATOR_DEPTH + 1];
        }
        self.levels[0].push(note_accumulator_leaf(batch_root));
        let mut index = self.len() - 1;
        for level in 0..NOTE_ACCUMULATOR_DEPTH {
            let parent = index / 2;
            let child = |offset: usize| {
                self.levels[level]
                    .get(parent * 2 + offset)
                    .copied()
                    .unwrap_or(Felt::ZERO)
            };
            let node = note_accumulator_node(child(0), child(1), level);
            match self.levels[level + 1].get_mut(parent) {
                Some(slot) => *slot = node,
                None => self.levels[level + 1].push(node),
            }
            index = parent;
        }
        self.root()
    }

    /// the membership of leaf `leaf_index` of batch `batch_index`, whose leaves are `batch_leaves`
    /// (a deposit is a batch of one).
    pub fn membership(
        &self,
        batch_index: usize,
        batch_leaves: &[Felt],
        leaf_index: usize,
    ) -> Option<NoteMembership> {
        if batch_index >= self.len() || leaf_index >= batch_leaves.len() {
            return None;
        }
        let (subtree_path, subtree_directions) = if batch_leaves.len() == 1 {
            (Vec::new(), Vec::new())
        } else {
            output_tree_path(batch_leaves, leaf_index)
        };
        let mut index = batch_index;
        let mut accumulator_path = Vec::with_capacity(NOTE_ACCUMULATOR_DEPTH);
        let mut accumulator_directions = Vec::with_capacity(NOTE_ACCUMULATOR_DEPTH);
        for level in &self.levels[..NOTE_ACCUMULATOR_DEPTH] {
            accumulator_path.push(level.get(index ^ 1).copied().unwrap_or(Felt::ZERO));
            accumulator_directions.push(index & 1 == 1);
            index >>= 1;
        }
        Some(NoteMembership {
            subtree_path,
            subtree_directions,
            accumulator_path,
            accumulator_directions,
        })
    }
}

/// where a note sits: its leaf inside a deposit (single leaf) or an output subtree, and that
/// subtree's root inside the note accumulator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteMembership {
    /// the output subtree path, empty for a deposit.
    #[serde(with = "felt_vec_hex_serde")]
    pub subtree_path: Vec<Felt>,
    pub subtree_directions: Vec<bool>,
    #[serde(with = "felt_vec_hex_serde")]
    pub accumulator_path: Vec<Felt>,
    pub accumulator_directions: Vec<bool>,
}

impl NoteMembership {
    pub fn root(&self, leaf: Felt) -> Result<Felt, ProtocolError> {
        if self.subtree_path.len() != self.subtree_directions.len() || self.subtree_path.len() > 16
        {
            return Err(invalid("note subtree path is malformed"));
        }
        if self.accumulator_path.len() != NOTE_ACCUMULATOR_DEPTH
            || self.accumulator_directions.len() != NOTE_ACCUMULATOR_DEPTH
        {
            return Err(invalid("note accumulator path must have depth 32"));
        }
        let mut node = leaf;
        for (sibling, right) in self.subtree_path.iter().zip(&self.subtree_directions) {
            node = if *right {
                output_note_node(*sibling, node)
            } else {
                output_note_node(node, *sibling)
            };
        }
        let mut node = note_accumulator_leaf(node);
        for (level, (sibling, right)) in self
            .accumulator_path
            .iter()
            .zip(&self.accumulator_directions)
            .enumerate()
        {
            node = if *right {
                note_accumulator_node(*sibling, node, level)
            } else {
                note_accumulator_node(node, *sibling, level)
            };
        }
        Ok(node)
    }
}

/// the next power of two at or above `count`, and at least `minimum`.
pub fn padded_len(count: usize, minimum: usize) -> usize {
    count.max(minimum).next_power_of_two()
}

/// deterministic padding: unpredictable without the operator's seed, indistinguishable from
/// real leaves and nullifiers.
pub fn padding_value(seed: Felt, domain: &str, index: usize) -> Felt {
    sponge(&[
        short_string(PADDING_DOMAIN),
        seed,
        short_string(domain),
        felt_u64(index as u64),
    ])
}
