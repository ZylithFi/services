use std::io::{self, Read};

use serde::Deserialize;
use zylith_core::{
    SettlementOutputWithdrawalWitness, sign_settlement_output_withdrawal_witness,
    withdraw_auth_key_felt_from_raw_key_hex,
};

#[derive(Deserialize)]
struct SignRequest {
    withdraw_key_hex: String,
    witness: SettlementOutputWithdrawalWitness,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: SignRequest = serde_json::from_str(&input)?;
    let withdraw_auth_key_felt = withdraw_auth_key_felt_from_raw_key_hex(&request.withdraw_key_hex);
    let mut witness = request.witness;
    witness.withdraw_authorization =
        sign_settlement_output_withdrawal_witness(&withdraw_auth_key_felt, &witness)?;
    println!("{}", serde_json::to_string(&witness)?);
    Ok(())
}
