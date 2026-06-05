use std::io::{self, Read};

use serde::Deserialize;
use zylith_core::{NoteCommitment, OutputNoteRecord, output_note_merkle_proof};

#[derive(Deserialize)]
struct ProofRequest {
    output_notes: Vec<OutputNoteRecord>,
    note_commitment: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: ProofRequest = serde_json::from_str(&input)?;
    let proof = output_note_merkle_proof(
        &request.output_notes,
        &NoteCommitment(request.note_commitment),
    )?;
    println!("{}", serde_json::to_string(&proof)?);
    Ok(())
}
