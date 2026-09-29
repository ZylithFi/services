use std::{env, fs};

use zylith_core::MarketRegistry;

fn main() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config/market-registry.json".into());
    let raw = fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
    let registry: MarketRegistry =
        serde_json::from_str(&raw).map_err(|error| format!("{path}: {error}"))?;
    let hash = registry.computed_hash()?;
    if env::args().any(|argument| argument == "--check") {
        registry.validate()?;
    }
    println!("{hash}");
    Ok(())
}
