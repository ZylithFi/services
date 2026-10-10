use std::{hint::black_box, time::Instant};

use rand::{SeedableRng, rngs::StdRng};
use zylith_core::private_envelope::{open_hpke, seal_hpke};

const ITERATIONS: usize = 1_000;
const RECIPIENT_PRIVATE_KEY: &str =
    "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
const RECIPIENT_PUBLIC_KEY: &str =
    "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";

fn percentile(samples: &mut [u128], numerator: usize, denominator: usize) -> u128 {
    samples.sort_unstable();
    let index = ((samples.len() * numerator).div_ceil(denominator)).saturating_sub(1);
    samples[index]
}

fn main() {
    let recipient_private = hex::decode(RECIPIENT_PRIVATE_KEY).expect("valid private key");
    let recipient_public = hex::decode(RECIPIENT_PUBLIC_KEY).expect("valid public key");
    let info = b"zylith/private-request-envelope/v3/benchmark";
    let aad = b"chain=sepolia;deployment=benchmark";
    let plaintext = vec![0x5a; 4_096];
    let mut rng = StdRng::from_seed([0x42; 32]);
    let mut seal_ns = Vec::with_capacity(ITERATIONS);
    let mut open_ns = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let (encapsulated_key, ciphertext) = seal_hpke(
            &recipient_public,
            info,
            aad,
            black_box(&plaintext),
            &mut rng,
        )
        .expect("benchmark seal must succeed");
        seal_ns.push(started.elapsed().as_nanos());

        let started = Instant::now();
        let opened = open_hpke(
            &recipient_private,
            info,
            aad,
            &encapsulated_key,
            &ciphertext,
        )
        .expect("benchmark open must succeed");
        open_ns.push(started.elapsed().as_nanos());
        assert_eq!(opened, plaintext);
    }

    let mut seal_p50 = seal_ns.clone();
    let mut seal_p95 = seal_ns.clone();
    let mut open_p50 = open_ns.clone();
    let mut open_p95 = open_ns.clone();
    println!(
        "{{\"iterations\":{ITERATIONS},\"plaintext_bytes\":{},\"seal_p50_ns\":{},\"seal_p95_ns\":{},\"open_p50_ns\":{},\"open_p95_ns\":{}}}",
        plaintext.len(),
        percentile(&mut seal_p50, 50, 100),
        percentile(&mut seal_p95, 95, 100),
        percentile(&mut open_p50, 50, 100),
        percentile(&mut open_p95, 95, 100),
    );
}
