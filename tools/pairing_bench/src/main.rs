//! BN254 unit costs for B9 (Zhang et al., TC 2025), Section VII-A notation:
//! t_x exponentiation in G1, t_g multiplication in G1, t_b bilinear pairing,
//! t_z multiplication in Z_p, t_a addition in Z_p, t_h hash (SHA-256), t_r PRF (SHA-256 based).
//! Prints medians in microseconds as CSV.
use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::UniformRand;
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

fn median<F: FnMut()>(n: usize, mut f: F) -> f64 {
    let mut v: Vec<f64> = (0..n).map(|_| { let t = Instant::now(); f(); t.elapsed().as_secs_f64() * 1e6 }).collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[n / 2]
}

fn main() {
    let mut rng = ark_std::test_rng();
    let g = G1Projective::generator();
    let h = G2Projective::generator();
    let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let p = g * a;
    let q = g * b;
    let pa: ark_bn254::G1Affine = (g * a).into();
    let hb: ark_bn254::G2Affine = (h * b).into();
    let data = [7u8; 64];
    let rows = [
        ("t_x", "G1 exponentiation (scalar multiplication)", median(400, || { black_box(p * black_box(b)); })),
        ("t_g", "G1 multiplication (point addition)", median(4000, || { black_box(black_box(p) + black_box(q)); })),
        ("t_b", "bilinear pairing", median(200, || { black_box(Bn254::pairing(pa, hb)); })),
        ("t_z", "multiplication in Z_p", median(20000, || { black_box(black_box(a) * black_box(b)); })),
        ("t_a", "addition in Z_p", median(20000, || { black_box(black_box(a) + black_box(b)); })),
        ("t_h", "SHA-256 of 64 bytes", median(20000, || { black_box(Sha256::digest(black_box(&data))); })),
        ("t_r", "PRF (SHA-256 of index and seed)", median(20000, || { black_box(Sha256::digest(black_box(&data[..40]))); })),
    ];
    println!("symbol,description,median_us,note");
    for (s, d, us) in rows {
        println!("{s},{d},{us:.3},arkworks 0.4 BN254");
    }
}
