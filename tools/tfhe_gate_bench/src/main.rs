//! TFHE gate-bootstrapping time (one NAND gate with bootstrapping), the unit cost of
//! PriSIEM's Boolean circuits (B5). Prints the median over N gates in microseconds,
//! single-threaded and with all cores evaluating independent gates in parallel.
use std::time::Instant;
use tfhe::boolean::prelude::*;

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let (ck, sk) = gen_keys();
    let a = ck.encrypt(true);
    let b = ck.encrypt(false);
    let _ = sk.nand(&a, &b); // warm-up
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let c = sk.nand(&a, &b);
        samples.push(t.elapsed().as_secs_f64() * 1e6);
        std::hint::black_box(c);
    }
    samples.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let median = samples[n / 2];
    assert!(ck.decrypt(&sk.nand(&a, &b)));
    let threads = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
    let per = n.max(threads) / threads;
    let t = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            let (sk, a, b) = (&sk, &a, &b);
            s.spawn(move || for _ in 0..per { std::hint::black_box(sk.nand(a, b)); });
        }
    });
    let par = t.elapsed().as_secs_f64() * 1e6 / (per * threads) as f64;
    println!("symbol,description,median_us,note");
    println!("T_gate,TFHE gate with bootstrapping (NAND; tfhe-rs 0.8.7 boolean default parameters),{median:.1},single thread");
    println!("T_gate_parallel,amortized gate time with {threads} threads,{par:.1},independent gates");
}
