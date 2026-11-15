use std::hint::black_box;
use std::time::{Duration, Instant};

const SAMPLES: usize = 30;
const TARGET: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub struct Bench {
    filter: Option<String>,
}

impl Bench {
    pub fn from_args() -> Self {
        let filter = std::env::args().skip(1).find(|a| !a.starts_with('-'));
        Bench { filter }
    }

    pub fn run<T>(&self, name: &str, mut f: impl FnMut() -> T) {
        if let Some(filter) = &self.filter
            && !name.contains(filter.as_str())
        {
            return;
        }
        let mut iters = 1u64;
        loop {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(f());
            }
            if t.elapsed() >= TARGET || iters >= 1 << 28 {
                break;
            }
            iters *= 2;
        }
        let mut samples: Vec<f64> = (0..SAMPLES)
            .map(|_| {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(f());
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            })
            .collect();
        samples.sort_by(f64::total_cmp);
        println!(
            "{name:<44} median {:>10}  min {:>10}  max {:>10}  ({iters} iters x {SAMPLES})",
            human(samples[SAMPLES / 2]),
            human(samples[0]),
            human(samples[SAMPLES - 1]),
        );
    }
}

fn human(ns: f64) -> String {
    if ns >= 1e9 {
        format!("{:.2} s", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.2} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.2} us", ns / 1e3)
    } else {
        format!("{ns:.1} ns")
    }
}
