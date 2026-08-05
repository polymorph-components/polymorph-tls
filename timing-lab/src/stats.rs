//! Welch's t-test machinery for the two-class timing experiments.
//!
//! Follows dudect ("dude, is my code constant time?", Reparaz, Balasch,
//! Verbauwhede, DATE 2017): per-class online mean/variance accumulators, a
//! t statistic over the full sample set plus upper-percentile-cropped
//! subsets, and a fixed decision threshold on max |t|. Carried over from
//! component-webcrypto's timing-lab so the two labs share one statistic.
//!
//! Kept self-contained so the test statistic can be swapped without touching
//! the samplers.

/// Online mean/variance accumulator (Welford's algorithm).
#[derive(Clone, Copy, Default)]
pub struct Accumulator {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Accumulator {
    pub fn push(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }

    pub fn count(&self) -> f64 {
        self.n
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Sample variance (n - 1 denominator).
    pub fn variance(&self) -> f64 {
        if self.n < 2.0 {
            return f64::NAN;
        }
        self.m2 / (self.n - 1.0)
    }
}

/// Welch's t statistic between two accumulated classes.
pub fn welch_t(a: &Accumulator, b: &Accumulator) -> f64 {
    let va = a.variance() / a.count();
    let vb = b.variance() / b.count();
    (a.mean() - b.mean()) / (va + vb).sqrt()
}

/// The verdict for one measured surface.
pub enum Verdict {
    /// max |t| stayed under the threshold.
    Quiet,
    /// max |t| crossed the threshold: timing depends on the class.
    Leak,
    /// Not enough usable samples to decide.
    Inconclusive,
}

/// The decision threshold on max |t|. The reference dudect uses 10 as its
/// "definitely leaky" line for exactly this statistic: taking the max over
/// many percentile crops inflates |t| well past the single-test 4.5, so a
/// lower threshold would over-report.
pub const THRESHOLD: f64 = 10.0;

/// The upper-percentile crops dudect applies before each t-test: timing
/// distributions are heavy-tailed (interrupts, allocator slow paths), and
/// cropping the slowest samples exposes differences the tail would drown.
const CROP_PERCENTILES: &[f64] = &[1.0, 0.7, 0.5, 0.3, 0.2, 0.1, 0.05, 0.02, 0.01];

/// max |t| over the full data and every cropped subset. Both classes are
/// cropped at the same absolute cutoff (a pooled percentile), so the crop
/// itself cannot introduce a class difference.
pub fn max_cropped_t(class0: &[f64], class1: &[f64]) -> f64 {
    let mut pooled: Vec<f64> = class0.iter().chain(class1).copied().collect();
    pooled.sort_by(|a, b| a.total_cmp(b));
    let mut max_t = f64::NAN;
    for &pct in CROP_PERCENTILES {
        let keep = ((pooled.len() as f64 * pct).ceil() as usize).min(pooled.len());
        if keep < 4 {
            continue;
        }
        let cutoff = pooled[keep - 1];
        let mut a = Accumulator::default();
        let mut b = Accumulator::default();
        for &x in class0.iter().filter(|&&x| x <= cutoff) {
            a.push(x);
        }
        for &x in class1.iter().filter(|&&x| x <= cutoff) {
            b.push(x);
        }
        if a.count() < 2.0 || b.count() < 2.0 {
            continue;
        }
        let t = welch_t(&a, &b);
        if t.is_finite() && (max_t.is_nan() || t.abs() > max_t.abs()) {
            max_t = t;
        }
    }
    max_t
}
