//! Per-process resource metrics for benchmark reporting.
//!
//! `ResourceMeter` samples this process's own CPU time and peak memory from
//! `/proc` (Linux). On a platform where those reads fail it reports
//! `available = false` and the caller prints "n/a" — the benchmark itself is
//! unaffected. `WireCounters` is a pair of atomics for tallying bytes actually
//! written to / read from sockets, so a protocol without a plane-level traffic
//! breakdown can still report total network volume.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

/// Clock ticks per second (`sysconf(_SC_CLK_TCK)`), 100 on every Linux target
/// this project runs on (GCP x86_64). Override with `SB_USER_HZ` if a target
/// ever differs.
fn user_hz() -> f64 {
    std::env::var("SB_USER_HZ")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(100.0)
}

/// utime + stime for this process, in clock ticks, from `/proc/self/stat`.
fn read_self_cpu_ticks() -> Option<(u64, u64)> {
    // "pid (comm) state ppid ... utime stime ..." — comm may contain spaces and
    // parentheses, so parse the fields after the final ')'.
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = after.split_whitespace().collect();
    // f[0] = state; utime is the 14th field overall => f[11], stime => f[12].
    Some((f.get(11)?.parse().ok()?, f.get(12)?.parse().ok()?))
}

/// Peak resident set size (VmHWM) in kB from `/proc/self/status`.
fn read_peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix("VmHWM:")
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
    })
}

pub struct ResourceMeter {
    start_wall: Instant,
    start_utime: u64,
    start_stime: u64,
    n_cores: usize,
    available: bool,
}

pub struct ResourceReport {
    pub available: bool,
    pub wall_secs: f64,
    pub user_cpu_secs: f64,
    pub sys_cpu_secs: f64,
    /// CPU time / wall time as a percentage of one core (can exceed 100).
    pub cpu_pct_one_core: f64,
    /// Same, divided by the core count — share of the whole machine.
    pub cpu_pct_machine: f64,
    pub peak_rss_mb: f64,
    pub n_cores: usize,
}

impl ResourceMeter {
    /// Take the start snapshot. Call once, just before the timed run begins.
    pub fn start() -> Self {
        let (start_utime, start_stime, available) = match read_self_cpu_ticks() {
            Some((u, s)) => (u, s, true),
            None => (0, 0, false),
        };
        Self {
            start_wall: Instant::now(),
            start_utime,
            start_stime,
            n_cores: std::thread::available_parallelism().map_or(1, |n| n.get()),
            available,
        }
    }

    /// Compute the delta from `start()` to now.
    pub fn report(&self) -> ResourceReport {
        let wall_secs = self.start_wall.elapsed().as_secs_f64().max(1e-6);
        let hz = user_hz();
        let (end_utime, end_stime) =
            read_self_cpu_ticks().unwrap_or((self.start_utime, self.start_stime));
        let user_cpu_secs = end_utime.saturating_sub(self.start_utime) as f64 / hz;
        let sys_cpu_secs = end_stime.saturating_sub(self.start_stime) as f64 / hz;
        let cpu_pct_one_core = (user_cpu_secs + sys_cpu_secs) / wall_secs * 100.0;
        ResourceReport {
            available: self.available,
            wall_secs,
            user_cpu_secs,
            sys_cpu_secs,
            cpu_pct_one_core,
            cpu_pct_machine: cpu_pct_one_core / self.n_cores.max(1) as f64,
            peak_rss_mb: read_peak_rss_kb().unwrap_or(0) as f64 / 1024.0,
            n_cores: self.n_cores,
        }
    }
}

/// Total socket bytes sent / received, tallied at the write and read call sites.
#[derive(Default)]
pub struct WireCounters {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl WireCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn tx(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }
    pub fn rx(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }
}
