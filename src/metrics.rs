//! Prometheus text-format metrics. Counters/gauges live in atomics so the
//! scan tasks (any thread) can record without locks; `/metrics` renders them.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static SCANS_SUBMITTED: AtomicU64 = AtomicU64::new(0);
static SCANS_COMPLETED: AtomicU64 = AtomicU64::new(0);
static SCANS_FAILED: AtomicU64 = AtomicU64::new(0);
static SCANS_TIMED_OUT: AtomicU64 = AtomicU64::new(0);
static SCANS_CANCELLED: AtomicU64 = AtomicU64::new(0);
static ACTIVE_SCANS: AtomicI64 = AtomicI64::new(0);
static SCAN_DURATION_MS: AtomicU64 = AtomicU64::new(0);
static SCAN_DURATION_COUNT: AtomicU64 = AtomicU64::new(0);
static RULE_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static STARTED_AT: OnceLock<Instant> = OnceLock::new();

fn started() -> Instant {
    *STARTED_AT.get_or_init(Instant::now)
}

pub fn scan_submitted() {
    SCANS_SUBMITTED.fetch_add(1, Ordering::Relaxed);
}

/// Counts one running scan until dropped. A drop guard, not paired calls:
/// cancelling a still-queued scan used to decrement a scan that never started
/// and drive the gauge negative.
pub struct ActiveScan(());

impl Drop for ActiveScan {
    fn drop(&mut self) {
        ACTIVE_SCANS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[must_use = "the scan counts as active only while the guard lives"]
pub fn scan_started() -> ActiveScan {
    ACTIVE_SCANS.fetch_add(1, Ordering::Relaxed);
    ActiveScan(())
}

/// Record completion. `ok` = scan produced a result; `matches` = rule hits.
pub fn scan_finished(ok: bool, timed_out: bool, duration_ms: u64, matches: u64) {
    if ok {
        SCANS_COMPLETED.fetch_add(1, Ordering::Relaxed);
        SCAN_DURATION_MS.fetch_add(duration_ms, Ordering::Relaxed);
        SCAN_DURATION_COUNT.fetch_add(1, Ordering::Relaxed);
        RULE_HITS_TOTAL.fetch_add(matches, Ordering::Relaxed);
    } else if timed_out {
        SCANS_TIMED_OUT.fetch_add(1, Ordering::Relaxed);
    } else {
        SCANS_FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn scan_cancelled() {
    SCANS_CANCELLED.fetch_add(1, Ordering::Relaxed);
}

pub fn active_scans() -> i64 {
    ACTIVE_SCANS.load(Ordering::Relaxed)
}

fn counter(block: &mut String, name: &str, help: &str, value: u64) {
    block.push_str(&format!(
        "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
        name, help, name, name, value
    ));
}

/// Render Prometheus text exposition. `pending` = scans queued in memory.
pub fn render(pending: usize) -> String {
    let mut out = String::new();
    counter(
        &mut out,
        "kalascan_scans_submitted_total",
        "Scans accepted into the queue.",
        SCANS_SUBMITTED.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "kalascan_scans_completed_total",
        "Scans that produced a result.",
        SCANS_COMPLETED.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "kalascan_scans_failed_total",
        "Scans that failed (excluding timeouts and cancellations).",
        SCANS_FAILED.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "kalascan_scans_timed_out_total",
        "Scans killed by the per-scan timeout.",
        SCANS_TIMED_OUT.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "kalascan_scans_cancelled_total",
        "Scans cancelled via DELETE.",
        SCANS_CANCELLED.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "kalascan_rule_hits_total",
        "Rule matches across completed scans.",
        RULE_HITS_TOTAL.load(Ordering::Relaxed),
    );

    out.push_str("# HELP kalascan_scans_active Current scans executing (permit held).\n# TYPE kalascan_scans_active gauge\n");
    out.push_str(&format!(
        "kalascan_scans_active {}\n",
        ACTIVE_SCANS.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP kalascan_scans_queued Scans waiting for a concurrency slot.\n# TYPE kalascan_scans_queued gauge\n");
    out.push_str(&format!("kalascan_scans_queued {}\n", pending));

    let total = SCAN_DURATION_COUNT.load(Ordering::Relaxed);
    out.push_str("# HELP kalascan_scan_duration_ms_sum Total scan wall-clock time (ms).\n# TYPE kalascan_scan_duration_ms_sum counter\n");
    out.push_str(&format!(
        "kalascan_scan_duration_ms_sum {}\n",
        SCAN_DURATION_MS.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP kalascan_scan_duration_ms_count Scans included in the duration sum.\n# TYPE kalascan_scan_duration_ms_count counter\n");
    out.push_str(&format!("kalascan_scan_duration_ms_count {}\n", total));

    out.push_str(
        "# HELP kalascan_uptime_seconds Process uptime.\n# TYPE kalascan_uptime_seconds gauge\n",
    );
    out.push_str(&format!(
        "kalascan_uptime_seconds {}\n",
        started().elapsed().as_secs()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_gauges_render() {
        scan_submitted();
        {
            let _active = scan_started();
            scan_finished(true, false, 250, 3);
        }
        {
            let _active = scan_started();
            scan_finished(false, false, 100, 0);
        }
        // Cancelled before it ever started: no guard, so no decrement.
        scan_cancelled();
        // Cancelled while running: the aborted task drops its guard.
        drop(scan_started());

        let text = render(1);
        assert!(text.contains("kalascan_scans_submitted_total 1"));
        assert!(text.contains("kalascan_scans_completed_total 1"));
        assert!(text.contains("kalascan_scans_failed_total 1"));
        assert!(text.contains("kalascan_scans_cancelled_total 1"));
        assert!(text.contains("kalascan_scans_active 0"));
        assert!(text.contains("kalascan_scans_queued 1"));
        assert!(text.contains("kalascan_scan_duration_ms_sum 250"));
        assert!(text.contains("kalascan_rule_hits_total 3"));
    }
}
