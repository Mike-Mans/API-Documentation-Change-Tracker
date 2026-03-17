//! Adaptive latency monitor for the Kalshi API server.
//!
//! Measures TCP connect time to api.elections.kalshi.com:443 each cycle.
//! Uses a two-phase state machine to distinguish real datacenter moves
//! from transient congestion:
//!
//!   Normal mode  (10 min intervals):
//!     First anomaly (>25% deviation from baseline) → enter Watch mode
//!
//!   Watch mode   (3 min intervals):
//!     10 consecutive anomalous readings → fire alert + stop bot
//!     Any single clean reading          → reset counter, back to Normal mode
//!
//! Baseline is established from the median of each of the first 3 cycles,
//! then averaged. No anomaly detection until baseline is set.

use crate::alerts::{Alert, AlertManager, AlertType, Severity};
use crate::database::Database;
use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn, error};

const TARGET_HOST: &str = "api.elections.kalshi.com";
const TARGET_PORT: u16 = 443;
const SAMPLES_PER_CYCLE: usize = 3;
const BASELINE_CYCLES: usize = 3;
const ANOMALY_THRESHOLD: f64 = 0.25; // 25% deviation in either direction
const CONSECUTIVE_NEEDED: u32 = 10;  // in Watch mode
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DB_KEY: &str = "api.elections.kalshi.com:latency";

pub enum PollMode {
    Normal,     // 10-minute cycle
    Watch,      // 3-minute cycle — anomaly under investigation
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state")]
enum PersistedBaseline {
    Accumulating { sum_ms: f64, n_cycles: usize },
    Established  { baseline_ms: f64 },
}

pub struct LatencyMonitor<'a> {
    db: &'a Database,
    alerts: &'a AlertManager,
    // In-memory watch state — intentionally resets if the tracker restarts.
    consecutive_anomalies: u32,
    in_watch_mode: bool,
}

impl<'a> LatencyMonitor<'a> {
    pub fn new(db: &'a Database, alerts: &'a AlertManager) -> Self {
        Self { db, alerts, consecutive_anomalies: 0, in_watch_mode: false }
    }

    /// Run one latency check. Returns the poll mode the main loop should use
    /// for its next sleep interval.
    pub fn check(&mut self) -> PollMode {
        match self.check_inner() {
            Ok(mode) => mode,
            Err(e) => {
                error!(error = %e, "latency check failed");
                PollMode::Normal
            }
        }
    }

    fn check_inner(&mut self) -> anyhow::Result<PollMode> {
        let median_ms = match sample_median(SAMPLES_PER_CYCLE) {
            Some(v) => v,
            None => {
                warn!(host = TARGET_HOST, "all TCP connect attempts failed — skipping latency check");
                return Ok(if self.in_watch_mode { PollMode::Watch } else { PollMode::Normal });
            }
        };

        info!(
            host = TARGET_HOST,
            latency_ms = format!("{:.1}", median_ms),
            watch_mode = self.in_watch_mode,
            consecutive_anomalies = self.consecutive_anomalies,
            "latency check"
        );

        // Load or update the persisted baseline.
        let baseline_ms = match self.update_baseline(median_ms)? {
            Some(b) => b,
            None => {
                // Still accumulating — no anomaly detection yet.
                return Ok(PollMode::Normal);
            }
        };

        let deviation = (median_ms - baseline_ms).abs() / baseline_ms;
        let is_anomaly = deviation > ANOMALY_THRESHOLD;

        info!(
            baseline_ms = format!("{:.1}", baseline_ms),
            current_ms  = format!("{:.1}", median_ms),
            deviation_pct = format!("{:.1}", deviation * 100.0),
            anomaly = is_anomaly,
            "latency vs baseline"
        );

        if is_anomaly {
            self.consecutive_anomalies += 1;
            self.in_watch_mode = true;

            warn!(
                consecutive = self.consecutive_anomalies,
                needed = CONSECUTIVE_NEEDED,
                "latency anomaly detected — watching"
            );

            if self.consecutive_anomalies >= CONSECUTIVE_NEEDED {
                self.fire_alert(median_ms, baseline_ms, deviation);
            }

            Ok(PollMode::Watch)
        } else {
            if self.in_watch_mode {
                info!(
                    consecutive_was = self.consecutive_anomalies,
                    "clean reading — resetting watch state, back to normal mode"
                );
            }
            self.consecutive_anomalies = 0;
            self.in_watch_mode = false;
            Ok(PollMode::Normal)
        }
    }

    /// Handles baseline accumulation and returns the established baseline_ms
    /// once ready, or None while still warming up.
    fn update_baseline(&self, current_ms: f64) -> anyhow::Result<Option<f64>> {
        let state: PersistedBaseline = match self.db.get_geo_baseline(DB_KEY)? {
            Some(json) => serde_json::from_str(&json).unwrap_or(
                PersistedBaseline::Accumulating { sum_ms: 0.0, n_cycles: 0 }
            ),
            None => PersistedBaseline::Accumulating { sum_ms: 0.0, n_cycles: 0 },
        };

        match state {
            PersistedBaseline::Established { baseline_ms } => {
                Ok(Some(baseline_ms))
            }
            PersistedBaseline::Accumulating { sum_ms, n_cycles } => {
                let new_sum = sum_ms + current_ms;
                let new_n   = n_cycles + 1;

                if new_n >= BASELINE_CYCLES {
                    let baseline_ms = new_sum / new_n as f64;
                    info!(
                        baseline_ms = format!("{:.1}", baseline_ms),
                        cycles = new_n,
                        "latency baseline established"
                    );
                    let persisted = PersistedBaseline::Established { baseline_ms };
                    self.db.set_geo_baseline(DB_KEY, &serde_json::to_string(&persisted)?)?;
                    Ok(Some(baseline_ms))
                } else {
                    info!(
                        cycles_so_far = new_n,
                        needed = BASELINE_CYCLES,
                        current_ms = format!("{:.1}", current_ms),
                        "accumulating latency baseline"
                    );
                    let persisted = PersistedBaseline::Accumulating {
                        sum_ms: new_sum,
                        n_cycles: new_n,
                    };
                    self.db.set_geo_baseline(DB_KEY, &serde_json::to_string(&persisted)?)?;
                    Ok(None)
                }
            }
        }
    }

    fn fire_alert(&mut self, current_ms: f64, baseline_ms: f64, deviation: f64) {
        let direction = if current_ms < baseline_ms { "dropped" } else { "rose" };
        self.alerts.emit(&Alert {
            alert_type: AlertType::ApiGeoRelocation,
            severity:   Severity::High,
            title: format!(
                "API server latency {direction} {:.0}% — possible datacenter move",
                deviation * 100.0
            ),
            details: format!(
                "Baseline: {baseline_ms:.1}ms\nCurrent:  {current_ms:.1}ms\n\
                 Deviation: {:.1}%\n\
                 10 consecutive anomalous readings at 3-min intervals (30 min sustained).\n\
                 Action: verify datacenter and consider relocating VPS.",
                deviation * 100.0
            ),
            source: TARGET_HOST.to_string(),
        });
    }
}

// ── TCP latency sampling ──────────────────────────��───────────────────────────

/// Take N cold TCP connect samples and return the median RTT in ms.
///
/// Each sample re-resolves DNS fresh and waits 500ms beforehand so the OS
/// has no residual TIME_WAIT or route-cache state from the previous sample.
/// Only the TCP SYN→SYNACK time is measured — DNS lookup happens before
/// the timer starts.
fn sample_median(n: usize) -> Option<f64> {
    let mut samples: Vec<f64> = Vec::with_capacity(n);

    for i in 0..n {
        // Gap between samples — lets OS retire any warm connection state.
        if i > 0 {
            thread::sleep(Duration::from_millis(500));
        }

        // Fresh DNS resolution per sample — no cached IP reuse across calls.
        let addr = match format!("{TARGET_HOST}:{TARGET_PORT}").to_socket_addrs() {
            Ok(mut it) => match it.next() {
                Some(a) => a,
                None => continue,
            },
            Err(_) => continue,
        };

        // Time only the TCP connect (SYN → SYNACK).
        let start = Instant::now();
        if TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).is_ok() {
            samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
    }

    if samples.is_empty() {
        return None;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(samples[samples.len() / 2])
}
