mod alerts;
mod bot_stop;
mod config;
mod database;
mod dns_monitor;
mod docs_monitor;
mod geo_monitor;
mod latency_monitor;
mod openapi_diff;

use alerts::AlertManager;
use config::Config;
use database::Database;
use dns_monitor::DnsMonitor;
use docs_monitor::DocsMonitor;
use geo_monitor::GeoMonitor;
use latency_monitor::{LatencyMonitor, PollMode};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info};

const NORMAL_INTERVAL_SECS: u64 = 600; // 10 min
const WATCH_INTERVAL_SECS:  u64 = 180; //  3 min

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("API Sentinel starting");

    let cfg = Config::with_cwd_data();

    let db = match Database::open(&cfg.db_path) {
        Ok(db) => db,
        Err(e) => {
            error!(error = %e, "failed to open database");
            std::process::exit(1);
        }
    };

    let alert_mgr = AlertManager::new(cfg.slack_webhook_url.clone());

    // LatencyMonitor holds mutable watch-mode state — lives outside the loop.
    let mut latency_monitor = LatencyMonitor::new(&db, &alert_mgr);

    info!(
        poll_interval_secs = NORMAL_INTERVAL_SECS,
        watch_interval_secs = WATCH_INTERVAL_SECS,
        "scheduler configured"
    );

    let mut last_trace = Instant::now() - Duration::from_secs(cfg.trace_interval_secs + 1);
    let mut poll_interval_secs = NORMAL_INTERVAL_SECS;

    loop {
        let cycle_start = Instant::now();
        info!(poll_interval_secs, "=== starting monitoring cycle ===");

        // 1. Documentation checks
        {
            let monitor = DocsMonitor::new(&db, &alert_mgr, cfg.request_timeout_secs);
            monitor.check_all(config::DOCS);
        }

        // 2. Latency check — may switch to 3-min watch mode
        let mode = latency_monitor.check();
        poll_interval_secs = match mode {
            PollMode::Normal => NORMAL_INTERVAL_SECS,
            PollMode::Watch  => WATCH_INTERVAL_SECS,
        };

        // 3. Infrastructure (hosting provider / AWS region) check
        {
            let monitor = GeoMonitor::new(&db, &alert_mgr);
            monitor.check();
        }

        // 4. DNS checks
        {
            let resolver_refs: Vec<&str> = config::RESOLVERS.iter().copied().collect();
            let monitor = DnsMonitor::new(&db, &alert_mgr, &resolver_refs);
            monitor.check_all(config::HOSTS);

            // Trace queries once per hour
            if last_trace.elapsed() >= Duration::from_secs(cfg.trace_interval_secs) {
                monitor.check_traces(config::HOSTS);
                last_trace = Instant::now();
            }
        }

        let elapsed = cycle_start.elapsed();
        info!(elapsed_secs = elapsed.as_secs(), "monitoring cycle complete");

        let sleep_dur = Duration::from_secs(poll_interval_secs).saturating_sub(elapsed);
        if !sleep_dur.is_zero() {
            info!(sleep_secs = sleep_dur.as_secs(), "sleeping until next cycle");
            thread::sleep(sleep_dur);
        }
    }
}
