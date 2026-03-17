mod alerts;
mod bot_stop;
mod config;
mod database;
mod dns_monitor;
mod docs_monitor;
mod openapi_diff;

use alerts::AlertManager;
use config::Config;
use database::Database;
use dns_monitor::DnsMonitor;
use docs_monitor::DocsMonitor;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info};

fn main() {
    // Initialize structured logging
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

    info!(
        poll_interval_secs = cfg.poll_interval_secs,
        trace_interval_secs = cfg.trace_interval_secs,
        "scheduler configured"
    );

    let mut last_trace = Instant::now() - Duration::from_secs(cfg.trace_interval_secs + 1);

    loop {
        let cycle_start = Instant::now();
        info!("=== starting monitoring cycle ===");

        // 1. Documentation checks
        {
            let monitor = DocsMonitor::new(&db, &alert_mgr, cfg.request_timeout_secs);
            monitor.check_all(config::DOCS);
        }

        // 2. DNS checks
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

        // Sleep until next interval
        let sleep_dur = Duration::from_secs(cfg.poll_interval_secs).saturating_sub(elapsed);
        if !sleep_dur.is_zero() {
            info!(sleep_secs = sleep_dur.as_secs(), "sleeping until next cycle");
            thread::sleep(sleep_dur);
        }
    }
}
