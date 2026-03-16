# API Sentinel

Continuously monitors API documentation changes and DNS infrastructure changes for Kalshi.

Runs every 10 minutes. Detects meaningful changes and emits structured alerts.

## What it monitors

**Documentation:**
- `https://docs.kalshi.com/openapi.yaml` — OpenAPI spec with semantic diffing
- `https://docs.kalshi.com/asyncapi.yaml` — AsyncAPI spec with semantic diffing
- `https://docs.kalshi.com/changelog` — raw change detection

**DNS infrastructure:**
- `docs.kalshi.com` — A, AAAA, CNAME records + hourly trace
- `api.elections.kalshi.com` — A, AAAA, CNAME records + hourly trace
- `kalshi.com` — NS records

Queries run against default resolver, `1.1.1.1`, and `8.8.8.8`.

## Semantic diff detection

For OpenAPI/AsyncAPI specs, detects:
- New / removed endpoints
- Parameter changes
- Auth requirement changes
- Request / response schema changes
- Enum value changes

## Alert types

| Alert | Severity |
|-------|----------|
| `DOC_RAW_CHANGE` | MEDIUM |
| `DOC_SEMANTIC_CHANGE` | LOW–HIGH (context-dependent) |
| `DNS_ANSWER_CHANGE` | MEDIUM |
| `DNS_TTL_CHANGE` | LOW |
| `DNS_DELEGATION_CHANGE` | HIGH |

## Requirements

- Rust 1.75+ (uses `Option<T>` in return position, `BTreeSet` methods)
- `dig` command available on PATH
- Internet access

## Build & run

```bash
cd apisentinel
cargo build --release
cargo run --release
```

The binary runs indefinitely, polling every 10 minutes.

## Configuration

Environment variables:

| Variable | Description |
|----------|-------------|
| `SENTINEL_SLACK_WEBHOOK` | Optional Slack incoming webhook URL for alerts |
| `RUST_LOG` | Log level filter (default: `info`) |

## Data

SQLite database and snapshots are stored in `apisentinel/data/`.

Tables: `doc_snapshots`, `doc_diffs`, `dns_snapshots`, `dns_events`.

## Project structure

```
apisentinel/
  Cargo.toml
  src/
    main.rs           # Entry point, scheduler loop
    config.rs         # URLs, hosts, resolvers, settings
    database.rs       # SQLite schema and queries
    docs_monitor.rs   # Documentation fetch + change detection
    dns_monitor.rs    # DNS dig queries + change detection
    openapi_diff.rs   # Semantic YAML spec diffing
    alerts.rs         # Console + Slack alert system
  data/
    snapshots/
```
