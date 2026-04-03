# CLAUDE.md — Sentinel (Personal Security / Phishing Protection)

## Overview

Sentinel is an on-device security app built on Ring's DNS interception engine. It detects phishing domains, flags malicious DNS resolutions, alerts users to suspicious app behavior, and provides a personal threat dashboard — all processed on-device for privacy.

## Origin

Forked from [Ring](../Ring/frontend/). The DNS interception, site grouping, and categorization engine are inherited. Sentinel adds threat intelligence, phishing detection, and security alerting on top.

## Stack

- **Rust**: packet engine, DNS parsing, threat matching engine, SQLite storage (inherited from Ring)
- **Swift/SwiftUI**: app UI, Network Extension, DNS forwarding
- **Backend**: **Shared** with Ring at `https://ring-backend-gccf.onrender.com` (lives at `../Ring/backend/`)

## Shared Backend — Decoupling Rules

Sentinel shares Ring's backend and PostgreSQL database. To prevent conflicts:

1. **Namespace all new tables** with `sentinel_` prefix (e.g., `sentinel_threat_feeds`, `sentinel_alerts`)
2. **Namespace all new endpoints** under `/api/sentinel/` (e.g., `/api/sentinel/threats`, `/api/sentinel/alerts`)
3. **Never modify existing Ring tables or endpoints** — only add new ones
4. **Device ID isolation** — all queries must be scoped to `device_id`; never read another app's data
5. **Schema migrations** — prefix migration files with `sentinel_` (e.g., `sentinel_001_threat_feeds.sql`)
6. **Feature flags** — use `app_id: "sentinel"` in API requests to distinguish from Ring/Guardian/Shield

## Build

```bash
./scripts/build-universal.sh              # Rust (run first)
cd ring && xcodebuild -scheme ring build   # iOS (physical device only)
cd rust/packet_engine && cargo test        # tests
```

> **Note:** Xcode project, bundle IDs, and scheme need renaming from `ring` to `sentinel` before App Store submission.

## Architecture

DNS queries → virtual IP `198.18.0.1` → NWUDPSession → `8.8.8.8` / `1.1.1.1`. On-demand auto-reconnect. Sleep/wake handlers for iOS 17+. Stall detection recreates sessions if read handler dies. SERVFAIL on timeout.

## Key Features (To Build)

- [ ] Phishing domain detection (on-device, in Rust)
- [ ] Threat intelligence feed integration (malware C2, phishing, DGA domains)
- [ ] Real-time security alerts ("App X contacted a known phishing domain")
- [ ] Personal threat dashboard (blocked threats, risk score)
- [ ] Domain reputation lookup
- [ ] Threat feed auto-update via backend

## Common Pitfalls

- Run `./scripts/build-universal.sh` after ANY Rust changes
- NWUDPSession read handler dies at >12 queries/sec — 50ms pacing mitigates
- Test on physical device — Network Extension doesn't work on simulator
- Backend changes go in `../Ring/backend/` — follow namespace rules above
- Threat matching happens in Rust for performance — bloom filters recommended for large feed lists

## Docs (Inherited from Ring)

| Doc | Purpose |
|-----|---------|
| `docs/vpn-engineering-guide.md` | Full VPN reference |
| `docs/rust-engine-internals.md` | Rust engine modules, SQLite, FFI |
| `docs/production-vpn-patterns.md` | How other VPN apps solve same problems |
| `docs/security-resources.md` | Blocklists, Rust crates, iOS security references |
