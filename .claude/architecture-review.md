# Ring VPN Architecture Review — 2026-03-22

## DNS Success Rate Progression

| Session | Date | sent | ok | timeout | rate | reconn | Fix applied |
|---------|------|------|-----|---------|------|--------|-------------|
| #1 | 01:00 | 1590 | 229 | 263 | **14%** | 0 | dual-DNS simultaneous |
| #3 | 01:16 | 191 | 90 | 13 | **47%** | 2 | primary-only + stall detection 10s |
| #4 | 01:20 | 101 | 50 | 6 | **50%** | ? | same |
| #5 | 01:29 | 328 | 271 | 4 | **83%** | 1 | 50ms pacing + stall 5s |

Session #5 shows 100% success at low rates, with one stall triggered by a burst of 62 queries in 5 seconds. After reconn, 100% success resumes.

## Architecture Status: What works, what's dead

### WORKING in production
- DNS query interception via virtual IP 198.18.0.1
- DNS forwarding via NWUDPSession (primary 8.8.8.8, secondary 1.1.1.1)
- DNS domain extraction in Rust engine
- Site grouping (site_mapper.rs)
- SQLite storage via App Group
- Stall detection + session recreation
- SERVFAIL on timeout
- DNS query type recording (dns_query_types table)

### DEAD CODE (TCP never enters tunnel — DNS-only routing)
- TCP reassembly (~470 lines)
- TLS SNI extraction (~400 lines)
- TLS version tracking (~380 lines) — extracted from ClientHello but TCP never arrives
- ECH downgrade (~200 lines)
- Byte volume tracking (~150 lines) — only counts DNS packet bytes, not data transfer
- Destination IP correlation for TCP (~100 lines)
- 65KB output buffer in RustBridge (only used for ECH packet modification)

Total: ~1700 lines of dead Rust code + Swift UI for features that can't work

### DECISION NEEDED
Ring must choose: DNS-only monitor OR full VPN.
- DNS-only: remove dead code, focus on DNS visibility
- Full VPN: add TCP/443 to includedRoutes, enables SNI/TLS/bytes but impacts battery

## Priority Bugs (from research + diagnostics)

### P0 — User-facing breakage
1. **NWUDPSession burst death** — sessions die at >12 queries/sec. Current 50ms pacing helps but mid-session bursts still kill sessions. Stall recovery takes ~6s.
   - Status: MITIGATED (83% success), not fully solved
   - Long-term: migrate to NWConnection

### P1 — Correctness
2. **txnID collision** — 16-bit ID, two apps with same txnID = first query silently lost. Use (srcPort, txnID) as compound key.
3. **busy_timeout mismatch** — Rust engine=5s, DatabaseReader=0.5s. Reader gives up during engine flush, UI shows empty.
4. **engineQueue.sync blocks packet processing** — SQLite flush on hot path can block DNS forwarding for up to 5s.
5. **Startup burst uncounted** — flushQueuedSends doesn't increment queriesSent, making ok > sent in stats.

### P2 — Reliability
6. **Debug log unbounded growth** — tunnel_status.txt grows without limit over days of VPN use.
7. **VPNManager.sendMessage hangs forever** — if tunnel crashes mid-IPC, Task never resumes.
8. **tunnelRemoteAddress 192.168.1.1** — conflicts with common LAN gateways.
9. **sendDelayCounter not reset on reconn** — stale counter from previous burst.

### P3 — Architecture
10. **NWUDPSession deprecated iOS 18** — migrate to NWConnection with recursive receiveMessage.
11. **No IPv6 DNS route** — dual-stack networks may bypass tunnel.
12. **SERVFAIL includes full original payload** — should include question section only.
13. **Visits table grows without bound** — no cleanup in the extension, only app-side.
14. **IPC stats protocol unversioned** — adding fields breaks the binary protocol.
