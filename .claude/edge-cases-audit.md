# VPN Edge Case Audit — 2026-03-21

## Iteration 1: Discovery

### CRITICAL (fix immediately)
1. **No SERVFAIL on DNS timeout/drop** — apps hang 5-30s with no feedback. Should synthesize SERVFAIL response. (PacketTunnelProvider.swift:672-678)
2. **IPv6 DNS queries silently dropped** — IPv6-only networks completely broken. (PacketTunnelProvider.swift:358-359)
3. **FFI thread safety** — Swift calls `get_stats` from UI thread while `process_packet` runs on tunnel thread. UB via aliased references. (lib.rs:260-298)
4. **AssertUnwindSafe masks corrupted state after panic** — continued use after caught panic = memory corruption. (lib.rs:116+)

### HIGH (fix soon)
5. **KVO double-remove crash** — rapid state transitions (.failed→.cancelled) call removeObserver twice = NSException crash. (PacketTunnelProvider.swift:533,552)
6. **DNS txnID collision** — 16-bit ID space, birthday paradox at 50+ concurrent queries. First query silently lost. (PacketTunnelProvider.swift:665-668)
7. **No DNS-over-TCP fallback** — DNSSEC/SVCB responses >512 bytes truncated, TCP retry dropped. (PacketTunnelProvider.swift:363)
8. **pending_bytes HashMap unbounded** — iOS NE has 15MB limit. (engine.rs:44)
9. **CNAME chains not followed** — byte attribution wrong for CDN-hosted sites. (dns.rs:212-257)
10. **Data loss on flush failure** — pending data drained before DB write; if write fails, data gone. (engine.rs:324-358)
11. **consent_synced flag not reset on consent change** — revoked consent still sends telemetry. (ConsentService.swift:15-48)
12. **Rapid VPN toggle race** — two packet loops can run concurrently. (PacketTunnelProvider.swift:22-116)
13. **Device ID in UserDefaults, not Keychain** — changes on reinstall, orphans backend data. (ConsentService.swift:68-76)
14. **No memory pressure handling** — NE has 15MB limit, no circuit breaker. (PacketTunnelProvider.swift entire)

### MEDIUM
15. sendDelayCounter grows unbounded under sustained load → 750ms+ delays
16. queuedSends unbounded before session ready
17. No response on query drop (maxPendingQueries hit)
18. TCP reassembly ignores segment ordering
19. Site mapper MULTI_PART_TLDS incomplete
20. batch_update_domain_bytes uses &self instead of &mut self
21. cleanup_old_data no validation on retention_days
22. Telemetry no deduplication
23. UserDefaults.standard vs AppGroup inconsistency in consent
24. LIKE pattern injection in search
25. writeDebugStatus creates ISO8601DateFormatter on every call

### Status (verified against code 2026-03-22)

**FIXED and verified in code:**
- [x] #1 SERVFAIL on timeout — sendServfail() called in timeout handler and flushQueuedSends timeout
- [x] #5 KVO crash — primaryObserverRemoved/secondaryObserverRemoved guard flags
- [x] #6 txnID collision — srcPort comparison: same port=retry (no SERVFAIL), different port=collision (SERVFAIL)
- [x] #11 consent flag — reset to false before each sendConsent call
- [x] #13 device ID — Keychain storage with UserDefaults migration
- [x] #14 memory pressure — DispatchSource.makeMemoryPressureSource flushes engine
- [x] #15 sendDelayCounter — NOW UNCAPPED (was capped at 10, then removed cap to fix burst piling)
- [x] #16 queuedSends cap — QUEUE_FULL logged, SERVFAIL sent on overflow
- [x] #19 MULTI_PART_TLDS — 14 added (gov, edu, ac, go, net, org variants for UK/AU/BR/JP/KR/CN)
- [x] #20 batch_update &mut self — changed from &self
- [x] #21 retention_days — rejects <= 0 with EngineError::DatabaseWrite
- [x] #22 telemetry dedup — lastSyncMs tracked, sites filtered by lastSeenMs > lastSync
- [x] #24 LIKE escape — %, _, \\ escaped with ESCAPE '\\' clause
- [x] #25 static formatter — static let debugDateFormatter = ISO8601DateFormatter()

**REVERTED after review (over-engineering):**
- [~] #8 pending_bytes threshold — REVERTED: 500ms timer sufficient, extra thresholds unnecessary
- [~] #10 flush re-queue — REVERTED: risks infinite retry loops, data is re-observable

**NOT sending SERVFAIL (audit was wrong):**
- [~] #17 query drop — logs dns_DROP but does NOT send SERVFAIL (query not yet registered in pending)

**Not fixed (architectural / low priority):**
- [ ] #2 IPv6 — tunnel only routes IPv4; iOS directs DNS to virtual IPv4 anyway
- [ ] #3 FFI thread safety — engine serialized via engineQueue; stats accessed from queue→engineQueue
- [ ] #4 AssertUnwindSafe — Rust design pattern, document risk
- [ ] #7 DNS-over-TCP — would need TCP session support
- [ ] #9 CNAME chains — byte attribution only (dead code with DNS-only routing)
- [ ] #12 rapid toggle — already guarded via isStopping flag
- [ ] #18 TCP reassembly ordering — dead code with DNS-only routing
- [ ] #23 UserDefaults vs AppGroup — verified NOT a bug (hasCompletedConsent correctly in .standard)
