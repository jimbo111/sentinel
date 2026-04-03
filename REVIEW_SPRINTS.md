# Code Review — Sprint Tracker

Findings from full codebase review (2026-03-19). All sprints completed + verification pass.

---

## Sprint 1 — Blocks TestFlight ✅

- [x] **#1 CRITICAL** — Data race on `RustPacketEngine` (two queues calling non-thread-safe engine concurrently)
  - Fix: Added `engineQueue` serial queue; all engine calls serialized through it
  - Files: `PacketTunnelProvider.swift`
- [x] **#3 HIGH** — `AppGroupConfig.containerURL` calls `fatalError` in production
  - Fix: Replaced with `assertionFailure` + fallback + `os_log(.fault)` for release visibility
  - Files: `AppGroupConfig.swift`
  - Verification fix: Added os_log(.fault) so fallback to temp dir is diagnosable in release
- [x] **#4 HIGH** — CSV export blocks main thread + security issues
  - Fix: `Task.detached`, UUID filename, quote escaping, error surfacing, cleanup on dismiss
  - Files: `SettingsViewModel.swift`, `SettingsView.swift`

---

## Sprint 2 — App Store Polish ✅

- [x] **#7 HIGH** — Onboarding copy says "no traffic leaves device" but DNS queries go to Google
  - Fix: Updated copy to accurately describe DNS forwarding to public resolver
  - Files: `OnboardingView.swift`
- [x] **#27 LOW** — `ConnectButton` missing accessibility label
  - Fix: Added `accessibilityLabel` with three states (connected, transitioning, disconnected)
  - Files: `ConnectButton.swift`
  - Verification fix: Label now correctly says "VPN connection in progress" during transitions
- [x] **#23 LOW** — Missing `idx_visits_domain_id` index (improves join performance)
  - Fix: Added `CREATE INDEX IF NOT EXISTS idx_visits_domain_id ON visits(domain_id)`
  - Files: `storage.rs`
- [x] **#25 LOW** — Dead methods: `observeStatus()`, `search(query:)`, `execute()`
  - Fix: Removed all three
  - Files: `VPNManager.swift`, `DomainListViewModel.swift`, `DatabaseReader.swift`
- [x] **#26 LOW** — Dead `#available(iOS 16)` guard (project targets iOS 17+)
  - Fix: Removed guard and fallback, using Chart directly
  - Files: `StatsView.swift`

### Deferred from Sprint 2 (not needed for V1)

- **#2 HIGH** — SQLite encryption → Deferred. iOS sandbox protects App Group on non-jailbroken devices. High effort (SQLCipher + FFI + migration). Revisit for V2 premium features.
- **#6 HIGH** — Schema migration → Deferred. Current schema is stable for DNS-only MVP. Add migration support when the first schema change is actually needed.

---

## Sprint 3 — Blocks Backend Integration ✅

- [x] **#5 HIGH** — Refresh token inserted outside transaction in `rotateRefreshToken`
  - Fix: `issueRefreshToken` now accepts optional `PoolClient`; `rotateRefreshToken` passes its client
  - Files: `userService.ts`
- [x] **#8 HIGH** — `authorizationCode` required by schema but never used
  - Fix: Made optional. Full Apple code exchange deferred to feature work.
  - Files: `routes/auth.ts`, `auth.test.ts`
- [x] **#19 MEDIUM** — `noiseFilterDomains` unsafe `string[]` cast from DB
  - Fix: Added `typeof d === 'string'` filter on array elements
  - Files: `configService.ts`

### Dropped / Deferred from Sprint 3

- **#20** — DROPPED (false positive). `findOrCreateUserByAppleSub` returns existing users unchanged — name is only set during creation.
- **#17** — DEFERRED. Access logging is a feature addition. Backend not in production.
- **#18** — DEFERRED. `DATABASE_SSL=false` is correct for dev docker-compose. Set in production env vars.

---

## Sprint 4 — Code Quality / Robustness ✅

- [x] **#10 MEDIUM** — `DomainListViewModel` missing `@MainActor`
  - Fix: Added `@MainActor` + converted GCD to structured concurrency (Task.detached)
  - Files: `DomainListViewModel.swift`
  - Verification fix: GCD pattern was incompatible with @MainActor under Swift 6 strict concurrency. Converted to Task.detached + MainActor continuation, matching StatsViewModel's pattern.
- [x] **#13 MEDIUM** — IPv4 `total_length` not validated against actual packet slice
  - Fix: Reject when `total_length > packet.len()` or `total_length < header_len`
  - Files: `ip.rs`
  - Verification fix: Also reject `total_length < header_len` (inconsistent IpHeader)
- [x] **#16 MEDIUM** — `DatabaseReader` docstring claimed read-only but class performs writes
  - Fix: Updated docstring to reflect actual behavior
  - Files: `DatabaseReader.swift`
- [x] **#22 LOW** — Dead `first_seen` field in TCP reassembly
  - Fix: Removed field and `#[allow(dead_code)]`
  - Files: `tcp_reassembly.rs`

### Skipped from Sprint 4 (after re-evaluation)

- **#9** — ECH buffer overflow fallback. DNS packets can't exceed 65KB. Not a practical concern.
- **#11** — GCD/async mix. Fixed as part of #10 verification (was incompatible with @MainActor).
- **#12** — Silent DNS drops. Already has `.error`-level logging. Adding a counter is over-engineering.
- **#14** — `an_count` uncapped. Existing per-iteration bounds checks prevent DoS. Not a real issue.
- **#15** — TCP reassembly `.clone()`. Required by borrow checker. Happens once per ClientHello, cost is negligible.
- **#21** — Dead ECH block. Intentional Phase 5 scaffolding. Leave for future use.
- **#24** — Spinner flash on refresh. Minor UX; requires async refactor with regression risk.

### Remaining LOW items (not blocking, address as needed)

- **#28** — Device ID in wrong defaults suite
- **#29** — Tunnel remote address LAN collision
- **#30** — Hardcoded dev password in docker-compose
- **#31** — `build.rs` writes outside `$OUT_DIR`
- **#32** — JWKS hand-rolled DER parser
- **#33** — `searchDomains` withCString pattern
- **#34** — `writeDebugStatus` not DEBUG-gated
- **#35** — Keychain `ThisDeviceOnly` attribute
- **#36** — No Rust toolchain pinning

---

## Verification Summary

Two code review agents verified all implementations. Findings addressed:
- AppGroupConfig fallback was silently creating phantom databases → added os_log(.fault)
- @MainActor + GCD pattern violated Swift 6 concurrency → converted to Task.detached
- ConnectButton accessibility label was wrong during transitions → fixed to three states
- IPv4 total_length < header_len was not rejected → added validation

All tests passing: 92 Rust + 20 backend = 112 total.
