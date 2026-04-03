# DNS Stress Test Lab — Findings

## Test Environment
- macOS, direct UDP socket to 8.8.8.8:53 (Google DNS)
- No VPN tunnel involved — tests the raw DNS forwarding path
- Date: 2026-03-21

## Test 1: Burst (all queries sent in <2ms)

| Queries | Success | Drop Rate | Avg Latency |
|---------|---------|-----------|-------------|
| 30      | 30%     | 70%       | 20ms        |
| 50      | 28%     | 72%       | 22ms        |

**Conclusion:** Google DNS drops 70%+ of rapid-fire UDP queries from a single source. This is the root cause of the YouTube thumbnail issue — thumbnail DNS queries (`i.ytimg.com`, `yt3.ggpht.com`) get lost in the initial burst.

## Test 2: Sustained (queries sent at fixed intervals)

| Interval | Queries | Success | Avg Latency |
|----------|---------|---------|-------------|
| 5ms      | 30      | 80%     | 106ms       |
| 10ms     | 30      | 100%    | 178ms       |
| 10ms     | 50      | 100%    | 299ms       |
| 20ms     | 30      | 100%    | 355ms       |
| 30ms     | 30      | 100%    | 512ms       |
| 50ms     | 30      | 100%    | 816ms       |

**Conclusion:** 10ms spacing achieves 100% success rate. This is the sweet spot — fast enough for users (30 queries take 300ms total), reliable enough for Google DNS.

## Test 3: Retry (same txnID re-sent after 2s intervals)

| Queries | Retries | Success | Avg Latency |
|---------|---------|---------|-------------|
| 30      | 3       | 100%    | ~6000ms     |
| 50      | 3       | 100%    | ~6013ms     |

**Conclusion:** Retrying with the same txnID always works eventually. The iOS retry mechanism (every ~2s) is correct. Latency is high (6s) because the first responses arrive only after the 3rd retry.

## Root Cause Analysis

The on-device VPN's `flushQueuedSends()` fires all queued queries simultaneously via `writeMultipleDatagrams`. During tunnel startup, 20-40 queries queue up and flush in <2ms. Google DNS (8.8.8.8) rate-limits rapid UDP from a single source, dropping 70% of the burst.

The surviving 30% resolve fine. The dropped 70% are retried by iOS every 2 seconds (our retry mechanism correctly replaces stale entries). Most eventually resolve, but with 6+ second latency — by which time the requesting app (Safari, YouTube) has already timed out.

## Recommended Fix

**Stagger `flushQueuedSends` at 10ms intervals** instead of sending all at once.

Current: `writeMultipleDatagrams([all 30 payloads])` → 70% dropped
Fixed: send one query every 10ms → 100% success, 300ms total flush time

The 300ms delay is imperceptible to users (DNS round-trip is ~20ms per query, well under the iOS resolver's 5s timeout).

## How to Run

```bash
cd frontend
./tests/run-lab.sh                    # defaults: burst=30, sustained=100
./tests/run-lab.sh 50 200 1.1.1.1    # custom: burst=50, sustained=200, Cloudflare DNS
swift tests/dns-stress/main.swift --burst 100 --interval 10 --timeout 15
```
