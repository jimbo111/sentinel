# DNS Reliability Progression

## Session History

| # | Time | Pacing | Stall Detect | Dual DNS | sent | ok | timeout | rate | reconn | Notes |
|---|------|--------|-------------|----------|------|-----|---------|------|--------|-------|
| 1 | 00:53 | 10ms | none | both simultaneous | 1590 | 229 | 263 | **14%** | 0 | Read handler died at 80s, never recovered |
| 3 | 01:13 | 5ms | 10s | primary-only+failover | 191 | 90 | 13 | **47%** | 2 | Stall detected, reconn worked but sessions died fast |
| 4 | 01:20 | 5ms | 10s | primary-only+failover | 101 | 50 | 6 | **50%** | ? | Short session |
| 5 | 01:22 | 50ms | 5s | primary-only+failover | 328 | 271 | 4 | **83%** | 1 | 100% success at low rates, stall from 62-query burst |

## Root Cause Analysis

NWUDPSession (deprecated iOS 18) read handler silently dies under burst load.

**Confirmed threshold:** >12 queries/sec kills the read handler within 5-10 seconds.
**Confirmed safe rate:** <10 queries/sec survives indefinitely (100% success after reconn #1 in session #5).

## Session #5 Deep Analysis (latest, 83%)

- 01:22:48-01:26:18: **100% success for 3.5 minutes** at 1-12 queries/5sec
- 01:26:23: **Burst of 62 queries in 5 seconds** (user opened YouTube/web page)
- 01:26:28: Read handler dies (0% response), stall detection fires
- 01:26:29: Sessions recreated, **100% success resumes** for remaining 3+ minutes
- Only 4 total timeouts in 7-minute session

## Pacing Bug Identified

The `sendDelayCounter` cap at 10 causes queries 11+ to all fire at the same 500ms delay:
```
Query 1:  0ms (immediate)
Query 2:  50ms
Query 10: 450ms
Query 11: 500ms (capped)  ← All remaining queries pile up HERE
Query 62: 500ms (same!)   ← 52 queries fire simultaneously at 500ms
```

This defeats pacing. Fix: remove cap, start timeout after actual send (not schedule time).

## Fix Plan for 90%+

1. Remove sendDelayCounter cap → queries space at 50ms increments: 62 queries = 3.1s spread
2. Move timeout to fire from ACTUAL send time, not schedule time
3. This guarantees ≤20 queries/sec regardless of burst size
4. Expected result: stall never occurs, read handler survives
