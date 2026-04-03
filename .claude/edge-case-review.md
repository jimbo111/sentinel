# Edge Case Fix Review — Final State (verified 2026-03-22)

## What was kept, reverted, or evolved

### KEPT (verified in code)
- #1 SERVFAIL on timeout — essential UX improvement
- #5 KVO double-remove guards — prevents crash
- #11 consent flag reset — privacy correctness
- #13 Keychain device ID — persistence across reinstalls
- #14 memory pressure monitor — correct for NE environment
- #19 MULTI_PART_TLDS — correct, low cost
- #20 &mut self — API consistency
- #21 retention_days validation — defensive, low cost
- #22 telemetry dedup — prevents inflated backend counts
- #24 LIKE escape — correct, low cost
- #25 static formatter — marginal but harmless

### REVERTED (confirmed removed from code)
- #8 pending_bytes flush threshold — removed, 500ms timer is sufficient
- #10 flush data re-queue — removed, risks infinite retry loops

### EVOLVED (changed from original fix)
- #6 txnID collision — Originally: SERVFAIL on retry (HARMFUL). Now: srcPort comparison distinguishes retry (same port, no SERVFAIL) from collision (different port, SERVFAIL). Correct.
- #15 sendDelayCounter — Originally: capped at 10. Now: UNCAPPED. The cap caused queries to pile up at 500ms, defeating pacing. Uncapped = each query gets its own 50ms slot.
- #16 queuedSends cap — Kept, sends SERVFAIL on overflow.
- #17 query drop — Audit claimed SERVFAIL on drop, but code only logs dns_DROP and returns. No SERVFAIL sent because query isn't registered yet. Low priority edge case (128 concurrent queries).

## Lesson learned

The SERVFAIL-on-retry mistake (#6 original) taught an important lesson: iOS DNS retries reuse the same txnID deliberately. Sending SERVFAIL for a "replaced" query is harmful because the original requester receives a SERVFAIL for a query it's still waiting on via retry. The fix: compare srcPort to distinguish retry (same app retrying) from collision (different app, same txnID).
