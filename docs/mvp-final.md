# Sentinel MVP — Final Specification

**Version:** 1.0 Final  
**Date:** 2026-03-30  
**Status:** Approved for Build  
**Supersedes:** `mvp-features.md` (original) — all prior drafts are void

---

## Decision Record

This document incorporates the challenge review (`mvp-challenge.md`) in full. Every structural risk raised has been accepted or explicitly rejected with a stated reason. This is the spec that gets built.

---

## 1. Core Positioning

Sentinel blocks known malware and phishing infrastructure at the DNS layer — silently, on-device, with no account or tracking. Its specific value is protection inside in-app browsers (WKWebView in Instagram, WhatsApp, Telegram, and third-party apps) where Safari's built-in Safe Browsing does not operate.

It does not replace Safari's Safe Browsing. It extends coverage to the browsing surfaces Safari does not touch.

---

## 2. Honest Detection Coverage Statement

This section is non-negotiable. It must be reflected accurately in App Store copy, onboarding text, and any marketing material.

### What Sentinel Catches

- Known malware C2 domains and botnet infrastructure (high-confidence; these domains are long-lived and well-documented in threat feeds)
- Known phishing domains that have been live long enough to appear in community threat feeds (typically 2-7 days old by the time they are blocked)
- DGA-generated domains flagged by entropy heuristics (zero-day botnet detection, not phishing)
- Known bad domains resolved inside WKWebView in-app browsers — the one gap Safari Safe Browsing does not cover

### What Sentinel Does Not Catch

- Zero-day phishing campaigns (average phishing domain lives under 54 hours; weekly-synced feeds have a structural lag of up to 7 days)
- Phishing pages hosted on legitimate CDN domains: Cloudflare Pages, GitHub Pages, Google Sites, Vercel, Notion, Carrd — the domain is trusted; only the path is malicious; DNS-level blocking cannot distinguish
- Subdomain rotation attacks (attacker registers a new subdomain before the original is flagged)
- URL-path attacks (legitimate domain, malicious path — invisible to DNS)
- SMS/iMessage phishing (smishing) — DNS interception never sees message content; the tap goes through Safari, not Sentinel
- Any connection that bypasses the VPN tunnel: iCloud Private Relay (routes DNS through Apple's resolvers, bypassing the local VPN entirely), pre-established app connections at VPN activation time, and Apple's own apps (App Store, Maps, Health, Wallet)

### Quantitative Estimate

For novel phishing campaigns: detection rate is likely 15-30%. For persistent malware C2 infrastructure: detection rate is meaningfully higher, as these domains are stable and well-catalogued. Sentinel is better positioned as a malware C2 and known-bad-domain blocker than as a real-time phishing shield. The positioning and copy must reflect this.

### iCloud Private Relay — Required Disclosure

Users with iCloud+ and Private Relay enabled have zero DNS visibility through Sentinel. This affects an estimated majority of active US iPhone users. The app must detect this state and display a clear, non-alarming notice: "iCloud Private Relay is active. Sentinel cannot inspect DNS queries while Private Relay is enabled. Disable it in Settings > Apple ID > iCloud to enable full protection." This is a required onboarding and settings screen disclosure, not optional UX polish.

---

## 3. Shield vs. Sentinel — Consolidation Decision

### Finding

The challenge review is correct. The architecture is byte-for-byte identical:

- Shield: Rust DNS engine + HashSet(EasyList/EasyPrivacy) + "trackers blocked" counter
- Sentinel: Rust DNS engine + HashSet(HaGeZi/Block List Project security feeds) + "threats blocked" counter

The only technical difference is which SQLite blob is loaded. iOS allows only one active VPN profile per device. Shield and Sentinel are mutually exclusive on a single device.

### Decision: Keep Sentinel Separate — Conditional

Sentinel exists as a separate App Store product for one reason only: search intent segmentation. "Phishing protection iOS" and "ad blocker iOS" are different search queries with different user mindsets and different conversion psychology. A user downloading Sentinel self-selects into a security-conscious framing that justifies different onboarding copy, different dashboard language, and potentially a different monetization path (see Section 7).

This justification holds only if:

1. Sentinel ships with a distinct monetization path before or at launch (not deferred indefinitely)
2. The feed strategy is meaningfully differentiated — security-grade feeds only, no ad/tracker noise that would cause the counter to overlap with Shield's counter
3. The app copy never claims capabilities that Shield also provides in identical fashion

If these three conditions are not met within two sprints of launch, the correct decision is to merge Sentinel into Shield as a "Security Mode" toggle. That merge path must be kept technically available — do not build UI or data structures that make consolidation impossible.

### What Sentinel Must NOT Do

- Bundle EasyList, EasyPrivacy, or any ad/tracker-focused blocklist. Those belong in Shield. Any domain on both a security feed and an ad-blocking feed that fires in Sentinel degrades the signal-to-noise ratio and causes dashboard counter overlap.
- Show a counter that is indistinguishable from Shield's tracker counter. The user who runs both should see clearly different numbers tracking clearly different threat categories.

---

## 4. MVP Feature Set (Revised)

### P0 — Must Ship Before Launch

| Feature | Description | What Changed from Original |
|---------|-------------|---------------------------|
| **Security Feed Integration** | Bundle HaGeZi Light (phishing/malware only, stripped of PUA/adware categories) + Block List Project Malware + Block List Project Phishing. Target: ~30K high-confidence domains. Strip PUA category entries — these generate noise, not signal. | PUA category removed. Feed is narrower and higher-confidence. |
| **URLhaus Active Malware Feed** | Integrate URLhaus (abuse.ch) at P0, not P1. Backend pulls 2x daily. Reduces structural feed lag from 7 days to ~12 hours for active malware URLs. | Promoted from P1. This is the primary freshness lever available without a paid API. |
| **Threat Matching** | Rust HashSet matching during DNS query interception — inherited. Bloom filter recommended if feed grows past 100K domains. | No change. |
| **Silent Blocking + Selective Alert** | Block all feed matches silently. Fire a modal alert ONLY for high-confidence phishing and malware categories — not PUA, not adware, not suspicious. A user should see a modal alert fewer than once per week on average; daily alerts are a sign of miscategorization. | Major change. Original spec fired alerts on every match. This prevents alert fatigue and wolf-crying. |
| **Home Dashboard** | Show: Threats Blocked (all-time and today), feed freshness timestamp, VPN status, and last 5 silent blocks. No big "5 threats today" hero number — replace with "X known-bad domains blocked this month." Monthly framing is more honest for the actual catch rate. | Changed from daily to monthly framing. Daily counter removed as primary metric. |
| **Private Relay Detection** | Detect iCloud Private Relay active state. Display non-alarming disclosure in onboarding and settings. Do not block onboarding — inform and continue. | New requirement. Not in original spec. |
| **Feed Freshness Indicator** | Dashboard shows "Feed last updated: 6 hours ago" (URLhaus) and "Base feed: 3 days ago." User can see the protection is current. | New. Directly addresses the trust problem from stale feeds. |
| **Onboarding Flow** | 3 screens: (1) What it catches and what it does not — honest framing; (2) Private Relay disclosure if detected; (3) Enable VPN. No overclaiming. | Extended. Honesty in onboarding prevents App Store reviews that say "this app lied." |
| **Anonymous Analytics** | Track: `threats_blocked_by_category`, `alerts_shown`, `vpn_uptime_pct` — sent anonymously every 24h. Used to validate feed quality and alert calibration. | No change in mechanism. PUA removed from tracked categories. |

### P1 — Sprint 2

| Feature | Description | Rationale |
|---------|-------------|-----------|
| **DGA Heuristic Detection** | Shannon entropy + consonant runs + n-gram Markov chain in Rust. Catches zero-day botnet domains not in any feed. ~20 lines of Rust. | Valid original feature. Moved to P1 to reduce scope pressure on P0. |
| **Per-Domain Allowlist** | User can whitelist a domain that was incorrectly blocked. Single tap from the block log. | Required for trust. The original spec deferred this to out-of-scope. That is wrong — without an allowlist, a false positive that blocks a banking app generates a 1-star review with no recourse. This is P1, not P2. |
| **Domain Age Lookup** | Backend call on alert: domain registered within last 30 days is flagged as high-risk. Newly registered domains are a strong phishing signal even without a feed match. | Adds signal beyond static feed matching. |
| **Google Safe Browsing Lookup API** | On-demand backend call when a domain is flagged by a heuristic but not in the static feed. GSB checks URL-level (not just domain-level) against a real-time threat database. Rate-limited to triggered checks only — not all DNS queries. | Partially closes the zero-day gap for alert-worthy matches. Requires a free GSB API key. |

### Explicitly Deferred (Do Not Build)

| Feature | Reason |
|---------|--------|
| Risk Score (1-5) | Gamification of a noisy signal. Deferred until the underlying detection quality is validated. |
| "5 threats/day" success metric | Removed. See Section 5. |
| Real-time modal for every match | Replaced by silent blocking + selective high-confidence alert. |
| Full-URL path-level scanning | Not possible within DNS interception architecture. Requires a proxy or content extension — different product. |
| SMS/smishing protection | Outside the DNS tunnel. Requires different Apple entitlements and a different product architecture. |

---

## 5. Success Metrics (Revised)

The original "5 threats blocked per day" metric is removed. It measures noise, not security value.

| Metric | Target | Why This Metric |
|--------|--------|-----------------|
| Install to VPN enabled | >70% | Basic funnel health |
| VPN stay-on rate (7-day) | >50% | Measures whether users find it trustworthy enough to leave on |
| High-confidence alert rate | <2 per user per week | If higher, the alert threshold is miscalibrated — investigate feed category tagging |
| False positive reports (allowlist additions) | <0.5% of active users per week | If higher, the feed has a false positive problem requiring feed surgery |
| Feed freshness (URLhaus lag) | <14 hours from URLhaus publication to device | Validates the 2x daily sync pipeline is operational |
| Crash-free rate | >99% | Table stakes |
| Monthly threats blocked (all categories, silent + alerted) | Track distribution — do not set a target until 30 days of data | Baseline only; used to calibrate future targets |

---

## 6. Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| iCloud Private Relay bypasses VPN entirely | High | Required disclosure in onboarding; detect state at runtime; no silent failure |
| False positive blocks a banking or healthcare domain | High | Per-domain allowlist at P1 (not deferred); HaGeZi Light tier only; PUA category stripped |
| App Store rejection for VPN-based content blocking | Medium | Frame as security tool, not content blocker; do not use "ad blocking" language anywhere; review Apple's App Store guideline 5.4 before submission |
| Alert fatigue drives uninstalls | High | Silent-by-default blocking; modal alerts only on high-confidence phishing/malware; target <2 alerts/user/week |
| Feed staleness for novel phishing | High (accepted) | Honest positioning as malware C2 blocker; URLhaus at P0 for freshness; GSB API at P1 for on-demand real-time check; do not claim real-time phishing protection in copy |
| NWUDPSession dies at >12 queries/sec | Medium | Inherited mitigation (50ms pacing); stall detection with session recreation. Known ceiling — document it, do not hide it |
| Pre-VPN connections bypass tunnel | Low-Medium | Disclosed in app. Not mitigatable within current architecture without full-proxy approach |
| HashSet memory pressure at scale | Low at MVP | Bloom filter path ready per CLAUDE.md; trigger at 100K domain threshold |

---

## 7. Sustainability Plan

The original spec has no monetization path. The challenger is correct that free + scaling backend costs is a structural funding problem. This section defines the path even though it is not activated at launch.

### Free Tier (Launch)

- Bundled base feed (HaGeZi Light + Block List Project) — weekly backend sync
- URLhaus integration — 2x daily sync
- Silent blocking + selective alerts
- Full dashboard
- No account required

### Premium Tier (Target: 90 days post-launch, conditional on user traction)

Trigger: 1,000+ active devices with >50% 7-day VPN retention. If not reached by day 90, re-evaluate the entire product before investing in premium features.

| Premium Feature | Rationale |
|-----------------|-----------|
| Google Safe Browsing real-time URL lookup on flagged domains | Real infrastructure cost per query; justifies paywall |
| Domain age + WHOIS enrichment on every alert | Backend call cost; justifies paywall |
| URLhaus + additional commercial feeds (2x daily) vs. weekly-only on free | Freshness tiering is a natural freemium split |
| Family plan (up to 5 devices, shared dashboard) | Expands TAM; Ring family is already multi-device |

**Pricing target:** $1.99/month or $14.99/year. Comparable to iVerify. Below Norton. Justified by the privacy-first, no-account positioning.

### Backend Cost Control (Pre-Revenue)

- Feed sync: serve delta updates, not full SQLite blobs on every sync. A delta for URLhaus (2x daily, ~1-5 MB new entries) is orders of magnitude smaller than a full 3 MB blob. Implement delta sync before scaling past 500 devices.
- Analytics writes: batch to once per 24h per device. Already in spec.
- PostgreSQL retention: add a 90-day rolling retention policy on `sentinel_analytics` rows at schema creation. Do not let the table grow unbounded.
- Bandwidth ceiling on Render: at 10,000 users on weekly full-sync (worst case), that is 20-30 GB/week. Implement delta sync before hitting 2,000 active users.

### Fallback Decision

If premium tier does not achieve 5% conversion within 6 months of launch, evaluate merging Sentinel into Shield as a "Security Mode" toggle. The incremental maintenance cost of a separate app is not justified by a product that cannot sustain itself. This is not failure — it is a rational portfolio decision.

---

## 8. Differentiation from Competitors

| Competitor | Gap Sentinel Fills | Sentinel's Weakness vs. Them |
|------------|--------------------|------------------------------|
| Safari Safe Browsing | WKWebView in-app browsers (Instagram, WhatsApp, etc.) — Safari doesn't cover these | Safari has real-time GSB; Sentinel has weekly-synced feeds |
| Lockdown Privacy | Lockdown is open-source and trust-verified by community; Sentinel's differentiator must be user experience, not privacy claims (Lockdown already owns that) | Lockdown has stronger trust credentials via open source |
| Norton Mobile Security | Zero-account, no subscription, no telemetry | Norton has AI smishing protection, 99.9% tested block rate, brand trust |
| iVerify | Mass-market focus vs. iVerify's high-risk user niche | iVerify has device integrity and spyware detection — technically deeper |

**Sentinel's one defensible claim:** On-device DNS protection for in-app browsers, zero account, zero telemetry, free entry point. It is not the most powerful iOS security tool. It is the most frictionless one for users who want baseline protection without handing data to a security vendor.

---

## 9. Realistic Timeline

Assumes one developer working on Sentinel alongside Ring/Shield/Guardian maintenance. These are calendar weeks, not sprints.

| Week | Deliverable |
|------|-------------|
| 1 | Feed pipeline: strip PUA from HaGeZi Light; build Rust HashSet loader for security-only feeds; URLhaus backend endpoint at 2x daily pull; verify delta update path |
| 2 | Silent blocking live on device; threat category tagging validated; Private Relay detection implemented; onboarding flow with honest framing |
| 3 | Dashboard: monthly block counter, feed freshness timestamp, last 5 block log; high-confidence alert modal (phishing + malware categories only, not PUA) |
| 4 | Analytics pipeline: `threats_blocked_by_category`, `alerts_shown`, `vpn_uptime_pct`; alert rate validation on test device (target <2/week) |
| 5 | TestFlight internal testing; false positive audit against top 500 US domains; allowlist P1 implementation starts |
| 6 | External TestFlight (20-50 users); 7-day retention measurement; alert calibration tuning based on real data |
| 7 | Per-domain allowlist shipped; app copy finalized with accurate capability language; privacy policy drafted |
| 8 | App Store submission; Developer account Sentinel listing created |

**Total: 8 weeks to App Store submission.** This is aggressive for a solo developer maintaining three other apps. The more honest estimate is 10-12 weeks if Ring or Shield have parallel active development.

---

## 10. First-Week Action Items

These must be completed before any other build work begins. They are blocking decisions, not implementation tasks.

1. **Strip PUA from HaGeZi Light feed.** Pull the raw feed and audit which category tags are present. Remove any entry tagged PUA, adware, or tracker — these belong in Shield, not Sentinel. Validate the remaining domain count. If it falls below 20K, evaluate supplementing with a third security-specific feed (Abuse.ch Botnet C2 tracker is a good candidate).

2. **Build the URLhaus backend endpoint first, not last.** URLhaus is P0. The 2x daily pull pipeline must be live before the app ships. It is the primary freshness mechanism. Do not ship with weekly-only syncing and call it P1 later.

3. **Write the App Store copy before writing code.** The copy forces honest positioning. If you cannot write a truthful App Store description that makes Sentinel sound worth downloading, the positioning is wrong — fix that before building UI. Key constraint: the copy must not claim real-time phishing detection. "Blocks known malware and phishing infrastructure" is accurate. "Real-time phishing protection" is not.

4. **Implement Private Relay detection on day one.** This is not a polish item. It is a required disclosure. A user with Private Relay active who sees "Protection Active" in the app and then gets phished has a legitimate grievance. The detection code is straightforward (check `NEVPNStatus` and whether DNS queries are routing through the tunnel).

5. **Define the premium trigger before launch.** Agree on the specific metric and threshold that activates premium development: "If we reach 1,000 active devices with >50% 7-day retention by day 90, we build the premium tier." Write this down. Without a written trigger, premium stays "future work" forever and the sustainability problem is never resolved.

6. **Run a false positive audit before TestFlight.** Take the final bundled feed and test it against the Alexa/Tranco top 500 US domains. Any match is a potential critical false positive. Log the findings. Anything in the top 500 that is blocked should be manually reviewed and likely allowlisted in the bundle.

---

## 11. Out of Scope — Final

These are closed decisions. Do not revisit them for this MVP.

- Parental controls (Shield territory)
- Ad/tracker blocking (Shield territory — any overlap degrades Sentinel's signal quality)
- SMS/smishing detection (requires different Apple entitlements and a different product; not buildable on this architecture)
- Mac/iPad support
- Remote threat management console
- Full-URL path-level scanning (requires a full proxy, not a DNS tunnel)
- DGA LSTM/CoreML models (Rust heuristics are sufficient for MVP)
- Integration with Apple MDM or enterprise security tooling

---

## 12. Database Schema (Final)

**Retention policy is a first-class requirement, not an afterthought.**

```sql
-- Feed metadata
CREATE TABLE sentinel_feeds (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   UUID NOT NULL,
  feed_id     TEXT NOT NULL,        -- 'phishing', 'malware', 'urlhaus', 'dga'
  version     INT  NOT NULL,
  downloaded_at TIMESTAMP NOT NULL,
  size_bytes  INT,
  checksum    TEXT,
  delta       BOOLEAN DEFAULT false -- true if this row is a delta update
);

-- Anonymous analytics — 90-day rolling retention enforced by cron
CREATE TABLE sentinel_analytics (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id           UUID NOT NULL,
  threats_blocked     INT  NOT NULL DEFAULT 0,
  threats_by_category JSONB,        -- { "phishing": 4, "malware": 1 } — PUA excluded
  alerts_shown        INT  NOT NULL DEFAULT 0,
  vpn_uptime_pct      NUMERIC(5,2), -- 0.00-100.00
  report_date         DATE NOT NULL,
  created_at          TIMESTAMP NOT NULL DEFAULT now()
);

-- Retention: delete rows older than 90 days
-- Implement as a daily cron job or pg_cron task on the backend:
-- DELETE FROM sentinel_analytics WHERE created_at < now() - INTERVAL '90 days';
```

---

## Document Control

| Document | Status |
|----------|--------|
| `mvp-features.md` | Superseded — do not build from this |
| `mvp-challenge.md` | Accepted — findings incorporated above |
| `mvp-final.md` | **This document — authoritative** |

All build decisions, scope questions, and specification disputes resolve against this document. If this document is silent on a topic, the default answer is: defer to P1, document the gap, do not ship untested behavior.
