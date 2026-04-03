# Research: Sentinel MVP — On-Device Phishing Protection iOS App
**Date:** 2026-04-02
**Sources:** 30+ sources referenced

## TL;DR
- Sentinel has a **fully working DNS interception engine** (Rust, 86 tests) but **zero security features implemented** — no threat feeds, no matching, no alerts, no dashboard
- MVP must ship: blocklist matching (HaGeZi Pro + URLhaus), real-time block counter, threat alerts, and a security dashboard
- Use a **bloom filter in the Network Extension** (~5 MB for 400K domains) + **SQLite confirmation in main app** — HashSet won't fit in the 50 MB jetsam limit
- **NRD (Newly Registered Domain) flagging is the highest-signal heuristic** — 63% of phishing domains are <4 days old
- Hard paywall with 7-day free trial converts at 12%+ vs 2% freemium — price at $2.99/mo or $19.99/yr
- Estimated build time for MVP: **2–3 weeks** for a solo dev with the existing engine

## Current State: What's Implemented vs Missing

| Component | Status | Details |
|-----------|--------|---------|
| Rust DNS engine | **DONE** | Full DNS/TLS parsing, ECH stripping, 86 tests passing |
| SQLite storage | **DONE** | domains, visits, domain_ips, dns_query_types tables |
| Domain grouping | **DONE** | eTLD+1, CDN attribution, 100+ site mappings |
| Noise filtering | **DONE** | Apple infra, CDNs, mDNS filtered out |
| ECH downgrade | **DONE** | Strips ECH configs to reveal SNI |
| Swift monitoring UI | **DONE** | 6 tabs: Connection, Domains, Stats, Settings, Onboarding, Live Activity |
| Threat feed loading | **NOT STARTED** | No code to ingest any feed |
| Domain matching | **NOT STARTED** | No HashSet, bloom filter, or trie |
| DGA detection | **NOT STARTED** | Entropy/heuristic approach documented but not coded |
| Typosquatting detection | **NOT STARTED** | Not coded |
| Alert UI / dashboard | **NOT STARTED** | No threat views, no push notifications |
| Allowlist / custom rules | **NOT STARTED** | No user bypass functionality |
| Proto definitions | **PARTIAL** | Ring analytics only — no threat messages |

## Competitive Landscape

| App | Mechanism | On-Device? | Price | Differentiator |
|-----|-----------|-----------|-------|---------------|
| **NextDNS** | Cloud DNS resolver (DoH/DoT) | No — queries go to NextDNS servers | Free 300K queries/mo; $1.99/mo | 30+ blocklists, analytics dashboard |
| **AdGuard DNS** | Cloud resolver + on-device profile | Hybrid | $0.99/mo; Pro $2.99 one-time | Lightweight, parental controls |
| **Lockdown Privacy** | Local VPN (NEPacketTunnelProvider) | Yes | Free (open source) + paid VPN | "Openly Operated" certified, open source |
| **Guardian Firewall** | VPN + DNSFilter servers | Hybrid | Pro tier, family sharing | Acquired by DNSFilter (Aug 2022) |
| **ControlD** | Cloud DNS with 20 categories | No | $1.66–$3.33/mo | 99.98% malware block rate, NRD blocking |
| **DNSCloak** | Local VPN → DoH/DNSCrypt resolver | On-device proxy | Free | Pi-hole equivalent on iOS |

**Sentinel's structural advantage:** All cloud-resolver apps transmit every DNS query to a remote server. Sentinel's local VPN + local SQLite is privacy-superior — a genuine differentiator that Lockdown and Guardian initially positioned on.

## Detection Techniques — What Works at DNS Level

### Detection Stack (ordered by implementation priority)

```
DNS query arrives
  → 1. Blocklist lookup (bloom filter)     < 1 µs    — MVP P0
  → 2. NRD age check                       < 1 ms    — MVP P0
  → 3. IDN homograph detection             < 0.5 ms  — MVP P1
  → 4. Typosquat Levenshtein check         < 2 ms    — MVP P1
  → 5. DGA entropy heuristic               < 0.5 ms  — v1.1
  → ALLOW or BLOCK/WARN
```

All deterministic, no network call in the hot path.

### 1. Known-Bad Domain Blocklists (P0 — must ship)
- Highest precision, lowest implementation cost
- Recall bounded by feed freshness (median phishing domain lifetime < 24 hours)
- Implementation: bloom filter in Rust, SQLite confirmation for audit

### 2. Newly Registered Domain (NRD) Flagging (P0 — must ship)
- **63% of phishing domains are <4 days old** (Palo Alto Unit42)
- **>70% of NRDs are malicious, suspicious, or NSFW**
- Soft-block with interstitial warning, not hard block (reduces false positives)
- Data: WhoisXML API community feed (week-delayed, free), rolling 32-day list

### 3. IDN Homograph Detection (P1 — ship in v1.1)
- Detect punycode domains (`xn--` prefix) impersonating brands
- Unicode confusables table from Unicode Consortium — deterministic, zero latency
- No ML needed — simple confusable character mapping + brand keyword comparison

### 4. Typosquatting Detection (P1 — ship in v1.1)
- Damerau-Levenshtein distance ≤ 1 against top 500 brand domains
- Apply to SLD only (not full FQDN)
- Pre-filter with bloom filter to avoid running Levenshtein on every query
- Reference list: Tranco top 1M (research-grade, updated weekly)

### 5. DGA Detection (v1.1)
- Three-signal heuristic (no ML):
  - Shannon entropy > 3.8 on SLD
  - Consonant run > 6 consecutive
  - SLD length > 12 characters
- Example: `login.microsoftonline.com` entropy = 3.47 (benign), `eywonbdkjgmvsstgkblztpkfxhi.ru` = 4.48 (DGA)
- Limitation: dictionary-concatenation DGAs (`quickbrownfox-bank-login.com`) defeat entropy detection

## Threat Intelligence Feeds

| Feed | Domains | Update Freq | Format | License | API Key |
|------|---------|-------------|--------|---------|---------|
| **HaGeZi Pro** | ~402K | Daily | Hosts, domains, AdGuard, RPZ | MIT | No |
| **HaGeZi Pro mini** | ~76K | Daily | Compressed domains | MIT | No |
| **URLhaus** | ~20–40K active | 5 min (IDS), daily (hosts) | CSV, JSON, hosts | CC0 | No |
| **Phishing Army** | Aggregated | Every 6 hours | Hosts, domain list | CC BY-NC-SA | No |
| **PhishTank** | Not disclosed | Real-time API | JSON, CSV | Free non-commercial | Yes |
| **OpenPhish** | Not disclosed | Every 12 hours | Plain text URLs | Restrictive | No |
| **Google Safe Browsing v4** | Billions | Real-time | Binary hash lists | Free non-commercial | Yes |

**MVP recommendation:** Start with **HaGeZi Pro** (402K domains, MIT, no API key) + **URLhaus hosts** (CC0, free). Both CDN-hosted, no auth needed.

## Architecture: Memory-Constrained Design

### The Critical Constraint
iOS Network Extension jetsam limit: **50 MB** (iOS 15+), some devices still enforce **15 MB**.

| Data Structure | 400K domains | Memory | Viable in Extension? |
|----------------|-------------|--------|---------------------|
| `HashSet<String>` | 400K | ~120–150 MB | **NO** — killed by jetsam |
| Bloom filter (0.1% FP) | 400K | ~5–6 MB | **YES** |
| Bloom filter (1% FP) | 400K | ~1.7 MB | YES (higher FP noise) |
| Xor filter | 400K | ~3–4 MB | YES (immutable after build) |
| SQLite (Pi-hole style) | 400K | ~80–140 MB RAM | **NO** for hot path |

### Recommended Two-Tier Architecture

```
┌─────────────────────────────────┐
│   Network Extension Process     │
│   (50 MB jetsam limit)          │
│                                 │
│   Rust Engine (~3 MB)           │
│   + Bloom Filter (~5 MB)        │
│   = ~8–10 MB total              │
│                                 │
│   On bloom hit → record to      │
│   shared SQLite + Darwin notify │
└──────────────┬──────────────────┘
               │ Darwin Notification
┌──────────────▼──────────────────┐
│   Main App Process              │
│   (no memory limit)             │
│                                 │
│   Full SQLite blocklist         │
│   Authoritative block/allow     │
│   Push notification to user     │
│   Threat dashboard UI           │
└─────────────────────────────────┘
```

**Rust crates for bloom filters:**
- `fastbloom` — fastest Rust bloom filter (benchmarked)
- `xorf` — xor filters, smaller than bloom, immutable after build

**Critical SQLite gotcha:** Storing blocklist SQLite in App Group container triggers `0xDEAD10CC` crash if main app holds write lock when suspended. Mitigate: write to temp file, atomic rename. Extension opens read-only.

## Trade-offs & Risks

### False Positives
- DNS blockers break legitimate apps, banking sites, healthcare portals when feeds contain false entries
- Pi-hole and AdGuard communities report constant false positive complaints
- **Mitigation:** Use curated feeds (HaGeZi is manually reviewed), offer easy per-domain allowlist, soft-block NRDs with interstitial instead of hard block

### Feed Staleness
- Median phishing domain lifetime: <24 hours
- Free feeds update daily at best (HaGeZi), every 6 hours (Phishing Army)
- **Honest coverage:** Catches known malware C2 + phishing in feeds (2–7 days old), misses zero-day (<54 hours old)
- Detection rate: **15–30% for novel phishing**, higher for stable malware C2

### iCloud Private Relay Bypass
- Domains that go through Apple's Private Relay are invisible to the local VPN tunnel
- Must disclose this limitation in the app — don't claim total protection

### Battery & Performance
- Always-on VPN adds battery drain
- DNS resolution latency from interception: negligible if bloom filter lookup is sub-microsecond
- Feed refresh should use `BGProcessingTask`, not foreground network calls

### App Store Review Risks
- VPN apps require **Organization** developer enrollment (not Individual)
- Must declare privacy nutrition labels accurately
- Guideline 2.5.1 risk: apps using VPN for non-VPN purposes face ambiguous rejection
- Privacy manifests mandatory since May 2024

### User Trust & Liability
- Users who think they're protected but aren't = liability risk
- Must be transparent: "Sentinel blocks known threats from curated feeds. It cannot detect zero-day phishing."

## What Makes Users Pay

- **56% of US consumers** say "total protection" is critical to download decision (Appdome 2024)
- **87%** want brands to proactively prevent fraud, not reimburse post-breach
- More Americans **paid** for VPNs in 2024 than used free ones (42%/42% split)

### Conversion triggers (ranked):
1. **Proof of protection** — real-time block count ("47 threats blocked in 30 days")
2. **Phishing alert notifications** — the "it just saved you" moment
3. **Domain activity log** — privacy-conscious users pay for device surveillance
4. **Contextual threat detail** — "This domain was registered 2 days ago, impersonating PayPal"
5. **Family plan / multi-device** — proven upsell (NextDNS, Guardian)

### Pricing model:
- **Hard paywall + 7-day free trial** converts at 12%+ (vs 2% freemium)
- $2.99/month or $19.99/year
- Lifetime $39.99 as upsell anchor (matches AdGuard Pro's proven model)

## MVP Feature Set — Prioritized

### P0: Must Ship (Week 1–2)
- [ ] **Threat feed ingestion** — Download HaGeZi Pro + URLhaus on launch/daily. Parse hosts format. Build bloom filter in Rust.
- [ ] **Hot-path domain matching** — Bloom filter check in VPN tunnel. On hit → record to SQLite + Darwin notify main app.
- [ ] **Block counter** — Home screen showing "X threats blocked today/this week/all time"
- [ ] **Threat alert notifications** — LocalNotification for high-confidence blocks
- [ ] **Security dashboard** — SwiftUI view: threat log, block stats, feed freshness status
- [ ] **Per-domain allowlist** — User can whitelist false positives

### P1: Ship in v1.1 (Week 3–4)
- [ ] **NRD flagging** — Soft-block with interstitial warning for domains <4 days old
- [ ] **IDN homograph detection** — Punycode decode + confusable check vs brand list
- [ ] **Typosquatting detection** — Damerau-Levenshtein ≤ 1 vs top 500 brands
- [ ] **Threat detail screen** — "Why was this blocked?" with feed attribution, domain age, threat type
- [ ] **Feed update scheduler** — BGProcessingTask, daily refresh, checksum diff

### v2: Premium Tier
- [ ] DGA detection (entropy + consonant + length heuristic)
- [ ] `NEURLFilterManager` URL-level blocking (iOS 26+ — WWDC 2025 API)
- [ ] Weekly threat digest ("3 apps contacted unusual domains this week")
- [ ] Google Safe Browsing v4 integration
- [ ] Family plan / multi-device
- [ ] Domain reputation lookup API
- [ ] Threat feed auto-update via backend push

## Timeline Estimate (Solo Dev)

| Phase | Work | Days |
|-------|------|------|
| Feed ingestion pipeline | Download, parse hosts, build bloom filter in Rust | 2–3 |
| Hot-path matching | Bloom filter check in engine, block decision, SQLite record | 1–2 |
| Alert system | LocalNotification, persist alerts to SQLite | 1–2 |
| Security dashboard (SwiftUI) | Threat log, block counter, feed status, allowlist | 3–5 |
| Feed update scheduler | BGProcessingTask, daily refresh, diff reload | 1 |
| **Total MVP** | | **~10–16 days (2–3 weeks)** |

## iOS 26 Opportunity: NEURLFilterManager

Apple announced `NEURLFilterManager` at WWDC 2025 (session 234):
- Full-URL-based filtering (not just DNS/hostname)
- On-device bloom filter prefilter + Private Information Retrieval for backend lookups
- Oblivious HTTP Relay hides client IP from your server
- **Not in the network path** — no memory pressure from traffic volume

This is complementary to Sentinel's DNS-layer approach. Worth prototyping for v2 to catch phishing pages that resolve on legitimate DNS but serve malicious content at the URL path level.

## Recommendation

**Ship P0 features in 2–3 weeks.** The existing Ring engine is production-ready. The gap is entirely in threat intelligence + UI — not infrastructure.

**Start with HaGeZi Pro + URLhaus** — both MIT/CC0, no API keys, CDN-hosted. This gives ~420K blocked domains on day one.

**Use bloom filter in extension, SQLite in main app.** This is the only architecture that fits the iOS memory constraints while maintaining sub-microsecond lookup speed.

**Be honest about coverage.** Don't claim "total protection." Sentinel blocks known threats from curated feeds. It cannot detect zero-day phishing. Transparency builds trust and avoids liability.

**Price with a hard paywall + 7-day trial.** The data shows this converts 6x better than freemium for utility/security apps.

## Sources
1. [NextDNS Pricing](https://nextdns.io/pricing)
2. [AdGuard DNS Launch Nov 2025](https://betanews.com/2025/11/20/adguard-launched-adguard-dns-a-lightweight-dns-app-for-android-and-ios/)
3. [Lockdown Privacy](https://lockdownprivacy.com)
4. [DNSFilter acquires Guardian (TechCrunch)](https://techcrunch.com/2022/08/10/dnsfilter-guardian-ios-firewall/)
5. [ControlD Pricing](https://www.saasworthy.com/product/control-d/pricing)
6. [PhishHunter: IDN Siamese NN (ScienceDirect 2023)](https://www.sciencedirect.com/science/article/abs/pii/S0167404823005783)
7. [BadDomains: NRD Detection (PMC 2025)](https://pmc.ncbi.nlm.nih.gov/articles/PMC12900114/)
8. [Palo Alto Unit42: NRD Research](https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/)
9. [LLMs for DGA Detection (arXiv Nov 2024)](https://arxiv.org/html/2411.03307v1)
10. [FIRST.org DGA Detection Guide](https://www.first.org/global/sigs/dns/stakeholder-advice/detection/dga)
11. [Splunk: Levenshtein + Shannon Detection](https://www.splunk.com/en_us/blog/security/domain-detection-levenshtein-shannon.html)
12. [HaGeZi DNS Blocklists (GitHub)](https://github.com/hagezi/dns-blocklists)
13. [Phishing Army](https://phishing.army/)
14. [URLhaus API (abuse.ch)](https://urlhaus.abuse.ch/api/)
15. [Google Safe Browsing v4](https://developers.google.com/safe-browsing/v4/usage-limits)
16. [Quad9 Partners](https://quad9.net/about/partners/)
17. [Appdome 2024 US Mobile Security Survey](https://www.appdome.com/press-release/us-consumer-security-survey-reveals-highest-demand-for-mobile-app-security-in-4-years/)
18. [NordVPN Usage Survey 2025](https://nordvpn.com/blog/vpn-usage-survey-2025/)
19. [Business of Apps: Conversion Rates](https://www.businessofapps.com/data/app-conversion-rates/)
20. [NEPacketTunnelProvider Memory (Apple Forums)](https://developer.apple.com/forums/thread/106377)
21. [WWDC 2025 Session 234: NEURLFilterManager](https://developer.apple.com/videos/play/wwdc2025/234/)
22. [IVPN: App Store VPN Rules](https://www.ivpn.net/blog/insights-apple-app-store-rules-vpn-apps/)
23. [SQLite App Group Container Risk](https://ryanashcraft.com/sqlite-databases-in-app-group-containers/)
24. [Pi-hole Gravity System](https://deepwiki.com/pi-hole/pi-hole/2.1-gravity-system)
25. [AdGuard urlfilter (GitHub)](https://github.com/AdguardTeam/urlfilter)
26. [AdGuard Home RAM Issue #5606](https://github.com/AdguardTeam/AdGuardHome/issues/5606)
27. [AdGuard DNS Blocking at Scale](https://adguard-dns.io/en/blog/dns-content-blocking-at-scale.html)
28. [arXiv: Gravity Falls DGA Analysis](https://arxiv.org/abs/2603.03270)
29. [fastbloom Rust crate](https://github.com/tomtomwombat/fastbloom)
30. [xorf Rust crate](https://github.com/ayazhafiz/xorf)
31. [Tranco Top 1M](https://tranco-list.eu/)
