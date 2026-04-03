# Sentinel MVP — Feature Specification

## Core Value Proposition

Sentinel is a free, on-device iOS security app that detects and blocks phishing domains and malware in real-time — no tracking, no ads, all processing happens locally on your phone.

---

## MVP Feature Set

### P0 — Must Ship

| Feature | Description | Location | Rationale |
|---------|-------------|----------|-----------|
| **Threat Feed Integration** | Bundle HaGeZi Light + Block List Project malware/phishing blocklists (~50K domains) locally on-device | Rust engine + SQLite | Core security value; no backend dependency; low latency |
| **Threat Matching** | Fast domain matching against threat feed using HashSet during DNS query interception | Rust packet engine | Real-time blocking; inherited from Ring DNS pipeline |
| **Real-Time Security Alert** | Modal alert when a query matches known threat — shows domain, threat category (phishing/malware), and Allow/Block action | Swift UI | Gives users immediate feedback; builds trust |
| **Home Dashboard** | Show: (1) Threats Blocked (counter), (2) Last 10 blocked domains, (3) Status (VPN on/off) | Swift UI | Demonstrates tangible security benefit; no setup friction |
| **Threat Feed Auto-Update** | Fetch updated blocklists weekly via backend; store as SQLite blob; fallback to bundled feed if offline | Rust + Backend `/api/sentinel/feeds` | Maintains freshness; zero UX burden on user |
| **Device Analytics** | Track: `threats_blocked`, `threats_by_category`, `top_blocked_domains` — sent anonymously every 24h | Rust + Backend `/api/sentinel/analytics` | Measure product effectiveness; validate threat detection working |
| **Onboarding Flow** | 1-screen intro: "Blocks malware & phishing domains" + "On-device, no tracking" + Enable VPN → Home | Swift UI | Fast path to value; no config needed |

### P1 — Next Sprint

| Feature | Description | Location | Rationale |
|---------|-------------|----------|-----------|
| **URLhaus Active Malware Feed** | Integrate dedicated abuse.ch active malware distribution feed (updated 2x daily) | Rust + Backend | Complements phishing; real-time threat freshness |
| **DGA Heuristic Detection** | Detect algorithmically-generated domains using Shannon entropy + consonant runs + n-gram Markov chains (Rust ~20 lines) | Rust engine | Catches zero-day botnets; no feed latency |
| **Risk Score Dashboard** | Aggregate: threats blocked today/week, categories hit, risky app behavior flags → simple 1-5 score | Swift UI | Helps users understand personal risk posture |
| **Domain Reputation Lookup** | On-demand WHOIS/age/registrar metadata for visited domains (backend enrichment) | Backend `/api/sentinel/domain-rep` | Helps power users investigate borderline domains |

---

## Threat Feed Strategy

### Bundled (Shipped in App)

- **HaGeZi Light** (~15K domains): phishing, malware, PUA  
- **Block List Project Malware** (~8K): C2, botnets, ransomware  
- **Block List Project Phishing** (~12K): phishing URLs  
- **Combined:** ~35K high-confidence domains; ~2–3 MB SQLite database  
- **Format:** Plaintext list → Rust build script converts to SQLite during CI

### Backend-Synced (Weekly)

- **Endpoint:** `GET /api/sentinel/feeds?device_id=...&feed_id=phishing&version=2`  
- **Payload:** Gzipped SQLite blob (deltas preferred; full sync fallback)  
- **Fallback:** If offline >7 days, app uses bundled feed; still blocks domains  
- **Updates:** Trigger weekly on Monday 2am UTC; store version locally to skip redundant downloads  

### Not Included (Defer to P2+)

- OpenPhish feed (requires verification of commercial use ToS)  
- Energized Protection (redundant with HaGeZi + Block List Project)  
- DGA LSTM/CoreML models (overkill for MVP; heuristics sufficient)  

---

## Out of Scope for MVP

- **Parental controls** — defer category-based filtering to Shield  
- **Ad/tracker blocking** — defer to Shield  
- **VPN protocol upgrades** — use inherited Ring DNS interception as-is  
- **Mac/iPad support** — iOS only for MVP  
- **Allowlist/custom rules** — users can toggle VPN off per-domain  
- **Remote threat feed management** — no console or account required  
- **Threat intelligence dashboard** — reserved for P1+; MVP focuses on blocking + counter  
- **Integration with security alerts (Apple, MDM)** — future enhancement  

---

## Key User Flows

### 1. Onboarding (30 seconds)

```
Launch App
  ↓
1-screen explainer: "Blocks phishing & malware domains" + "Your data stays on your phone"
  ↓
Tap "Enable Protection"
  ↓
System dialog: "Allow 'Sentinel' to set up a VPN profile?"
  ↓
User grants permission
  ↓
Home dashboard: "Protection Active — 0 threats blocked"
```

**Success metric:** Onboarding completion >75%; VPN enabled within 1st session

---

### 2. Threat Detection & Alert (real-time)

```
User opens malicious link (e.g., phishing.evil.com)
  ↓
DNS query intercepted by Rust packet engine
  ↓
Domain matched against threat feed → HIT (phishing category)
  ↓
Rust notifies Swift via FFI
  ↓
Modal alert appears: "Threat Detected: phishing.evil.com (Phishing)"
  Options: [Block] [Allow Once]
  ↓
User taps "Block"
  ↓
Resolution fails (SERVFAIL); app returns to previous screen
  ↓
Counter increments: "1 threat blocked"
```

**Success metric:** Alert appears <500ms after user action; no VPN stalls

---

### 3. Dashboard Review (daily habit)

```
User opens Home tab
  ↓
Sees card: "Threats Blocked: 7 today" (big number)
  ↓
Below: "Top threats: phishing (4), malware (2), suspicious (1)"
  ↓
Scrolls: Last 10 blocked domains with timestamp + category
  ↓
User sees "example-phish.ru — Phishing (2:47pm)"
  ↓
User taps to see more context (domain reputation lookup → P1)
  ↓
User feels informed; enables VPN again for tomorrow
```

**Success metric:** Daily active users >60%; avg session >45 seconds

---

## Success Metrics (30 days post-launch)

| Metric | Target | How Measured |
|--------|--------|--------------|
| Install → VPN enabled | >75% | Analytics event: `onboarding_complete` |
| VPN stay-enabled | >60% daily active | Timestamp `vpn_state=active` in daily telemetry |
| Threats blocked (avg user) | >5/day | `threats_blocked` counter in analytics |
| User satisfaction (crash-free rate) | >98% | iOS App Store crash metrics |
| Avg session length | >2 min | Timestamp from launch to exit |

---

## Database Schema (Backend Additions)

**Namespace: `sentinel_*` prefix** (see Ring backend CLAUDE.md for isolation rules)

```sql
-- Threat feeds metadata
sentinel_feeds (
  id UUID,
  device_id UUID,
  feed_id TEXT,              -- 'phishing', 'malware', 'dga'
  version INT,                -- incremented on each update
  downloaded_at TIMESTAMP,
  size_bytes INT,
  checksum TEXT               -- for delta verification
)

-- Anonymous threat analytics
sentinel_analytics (
  id UUID,
  device_id UUID,
  threats_blocked INT,
  threats_by_category JSONB,  -- { "phishing": 4, "malware": 1 }
  top_domains JSONB,          -- [ { "domain": "evil.ru", "count": 2 }, ... ]
  report_date DATE,
  created_at TIMESTAMP
)
```

---

## Build & Deployment Checklist

- [ ] Rename Xcode project from `ring` to `sentinel`  
- [ ] Bundle HaGeZi + Block List Project feeds in app (Rust build step)  
- [ ] Implement threat matching in Rust packet engine  
- [ ] Swift UI: alert modal + home dashboard  
- [ ] Backend: `/api/sentinel/feeds` and `/api/sentinel/analytics` endpoints  
- [ ] Test on physical device (>12 queries/sec stress test)  
- [ ] Create TestFlight invite link  
- [ ] Write privacy policy (on-device processing emphasized)  
- [ ] App Store submission (Developer account setup)  

---

## Related Docs

- **[security-resources.md](security-resources.md)** — blocklist URLs, Rust crate options, threat detection papers  
- **[../CLAUDE.md](../CLAUDE.md)** — build commands, pitfalls, shared backend decoupling  
- **[../../Ring/frontend/docs/vpn-engineering-guide.md](../../Ring/frontend/docs/vpn-engineering-guide.md)** — DNS interception deep-dive  
