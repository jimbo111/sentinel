# MVP Challenge: Sentinel

**Date:** 2026-03-30  
**Reviewer:** Counter-Research / Devil's Advocate  
**Purpose:** Identify structural risks before committing build time. Goal is a stronger MVP, not a killed one.

---

## Trade-offs Summary

| What you gain | What you lose |
|---|---|
| Zero cost to user, low friction onboarding | No monetization path — every user is a cost center |
| On-device, privacy-first positioning | iOS constrains what "on-device" can actually intercept |
| Real threat feed (HaGeZi + Block List Project) | Feeds are weekly-stale; most phishing domains live < 24 hours |
| Inherited Rust engine — fast time to ship | Differentiation from Shield is almost entirely skin-deep at MVP |
| "Threats blocked" counter builds engagement | Counter may be counting ad trackers and CDN noise, not real phishing |
| Shared backend keeps infra simple | Backend is a single point of failure for 4 apps with no revenue model |

---

## 1. Market Reality

### iOS Already Has Layered Phishing Protection

Safari's Fraudulent Website Warning checks every URL against Google Safe Browsing (via hashed prefix) and Tencent Safe Browsing before the page loads. iOS 26 added on-device ML that analyzes page content, domain behavior, and redirect chains in real time. This runs for every user, with zero install friction, on every browser tab.

**The gap Sentinel targets:** in-app browsing (WKWebView inside Instagram, WhatsApp, etc.) and non-Safari browsers. This is a real gap. But it is a narrower gap than the marketing copy implies, and it has been narrowing with every iOS release.

### Competitor Landscape

| App | Model | Actual iOS capability | Differentiator |
|---|---|---|---|
| **Safari built-in** | Free, zero-install | URL-level Google Safe Browsing + iOS 26 on-device ML | Already on every device |
| **Lockdown Privacy** | Free + Pro | On-device DNS firewall, open-source | Trust via open source; no backend |
| **Norton Mobile Security** | $14.99/yr | Web protection + scam SMS/call filtering | Brand trust, 99.9% web threat block rate in tests |
| **Malwarebytes iOS** | Free (limited) | Cannot scan for malware due to iOS sandbox; web protection only | Brand; desktop product ecosystem |
| **iVerify** | $1.99/mo | Device integrity checks, spyware detection, MDM threat analysis | Targets high-risk users (journalists, executives); not mass market |
| **Lookout** | Free + paid | Phishing + identity monitoring | 22.4% mindshare in Mobile Threat Defense category |

**Key finding:** Every major competitor has a paid tier that funds threat feed quality, research, and response time. Sentinel competing free against $15/yr Norton with no revenue model is not a positioning advantage — it is an unsustainable cost structure.

**Specific capability Sentinel lacks vs. Norton:** SMS/iMessage phishing (smishing). DNS interception cannot see the content of a text message. A user receiving a smishing link and tapping it in Messages will go through Safari — which has its own Safe Browsing — and Sentinel's DNS layer will only help if that exact domain is already on the feed. Norton's AI Scam Protection reads the text before the tap.

### What Sentinel Can Claim That Competitors Cannot

One defensible statement: truly zero-telemetry, on-device, no account, no subscription. Lockdown Privacy also claims this and is open-source. Sentinel needs a clearer reason why it exists alongside Lockdown.

**Actionable:** Define the one user persona that Safari + Lookout's free tier doesn't serve. The current spec tries to serve everyone and therefore has no clear message.

---

## 2. Technical Risks

### DNS-Only Detection Misses the Modern Phishing Playbook

The spec blocks at the domain level. The modern phishing playbook exploits this in at least four documented ways:

**a) Legitimate domain hosting.** Research shows a significant portion of phishing pages are hosted on free web-building services (Google Sites, Carrd, Notion, GitHub Pages, Cloudflare Pages, Vercel). These inherit the host's SSL certificate and domain. The phishing URL is `https://sites.google.com/view/chase-login-verify` — the domain is `sites.google.com`. Blocking that domain would break Google Docs, Slides, and Forms for the user. Sentinel cannot block this class of attack without an unacceptable false positive rate.

**b) Shared CDN domains.** 68% of phishing websites use Cloudflare's CDN. The domain `cdnjs.cloudflare.com` or `pages.dev` hosts both attack pages and legitimate content. DNS-level blocking is binary per domain.

**c) Subdomain phishing.** Attackers register `secure-login.badactor.com` and within hours rotate to `account-verify.badactor.com`. The blocklist catches the first subdomain days after it goes live; the rotation domain is zero-day. Since 50% of phishing sites remain undetected in the first week of existence, a weekly-synced feed has a structural detection gap for the most dangerous, freshest attacks.

**d) URL-path attacks.** A legitimate-looking domain can serve a phishing page at a specific path (`legitimate-news-site.com/sponsored/login-now`). DNS blocking sees only the domain. This entire attack class is invisible to Sentinel.

**Quantitative estimate of catch rate:** Given that the average phishing domain lifespan is under 54 hours, that 84% of phishing sites are taken down within 24 hours, and that a weekly-synced feed has a structural lag of up to 7 days, Sentinel's real-time catch rate for novel phishing campaigns is likely under 30% — possibly under 15% for targeted attacks. The feeds are better suited to catching long-lived C2 infrastructure (botnets, malware) where domain stability is higher.

**iOS DNS tunnel limitations compound this.** Apple's local VPN implementation has a documented bypass vulnerability: connections already established before VPN activation continue outside the tunnel. Apple services (App Store, Maps, Find My, Health) explicitly bypass the tunnel. iCloud Private Relay, when enabled by the user, routes DNS through Apple's own resolvers — bypassing the local VPN entirely. The spec does not address what happens to users who have Private Relay enabled.

**Actionable:** The spec should state explicitly: "Sentinel is effective against persistent malware C2 infrastructure and known phishing domains. It is not effective against zero-day phishing campaigns, subdomain rotation, or attacks hosted on shared CDNs. It is complementary to, not a replacement for, Safari's Safe Browsing."

---

## 3. Threat Feed Quality

### Volume: 35K Domains Is Not a Security-Grade Feed

| Feed | Size | Update frequency | Source |
|---|---|---|---|
| HaGeZi Light (bundled) | ~15K | Weekly | Aggregated community lists |
| Block List Project Malware | ~8K | Community-maintained | Aggregated |
| Block List Project Phishing | ~12K | Community-maintained | Aggregated |
| **Sentinel combined** | **~35K** | **Weekly** | — |
| Google Safe Browsing | Billions of URLs | Real-time | Google crawlers + reports |
| Spamhaus DBL | Millions of domains | Real-time | Professional threat intel |
| URLhaus (P1 feed) | 30K+ active malware URLs | Updated 2x/day | abuse.ch researcher network |

The bundled 35K domains represent a snapshot of known-bad domains as of the last community update. Given that 60% of new phishing domains get SSL certificates within 2 hours of registration and that attackers deploy thousands of disposable domains daily using AI generation, the static feed is always trailing the threat landscape by days.

### False Positive Risk Is Real and Documented

HaGeZi's GitHub issue tracker has open reports of false positives affecting Marriott, Whole Foods, Snapchat, and USPS domains across various list versions. Issue #4148 documented 18 false positive domains in a single HaGeZi Multi Pro++ list update. The Pro++ tier (which is more aggressive) explicitly warns it "should only be used by experienced users" with an admin available to unblock domains.

The Light tier (which is what the spec uses) is more conservative, but the risk pattern remains: any weekly-synced community list will have transient false positives. For a security app, a false positive that blocks a banking domain or a healthcare portal is not just a UX annoyance — it is a trust-destroying event that will generate App Store reviews saying "this app blocked my bank."

### Feed Freshness vs. Security Use Case

These feeds were designed for ad blocking and tracker blocking, where staleness is measured in weeks and a false positive just means an ad doesn't load. Repurposing them as a real-time security shield against phishing — where freshness needs to be measured in hours — is a category mismatch. The spec's marketing copy ("detects and blocks phishing domains in real-time") is technically misleading: the feed is weekly-synced, not real-time.

The P1 URLhaus feed (2x daily updates) is meaningfully better for freshness, but it focuses on active malware distribution URLs, not phishing pages, and still does not close the zero-day gap.

**Actionable:** Either downgrade the marketing language to "blocks known malicious domains" or upgrade the feed strategy. Specifically: integrate URLhaus at P0 (not P1), and consider Google Safe Browsing Lookup API for real-time URL checking as a P1 backend call on flagged domains.

---

## 4. User Psychology

### The "5+ Threats Blocked Per Day" Target Is a Red Flag

The spec sets a success metric of >5 threats blocked per day per user. This number needs scrutiny.

A typical iOS user making 200-400 DNS queries per day across all apps visits roughly 50-100 unique domains. For the average user to see 5 threat blocks per day, 1-2.5% of their DNS queries would need to match the threat feed. That is an implausibly high true positive rate for a general audience not visiting dark web markets.

What actually generates this count in practice: ad networks that dual-list as trackers and are on HaGeZi's blocklist, CDN subdomains that are flagged as PUA (Potentially Unwanted Applications), and low-confidence phishing feeds that include recently expired domains now reregistered for unrelated purposes.

The result: the majority of the "5 threats blocked" are likely not phishing attempts against the user. They are background noise — ad fetches, app telemetry pings, and tracker calls that happen to be on a blocklist.

This creates a direct user psychology problem with two failure modes:

**Failure mode A: Alert fatigue.** Real-time modal alerts for background ad-network DNS queries will interrupt users mid-task. Research on alert fatigue shows that users who see repeated alerts they cannot explain or act on will disable the feature or delete the app. SOC teams experience this at enterprise scale; consumer users will exit faster.

**Failure mode B: Erosion of trust.** When a user taps the blocked domain `ad.doubleclick.net` and searches for it, they learn it is a Google advertising domain, not a phishing site. The app will be perceived as exaggerating threats for engagement. This is the security-app equivalent of scareware positioning.

**The core tension:** A low block count makes the app feel useless. A high block count that is mostly noise makes the app feel dishonest. The spec has not resolved this tension.

**Actionable:** Separate the blocking layer from the alerting layer. Block silently by default; alert only on high-confidence phishing/malware category matches (not PUA or adware). The dashboard counter can show all blocks; the modal alert should fire only for the narrow set of threat categories that represent genuine user risk. This requires cleaner category tagging on the feed.

---

## 5. Sustainability

### Free + Shared Backend = Structural Funding Problem

The backend runs on Render and shares costs across Ring, Guardian, Shield, and Sentinel. Every additional app adds:

- Feed sync requests (weekly per device, O(n) with user count)
- Analytics writes (daily per device)
- PostgreSQL storage growth (sentinel_analytics rows accumulate indefinitely without a retention policy)
- Feed storage and delivery bandwidth (gzipped SQLite blob per device per week)

At 10,000 active users doing weekly feed syncs of a 2-3 MB gzipped blob, that is 20-30 GB of bandwidth per week from Sentinel alone. Render's free/starter tiers have bandwidth limits that will be hit before any meaningful scale is achieved.

There is no monetization path in the spec. The stated business model is "completely free." There is no premium tier, no B2B licensing, no data product (the spec explicitly excludes telemetry that could generate insights). The sustainability assumption appears to be that the backend cost stays negligible — which is only true until the app succeeds.

**The paradox:** if Sentinel fails to get users, it costs almost nothing and provides no value. If it succeeds at getting users, the infrastructure costs scale faster than any free app can sustain without revenue.

**Comparison point:** Lockdown Privacy, which has a similar free + privacy-first model, has survived by offering a paid VPN service alongside the free firewall. iVerify charges $1.99/month. Norton charges $14.99/year. The only free security apps at scale are loss leaders for paid products (Malwarebytes, Lookout) funded by enterprise B2B revenue.

**Actionable:** Define the monetization path before launch, even if it is not activated at launch. Options: (1) Premium tier with real-time feed (URLhaus + Google Safe Browsing API calls) vs. free tier with weekly static feed; (2) Family plan with multi-device dashboard; (3) B2B/MDM licensing of the Rust engine. Without a path, this is a charitable project with a finite runway.

---

## 6. Feature Overlap with Shield

### The Differentiation Is Paper-Thin at the Rust Layer

Reading both CLAUDE.md files side by side:

**Shield:** DNS queries → Rust engine → HashSet match against EasyList/EasyPrivacy/custom blocklists → SERVFAIL on match → dashboard shows "trackers blocked."

**Sentinel:** DNS queries → Rust engine → HashSet match against HaGeZi/Block List Project security feeds → SERVFAIL on match → dashboard shows "threats blocked."

The architecture is byte-for-byte identical. The only difference is which SQLite blob is loaded into the HashSet. Both update their feed weekly via the shared backend. Both show a "blocked today" counter. Both are forks of Ring with namespaced tables and endpoints.

From a user perspective: a person who installs both Shield and Sentinel would be running two local VPN profiles, which iOS will not allow simultaneously — only one VPN profile can be active at a time. This means Sentinel and Shield are mutually exclusive on a single device, which means users must choose, which means Sentinel needs a clear reason to be chosen over Shield or Ring or Guardian.

The spec states Shield defers "ad/tracker blocking" and "parental controls" to other apps. What is left for Sentinel is exclusively security-framed domain blocking. The question is whether "security framing" alone — same engine, different list, different counter label — justifies a separate App Store listing and maintenance burden.

**The strongest argument for keeping Sentinel separate:** App Store discoverability. A user searching "phishing protection iOS" finds Sentinel. A user searching "ad blocker iOS" finds Shield. These are different search intents and different user acquisition channels. The separation is a marketing decision more than a technical one.

**The strongest argument against:** You are now maintaining four Rust forks, four Xcode projects, four App Store listings, and four sets of backend endpoints — all sharing one unpaid backend, one developer, and one thread pool that dies at >12 queries/sec. The marginal cost of each additional app in this family is not zero; it is maintenance drag that compounds over time.

**Actionable:** Either consolidate into a single app with per-use-case modes (Ring already has the telemetry; add a "Security Mode" that loads the security feed), or commit to Sentinel as a standalone product with a distinct monetization path that justifies its separate existence. The current plan — same engine, different skin, free, no path to revenue — is not sustainable as a separate product.

---

## Known Limitations (Specific Conditions)

- **iOS Private Relay bypass:** When the user has iCloud+ with Private Relay enabled, DNS queries are routed through Apple's resolvers, bypassing the local VPN tunnel entirely. Sentinel has zero visibility in this state. Estimated iCloud+ subscriber base on iOS: >50% of active iPhone users in the US. (Source: Apple iCloud+ pricing is bundled with iCloud storage; 200M+ subscribers globally.)
- **Pre-existing connections bypass:** Connections established before VPN activation continue outside the tunnel. Apps that use persistent connections (Spotify, WhatsApp, video calls) can continue resolving DNS through existing sessions. (Source: Proton VPN disclosure, documented iOS behavior since iOS 13.)
- **Apple service exclusions:** Apple's own apps — App Store, Maps, Wallet, Health — bypass the local VPN tunnel. Apple has stated this is expected behavior. These are high-value phishing targets (fake App Store payment alerts, fake Apple ID login pages) that Sentinel cannot protect against in the DNS tunnel. (Source: Proton VPN and multiple security researchers.)
- **12 queries/sec ceiling:** The inherited NWUDPSession read handler dies above 12 queries/sec. The spec notes this but offers only 50ms pacing as mitigation. Under load (background app refresh storm, video streaming, social media scrolling), this ceiling can be hit, causing the VPN to stall and requiring session recreation — during which no blocking occurs.
- **Feed size ceiling for HashSet approach:** At 35K domains, a Rust HashSet is fast and memory-efficient. At 500K+ domains (if feeds are expanded), memory pressure on older devices (iPhone 8/SE with 2GB RAM) becomes a concern. The spec does not address the scaling ceiling of the current storage model.

---

## Recurring Community Complaints (Analogous Apps)

- DNS-blocking VPN apps frequently receive App Store rejections for "using a VPN profile to block content in a third-party app" — Apple has pulled apps for this. The framing as a "security app" (vs. ad blocker) may provide some protection, but the technical implementation is identical. Risk of rejection exists. (Source: IVPN App Store rules analysis; documented rejections of content-blocking VPN apps.)
- Users of Lockdown Privacy and NextDNS consistently report needing to whitelist domains when apps break — DoorDash, Uber, and banking apps are recurring examples. A free app with no support channel and no per-domain allowlist (deferred to out-of-scope) will generate negative reviews when a blocked domain breaks a legitimate app.
- Alert fatigue from DNS-level security tools is a documented pattern: Pi-hole users on r/pihole regularly discuss disabling alerts because the volume of blocked requests generates notification noise that does not correspond to real threats.

---

## Sources

1. [Proton VPN — Apple iOS vulnerability causes VPN bypass](https://protonvpn.com/blog/apple-ios-vulnerability-disclosure)
2. [The Register — Two years on, Apple iOS VPNs still leak IP addresses (2022)](https://www.theregister.com/2022/08/19/apple_ios_vpn/)
3. [Infosecurity Magazine — 84% of phishing sites last less than 24 hours](https://www.infosecurity-magazine.com/news/84-of-phishing-sites-last-for-less/)
4. [ACM Web Conference 2025 — 7 Days Later: Analyzing Phishing-Site Lifespan After Detection](https://dl.acm.org/doi/10.1145/3696410.3714678)
5. [Zimperium — Deep Dive into Phishing Chronology](https://zimperium.com/blog/deep-dive-into-phishing-chronology-threats-and-trends)
6. [Sicuranext — 68% of phishing websites protected by Cloudflare](https://blog.sicuranext.com/68-of-phishing-websites-are-protected-by-cloudflare/)
7. [Palo Alto Unit 42 — Detecting malicious subdomains of public apex domains](https://unit42.paloaltonetworks.com/detecting-malicious-subdomains/)
8. [HaGeZi dns-blocklists GitHub — Issue #4148: 18 false positive domains in Multi Pro++](https://github.com/hagezi/dns-blocklists/issues/4148)
9. [HaGeZi dns-blocklists GitHub — FAQ on false positives and Pro++ limitations](https://github.com/hagezi/dns-blocklists/wiki/FAQ)
10. [Privacy Guides Community — iOS DNS profile + Private Relay domains not blocked](https://discuss.privacyguides.net/t/ios-dns-profile-private-dns-icloud-private-relay-domains-not-blocked/32894)
11. [iOS allows DNS request to escape the VPN tunnel — Hacker News](https://news.ycombinator.com/item?id=33177629)
12. [Malwarebytes iOS — cannot scan for malware due to iOS sandbox](https://help.malwarebytes.com/hc/en-us/articles/31589406020251-iOS-Content-Privacy-Restrictions-prevent-enabling-Malwarebytes-for-iOS-v1-features)
13. [How To Geek — Do iPhone security apps actually do anything?](https://www.howtogeek.com/414818/do-iphone-security-apps-actually-do-anything/)
14. [Corelight — False positives in cybersecurity: alert fatigue](https://corelight.com/resources/glossary/false-positives-cybersecurity)
15. [PCMatic — The High Cost of Crying Wolf: How False Alarms Are Causing Real Outages](https://www.pcmatic.com/blog/the-high-cost-of-crying-wolf-how-false-alarms-are-causing-real-outages/)
16. [arXiv — Large-scale analysis of phishing websites hosted on free web hosting domains](https://arxiv.org/html/2212.02563v2)
17. [IVPN — Insights about Apple App Store rules for VPN apps](https://www.ivpn.net/blog/insights-apple-app-store-rules-vpn-apps/)
18. [9to5Mac — Fraudulent Website Warning privacy boost in iOS 14.5](https://9to5mac.com/2021/02/11/fraudulent-website-warning/)
