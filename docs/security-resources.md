# Security & Filtering — Open Source Resources

## DNS Blocklists

| Project | Description | License | URL |
|---|---|---|---|
| HaGeZi DNS Blocklists | Tiered (Light→Ultimate) ads/trackers/phishing/malware. 21K stars, daily updates | MIT | https://github.com/hagezi/dns-blocklists |
| Block List Project | Per-category: malware, phishing, ransomware C2, gambling, adult, tracking. 2.2M+ domains | Unlicense | https://github.com/blocklistproject/Lists |
| URLhaus Filter | Active malware distribution domains from abuse.ch. Updated 2x daily | MIT | https://github.com/curbengh/urlhaus-filter |
| StevenBlack/hosts | Aggregated hosts file, ~86K entries. 31 variants (adware, malware, porn, gambling) | MIT | https://github.com/StevenBlack/hosts |
| OpenPhish | Real-time phishing URLs, updated every 12h | ToS (verify commercial use) | https://github.com/openphish/public_feed |
| Energized Protection | Aggregated blocklists with curated adult content pack | MIT | https://github.com/EnergizedProtection/block |

## Rust Crates

| Crate | Description | License | URL |
|---|---|---|---|
| brave/adblock-rust | Brave's filter engine — parses EasyList/ABP syntax natively in Rust | MPL-2.0 | https://github.com/brave/adblock-rust |
| aho-corasick | Multi-pattern string matching with SIMD. For wildcard domain matching | MIT/Unlicense | https://github.com/BurntSushi/aho-corasick |
| fast_radix_trie | Reversed-label suffix trie for `*.evil.com` matching at scale (~150ns/lookup) | MIT | https://github.com/bluecatengineering/fast_radix_trie |
| hickory-dns | Full Rust DNS stack (proto, client, server). Production-grade DNS parsing | Apache 2.0/MIT | https://github.com/hickory-dns/hickory-dns |

## On-Device Threat Detection

| Project | Description | License | URL |
|---|---|---|---|
| exp0se/dga_detector | DGA detection: Shannon entropy, consonant runs, n-gram Markov chains. Port to Rust (~20 lines) | Check repo | https://github.com/exp0se/dga_detector |
| hmaccelerate/DGA_Detection | Character-level LSTM + TLD features. Blueprint for CoreML model | Check repo | https://github.com/hmaccelerate/DGA_Detection |
| Gravity Falls paper (2026) | Mobile-focused DGA detection benchmark. Best threshold calibration reference | Public | https://arxiv.org/abs/2603.03270 |

## Parental Control Data

| Project | Description | License | URL |
|---|---|---|---|
| UT1 Capitole Blacklists | ~100 content categories (adult, drugs, gambling, violence). Updated daily | CC BY-SA 4.0 | https://github.com/olbat/ut1-blacklists |
| AdGuard Family Filter | Dedicated adult content filter. Used in AdGuard DNS Family mode | CC BY-SA 4.0 | https://filters.adtidy.org/extension/ublock/filters/27.txt |

## iOS Architecture References (study only)

| Project | What to learn | License | URL |
|---|---|---|---|
| AdGuard for iOS | Swift-to-C++ bridging in Network Extension (same pattern as Rust FFI) | GPL-3.0 | https://github.com/AdguardTeam/AdguardForiOS |
| AdGuard DnsLibs | C++ DNS filter running inside iOS Network Extension | Apache 2.0 | https://github.com/AdguardTeam/DnsLibs |
| IVPN iOS | AntiTracker blocklist integration in packet tunnel | GPL-3.0 | https://github.com/ivpn/ios-app |
| Passepartout | NetworkExtension profile lifecycle, DNS override config | GPL-3.0 | https://github.com/passepartoutvpn/passepartout-apple |
| Pi-hole FTL | SQLite-based blocklist storage, domain matching engine | EUPL-1.2 | https://github.com/pi-hole/FTL |
| AdGuard Home | Production DNS filter engine in Go (CNAME cloaking, safe search) | GPL-3.0 | https://github.com/AdguardTeam/AdGuardHome |

## Implementation Priority

**Tier 1 — Ship fast (low effort, high value):**
1. HaGeZi Light + Block List Project malware/phishing → `HashSet<String>` in Rust engine
2. URLhaus feed → dedicated "Active Malware" blocking
3. "Threats Blocked" counter on Home tab

**Tier 2 — Next sprint:**
4. DGA heuristic detector in Rust (entropy + consonant + n-gram + length)
5. `adblock-rust` for EasyList/EasyPrivacy compatibility
6. UT1 Capitole → SQLite for parental control categories

**Tier 3 — Strategic:**
7. CoreML LSTM for DGA detection on Neural Engine
8. Reversed-label suffix trie replacing HashSet at 500K+ domains
9. Architecture patterns from AdGuard iOS for Rust-Swift FFI hardening
