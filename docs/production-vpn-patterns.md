# Production iOS VPN App Patterns

> How real-world apps solve the same problems Ring faces. Research from open-source codebases and technical docs.

## Apps Studied

| App | Approach | Open Source |
|-----|----------|-------------|
| WireGuard | Full VPN, raw utun fd, C/Go backend | Yes |
| AdGuard | Local DNS proxy (dnsproxy Go lib), DoH/DoT | Yes |
| DNSCloak | NEDNSProxyProvider + dnscrypt-proxy Go | Yes |
| Lockdown | Local HTTP proxy (GCDHTTPProxyServer) | Yes |
| Outline | packetFlow → Go tun2socks (lwIP) | Yes |
| Surge | Fake-IP VIF + domain-based routing | Docs only |

## Key Patterns

### 1. Virtual DNS IP (Ring uses this)
All DNS apps use `198.18.0.0/15` (RFC 2544 benchmarking range) as virtual DNS. Never routable on public internet. Ring uses `198.18.0.1`.

### 2. Routing Loop Prevention — Three Approaches

**Pattern A — Exclude server IP (most common):**
```swift
settings.iPv4Settings?.excludedRoutes = [
    NEIPv4Route(destinationAddress: "8.8.8.8", subnetMask: "255.255.255.255")
]
```

**Pattern B — Localhost tunnel (Lockdown):**
VPN server is `127.0.0.1`. No external routing, no loop possible.

**Pattern C — Fake-IP (Surge/Shadowrocket):**
DNS returns IPs from `198.18.0.0/15`. Real DNS queries exit via `createUDPSessionThroughTunnel`. Fake IPs are never routable.

**Ring's approach:** Pattern A implicitly — `8.8.8.8` is NOT in `includedRoutes` (only `198.18.0.1/32` is), so `createUDPSession` naturally bypasses the tunnel.

### 3. Surge's Fake-IP Architecture (most sophisticated)

```
App calls getaddrinfo("evil-tracker.com")
  → Surge returns 198.18.4.7 (fake, TTL=1s)
  → App connects to 198.18.4.7:443
  → Surge intercepts TCP SYN
  → Fake-IP table: 198.18.4.7 → "evil-tracker.com"
  → Rule engine: REJECT / DIRECT / PROXY
```

This recovers the domain name at TCP connection time, enabling domain-based routing rules on raw IP packets.

### 4. Session Death Recovery — Production Pattern

All apps implement this lifecycle:

```
1. NWPathMonitor.pathUpdateHandler fires
2. Set reasserting = true (shows "Reconnecting")
3. Debounce 500ms (avoid thrashing)
4. Tear down backend
5. Re-resolve upstream endpoints
6. Reinitialize with same config
7. setTunnelNetworkSettings again
8. Set reasserting = false when ready
9. If 3+ failures: cancel tunnel with error
```

**AdGuard bug:** Failing to sequence proxy teardown/reinit on network change leaves tunnel "connected" but DNS proxy dead — silently unfiltered. Ring's stall detection avoids this.

### 5. WireGuard's FD Scanning (advanced)

WireGuard bypasses `packetFlow` entirely — scans file descriptors 0-1024, finds the utun interface via `getpeername()` + `ioctl()`, passes raw fd to C backend. This eliminates Swift/ObjC callback overhead. Ring doesn't need this (DNS-only volume is low).

### 6. `includeAllNetworks` is Broken (Mullvad 2025)

`NEVPNProtocol.includeAllNetworks = true` causes:
- ICMP and TCP sockets bound to tunnel interface stop working
- App Store updates deadlock device networking (VPN killed for update, no network without VPN)
- Mullvad reported to Apple Feb 2025, no fix as of March 2025

**Conclusion:** No production consumer app enables `includeAllNetworks`. Use explicit exclusion routes instead.

### 7. Apple Services Bypass VPN

Documented iOS behavior (Proton VPN disclosure, iOS 13.3.1+): Apple's push notifications, iCloud, Health, Maps establish connections BEFORE VPN activates. iOS does not kill existing connections. These persist outside tunnel for minutes to hours. Not fixable at app level.

## Battery & Performance (from Surge, AdGuard)

- DNS-only tunnel: **<2% additional battery in 24 hours** (Surge measurement)
- iOS attributes ALL network battery to VPN process — bookkeeping effect, not real drain
- Full VPN: **5-15% during active use** (encryption + per-packet processing)
- iOS enforces **150 wakeups/second limit** on extension processes — exceeded = killed
- DNS-only at 1-5 queries/sec is well within budget

## iOS 17+ Sleep/Wake Regression

- iOS 16: sleep/wake ~every 42 seconds
- iOS 17+: sleep/wake ~every **6 seconds** — constant oscillation
- `sleep(completionHandler:)` must be cheap — call handler immediately
- Multiple VPN developers filed Feedback; Apple acknowledged, no fix

## iOS 26 (WWDC25): NEURLFilterManager

New API for URL-level filtering on unsupervised consumer devices:
- App provides Bloom filter dataset for URL matching
- System uses Private Information Retrieval (PIR) via Apple relay for cache misses
- App never sees individual user traffic
- Complementary to Ring (doesn't replace DNS visibility)

## Organization Account Required

Apple App Store Review Guidelines 5.4: VPN apps require **organization developer account** (not individual). Ring must be enrolled as organization to ship.

## Sources

- WireGuard: github.com/WireGuard/wireguard-apple
- AdGuard: github.com/AdguardTeam/AdguardForiOS
- Lockdown: github.com/confirmedcode/Lockdown-iOS
- Outline: github.com/Jigsaw-Code/outline-go-tun2socks
- Surge: manual.nssurge.com/book/understanding-surge/en/
- Mullvad includeAllNetworks: mullvad.net/en/blog/2025/3/26/
- WWDC25 Session 234: developer.apple.com/videos/play/wwdc2025/234/
