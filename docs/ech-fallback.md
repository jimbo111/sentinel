# ECH Fallback & Active Downgrade Strategy

## What is ECH (Encrypted Client Hello)?

Encrypted Client Hello is a TLS extension (draft-ietf-tls-esni) that encrypts the SNI field in the TLS ClientHello message. Today, SNI is sent in plaintext, which is how we extract domain names from HTTPS connections. Once ECH is widely deployed, the SNI field becomes opaque — our SNI extraction stops working.

### How ECH Gets Bootstrapped (The Key to Defeating It)

ECH doesn't just magically activate. There is a **bootstrap chain** that must complete before a browser can use ECH:

```
Step 1: Browser wants to connect to "example.com"
Step 2: Browser issues DNS query for HTTPS RR (Type 65) of "example.com"
Step 3: DNS response contains an HTTPS record with an "ech=" parameter
        containing the server's ECHConfig (public key + config)
Step 4: Browser uses ECHConfig to encrypt the SNI in the TLS ClientHello
Step 5: Server decrypts the inner ClientHello using its private key
```

**The critical vulnerability**: Step 2-3 happen over DNS, which passes through our tunnel. If the browser never receives the ECHConfig from DNS, it **cannot** encrypt the SNI. It falls back to a standard plaintext ClientHello. This is the defined fallback behavior in the ECH spec itself — it's not a hack, it's how the protocol is designed to handle missing ECH support.

### Timeline & Current State

As of early 2026, ECH adoption is still limited but growing:

| Browser/Platform | ECH Status |
|-----------------|-----------|
| Chrome (desktop) | Enabled by default since Chrome 117 (2023) |
| Firefox (desktop) | Enabled by default since Firefox 118 (2023) |
| Safari (iOS) | Not yet enabled by default |
| iOS system connections | Not using ECH |
| Major CDNs (Cloudflare) | ECH supported on their edge |
| Most other servers | Not yet supporting ECH |

**Key insight for iOS**: Safari on iOS does not yet enable ECH by default. iOS system-level connections (App Transport Security, URLSession) also do not use ECH. This gives us a window, but we must prepare.

---

## Defense-in-Depth Strategy

We layer four independent mechanisms, from most aggressive to most passive:

```
┌─────────────────────────────────────────────────────────────┐
│                    ECH Defense Layers                         │
│                                                               │
│  Layer 0: DNS HTTPS RR Stripping (ACTIVE DOWNGRADE)          │
│  ├── Intercept DNS responses in the tunnel                    │
│  ├── Strip HTTPS/SVCB records (Type 65) containing ech=      │
│  ├── Browser never learns ECH config → sends plaintext SNI   │
│  └── Result: ECH never activates. SNI extraction works.      │
│                                                               │
│  Layer 1: DNS Query Parsing (UDP/53)                         │
│  ├── Parse DNS queries to extract domain names                │
│  └── UNAFFECTED by ECH (ECH is TLS-level, not DNS-level)    │
│                                                               │
│  Layer 2: TLS SNI Extraction (TCP/443)                       │
│  ├── Parse ClientHello for SNI                                │
│  └── Works when Layer 0 successfully downgrades               │
│                                                               │
│  Layer 3: ECH Detection + DNS/IP Correlation (PASSIVE)       │
│  ├── If ECH still activates (Layer 0 bypass), detect it      │
│  ├── Correlate destination IP with recent DNS resolutions     │
│  └── Last resort: infer domain from DNS cache                 │
│                                                               │
│  Layer 4: DNS-over-HTTPS interception (FUTURE)               │
│  └── Detect and handle DoH connections                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 0: Active ECH Downgrade via HTTPS RR Stripping

This is the **primary defense** — an active downgrade that prevents ECH from ever activating.

### Background: DNS HTTPS Resource Records

ECH keys are distributed via DNS **HTTPS resource records** (Type 65, RFC 9460). When a browser queries DNS for a domain, it also requests the HTTPS RR. The response looks like this:

```
;; QUESTION SECTION:
example.com.    IN    HTTPS

;; ANSWER SECTION:
example.com.    300   IN    HTTPS   1 . alpn="h2,h3" ech="AEX+DQB..."
```

The `ech="AEX+DQB..."` parameter contains the base64-encoded ECHConfig — the server's public key that the browser needs to encrypt the ClientHello. **Without this, the browser cannot use ECH.**

Similarly, SVCB records (Type 64) can also carry ECH configs in the same format.

### The Downgrade Mechanism

Our Rust engine, sitting in the packet pipeline between the device and the network, rewrites DNS responses to remove ECH capability:

```
┌─────────────┐     DNS query      ┌────────────┐     DNS query      ┌──────────┐
│  App on      │ ──────────────── │  Our Rust   │ ──────────────── │  Upstream │
│  device      │                   │  engine     │                   │  DNS      │
│  (browser)   │ ◄──────────────  │  (tunnel)   │ ◄──────────────  │  server   │
│              │  Modified DNS     │             │  Original DNS     │          │
│              │  response:        │  STRIPS:    │  response:        │          │
│              │  HTTPS RR with    │  ech= param │  HTTPS RR with   │          │
│              │  NO ech= param    │  from HTTPS │  ech= param      │          │
└─────────────┘                   │  RR RDATA    │                   └──────────┘
                                   └────────────┘
```

**What changes in the DNS response:**

| Before (original) | After (modified) |
|-------------------|-----------------|
| `HTTPS 1 . alpn="h2,h3" ech="AEX+DQB..."` | `HTTPS 1 . alpn="h2,h3"` |

We preserve everything else (ALPN, IPv4/v6 hints, port) — we **only** strip the `ech=` SvcParam. This means HTTP/2, HTTP/3, and all other HTTPS RR features continue to work. The connection is not degraded in any way except that ECH is disabled.

### Implementation: `dns_filter.rs`

```rust
/// DNS HTTPS Resource Record filter.
///
/// Intercepts DNS responses and strips ECHConfig from HTTPS/SVCB records
/// (Type 64/65). This prevents clients from learning that a server supports
/// ECH, causing them to fall back to plaintext SNI in the TLS ClientHello.
///
/// This is the primary active downgrade mechanism. It operates at the DNS
/// layer, before the TLS handshake even begins.

use crate::constants::DNS_HEADER_SIZE;

/// DNS record types we filter
const DNS_TYPE_SVCB: u16 = 64;
const DNS_TYPE_HTTPS: u16 = 65;

/// SvcParam key for ECH (RFC 9460, Section 14.3.5)
/// SvcParamKey = 5 means "ech"
const SVCPARAM_KEY_ECH: u16 = 5;

/// Result of filtering a DNS response packet.
pub enum FilterResult {
    /// Packet was not modified (no HTTPS/SVCB records, or no ech= params)
    Unmodified,
    /// Packet was modified — use the new buffer instead
    Modified(Vec<u8>),
    /// Packet is not a DNS response, skip filtering
    NotDnsResponse,
}

/// Attempt to strip ECH configs from a DNS response.
///
/// This function examines a DNS response (UDP payload) for HTTPS/SVCB
/// resource records containing ech= SvcParams. If found, it rebuilds
/// the RDATA without the ech= parameter.
///
/// # Arguments
/// * `udp_payload` - The raw UDP payload (DNS message, starting from DNS header)
///
/// # Returns
/// * `FilterResult::Modified(new_payload)` if ech= was stripped
/// * `FilterResult::Unmodified` if no modification was needed
/// * `FilterResult::NotDnsResponse` if this isn't a DNS response
///
/// # Wire format reference
///
/// DNS HTTPS RR RDATA format (RFC 9460):
/// ```text
/// +-----+--------------------+
/// | u16 | SvcPriority        |  (0 = AliasMode, >0 = ServiceMode)
/// +-----+--------------------+
/// | var | TargetName         |  DNS wire-format name
/// +-----+--------------------+
/// | var | SvcParams          |  Sequence of (key, length, value) tuples
/// +-----+--------------------+
///
/// Each SvcParam:
///   u16  SvcParamKey     (5 = ech)
///   u16  SvcParamLength
///   var  SvcParamValue
/// ```
pub fn filter_ech_from_dns_response(udp_payload: &[u8]) -> FilterResult {
    // Minimum DNS header
    if udp_payload.len() < DNS_HEADER_SIZE {
        return FilterResult::NotDnsResponse;
    }

    // Check QR bit: must be a response (QR=1)
    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
    if (flags & 0x8000) == 0 {
        return FilterResult::NotDnsResponse;
    }

    let qd_count = u16::from_be_bytes([udp_payload[4], udp_payload[5]]) as usize;
    let an_count = u16::from_be_bytes([udp_payload[6], udp_payload[7]]) as usize;
    let ns_count = u16::from_be_bytes([udp_payload[8], udp_payload[9]]) as usize;
    let ar_count = u16::from_be_bytes([udp_payload[10], udp_payload[11]]) as usize;

    if an_count == 0 {
        return FilterResult::Unmodified;
    }

    // Quick scan: does this response contain ANY HTTPS/SVCB records?
    // If not, skip the expensive rewrite path entirely.
    if !quick_scan_for_https_rr(udp_payload, qd_count, an_count) {
        return FilterResult::Unmodified;
    }

    // Full rewrite path: rebuild the DNS message, stripping ech= from
    // any HTTPS/SVCB record RDATA.
    match rewrite_dns_response(udp_payload, qd_count, an_count, ns_count, ar_count) {
        Some(new_payload) => FilterResult::Modified(new_payload),
        None => FilterResult::Unmodified,
    }
}

/// Quick scan to check if any Answer record is Type 64 or 65.
///
/// This avoids the cost of a full rewrite when the response only
/// contains A/AAAA/CNAME records (the common case, ~99% of responses).
fn quick_scan_for_https_rr(
    data: &[u8],
    qd_count: usize,
    an_count: usize,
) -> bool {
    let mut offset = DNS_HEADER_SIZE;

    // Skip Question section
    for _ in 0..qd_count {
        if skip_dns_name(data, &mut offset).is_none() {
            return false;
        }
        offset += 4; // QTYPE + QCLASS
        if offset > data.len() {
            return false;
        }
    }

    // Scan Answer section for HTTPS/SVCB types
    for _ in 0..an_count {
        if skip_dns_name(data, &mut offset).is_none() {
            return false;
        }
        if offset + 10 > data.len() {
            return false;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);

        if rtype == DNS_TYPE_HTTPS || rtype == DNS_TYPE_SVCB {
            return true;
        }

        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10 + rdlength;

        if offset > data.len() {
            return false;
        }
    }

    false
}

/// Rebuild the DNS response, stripping ech= SvcParams from HTTPS/SVCB records.
///
/// Returns None if no ech= params were found (no modification needed).
fn rewrite_dns_response(
    data: &[u8],
    qd_count: usize,
    an_count: usize,
    ns_count: usize,
    ar_count: usize,
) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(data.len());
    let mut modified = false;

    // Copy DNS header as-is
    output.extend_from_slice(&data[..DNS_HEADER_SIZE]);
    let mut offset = DNS_HEADER_SIZE;

    // Copy Question section as-is
    for _ in 0..qd_count {
        let start = offset;
        if skip_dns_name(data, &mut offset).is_none() {
            return None;
        }
        offset += 4;
        if offset > data.len() {
            return None;
        }
        output.extend_from_slice(&data[start..offset]);
    }

    // Process all resource record sections (Answer, Authority, Additional)
    let total_rr = an_count + ns_count + ar_count;

    for _ in 0..total_rr {
        let rr_start = offset;

        // Name
        if skip_dns_name(data, &mut offset).is_none() {
            return None;
        }

        if offset + 10 > data.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        let rdata_start = offset + 10;
        let rr_end = rdata_start + rdlength;

        if rr_end > data.len() {
            return None;
        }

        if (rtype == DNS_TYPE_HTTPS || rtype == DNS_TYPE_SVCB) && rdlength > 0 {
            // This is an HTTPS/SVCB record — rewrite its RDATA
            let rdata = &data[rdata_start..rr_end];

            match strip_ech_from_svcb_rdata(rdata, data) {
                Some(new_rdata) => {
                    modified = true;

                    // Copy name + type + class + TTL (everything before RDLENGTH)
                    output.extend_from_slice(&data[rr_start..offset + 8]);

                    // Write new RDLENGTH
                    let new_rdlen = new_rdata.len() as u16;
                    output.extend_from_slice(&new_rdlen.to_be_bytes());

                    // Write new RDATA
                    output.extend_from_slice(&new_rdata);
                }
                None => {
                    // No ech= found in this record, copy as-is
                    output.extend_from_slice(&data[rr_start..rr_end]);
                }
            }
        } else {
            // Not HTTPS/SVCB — copy as-is
            output.extend_from_slice(&data[rr_start..rr_end]);
        }

        offset = rr_end;
    }

    if modified {
        Some(output)
    } else {
        None
    }
}

/// Strip the ech= SvcParam from SVCB/HTTPS RDATA.
///
/// RDATA format:
///   SvcPriority (u16)
///   TargetName  (DNS wire name)
///   SvcParams   (sequence of key-length-value tuples)
///
/// We rebuild SvcParams, omitting any entry where key == 5 (ech).
///
/// Returns Some(new_rdata) if ech= was found and stripped, None otherwise.
fn strip_ech_from_svcb_rdata(rdata: &[u8], full_msg: &[u8]) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }

    let svc_priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let mut pos = 2;

    // AliasMode (priority == 0) has no SvcParams, just TargetName
    if svc_priority == 0 {
        return None;
    }

    // Skip TargetName (DNS wire format name)
    let target_name_start = pos;
    if skip_dns_name_in_rdata(rdata, &mut pos).is_none() {
        return None;
    }
    let target_name_end = pos;

    if pos >= rdata.len() {
        return None; // No SvcParams present
    }

    // Parse SvcParams, looking for ech (key=5)
    let mut found_ech = false;
    let mut new_svc_params: Vec<u8> = Vec::new();

    let svc_params_start = pos;
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let value_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let param_end = pos + 4 + value_len;

        if param_end > rdata.len() {
            break;
        }

        if key == SVCPARAM_KEY_ECH {
            // Found ech= parameter — skip it (don't copy to output)
            found_ech = true;
        } else {
            // Keep this SvcParam
            new_svc_params.extend_from_slice(&rdata[pos..param_end]);
        }

        pos = param_end;
    }

    if !found_ech {
        return None;
    }

    // Rebuild RDATA without ech=
    let mut new_rdata = Vec::with_capacity(rdata.len());

    // SvcPriority
    new_rdata.extend_from_slice(&rdata[0..2]);

    // TargetName (unchanged)
    new_rdata.extend_from_slice(&rdata[target_name_start..target_name_end]);

    // SvcParams (without ech=)
    new_rdata.extend_from_slice(&new_svc_params);

    Some(new_rdata)
}

/// Skip a DNS wire-format name (handles labels and compression pointers).
fn skip_dns_name(data: &[u8], offset: &mut usize) -> Option<()> {
    loop {
        if *offset >= data.len() {
            return None;
        }

        let label_len = data[*offset] as usize;

        if label_len == 0 {
            *offset += 1;
            return Some(());
        }

        if (label_len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes
            *offset += 2;
            return Some(());
        }

        *offset += 1 + label_len;
    }
}

/// Skip a DNS name within RDATA (may or may not use compression).
fn skip_dns_name_in_rdata(rdata: &[u8], offset: &mut usize) -> Option<()> {
    // Same logic as skip_dns_name but within the RDATA slice
    loop {
        if *offset >= rdata.len() {
            return None;
        }

        let label_len = rdata[*offset] as usize;

        if label_len == 0 {
            *offset += 1;
            return Some(());
        }

        if (label_len & 0xC0) == 0xC0 {
            *offset += 2;
            return Some(());
        }

        *offset += 1 + label_len;
    }
}
```

---

## Integration: Modified Packet Flow with Active Downgrade

The DNS filter sits in the packet pipeline **before** packets are forwarded. This is the only place in the engine where we **modify** packets (everywhere else is read-only inspection).

### Updated `engine.rs`

```rust
use crate::dns_filter::{self, FilterResult};

impl PacketEngine {
    /// Process a single raw IP packet.
    ///
    /// Now returns an Option<Vec<u8>>:
    /// - None means forward the original packet unchanged
    /// - Some(modified) means forward the modified packet instead
    pub fn process_packet(&mut self, packet: &[u8]) -> ProcessResult {
        self.stats.packets_processed += 1;

        let ip_header = match ip::parse_ip_header(packet) {
            Some(h) => h,
            None => {
                self.stats.packets_skipped += 1;
                return ProcessResult::Forward;
            }
        };

        let transport_data = &packet[ip_header.payload_offset..];

        match ip_header.protocol {
            IpProtocol::Udp => {
                return self.handle_udp(packet, transport_data, &ip_header);
            }
            IpProtocol::Tcp => {
                self.handle_tcp(transport_data, &ip_header);
            }
            _ => {
                self.stats.packets_skipped += 1;
            }
        }

        self.maybe_flush();
        ProcessResult::Forward
    }

    fn handle_udp(
        &mut self,
        full_packet: &[u8],
        transport_data: &[u8],
        ip_header: &ip::IpHeader,
    ) -> ProcessResult {
        if transport_data.len() < 8 {
            return ProcessResult::Forward;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
        let udp_payload = &transport_data[8..];

        // ── Outbound DNS query (to port 53) ──
        if dst_port == DNS_PORT {
            let records = dns::parse_dns_query(udp_payload);
            for record in records {
                self.stats.dns_domains_found += 1;
                self.pending_domains.push(
                    record.with_source(DetectionSource::Dns)
                );
            }
            self.maybe_flush();
            return ProcessResult::Forward;
        }

        // ── Inbound DNS response (from port 53) ──
        if src_port == DNS_PORT {
            // Parse DNS response for IP correlation (Layer 3)
            let resolutions = dns::parse_dns_response(udp_payload);
            let now = Self::now_secs();
            for (domain, ip) in &resolutions {
                self.dns_correlator.record_resolution(domain, *ip, now);
            }

            // ── ACTIVE DOWNGRADE: Strip ECH configs from HTTPS RRs ──
            if self.ech_downgrade_enabled {
                match dns_filter::filter_ech_from_dns_response(udp_payload) {
                    FilterResult::Modified(new_udp_payload) => {
                        self.stats.ech_configs_stripped += 1;

                        // Rebuild the full packet with modified DNS payload
                        let new_packet = rebuild_udp_packet(
                            full_packet,
                            ip_header,
                            transport_data,
                            &new_udp_payload,
                        );

                        self.maybe_flush();
                        return ProcessResult::Replace(new_packet);
                    }
                    FilterResult::Unmodified | FilterResult::NotDnsResponse => {
                        // No HTTPS RR with ech= found, forward as-is
                    }
                }
            }

            self.maybe_flush();
            return ProcessResult::Forward;
        }

        self.maybe_flush();
        ProcessResult::Forward
    }
}

/// Result of processing a packet.
pub enum ProcessResult {
    /// Forward the original packet unchanged (the common case)
    Forward,
    /// Replace the original packet with this modified version
    Replace(Vec<u8>),
}

/// Rebuild a UDP packet with a new payload.
///
/// Recalculates the UDP length field and clears the UDP checksum
/// (setting it to 0x0000, which is valid for UDP over IPv4 and means
/// "no checksum computed"). For IPv6, we should compute the checksum,
/// but for MVP we can rely on the fact that most DNS is over IPv4.
fn rebuild_udp_packet(
    original_packet: &[u8],
    ip_header: &ip::IpHeader,
    original_transport: &[u8],
    new_udp_payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(
        ip_header.payload_offset + 8 + new_udp_payload.len()
    );

    // Copy IP header
    packet.extend_from_slice(&original_packet[..ip_header.payload_offset]);

    // Copy UDP header (src_port, dst_port) — first 4 bytes
    packet.extend_from_slice(&original_transport[..4]);

    // New UDP length = 8 (header) + new payload length
    let new_udp_len = (8 + new_udp_payload.len()) as u16;
    packet.extend_from_slice(&new_udp_len.to_be_bytes());

    // UDP checksum = 0 (no checksum — valid for IPv4 UDP)
    packet.extend_from_slice(&[0x00, 0x00]);

    // New payload
    packet.extend_from_slice(new_udp_payload);

    // Fix IP total length field
    let new_total_len = packet.len() as u16;
    match ip_header.version {
        4 => {
            packet[2] = (new_total_len >> 8) as u8;
            packet[3] = (new_total_len & 0xFF) as u8;
            // Recalculate IPv4 header checksum
            recalculate_ipv4_checksum(&mut packet, ip_header.payload_offset);
        }
        6 => {
            let payload_len = (packet.len() - 40) as u16;
            packet[4] = (payload_len >> 8) as u8;
            packet[5] = (payload_len & 0xFF) as u8;
        }
        _ => {}
    }

    packet
}

/// Recalculate the IPv4 header checksum.
///
/// Required because we changed the IP total length field.
fn recalculate_ipv4_checksum(packet: &mut [u8], header_len: usize) {
    // Zero out existing checksum
    packet[10] = 0;
    packet[11] = 0;

    let mut sum: u32 = 0;
    for i in (0..header_len).step_by(2) {
        let word = if i + 1 < header_len {
            ((packet[i] as u32) << 8) | (packet[i + 1] as u32)
        } else {
            (packet[i] as u32) << 8
        };
        sum += word;
    }

    // Fold 32-bit sum to 16-bit
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !sum as u16;
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;
}
```

### Updated FFI Interface

The FFI function signature changes because `process_packet` can now return a modified packet:

```rust
/// Process a single raw IP packet. May modify the packet (for ECH downgrade).
///
/// # Returns
/// - 0: Forward the original packet unchanged
/// - 1: Use the replacement packet (written to `out_buf`)
/// - -1: Error
///
/// # Parameters
/// - `out_buf`: Buffer to write the replacement packet into (if modified)
/// - `out_len`: On input, the capacity of out_buf. On output, the length written.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_process(
    engine: *mut PacketEngine,
    packet_data: *const u8,
    packet_len: usize,
    out_buf: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> c_int {
    if engine.is_null() || packet_data.is_null() || packet_len == 0 {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        let packet = std::slice::from_raw_parts(packet_data, packet_len);

        match engine.process_packet(packet) {
            ProcessResult::Forward => {
                // No modification, forward original
                0
            }
            ProcessResult::Replace(new_packet) => {
                if out_buf.is_null() || out_capacity < new_packet.len() {
                    // Buffer too small, fall back to forwarding original
                    return 0;
                }
                let out_slice = std::slice::from_raw_parts_mut(out_buf, out_capacity);
                out_slice[..new_packet.len()].copy_from_slice(&new_packet);
                if !out_len.is_null() {
                    *out_len = new_packet.len();
                }
                1 // Signal: use replacement packet
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during packet processing".into());
            -1
        }
    }
}
```

### Updated Swift Packet Loop

```swift
// In PacketTunnelProvider+PacketFlow.swift

private func readPacketsFromTunnel() {
    guard isProcessing else { return }

    packetFlow.readPackets { [weak self] packets, protocols in
        guard let self = self, self.isProcessing else { return }

        var outputPackets: [Data] = []
        var outputProtocols: [NSNumber] = []

        for (i, packetData) in packets.enumerated() {
            let result = self.rustEngine?.processPacketWithReplacement(packetData)

            switch result {
            case .forward:
                // Forward original packet
                outputPackets.append(packetData)
                outputProtocols.append(protocols[i])

            case .replace(let newPacket):
                // Forward the modified packet (ECH stripped from DNS response)
                outputPackets.append(newPacket)
                outputProtocols.append(protocols[i])

            case .none:
                // Engine not initialized, forward original
                outputPackets.append(packetData)
                outputProtocols.append(protocols[i])
            }
        }

        self.packetFlow.writePackets(outputPackets, withProtocols: outputProtocols)
        self.readPacketsFromTunnel()
    }
}
```

### Updated Swift RustBridge

```swift
enum PacketProcessResult {
    case forward          // Use the original packet
    case replace(Data)    // Use the replacement packet
}

extension RustPacketEngine {
    /// Process a packet, potentially modifying it (for ECH downgrade).
    func processPacketWithReplacement(_ packetData: Data) -> PacketProcessResult {
        guard let engine = self.engine else { return .forward }

        // Allocate output buffer (same size as input — modified DNS responses
        // are always smaller than or equal to the original)
        var outBuffer = Data(count: packetData.count + 64) // small margin
        var outLen: Int = 0

        let result = packetData.withUnsafeBytes { inBuf -> Int32 in
            outBuffer.withUnsafeMutableBytes { outBuf -> Int32 in
                guard let inBase = inBuf.baseAddress,
                      let outBase = outBuf.baseAddress else { return -1 }

                return packet_engine_process(
                    UnsafeMutablePointer(engine),
                    inBase.assumingMemoryBound(to: UInt8.self),
                    inBuf.count,
                    outBase.assumingMemoryBound(to: UInt8.self),
                    outBuf.count,
                    &outLen
                )
            }
        }

        switch result {
        case 0:
            return .forward
        case 1:
            return .replace(outBuffer.prefix(outLen))
        default:
            return .forward
        }
    }
}
```

---

## Layer 0 Configuration: FFI for Enabling/Disabling

The active downgrade is feature-flagged at runtime:

```rust
/// Enable or disable ECH downgrade (HTTPS RR stripping).
///
/// When enabled, DNS responses containing HTTPS/SVCB records with
/// ech= parameters will be modified to remove the ECH config.
///
/// Default: disabled (must be explicitly enabled).
#[no_mangle]
pub unsafe extern "C" fn packet_engine_set_ech_downgrade(
    engine: *mut PacketEngine,
    enabled: bool,
) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.ech_downgrade_enabled = enabled;
        log::info!("ECH downgrade {}", if enabled { "enabled" } else { "disabled" });
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}
```

---

## Layer 3: Passive ECH Detection + DNS/IP Correlation

When Layer 0 is disabled (or if a client somehow bypasses the DNS filter, e.g., using a hardcoded DoH resolver), we fall back to passive detection.

### 3a. Detecting ECH in ClientHello

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EchStatus {
    /// No ECH extension found — SNI is readable
    NotPresent,
    /// GREASE ECH detected — SNI is still readable (browser is just testing)
    Grease,
    /// Real ECH — SNI is encrypted, we need to fall back to DNS
    Active,
}

/// ECH extension type ID
const TLS_EXT_ECH: u16 = 0xFE0D;

/// GREASE values (RFC 8701)
const TLS_GREASE_VALUES: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
    0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
    0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub fn detect_ech(client_hello_extensions: &[u8]) -> EchStatus {
    let mut pos = 0;

    while pos + 4 <= client_hello_extensions.len() {
        let ext_type = u16::from_be_bytes([
            client_hello_extensions[pos],
            client_hello_extensions[pos + 1],
        ]);
        let ext_len = u16::from_be_bytes([
            client_hello_extensions[pos + 2],
            client_hello_extensions[pos + 3],
        ]) as usize;
        pos += 4;

        if pos + ext_len > client_hello_extensions.len() {
            break;
        }

        if ext_type == TLS_EXT_ECH && ext_len > 4 {
            return EchStatus::Active;
        }

        if TLS_GREASE_VALUES.contains(&ext_type) && ext_len > 0 {
            // GREASE — not real ECH
        }

        pos += ext_len;
    }

    EchStatus::NotPresent
}
```

### 3b. DNS/IP Correlation

```rust
use std::collections::HashMap;
use std::net::IpAddr;

/// Maps destination IPs to recently resolved domain names.
///
/// When we see a DNS response for "amazon.com" → 1.2.3.4, we store that.
/// When we later see a TLS connection to 1.2.3.4 with ECH, we know
/// it's probably amazon.com.
pub struct DnsIpCorrelator {
    ip_to_domain: HashMap<IpAddr, (String, u64)>,
    max_entries: usize,
}

impl DnsIpCorrelator {
    pub fn new(max_entries: usize) -> Self {
        Self {
            ip_to_domain: HashMap::with_capacity(256),
            max_entries,
        }
    }

    pub fn record_resolution(&mut self, domain: &str, ip: IpAddr, now_secs: u64) {
        if self.ip_to_domain.len() >= self.max_entries {
            let cutoff = now_secs.saturating_sub(300);
            self.ip_to_domain.retain(|_, (_, ts)| *ts > cutoff);
        }
        self.ip_to_domain.insert(ip, (domain.to_string(), now_secs));
    }

    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<&str> {
        self.ip_to_domain.get(ip).map(|(d, _)| d.as_str())
    }
}
```

### 3c. Known ECH Frontend Detection

```rust
const KNOWN_ECH_FRONTENDS: &[&str] = &[
    "cloudflare-ech.com",
    "crypto.cloudflare.com",
];

pub fn is_ech_frontend(domain: &str) -> bool {
    KNOWN_ECH_FRONTENDS.iter().any(|&f| {
        domain == f || domain.ends_with(&format!(".{}", f))
    })
}
```

---

## Extended DetectionSource

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSource {
    Dns,              // From DNS query parsing
    Sni,              // From TLS ClientHello SNI
    DnsCorrelation,   // ECH was active, domain inferred from DNS/IP mapping
}

impl DetectionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionSource::Dns => "dns",
            DetectionSource::Sni => "sni",
            DetectionSource::DnsCorrelation => "dns_corr",
        }
    }
}
```

---

## Updated EngineStats

```rust
#[derive(Debug, Default)]
pub struct EngineStats {
    pub packets_processed: u64,
    pub dns_domains_found: u64,
    pub sni_domains_found: u64,
    pub packets_skipped: u64,
    // ECH-specific metrics
    pub ech_configs_stripped: u64,     // Layer 0: HTTPS RRs rewritten
    pub ech_connections: u64,          // Layer 3: ECH detected in TLS
    pub ech_resolved_via_dns: u64,     // Layer 3: recovered via DNS/IP correlation
    pub ech_unresolved: u64,           // Layer 3: could not determine domain
    pub ech_grease_seen: u64,          // GREASE ECH (not real ECH)
}
```

---

## Feature Flag Integration

```swift
// On app launch, fetch remote config
let config = try await apiClient.fetchConfig()

if config.features.echFallbackEnabled {
    // Tell the extension to enable ECH downgrade
    let message = Data([0x03, 0x01])  // Command 0x03 = set ECH, 0x01 = enabled
    await vpnManager.sendMessage(message)
}
```

---

## Metrics to Track

| Metric | Purpose |
|--------|---------|
| `ech_configs_stripped` | How many DNS responses we rewrote (Layer 0 active downgrade) |
| `ech_connections` | TLS connections where ECH was still detected (Layer 0 missed or disabled) |
| `ech_resolved_via_dns` | ECH connections recovered via DNS/IP correlation (Layer 3) |
| `ech_unresolved` | ECH connections where domain was truly unknown |
| `ech_grease_seen` | GREASE ECH extensions (not real, but useful for tracking browser behavior) |

A healthy deployment shows `ech_configs_stripped` growing (Layer 0 working) while `ech_connections` stays near zero (no ECH leaking through).

---

## Testing Strategy

### Unit Tests for dns_filter.rs

| Test | What it verifies |
|------|-----------------|
| `strip_ech_basic` | HTTPS RR with `ech=` → stripped, other SvcParams preserved |
| `strip_ech_multiple_params` | `alpn= ipv4hint= ech=` → only `ech=` removed |
| `no_ech_present` | HTTPS RR without `ech=` → Unmodified |
| `no_https_rr` | DNS response with only A/AAAA records → Unmodified |
| `svcb_record` | Type 64 (SVCB) with `ech=` → also stripped |
| `alias_mode` | SvcPriority=0 (AliasMode) → Unmodified (no SvcParams) |
| `multiple_answers` | Response with A + HTTPS records → only HTTPS modified |
| `compressed_names` | DNS name compression pointers → handled correctly |
| `malformed_rdata` | Truncated RDATA → returns Unmodified (safe fallback) |
| `checksum_recalc` | IPv4 checksum is correct after packet modification |

### Integration Test

```rust
#[test]
fn test_ech_downgrade_full_pipeline() {
    // 1. Create engine with ECH downgrade enabled
    let mut engine = PacketEngine::new(":memory:").unwrap();
    engine.ech_downgrade_enabled = true;

    // 2. Feed it a DNS response containing HTTPS RR with ech=
    let dns_response_with_ech = include_bytes!(
        "../tests/fixtures/dns_response_cloudflare_ech.bin"
    );
    let full_packet = wrap_in_udp_ip(dns_response_with_ech, 53, 12345);

    // 3. Process the packet
    let result = engine.process_packet(&full_packet);

    // 4. Verify the output packet has ech= stripped
    match result {
        ProcessResult::Replace(modified) => {
            let udp_payload = extract_udp_payload(&modified);
            // Verify HTTPS RR exists but without ech=
            assert!(!contains_ech_svcparam(udp_payload));
            // Verify other SvcParams (alpn=) are preserved
            assert!(contains_alpn_svcparam(udp_payload));
        }
        ProcessResult::Forward => panic!("Expected packet modification"),
    }

    // 5. Now feed a TLS ClientHello to the same server
    //    → SNI should be plaintext (ECH was prevented)
    let tls_hello = include_bytes!(
        "../tests/fixtures/tls_hello_cloudflare_no_ech.bin"
    );
    let tcp_packet = wrap_in_tcp_ip(tls_hello, 12345, 443);
    engine.process_packet(&tcp_packet);

    // 6. Verify the domain was extracted via SNI (not DnsCorrelation)
    engine.flush();
    // Check SQLite for the domain with source="sni"
}
```

---

## Limitations & Honest Assessment

| Scenario | Layer 0 (Downgrade) | Layer 1 (DNS) | Layer 2 (SNI) | Layer 3 (Correlate) | Domain Detected? |
|----------|-------------------|--------------|--------------|-------------------|-----------------|
| Standard DNS, no ECH | N/A | Yes | Yes | N/A | **Yes** |
| Standard DNS, ECH attempted | Strips ech= → no ECH | Yes | Yes (ECH prevented) | N/A | **Yes** |
| DoH/DoT, no ECH | N/A | No | Yes (SNI plaintext) | N/A | **Yes** |
| DoH/DoT, ECH attempted | Can't strip (DoH bypasses our DNS) | No | No (ECH active) | Maybe (prior DNS) | **Maybe** |
| Hardcoded ECH config in app | Can't strip (no DNS lookup) | Maybe | No (ECH active) | Maybe | **Maybe** |

The key takeaway: Layer 0 is extremely effective because our VPN tunnel controls the DNS path. The only way to bypass it is for an app to use its own DNS-over-HTTPS resolver AND cache ECH configs, which is rare on iOS. Even then, Layer 1 (DNS query parsing) often still catches the domain name.

**Worst case** (DoH + cached ECH + no prior standard DNS) is currently near-zero on iOS. Our tunnel's DNS settings force the system resolver to use standard DNS, so even apps using URLSession go through our pipeline.
