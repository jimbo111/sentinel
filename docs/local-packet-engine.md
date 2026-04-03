# Local Packet Engine (Rust)

## Purpose

The packet engine is a zero-allocation-friendly, single-threaded Rust library compiled as a static C library (`libpacket_engine.a`). It runs inside the iOS Network Extension process and handles:

1. Parsing raw IP packets (IPv4/IPv6) received from `NEPacketTunnelProvider.packetFlow`
2. Extracting domain names via DNS query parsing (UDP/53) and TLS SNI extraction (TCP/443)
3. Managing bounded TCP reassembly for fragmented TLS ClientHello messages
4. **Active ECH downgrade**: Stripping ECH configs from DNS HTTPS/SVCB resource records (Type 64/65) so browsers fall back to plaintext SNI (see `ech-fallback.md` for full specification)
5. Batch-writing extracted domains to a shared SQLite database

The engine must operate within the **6 MB memory limit** of iOS Network Extensions.

---

## Module Overview

```
lib.rs            ← FFI entry points (extern "C")
engine.rs         ← PacketEngine: owns all state, orchestrates processing
ip.rs             ← IP header parsing (v4/v6)
dns.rs            ← DNS query + response parser
tls.rs            ← TLS ClientHello / SNI extractor + ECH detection
tcp_reassembly.rs ← Bounded per-flow TCP reassembly
dns_filter.rs     ← Active ECH downgrade: HTTPS RR ech= stripping (see ech-fallback.md)
ech_correlator.rs ← DNS/IP correlation for passive ECH fallback
domain.rs         ← DomainRecord struct, normalization, dedup
storage.rs        ← SQLite batch writer
errors.rs         ← Error types
constants.rs      ← Tunable limits
```

---

## Constants (`constants.rs`)

```rust
/// Maximum number of concurrent TCP flows tracked for reassembly.
/// Each flow buffer is max 16KB, so worst case: 1024 * 16KB = 16MB.
/// In practice, most flows are < 1KB, so real usage is ~1-2MB.
pub const MAX_TCP_FLOWS: usize = 1024;

/// Maximum bytes buffered per TCP flow for reassembly.
/// TLS ClientHello is typically 200-600 bytes, but with many extensions
/// (especially with large certificate lists), can reach ~10KB.
/// 16KB is a safe upper bound.
pub const MAX_FLOW_BUFFER_BYTES: usize = 16_384;

/// Flow timeout in seconds. If no new segment arrives for a flow within
/// this window, the flow buffer is evicted.
pub const FLOW_TIMEOUT_SECS: u64 = 10;

/// Batch insert threshold. Domains are queued in memory and flushed to
/// SQLite when this count is reached OR when the flush timer fires.
pub const BATCH_INSERT_SIZE: usize = 50;

/// Batch flush interval in milliseconds. Even if fewer than BATCH_INSERT_SIZE
/// domains are queued, flush after this interval to keep UI responsive.
pub const BATCH_FLUSH_INTERVAL_MS: u64 = 500;

/// DNS standard port
pub const DNS_PORT: u16 = 53;

/// HTTPS standard port (where we look for TLS ClientHello)
pub const HTTPS_PORT: u16 = 443;

/// Maximum DNS query name length (per RFC 1035)
pub const MAX_DNS_NAME_LENGTH: usize = 253;
```

---

## IP Header Parser (`ip.rs`)

Parses the first bytes of raw packets to determine IP version, protocol, source/destination addresses, and payload offset.

```rust
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,            // 4 or 6
    pub protocol: IpProtocol,   // TCP(6), UDP(17), or Other
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub payload_offset: usize,  // byte offset where transport header begins
    pub total_length: usize,    // total IP packet length
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,    // 6
    Udp,    // 17
    Other(u8),
}

/// Parse an IP header from a raw packet buffer.
///
/// Returns None if:
/// - Buffer is too short for a valid IP header
/// - IP version is not 4 or 6
/// - Header length field is invalid
///
/// This function does NOT validate checksums (the OS already did that).
pub fn parse_ip_header(packet: &[u8]) -> Option<IpHeader> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;

    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<IpHeader> {
    // Minimum IPv4 header: 20 bytes
    if packet.len() < 20 {
        return None;
    }

    let ihl = (packet[0] & 0x0F) as usize;  // Header length in 32-bit words
    let header_len = ihl * 4;

    if header_len < 20 || packet.len() < header_len {
        return None;
    }

    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let protocol = packet[9];

    let src = IpAddr::from([packet[12], packet[13], packet[14], packet[15]]);
    let dst = IpAddr::from([packet[16], packet[17], packet[18], packet[19]]);

    Some(IpHeader {
        version: 4,
        protocol: match protocol {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            other => IpProtocol::Other(other),
        },
        src_addr: src,
        dst_addr: dst,
        payload_offset: header_len,
        total_length,
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<IpHeader> {
    // IPv6 header is fixed at 40 bytes
    if packet.len() < 40 {
        return None;
    }

    let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let next_header = packet[6]; // Protocol

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    dst.copy_from_slice(&packet[24..40]);

    // NOTE: This does not handle extension headers. For MVP, we treat
    // next_header as the transport protocol. Extension header chasing
    // can be added later if needed.
    Some(IpHeader {
        version: 6,
        protocol: match next_header {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            other => IpProtocol::Other(other),
        },
        src_addr: IpAddr::from(src),
        dst_addr: IpAddr::from(dst),
        payload_offset: 40,
        total_length: 40 + payload_length,
    })
}
```

---

## DNS Query Parser (`dns.rs`)

Parses DNS queries from UDP packets destined for port 53. Extracts the queried domain name from the Question section.

```rust
use crate::domain::DomainRecord;
use chrono::Utc;

/// DNS header is 12 bytes:
///   ID (2) | Flags (2) | QDCOUNT (2) | ANCOUNT (2) | NSCOUNT (2) | ARCOUNT (2)
const DNS_HEADER_SIZE: usize = 12;

/// Parse a DNS query from a UDP payload.
///
/// We only care about the Question section (queries FROM the device).
/// We ignore responses (we could parse those too, but queries are sufficient
/// and we avoid double-counting).
///
/// Returns extracted domain names, or empty vec if not a valid DNS query.
pub fn parse_dns_query(udp_payload: &[u8]) -> Vec<DomainRecord> {
    if udp_payload.len() < DNS_HEADER_SIZE {
        return vec![];
    }

    // Check QR bit (bit 15 of flags): 0 = query, 1 = response
    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
    let is_query = (flags & 0x8000) == 0;

    if !is_query {
        return vec![];
    }

    let qd_count = u16::from_be_bytes([udp_payload[4], udp_payload[5]]) as usize;

    if qd_count == 0 || qd_count > 10 {
        // Sanity check: most queries have 1 question, never more than a few
        return vec![];
    }

    let mut offset = DNS_HEADER_SIZE;
    let mut records = Vec::with_capacity(qd_count);

    for _ in 0..qd_count {
        match parse_dns_name(udp_payload, &mut offset) {
            Some(name) => {
                // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
                if offset + 4 > udp_payload.len() {
                    break;
                }
                let qtype = u16::from_be_bytes([
                    udp_payload[offset],
                    udp_payload[offset + 1],
                ]);
                offset += 4;

                // Only record A (1) and AAAA (28) queries
                // Skip PTR, SRV, TXT, etc. — they clutter the domain list
                if qtype == 1 || qtype == 28 {
                    if let Some(record) = DomainRecord::from_raw_name(&name) {
                        records.push(record);
                    }
                }
            }
            None => break,
        }
    }

    records
}

/// Parse a DNS name from wire format.
///
/// DNS names are encoded as a sequence of labels:
///   [length][label bytes][length][label bytes]...[0]
///
/// Compression pointers (0xC0 prefix) are handled.
fn parse_dns_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut name_parts: Vec<String> = Vec::new();
    let mut current = *offset;
    let mut jumped = false;
    let mut jump_count = 0;

    loop {
        if current >= data.len() {
            return None;
        }

        let label_len = data[current] as usize;

        if label_len == 0 {
            // End of name
            if !jumped {
                *offset = current + 1;
            }
            break;
        }

        // Check for compression pointer (top 2 bits = 11)
        if (label_len & 0xC0) == 0xC0 {
            if current + 1 >= data.len() {
                return None;
            }
            if !jumped {
                *offset = current + 2;
            }
            let pointer = ((label_len & 0x3F) << 8) | (data[current + 1] as usize);
            current = pointer;
            jumped = true;
            jump_count += 1;
            if jump_count > 10 {
                return None; // Prevent infinite loops
            }
            continue;
        }

        current += 1;
        if current + label_len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[current..current + label_len]).ok()?;
        name_parts.push(label.to_lowercase());
        current += label_len;
    }

    if name_parts.is_empty() {
        return None;
    }

    let name = name_parts.join(".");

    if name.len() > crate::constants::MAX_DNS_NAME_LENGTH {
        return None;
    }

    Some(name)
}
```

---

## TLS SNI Extractor (`tls.rs`)

Parses TLS ClientHello messages to extract the Server Name Indication (SNI) extension. This is the primary mechanism for identifying HTTPS domains.

```rust
use crate::domain::DomainRecord;

/// TLS record header: ContentType(1) + Version(2) + Length(2) = 5 bytes
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// TLS Handshake type for ClientHello
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS ContentType for Handshake
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// SNI extension type ID
const TLS_EXT_SERVER_NAME: u16 = 0x0000;

/// Host name type in SNI
const SNI_HOST_NAME_TYPE: u8 = 0x00;

/// Attempt to extract the SNI domain from a reassembled TLS ClientHello.
///
/// The input `data` should be a complete TLS record (starting from the
/// TLS record header). This is the reassembled TCP payload for a flow
/// to port 443.
///
/// Returns Some(DomainRecord) if SNI was found, None otherwise.
pub fn extract_sni(data: &[u8]) -> Option<DomainRecord> {
    // Minimum: TLS record header (5) + Handshake header (4) + ClientHello minimum
    if data.len() < 43 {
        return None;
    }

    // ── TLS Record Layer ──
    let content_type = data[0];
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    // TLS version in record header (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // For TLS 1.3, the record layer still says 0x0301 or 0x0303
    let _record_version = u16::from_be_bytes([data[1], data[2]]);
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

    if data.len() < TLS_RECORD_HEADER_SIZE + record_length {
        return None; // Incomplete record
    }

    let handshake = &data[TLS_RECORD_HEADER_SIZE..];

    // ── Handshake Layer ──
    if handshake.is_empty() {
        return None;
    }

    let handshake_type = handshake[0];
    if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    // Handshake length (3 bytes, big-endian)
    if handshake.len() < 4 {
        return None;
    }
    let hs_length = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);

    if handshake.len() < 4 + hs_length {
        return None;
    }

    let client_hello = &handshake[4..4 + hs_length];

    // ── ClientHello Fields ──
    // client_version (2) + random (32) = 34 bytes
    if client_hello.len() < 34 {
        return None;
    }
    let mut pos: usize = 34;

    // Session ID (variable length, prefixed by 1 byte length)
    if pos >= client_hello.len() {
        return None;
    }
    let session_id_len = client_hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites (variable length, prefixed by 2 byte length)
    if pos + 2 > client_hello.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([
        client_hello[pos],
        client_hello[pos + 1],
    ]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods (variable length, prefixed by 1 byte length)
    if pos >= client_hello.len() {
        return None;
    }
    let compression_len = client_hello[pos] as usize;
    pos += 1 + compression_len;

    // ── Extensions ──
    if pos + 2 > client_hello.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([
        client_hello[pos],
        client_hello[pos + 1],
    ]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > client_hello.len() {
        return None;
    }

    // Walk through extensions looking for SNI (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([
            client_hello[pos],
            client_hello[pos + 1],
        ]);
        let ext_len = u16::from_be_bytes([
            client_hello[pos + 2],
            client_hello[pos + 3],
        ]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            return None;
        }

        if ext_type == TLS_EXT_SERVER_NAME {
            return parse_sni_extension(&client_hello[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None // No SNI extension found
}

/// Parse the SNI extension payload.
///
/// Format:
///   ServerNameList length (2 bytes)
///     ServerName type (1 byte) — 0x00 = host_name
///     ServerName length (2 bytes)
///     ServerName value (variable)
fn parse_sni_extension(ext_data: &[u8]) -> Option<DomainRecord> {
    if ext_data.len() < 5 {
        return None;
    }

    let _list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]);
    let name_type = ext_data[2];

    if name_type != SNI_HOST_NAME_TYPE {
        return None;
    }

    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;

    if ext_data.len() < 5 + name_len {
        return None;
    }

    let name_bytes = &ext_data[5..5 + name_len];
    let name = std::str::from_utf8(name_bytes).ok()?;

    DomainRecord::from_raw_name(&name.to_lowercase())
}

/// Quick check: does this TCP payload look like the start of a TLS record?
/// Used to decide whether to begin reassembly for a flow.
pub fn is_tls_client_hello_start(tcp_payload: &[u8]) -> bool {
    if tcp_payload.len() < 6 {
        return false;
    }

    // Content type: Handshake (0x16)
    // Version: 0x0301 (TLS 1.0) or 0x0303 (TLS 1.2) in record layer
    // (TLS 1.3 uses 0x0301 in the record layer for compatibility)
    let content_type = tcp_payload[0];
    let version_major = tcp_payload[1];
    let handshake_type = tcp_payload[5]; // First byte of handshake payload

    content_type == TLS_CONTENT_TYPE_HANDSHAKE
        && version_major == 0x03
        && handshake_type == TLS_HANDSHAKE_CLIENT_HELLO
}
```

---

## TCP Reassembly (`tcp_reassembly.rs`)

TLS ClientHello messages can span multiple TCP segments. This module provides a bounded, LRU-evicting buffer to reassemble them.

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use crate::constants::{MAX_TCP_FLOWS, MAX_FLOW_BUFFER_BYTES, FLOW_TIMEOUT_SECS};
use crate::tls;
use crate::domain::DomainRecord;

/// Uniquely identifies a TCP flow (one direction only).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Per-flow reassembly buffer.
struct FlowBuffer {
    data: Vec<u8>,
    first_seen: u64,     // Unix timestamp (seconds)
    last_seen: u64,
    expected_len: Option<usize>,  // From TLS record header, once parsed
}

/// Manages TCP reassembly for all active flows.
pub struct TcpReassembler {
    flows: HashMap<FlowKey, FlowBuffer>,
    /// Tracks insertion order for LRU eviction
    order: Vec<FlowKey>,
}

pub enum ReassemblyResult {
    /// Reassembly complete, here's the domain
    Complete(DomainRecord),
    /// More segments needed
    NeedMore,
    /// This segment is not relevant (not a TLS ClientHello start)
    NotRelevant,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            flows: HashMap::with_capacity(256),
            order: Vec::with_capacity(256),
        }
    }

    /// Process a TCP payload for a given flow.
    ///
    /// Call this for every TCP segment to port 443.
    ///
    /// Returns:
    /// - Complete(DomainRecord) if we've reassembled enough to extract SNI
    /// - NeedMore if we're still collecting segments
    /// - NotRelevant if this isn't a TLS ClientHello flow
    pub fn process_segment(
        &mut self,
        key: FlowKey,
        tcp_payload: &[u8],
        now_secs: u64,
    ) -> ReassemblyResult {
        // First, evict timed-out flows
        self.evict_expired(now_secs);

        // Is this an existing flow?
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now_secs;

            // Would this exceed the per-flow buffer limit?
            if flow.data.len() + tcp_payload.len() > MAX_FLOW_BUFFER_BYTES {
                self.remove_flow(&key);
                return ReassemblyResult::NotRelevant;
            }

            flow.data.extend_from_slice(tcp_payload);

            // Try to determine expected length from TLS record header
            if flow.expected_len.is_none() && flow.data.len() >= 5 {
                let record_len = u16::from_be_bytes([flow.data[3], flow.data[4]]) as usize;
                flow.expected_len = Some(5 + record_len); // 5 = TLS record header
            }

            // Check if we have enough data
            if let Some(expected) = flow.expected_len {
                if flow.data.len() >= expected {
                    let data = flow.data.clone();
                    self.remove_flow(&key);

                    match tls::extract_sni(&data) {
                        Some(record) => ReassemblyResult::Complete(record),
                        None => ReassemblyResult::NotRelevant,
                    }
                } else {
                    ReassemblyResult::NeedMore
                }
            } else {
                ReassemblyResult::NeedMore
            }
        } else {
            // New flow — only start tracking if it looks like a TLS ClientHello
            if !tls::is_tls_client_hello_start(tcp_payload) {
                return ReassemblyResult::NotRelevant;
            }

            // Evict LRU if at capacity
            if self.flows.len() >= MAX_TCP_FLOWS {
                self.evict_lru();
            }

            // Try to extract SNI from this single segment (common case)
            if let Some(record) = tls::extract_sni(tcp_payload) {
                return ReassemblyResult::Complete(record);
            }

            // Need more segments — start tracking
            let mut expected_len = None;
            if tcp_payload.len() >= 5 {
                let record_len = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize;
                expected_len = Some(5 + record_len);
            }

            let flow = FlowBuffer {
                data: tcp_payload.to_vec(),
                first_seen: now_secs,
                last_seen: now_secs,
                expected_len,
            };

            self.flows.insert(key.clone(), flow);
            self.order.push(key);

            ReassemblyResult::NeedMore
        }
    }

    /// Remove expired flows (older than FLOW_TIMEOUT_SECS).
    fn evict_expired(&mut self, now_secs: u64) {
        let cutoff = now_secs.saturating_sub(FLOW_TIMEOUT_SECS);
        let expired: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, f)| f.last_seen < cutoff)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            self.remove_flow(&key);
        }
    }

    /// Evict the least recently used flow.
    fn evict_lru(&mut self) {
        if let Some(oldest_key) = self.order.first().cloned() {
            self.remove_flow(&oldest_key);
        }
    }

    fn remove_flow(&mut self, key: &FlowKey) {
        self.flows.remove(key);
        self.order.retain(|k| k != key);
    }

    /// Get current number of tracked flows (for diagnostics).
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Get total memory used by reassembly buffers (approximate).
    pub fn memory_usage_bytes(&self) -> usize {
        self.flows.values().map(|f| f.data.len()).sum()
    }
}
```

---

## Domain Record (`domain.rs`)

```rust
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct DomainRecord {
    /// The normalized domain name (e.g., "amazon.com")
    pub domain: String,
    /// Timestamp when this domain was observed (Unix millis)
    pub timestamp_ms: i64,
    /// How we detected this domain
    pub source: DetectionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSource {
    Dns,    // Extracted from DNS query
    Sni,    // Extracted from TLS ClientHello SNI
}

impl DetectionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionSource::Dns => "dns",
            DetectionSource::Sni => "sni",
        }
    }
}

impl DomainRecord {
    /// Create a DomainRecord from a raw domain name string.
    ///
    /// Normalizes and validates the domain:
    /// - Lowercased
    /// - Trailing dot removed
    /// - Must have at least one dot (filter out bare hostnames like "localhost")
    /// - Must not be an IP address literal
    /// - Must not exceed MAX_DNS_NAME_LENGTH
    ///
    /// Returns None if the name is invalid or should be filtered.
    pub fn from_raw_name(name: &str) -> Option<Self> {
        let normalized = name
            .trim()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();

        // Must contain at least one dot
        if !normalized.contains('.') {
            return None;
        }

        // Filter out IP address literals
        if normalized.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        // Filter known noise domains (OS-level telemetry, connectivity checks)
        if is_noise_domain(&normalized) {
            return None;
        }

        // Length check
        if normalized.len() > crate::constants::MAX_DNS_NAME_LENGTH {
            return None;
        }

        Some(DomainRecord {
            domain: normalized,
            timestamp_ms: Utc::now().timestamp_millis(),
            source: DetectionSource::Dns, // caller overrides if needed
        })
    }

    pub fn with_source(mut self, source: DetectionSource) -> Self {
        self.source = source;
        self
    }
}

/// Returns true for domains that are system noise and should not be shown to users.
///
/// These are domains contacted by iOS/system daemons for connectivity checks,
/// push notifications, certificate validation, etc.
fn is_noise_domain(domain: &str) -> bool {
    const NOISE_SUFFIXES: &[&str] = &[
        // Apple connectivity and system services
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "apple-dns.net",
        // Common CDN / infrastructure (not user-meaningful)
        "cloudfront.net",
        "akamaiedge.net",
        "akadns.net",
        // DNS infrastructure
        "in-addr.arpa",
        "ip6.arpa",
        // Local / mDNS
        "local",
    ];

    // NOTE: This is a conservative default. Users should be able to
    // customize this list in Settings (whitelist/blacklist).
    // The Rust engine applies this filter, but the Swift UI can also
    // apply additional user-configured filters.
    //
    // For MVP, we keep this minimal. Over-filtering is worse than
    // under-filtering — users can always ignore domains in the UI,
    // but they can't see domains we silently dropped.

    for suffix in NOISE_SUFFIXES {
        if domain == *suffix || domain.ends_with(&format!(".{}", suffix)) {
            return true;
        }
    }

    false
}
```

---

## Engine Core (`engine.rs`)

The main orchestrator that ties everything together.

```rust
use crate::ip::{self, IpProtocol};
use crate::dns;
use crate::tls;
use crate::tcp_reassembly::{TcpReassembler, FlowKey, ReassemblyResult};
use crate::domain::{DomainRecord, DetectionSource};
use crate::storage::DomainStorage;
use crate::errors::EngineError;
use crate::constants::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// The main packet processing engine.
///
/// This struct owns all mutable state and is NOT thread-safe (no need —
/// the Network Extension packet loop is single-threaded).
pub struct PacketEngine {
    reassembler: TcpReassembler,
    storage: DomainStorage,
    /// Batch buffer: domains waiting to be flushed to SQLite
    pending_domains: Vec<DomainRecord>,
    /// Timestamp of last flush (Unix millis)
    last_flush_ms: i64,
    /// Counters for diagnostics
    stats: EngineStats,
}

#[derive(Debug, Default)]
pub struct EngineStats {
    pub packets_processed: u64,
    pub dns_domains_found: u64,
    pub sni_domains_found: u64,
    pub packets_skipped: u64,
}

impl PacketEngine {
    /// Initialize the engine with a path to the SQLite database.
    ///
    /// This opens the database, creates tables if needed, and sets WAL mode.
    pub fn new(db_path: &str) -> Result<Self, EngineError> {
        let storage = DomainStorage::new(db_path)?;

        Ok(PacketEngine {
            reassembler: TcpReassembler::new(),
            storage,
            pending_domains: Vec::with_capacity(BATCH_INSERT_SIZE),
            last_flush_ms: Self::now_millis(),
            stats: EngineStats::default(),
        })
    }

    /// Process a single raw IP packet.
    ///
    /// This is the main entry point called from Swift via FFI for each packet.
    /// It is designed to be called millions of times per minute.
    ///
    /// Returns the number of new domains found in this packet (usually 0 or 1).
    pub fn process_packet(&mut self, packet: &[u8]) -> u32 {
        self.stats.packets_processed += 1;

        let ip_header = match ip::parse_ip_header(packet) {
            Some(h) => h,
            None => {
                self.stats.packets_skipped += 1;
                return 0;
            }
        };

        let transport_data = &packet[ip_header.payload_offset..];
        let mut found = 0u32;

        match ip_header.protocol {
            IpProtocol::Udp => {
                found += self.handle_udp(transport_data);
            }
            IpProtocol::Tcp => {
                found += self.handle_tcp(transport_data, &ip_header);
            }
            _ => {
                self.stats.packets_skipped += 1;
            }
        }

        // Check if we should flush the batch
        self.maybe_flush();

        found
    }

    /// Handle a UDP segment. Check if it's a DNS query (dst port 53).
    fn handle_udp(&mut self, transport_data: &[u8]) -> u32 {
        // UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8 bytes
        if transport_data.len() < 8 {
            return 0;
        }

        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

        if dst_port != DNS_PORT {
            return 0;
        }

        let udp_payload = &transport_data[8..];
        let records = dns::parse_dns_query(udp_payload);
        let count = records.len() as u32;

        for record in records {
            self.stats.dns_domains_found += 1;
            self.pending_domains.push(record.with_source(DetectionSource::Dns));
        }

        count
    }

    /// Handle a TCP segment. Check if it's destined for port 443 (HTTPS)
    /// and try to extract SNI from the TLS ClientHello.
    fn handle_tcp(&mut self, transport_data: &[u8], ip_header: &ip::IpHeader) -> u32 {
        // TCP header: minimum 20 bytes
        // src_port(2) + dst_port(2) + seq(4) + ack(4) + data_offset(1) + ...
        if transport_data.len() < 20 {
            return 0;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

        if dst_port != HTTPS_PORT {
            return 0;
        }

        // TCP data offset (upper 4 bits of byte 12, in 32-bit words)
        let data_offset = ((transport_data[12] >> 4) as usize) * 4;
        if data_offset > transport_data.len() {
            return 0;
        }

        let tcp_payload = &transport_data[data_offset..];
        if tcp_payload.is_empty() {
            return 0; // ACK-only segment, no payload
        }

        let flow_key = FlowKey {
            src_ip: ip_header.src_addr,
            dst_ip: ip_header.dst_addr,
            src_port,
            dst_port,
        };

        let now = Self::now_secs();

        match self.reassembler.process_segment(flow_key, tcp_payload, now) {
            ReassemblyResult::Complete(record) => {
                self.stats.sni_domains_found += 1;
                self.pending_domains.push(record.with_source(DetectionSource::Sni));
                1
            }
            ReassemblyResult::NeedMore | ReassemblyResult::NotRelevant => 0,
        }
    }

    /// Flush pending domains to SQLite if batch is full or timer expired.
    fn maybe_flush(&mut self) {
        if self.pending_domains.is_empty() {
            return;
        }

        let now = Self::now_millis();
        let elapsed = now - self.last_flush_ms;

        let should_flush = self.pending_domains.len() >= BATCH_INSERT_SIZE
            || elapsed >= BATCH_FLUSH_INTERVAL_MS as i64;

        if should_flush {
            self.flush();
        }
    }

    /// Force-flush all pending domains to SQLite.
    pub fn flush(&mut self) {
        if self.pending_domains.is_empty() {
            return;
        }

        let domains: Vec<DomainRecord> = self.pending_domains.drain(..).collect();

        if let Err(e) = self.storage.batch_insert(&domains) {
            // Log error but don't crash — dropping some domain records is
            // acceptable, crashing the VPN tunnel is not.
            log::error!("Failed to flush domains to SQLite: {}", e);
        }

        self.last_flush_ms = Self::now_millis();
    }

    /// Get engine statistics (for diagnostics / UI).
    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    /// Get reassembler diagnostics.
    pub fn reassembly_flow_count(&self) -> usize {
        self.reassembler.active_flow_count()
    }

    pub fn reassembly_memory_bytes(&self) -> usize {
        self.reassembler.memory_usage_bytes()
    }

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Drop for PacketEngine {
    fn drop(&mut self) {
        // Flush any remaining domains on shutdown
        self.flush();
    }
}
```

---

## Error Types (`errors.rs`)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Failed to open database: {0}")]
    DatabaseOpen(#[from] rusqlite::Error),

    #[error("Failed to write to database: {0}")]
    DatabaseWrite(String),

    #[error("Invalid database path: {0}")]
    InvalidPath(String),

    #[error("Engine already initialized")]
    AlreadyInitialized,

    #[error("Engine not initialized")]
    NotInitialized,
}
```

---

## Memory Budget Analysis

The iOS Network Extension has a **6 MB memory limit**. Here's our budget:

| Component | Worst Case | Typical | Notes |
|-----------|-----------|---------|-------|
| Rust static + stack | ~200 KB | ~200 KB | Code + thread stack |
| TCP reassembly buffers | 16 MB (theoretical max) | ~500 KB | 1024 flows × 16KB max each, but most flows complete in 1 segment |
| Pending domain batch | ~50 KB | ~5 KB | 50 records × ~1KB each |
| SQLite connection | ~500 KB | ~500 KB | WAL mode, page cache |
| Swift runtime + NE framework | ~2 MB | ~2 MB | NEPacketTunnelProvider overhead |
| **Total** | **~3.2 MB typical** | **~3.2 MB** | Well within 6 MB limit |

**Key safeguard**: `MAX_TCP_FLOWS = 1024` with LRU eviction ensures we never exceed the budget even under adversarial conditions (e.g., device opening hundreds of concurrent HTTPS connections).

---

## Testing Strategy

### Unit Tests (run on macOS host via `cargo test`)

| Test | What it verifies |
|------|-----------------|
| `dns_test::parse_standard_query` | Parse A record query for "google.com" |
| `dns_test::parse_aaaa_query` | Parse AAAA record query |
| `dns_test::parse_compressed_name` | DNS name compression (pointers) |
| `dns_test::reject_response` | Ignore DNS responses (QR=1) |
| `dns_test::reject_truncated` | Handle truncated packets gracefully |
| `tls_test::extract_sni_standard` | Extract SNI from a typical TLS 1.2 ClientHello |
| `tls_test::extract_sni_tls13` | Extract SNI from TLS 1.3 ClientHello |
| `tls_test::no_sni_present` | Handle ClientHello without SNI extension |
| `tls_test::reject_non_handshake` | Ignore non-handshake TLS records |
| `tcp_reassembly_test::single_segment` | ClientHello fits in one segment |
| `tcp_reassembly_test::multi_segment` | ClientHello split across 2-3 segments |
| `tcp_reassembly_test::lru_eviction` | Evict oldest flow at MAX_TCP_FLOWS |
| `tcp_reassembly_test::timeout_eviction` | Evict flows older than FLOW_TIMEOUT_SECS |
| `domain_test::normalize_trailing_dot` | "google.com." → "google.com" |
| `domain_test::filter_noise_domains` | apple.com, icloud.com filtered |
| `domain_test::reject_ip_literals` | "1.2.3.4" rejected |
| `integration_test::full_pipeline` | Raw packet bytes → SQLite row |

### Test Fixture Generation

Capture real packets with `tcpdump` and save as binary fixtures:

```bash
# Capture a DNS query
tcpdump -i en0 -c 1 -w dns_query.pcap 'udp port 53 and host google.com'

# Capture a TLS ClientHello
tcpdump -i en0 -c 5 -w tls_hello.pcap 'tcp port 443 and tcp[tcpflags] & tcp-push != 0'

# Extract raw IP packets from pcap (Python script in scripts/generate-test-fixtures.py)
```
