use crate::ip::{self, IpProtocol};
use std::collections::{HashMap, HashSet};

// Compile-time assertion: BATCH_FLUSH_INTERVAL_MS must fit in i64 so that the
// cast in maybe_flush is safe for any future value of the constant.
const _: () = assert!(
    crate::constants::BATCH_FLUSH_INTERVAL_MS <= i64::MAX as u64,
    "BATCH_FLUSH_INTERVAL_MS must fit in i64"
);
use crate::dns;
use crate::tls;
use crate::tcp_reassembly::{TcpReassembler, FlowKey, ReassemblyResult};
use crate::dns_filter::{self, FilterResult};
use crate::ech_correlator::DnsIpCorrelator;
use crate::domain::{DomainRecord, DetectionSource};
use crate::storage::DomainStorage;
use crate::errors::EngineError;
use crate::constants::*;
use crate::threat_matcher::{ThreatMatch, ThreatMatcher};
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of processing a packet.
pub enum ProcessResult {
    /// Forward the original packet unchanged (the common case)
    Forward,
    /// Replace the original packet with this modified version
    Replace(Vec<u8>),
    /// Block: synthesize a DNS response with 0.0.0.0 (sinkhole)
    Block(Vec<u8>),
}

/// The main packet processing engine.
///
/// Owns all mutable state and is NOT thread-safe (no need —
/// the Network Extension packet loop is single-threaded).
pub struct PacketEngine {
    reassembler: TcpReassembler,
    storage: DomainStorage,
    dns_correlator: DnsIpCorrelator,
    /// Batch buffer: domains waiting to be flushed to SQLite
    pending_domains: Vec<DomainRecord>,
    /// Batch buffer: (domain, ip, timestamp_ms) pairs for domain_ips table
    pending_domain_ips: Vec<(String, String, i64)>,
    /// Batch buffer: (domain, query_type, query_type_name, timestamp_ms) for dns_query_types
    pending_query_types: Vec<(String, u16, String, i64)>,
    /// Per-domain accumulated byte counts: domain → (bytes_in, bytes_out).
    pending_bytes: HashMap<String, (u64, u64)>,
    /// Timestamp of last flush (Unix millis)
    last_flush_ms: i64,
    /// Counters for diagnostics
    stats: EngineStats,
    /// Whether active ECH downgrade is enabled
    pub ech_downgrade_enabled: bool,
    /// Whether to filter well-known noise domains (Apple, CDN, mDNS, etc.)
    pub noise_filter_enabled: bool,
    /// Optional threat detection engine; `None` until the first feed is loaded.
    threat_matcher: Option<ThreatMatcher>,
    /// Pending threat alerts to flush to SQLite.
    pending_alerts: Vec<ThreatMatch>,
    /// Domains that have already produced an alert in this session.
    /// Prevents duplicate alerts for the same domain queried repeatedly.
    alerted_domains: HashSet<String>,
}

/// Aggregate statistics for threat detection.
#[derive(Debug, Default, Clone)]
pub struct ThreatStats {
    /// Number of domains blocked by the threat matcher.
    pub threats_blocked: u64,
    /// Number of domains that hit a feed but were on the allowlist.
    pub threats_allowed: u64,
    /// Total threat domains across all loaded feeds.
    pub feed_domain_count: usize,
    /// Number of feeds loaded.
    pub feeds_loaded: usize,
}

#[derive(Debug, Default)]
pub struct EngineStats {
    pub packets_processed: u64,
    pub dns_domains_found: u64,
    pub sni_domains_found: u64,
    pub packets_skipped: u64,
    pub ech_configs_stripped: u64,
    pub ech_connections: u64,
    pub ech_resolved_via_dns: u64,
    pub ech_unresolved: u64,
    pub ech_grease_seen: u64,
    /// Number of times a flush to SQLite failed.
    pub flush_errors: u64,
}

impl PacketEngine {
    /// Initialize the engine with a path to the SQLite database.
    pub fn new(db_path: &str) -> Result<Self, EngineError> {
        let storage = DomainStorage::new(db_path)?;

        Ok(PacketEngine {
            reassembler: TcpReassembler::new(),
            storage,
            dns_correlator: DnsIpCorrelator::new(MAX_CORRELATOR_ENTRIES),
            pending_domains: Vec::with_capacity(BATCH_INSERT_SIZE),
            pending_domain_ips: Vec::new(),
            pending_query_types: Vec::new(),
            pending_bytes: HashMap::new(),
            last_flush_ms: Self::now_millis(),
            stats: EngineStats::default(),
            ech_downgrade_enabled: false,
            noise_filter_enabled: true,
            threat_matcher: None,
            pending_alerts: Vec::new(),
            alerted_domains: HashSet::new(),
        })
    }

    /// Process a single raw IP packet.
    ///
    /// Returns ProcessResult::Forward for unmodified passthrough,
    /// or ProcessResult::Replace with a modified packet (ECH downgrade).
    pub fn process_packet(&mut self, packet: &[u8]) -> ProcessResult {
        self.stats.packets_processed += 1;

        let ip_header = match ip::parse_ip_header(packet) {
            Some(h) => h,
            None => {
                self.stats.packets_skipped += 1;
                return ProcessResult::Forward;
            }
        };

        if ip_header.payload_offset >= packet.len() {
            self.stats.packets_skipped += 1;
            return ProcessResult::Forward;
        }

        // --- Byte volume tracking -----------------------------------------
        // Correlate the packet's source/destination IP against the DNS
        // resolution table and accumulate bytes toward the associated domain.
        let now_secs_for_bytes = Self::now_secs();
        let total_bytes = ip_header.total_length as u64;

        if let Some(domain) =
            self.dns_correlator.lookup_domain_at(ip_header.dst_addr, now_secs_for_bytes)
        {
            // Outbound: device is sending to this domain's IP.
            let entry = self.pending_bytes.entry(domain.to_owned()).or_insert((0, 0));
            entry.1 = entry.1.saturating_add(total_bytes);
        }

        if let Some(domain) =
            self.dns_correlator.lookup_domain_at(ip_header.src_addr, now_secs_for_bytes)
        {
            // Inbound: device is receiving from this domain's IP.
            let entry = self.pending_bytes.entry(domain.to_owned()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(total_bytes);
        }
        // ------------------------------------------------------------------

        let transport_data = &packet[ip_header.payload_offset..];

        let result = match ip_header.protocol {
            IpProtocol::Udp => self.handle_udp(packet, transport_data, &ip_header),
            IpProtocol::Tcp => {
                self.handle_tcp(transport_data, &ip_header);
                ProcessResult::Forward
            }
            _ => {
                self.stats.packets_skipped += 1;
                ProcessResult::Forward
            }
        };

        self.maybe_flush();
        result
    }

    /// Handle a UDP segment.
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

        // Outbound DNS query (to port 53)
        if dst_port == DNS_PORT {
            let records = dns::parse_dns_query(udp_payload);
            let mut should_block = false;

            for record in records {
                if self.noise_filter_enabled && crate::domain::is_noise_domain(&record.domain) {
                    continue;
                }
                self.stats.dns_domains_found += 1;

                // Threat check before buffering the domain.
                if let Some(ref mut matcher) = self.threat_matcher {
                    if let Some(threat) = matcher.check_domain(&record.domain) {
                        should_block = true;
                        // Dedup: only record one alert per domain per session.
                        // Cap at 10K entries to prevent unbounded memory growth
                        // during long-running sessions.
                        if self.alerted_domains.len() >= 10_000 {
                            self.alerted_domains.clear();
                        }
                        if self.alerted_domains.insert(threat.domain.clone()) {
                            self.pending_alerts.push(threat);
                        }
                    }
                }

                self.pending_domains
                    .push(record.with_source(DetectionSource::Dns));
            }

            // If a threat was detected, synthesize a sinkhole DNS response
            // (A 0.0.0.0) so the connection fails immediately instead of
            // timing out after 5 seconds.
            if should_block {
                if let Some(sinkhole) = build_dns_sinkhole_response(udp_payload) {
                    let blocked_packet = rebuild_udp_packet(
                        full_packet,
                        ip_header,
                        transport_data,
                        &sinkhole,
                    );
                    return ProcessResult::Block(blocked_packet);
                }
            }

            // Capture all query types (including non-A/AAAA) as metadata.
            let now_ms = Self::now_millis();
            let query_types = dns::parse_dns_query_types(udp_payload);
            for (domain, qtype) in query_types {
                if self.noise_filter_enabled && crate::domain::is_noise_domain(&domain) {
                    continue;
                }
                let type_name = dns::query_type_name(qtype).to_owned();
                self.pending_query_types.push((domain, qtype, type_name, now_ms));
            }

            return ProcessResult::Forward;
        }

        // Inbound DNS response (from port 53)
        if src_port == DNS_PORT {
            // Parse DNS response for IP correlation
            let resolutions = dns::parse_dns_response(udp_payload);
            let now = Self::now_secs();
            let now_ms = Self::now_millis();
            for (domain, ip) in &resolutions {
                self.dns_correlator.record_resolution(domain, *ip, now);
                // Record the resolved IP address for the domain.
                if !self.noise_filter_enabled || !crate::domain::is_noise_domain(domain) {
                    self.pending_domain_ips
                        .push((domain.clone(), ip.to_string(), now_ms));
                }
            }

            // Active ECH downgrade: strip ech= from HTTPS RRs
            if self.ech_downgrade_enabled {
                match dns_filter::filter_ech_from_dns_response(udp_payload) {
                    FilterResult::Modified(new_udp_payload) => {
                        self.stats.ech_configs_stripped += 1;

                        let new_packet = rebuild_udp_packet(
                            full_packet,
                            ip_header,
                            transport_data,
                            &new_udp_payload,
                        );

                        return ProcessResult::Replace(new_packet);
                    }
                    FilterResult::Unmodified | FilterResult::NotDnsResponse => {}
                }
            }

            return ProcessResult::Forward;
        }

        ProcessResult::Forward
    }

    /// Handle a TCP segment. Check if it's destined for port 443 (HTTPS)
    /// and try to extract SNI from the TLS ClientHello.
    fn handle_tcp(&mut self, transport_data: &[u8], ip_header: &ip::IpHeader) {
        if transport_data.len() < 20 {
            return;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

        if dst_port != HTTPS_PORT {
            return;
        }

        // TCP data offset (upper 4 bits of byte 12, in 32-bit words)
        let data_offset = ((transport_data[12] >> 4) as usize) * 4;
        if data_offset > transport_data.len() {
            return;
        }

        let tcp_payload = &transport_data[data_offset..];
        if tcp_payload.is_empty() {
            return;
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
                if self.noise_filter_enabled && crate::domain::is_noise_domain(&record.domain) {
                    return;
                }
                self.stats.sni_domains_found += 1;

                // Threat check before buffering the domain.
                if let Some(ref mut matcher) = self.threat_matcher {
                    if let Some(threat) = matcher.check_domain(&record.domain) {
                        self.pending_alerts.push(threat);
                    }
                }

                self.pending_domains
                    .push(record.with_source(DetectionSource::Sni));
            }
            ReassemblyResult::NeedMore | ReassemblyResult::NotRelevant => {
                // For ECH fallback: if we detect ECH, try DNS/IP correlation
                if tcp_payload.len() >= 6 && tls::is_tls_client_hello_start(tcp_payload) {
                    // Check if this is an ECH ClientHello
                    // We'd need the full extensions to detect ECH,
                    // but for the correlation fallback we use the dst IP
                    if let Some(domain) =
                        self.dns_correlator.lookup_domain_at(ip_header.dst_addr, now)
                    {
                        let _ = domain; // correlation logic used in Phase 5 integration
                    }
                }
            }
        }
    }

    /// Flush pending data to SQLite if batch is full or timer expired.
    fn maybe_flush(&mut self) {
        let has_pending = !self.pending_domains.is_empty()
            || !self.pending_domain_ips.is_empty()
            || !self.pending_query_types.is_empty()
            || !self.pending_bytes.is_empty()
            || !self.pending_alerts.is_empty();

        if !has_pending {
            return;
        }

        let now = Self::now_millis();
        let elapsed = now.saturating_sub(self.last_flush_ms);

        let should_flush = self.pending_domains.len() >= BATCH_INSERT_SIZE
            || elapsed >= BATCH_FLUSH_INTERVAL_MS as i64;

        if should_flush {
            self.flush();
        }
    }

    /// Force-flush all pending domains, destination IPs, query types, byte
    /// counters, and threat alerts to SQLite.
    pub fn flush(&mut self) {
        if self.pending_domains.is_empty()
            && self.pending_domain_ips.is_empty()
            && self.pending_query_types.is_empty()
            && self.pending_bytes.is_empty()
            && self.pending_alerts.is_empty()
        {
            return;
        }

        if !self.pending_domains.is_empty() {
            let domains: Vec<DomainRecord> = self.pending_domains.drain(..).collect();
            if let Err(e) = self.storage.batch_insert(&domains) {
                log::error!("Failed to flush domains to SQLite: {}", e);
                self.stats.flush_errors += 1;
            }
        }

        if !self.pending_domain_ips.is_empty() {
            let ips: Vec<_> = self.pending_domain_ips.drain(..).collect();
            if let Err(e) = self.storage.batch_upsert_domain_ips(&ips) {
                log::error!("Failed to flush domain IPs: {}", e);
                self.stats.flush_errors += 1;
            }
        }

        if !self.pending_query_types.is_empty() {
            let qtypes: Vec<_> = self.pending_query_types.drain(..).collect();
            if let Err(e) = self.storage.batch_upsert_query_types(&qtypes) {
                log::error!("Failed to flush query types: {}", e);
                self.stats.flush_errors += 1;
            }
        }

        if !self.pending_bytes.is_empty() {
            let bytes: Vec<_> = self
                .pending_bytes
                .drain()
                .map(|(d, (bi, bo))| (d, bi, bo))
                .collect();
            if let Err(e) = self.storage.batch_update_domain_bytes(&bytes) {
                log::error!("Failed to flush byte counts: {}", e);
                self.stats.flush_errors += 1;
            }
        }

        if !self.pending_alerts.is_empty() {
            let alerts: Vec<ThreatMatch> = self.pending_alerts.drain(..).collect();
            for alert in &alerts {
                if let Err(e) = self.storage.insert_alert(
                    &alert.domain,
                    alert.threat_type.as_str(),
                    &alert.feed_name,
                    alert.confidence,
                    alert.timestamp_ms,
                ) {
                    log::error!("Failed to flush threat alert to SQLite: {}", e);
                    self.stats.flush_errors += 1;
                }
            }
        }

        self.last_flush_ms = Self::now_millis();
    }

    /// Get engine statistics.
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

    /// Cleanup old visits. `retention_days` must be positive.
    pub fn cleanup_old_data(&self, retention_days: i64) -> Result<usize, EngineError> {
        if retention_days <= 0 {
            return Err(EngineError::DatabaseWrite(
                "retention_days must be positive".to_string(),
            ));
        }
        let cutoff_ms = Self::now_millis() - (retention_days * 86_400_000);
        self.storage.cleanup_old_visits(cutoff_ms)
    }

    // ═══════════════════════════════════════════════════════════
    // Threat detection API
    // ═══════════════════════════════════════════════════════════

    /// Parse `data` as a hosts-format list and register it as a threat feed.
    ///
    /// Initialises the internal [`ThreatMatcher`] on first call.  Subsequent
    /// calls add additional feeds.
    ///
    /// The feed is checked against every domain seen by the engine from this
    /// point forward; historical domains already in SQLite are not
    /// retroactively scanned.
    pub fn load_threat_feed(&mut self, data: &str, feed_name: &str) {
        let matcher = self.threat_matcher.get_or_insert_with(ThreatMatcher::new);
        matcher.load_feed(data, feed_name);
    }

    /// Add `domain` to the in-memory allowlist **and** persist it to SQLite.
    ///
    /// Allowlisted domains will not generate alerts even if they appear in a
    /// loaded threat feed.
    pub fn add_allowlist_domain(&mut self, domain: &str) {
        if let Some(ref mut matcher) = self.threat_matcher {
            matcher.add_allowlist(domain);
        }
        let now_ms = Self::now_millis();
        if let Err(e) = self.storage.insert_allowlist(domain, now_ms) {
            log::error!("Failed to persist allowlist entry for {}: {}", domain, e);
        }
    }

    /// Remove `domain` from the in-memory allowlist **and** from SQLite.
    pub fn remove_allowlist_domain(&mut self, domain: &str) {
        if let Some(ref mut matcher) = self.threat_matcher {
            matcher.remove_allowlist(domain);
        }
        if let Err(e) = self.storage.remove_allowlist(domain) {
            log::error!("Failed to remove allowlist entry for {}: {}", domain, e);
        }
    }

    /// Return a snapshot of threat detection statistics.
    ///
    /// Returns zeroed stats if no threat feeds have been loaded.
    #[must_use]
    pub fn threat_stats(&self) -> ThreatStats {
        match &self.threat_matcher {
            Some(m) => ThreatStats {
                threats_blocked: m.threats_blocked,
                threats_allowed: m.threats_allowed,
                feed_domain_count: m.total_threat_domains(),
                feeds_loaded: m.feeds_loaded(),
            },
            None => ThreatStats::default(),
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Private helpers
    // ═══════════════════════════════════════════════════════════

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64
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
        self.flush();
    }
}

/// Rebuild a UDP packet with a new payload.
fn rebuild_udp_packet(
    original_packet: &[u8],
    ip_header: &ip::IpHeader,
    original_transport: &[u8],
    new_udp_payload: &[u8],
) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(ip_header.payload_offset + 8 + new_udp_payload.len());

    // Copy IP header
    packet.extend_from_slice(&original_packet[..ip_header.payload_offset]);

    // Copy UDP header (src_port, dst_port) — first 4 bytes
    if original_transport.len() >= 4 {
        packet.extend_from_slice(&original_transport[..4]);
    } else {
        return original_packet.to_vec();
    }

    // New UDP length = 8 (header) + new payload length
    let new_udp_len = (8 + new_udp_payload.len()) as u16;
    packet.extend_from_slice(&new_udp_len.to_be_bytes());

    // UDP checksum: zero is valid for IPv4 (RFC 768); mandatory for IPv6 (RFC 8200).
    // We fill the checksum field after appending the payload so we can compute
    // it over the complete UDP datagram together with the IPv6 pseudo-header.
    let checksum_offset = packet.len(); // remember where the 2-byte field lives
    packet.extend_from_slice(&[0x00, 0x00]); // placeholder

    // New payload
    packet.extend_from_slice(new_udp_payload);

    // Fix IP total length field
    let new_total_len = packet.len() as u16;
    match ip_header.version {
        4 => {
            if packet.len() >= 4 {
                packet[2] = (new_total_len >> 8) as u8;
                packet[3] = (new_total_len & 0xFF) as u8;
                recalculate_ipv4_checksum(&mut packet, ip_header.payload_offset);
            }
        }
        6 => {
            if packet.len() >= 40 {
                let payload_len = (packet.len() - 40) as u16;
                packet[4] = (payload_len >> 8) as u8;
                packet[5] = (payload_len & 0xFF) as u8;

                // Compute and write the mandatory IPv6 UDP checksum (RFC 8200).
                // The IPv6 source address lives at bytes 8..24 and destination
                // at 24..40 of a standard 40-byte IPv6 header.
                if packet.len() >= 40 {
                    let src: [u8; 16] = packet[8..24].try_into().unwrap_or([0u8; 16]);
                    let dst: [u8; 16] = packet[24..40].try_into().unwrap_or([0u8; 16]);
                    // The UDP datagram starts at payload_offset (== 40 for a
                    // plain IPv6 header with no extension headers).
                    let udp_datagram = &packet[ip_header.payload_offset..];
                    let cksum = compute_udp_checksum_ipv6(&src, &dst, udp_datagram);
                    packet[checksum_offset] = (cksum >> 8) as u8;
                    packet[checksum_offset + 1] = (cksum & 0xFF) as u8;
                }
            }
        }
        _ => {}
    }

    packet
}

/// Compute the UDP checksum for an IPv6 packet per RFC 8200.
///
/// The pseudo-header consists of:
/// - Source address (16 bytes)
/// - Destination address (16 bytes)
/// - UDP length as a 32-bit big-endian value (4 bytes)
/// - Next-header value 17 (UDP) as a 32-bit big-endian value (4 bytes)
///
/// `udp_datagram` must be the full UDP header (8 bytes) followed by the payload.
/// Returns the one's-complement 16-bit checksum; a computed value of 0x0000
/// is returned as 0xFFFF per RFC 768.
fn compute_udp_checksum_ipv6(src: &[u8; 16], dst: &[u8; 16], udp_datagram: &[u8]) -> u16 {
    let udp_len = udp_datagram.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header: source address.
    for chunk in src.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    // Pseudo-header: destination address.
    for chunk in dst.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    // Pseudo-header: UDP length (as u32 big-endian).
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;
    // Pseudo-header: next header = 17 (as u32 big-endian → 0x00000011).
    sum += 0x0011_u32;

    // UDP header + payload.
    let mut i = 0;
    while i + 1 < udp_datagram.len() {
        sum += ((udp_datagram[i] as u32) << 8) | (udp_datagram[i + 1] as u32);
        i += 2;
    }
    // Handle an odd trailing byte.
    if i < udp_datagram.len() {
        sum += (udp_datagram[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16-bit.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !sum as u16;
    // RFC 768: a checksum of 0x0000 means "no checksum"; use 0xFFFF instead.
    if result == 0x0000 { 0xFFFF } else { result }
}

/// Recalculate the IPv4 header checksum.
fn recalculate_ipv4_checksum(packet: &mut [u8], header_len: usize) {
    if packet.len() < header_len || header_len < 12 {
        return;
    }

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

/// Build a DNS sinkhole response for a blocked query.
///
/// Takes the original DNS query payload and constructs a valid DNS response
/// with the same transaction ID and question section, but answering with
/// `A 0.0.0.0` (TTL 60s).  Returns `None` if the query payload is too short
/// to parse.
fn build_dns_sinkhole_response(query_payload: &[u8]) -> Option<Vec<u8>> {
    // Minimum DNS header is 12 bytes.
    if query_payload.len() < 12 {
        return None;
    }

    let mut resp = Vec::with_capacity(query_payload.len() + 16);

    // Copy transaction ID (bytes 0–1).
    resp.extend_from_slice(&query_payload[0..2]);

    // Flags: 0x8180 = response, recursion desired + available, no error.
    resp.extend_from_slice(&[0x81, 0x80]);

    // QDCOUNT = 1 (copy from query for safety, but force to 1).
    resp.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT = 1.
    resp.extend_from_slice(&[0x00, 0x01]);
    // NSCOUNT = 0, ARCOUNT = 0.
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Copy the question section from the original query.
    // Walk past the 12-byte header to find the end of the QNAME.
    let mut pos = 12;
    while pos < query_payload.len() {
        let label_len = query_payload[pos] as usize;
        if label_len == 0 {
            pos += 1; // skip the zero-length root label
            break;
        }
        pos += 1 + label_len;
    }
    // QTYPE (2 bytes) + QCLASS (2 bytes).
    pos += 4;

    if pos > query_payload.len() {
        return None;
    }

    // Append question section.
    resp.extend_from_slice(&query_payload[12..pos]);

    // Answer section: NAME = pointer to offset 12 (0xC00C), TYPE A, CLASS IN,
    // TTL 60, RDLENGTH 4, RDATA 0.0.0.0.
    resp.extend_from_slice(&[
        0xC0, 0x0C, // name pointer to question QNAME
        0x00, 0x01, // TYPE = A
        0x00, 0x01, // CLASS = IN
        0x00, 0x00, 0x00, 0x3C, // TTL = 60 seconds
        0x00, 0x04, // RDLENGTH = 4
        0x00, 0x00, 0x00, 0x00, // RDATA = 0.0.0.0
    ]);

    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_query_packet(domain: &str) -> Vec<u8> {
        let mut udp_payload = Vec::new();

        // DNS header: ID=0x1234, Flags=0x0100 (standard query), QDCOUNT=1
        udp_payload.extend_from_slice(&[
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]);

        // Question: domain name in wire format
        for label in domain.split('.') {
            udp_payload.push(label.len() as u8);
            udp_payload.extend_from_slice(label.as_bytes());
        }
        udp_payload.push(0x00); // root label

        // QTYPE = A (1), QCLASS = IN (1)
        udp_payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Build UDP header
        let udp_len = (8 + udp_payload.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&[0xAB, 0xCD]); // src port
        udp.extend_from_slice(&[0x00, 0x35]); // dst port 53
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]); // checksum
        udp.extend_from_slice(&udp_payload);

        // Build IPv4 header (20 bytes)
        let total_len = (20 + udp.len()) as u16;
        let mut packet = vec![
            0x45, // version=4, IHL=5
            0x00, // DSCP/ECN
            (total_len >> 8) as u8,
            (total_len & 0xFF) as u8,
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // TTL
            17,   // protocol = UDP
            0x00, 0x00, // checksum (skip for test)
            10, 0, 0, 1, // src IP
            8, 8, 8, 8, // dst IP
        ];
        packet.extend_from_slice(&udp);
        packet
    }

    fn build_tls_client_hello_packet(hostname: &str) -> Vec<u8> {
        let sni_bytes = hostname.as_bytes();
        let sni_ext_len = 5 + sni_bytes.len();
        let sni_list_len = 3 + sni_bytes.len();

        let mut extensions = Vec::new();
        // SNI extension
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        extensions.push(0x00); // host_name type
        extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni_bytes);

        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        client_hello.extend_from_slice(&[0u8; 32]); // random
        client_hello.push(0); // session ID length
        client_hello.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // cipher suites
        client_hello.extend_from_slice(&[0x01, 0x00]); // compression methods
        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        let hs_len = client_hello.len();
        let mut handshake = vec![0x01]; // ClientHello
        handshake.push(0);
        handshake.extend_from_slice(&(hs_len as u16).to_be_bytes());
        handshake.extend_from_slice(&client_hello);

        let record_len = handshake.len();
        let mut tls_record = vec![0x16, 0x03, 0x01]; // TLS handshake
        tls_record.extend_from_slice(&(record_len as u16).to_be_bytes());
        tls_record.extend_from_slice(&handshake);

        // TCP header (20 bytes, data offset = 5)
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&[0xC0, 0x00]); // src port
        tcp.extend_from_slice(&[0x01, 0xBB]); // dst port 443
        tcp.extend_from_slice(&[0x00; 4]); // seq
        tcp.extend_from_slice(&[0x00; 4]); // ack
        tcp.push(0x50); // data offset = 5 (20 bytes)
        tcp.push(0x18); // flags
        tcp.extend_from_slice(&[0xFF, 0xFF]); // window
        tcp.extend_from_slice(&[0x00, 0x00]); // checksum
        tcp.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        tcp.extend_from_slice(&tls_record);

        // IPv4 header
        let total_len = (20 + tcp.len()) as u16;
        let mut packet = vec![
            0x45, 0x00,
            (total_len >> 8) as u8,
            (total_len & 0xFF) as u8,
            0x00, 0x00, 0x00, 0x00,
            0x40, 6, // protocol = TCP
            0x00, 0x00,
            10, 0, 0, 1,
            93, 184, 216, 34,
        ];
        packet.extend_from_slice(&tcp);
        packet
    }

    #[test]
    fn engine_processes_dns_query() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let packet = build_dns_query_packet("github.com");

        let result = engine.process_packet(&packet);
        assert!(matches!(result, ProcessResult::Forward));

        engine.flush();
        assert_eq!(engine.storage.domain_count().unwrap(), 1);
        assert_eq!(engine.stats.dns_domains_found, 1);
    }

    #[test]
    fn engine_processes_tls_client_hello() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let packet = build_tls_client_hello_packet("github.com");

        let result = engine.process_packet(&packet);
        assert!(matches!(result, ProcessResult::Forward));

        engine.flush();
        assert_eq!(engine.storage.domain_count().unwrap(), 1);
        assert_eq!(engine.stats.sni_domains_found, 1);
    }

    #[test]
    fn engine_skips_non_ip_packets() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let garbage = vec![0xFF; 20];

        let result = engine.process_packet(&garbage);
        assert!(matches!(result, ProcessResult::Forward));
        assert_eq!(engine.stats.packets_skipped, 1);
    }

    #[test]
    fn engine_stats_accumulate() {
        let mut engine = PacketEngine::new(":memory:").unwrap();

        let dns = build_dns_query_packet("example.com");
        engine.process_packet(&dns);

        let tls = build_tls_client_hello_packet("example.org");
        engine.process_packet(&tls);

        assert_eq!(engine.stats.packets_processed, 2);
        assert_eq!(engine.stats.dns_domains_found, 1);
        assert_eq!(engine.stats.sni_domains_found, 1);
    }

    #[test]
    fn engine_has_pending_domains_before_flush() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let packet = build_dns_query_packet("droptest.com");
        engine.process_packet(&packet);
        // Domain is pending (batch threshold not reached, timer not expired)
        assert_eq!(engine.pending_domains.len(), 1);
        // After explicit flush, pending is empty and domain is in DB
        engine.flush();
        assert_eq!(engine.pending_domains.len(), 0);
        assert_eq!(engine.storage.domain_count().unwrap(), 1);
    }

    // ═══════════════════════════════════════════════════════════
    // Threat detection integration tests
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn dns_query_to_threat_domain_produces_alert_after_flush() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        engine.load_threat_feed("evil-test.com\n", "phishing");

        let packet = build_dns_query_packet("evil-test.com");
        engine.process_packet(&packet);

        // Alert must be pending before flush.
        assert_eq!(engine.pending_alerts.len(), 1, "one alert must be pending");

        engine.flush();

        // After flush, pending_alerts is drained.
        assert_eq!(engine.pending_alerts.len(), 0);

        // Alert must be in SQLite.
        let count = engine.storage.get_alert_count().unwrap();
        assert_eq!(count, 1, "one alert must be stored in SQLite after flush");
    }

    #[test]
    fn clean_dns_query_produces_no_alert() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        engine.load_threat_feed("evil-test.com\n", "phishing");

        let packet = build_dns_query_packet("safe-domain.com");
        engine.process_packet(&packet);
        engine.flush();

        let count = engine.storage.get_alert_count().unwrap();
        assert_eq!(count, 0, "no alert for a clean domain");
    }

    #[test]
    fn allowlisted_threat_domain_does_not_produce_alert() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        engine.load_threat_feed("evil-test.com\n", "phishing");
        engine.add_allowlist_domain("evil-test.com");

        let packet = build_dns_query_packet("evil-test.com");
        engine.process_packet(&packet);
        engine.flush();

        let count = engine.storage.get_alert_count().unwrap();
        assert_eq!(count, 0, "allowlisted domain must not produce an alert");

        // threats_allowed must be incremented.
        let stats = engine.threat_stats();
        assert_eq!(stats.threats_allowed, 1);
        assert_eq!(stats.threats_blocked, 0);
    }

    #[test]
    fn threat_stats_are_accurate() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        engine.load_threat_feed("evil1.com\nevil2.com\n", "malware");

        let p1 = build_dns_query_packet("evil1.com");
        let p2 = build_dns_query_packet("evil2.com");
        let p3 = build_dns_query_packet("safe.com");
        engine.process_packet(&p1);
        engine.process_packet(&p2);
        engine.process_packet(&p3);
        engine.flush();

        let stats = engine.threat_stats();
        assert_eq!(stats.threats_blocked, 2);
        assert_eq!(stats.threats_allowed, 0);
        assert_eq!(stats.feed_domain_count, 2);
        assert_eq!(stats.feeds_loaded, 1);
    }

    #[test]
    fn remove_allowlist_re_enables_alert() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        engine.load_threat_feed("evil-test.com\n", "phishing");
        engine.add_allowlist_domain("evil-test.com");

        // First pass — allowlisted, no alert.
        engine.process_packet(&build_dns_query_packet("evil-test.com"));
        engine.flush();
        assert_eq!(engine.storage.get_alert_count().unwrap(), 0);

        // Remove from allowlist.
        engine.remove_allowlist_domain("evil-test.com");

        // Second pass — should now produce an alert.
        engine.process_packet(&build_dns_query_packet("evil-test.com"));
        engine.flush();
        assert_eq!(engine.storage.get_alert_count().unwrap(), 1);
    }

    #[test]
    fn no_threat_matcher_means_no_alerts() {
        // Engine with no feeds loaded must not panic and produce zero alerts.
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let packet = build_dns_query_packet("anything.com");
        engine.process_packet(&packet);
        engine.flush();
        assert_eq!(engine.storage.get_alert_count().unwrap(), 0);
    }
}
