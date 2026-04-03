//! TCP stream reassembly for TLS ClientHello SNI extraction.
//!
//! Tracks a bounded set of TCP flows and reassembles their payloads until a
//! complete TLS ClientHello can be parsed.  Flows are evicted either when they
//! time out or when the table reaches [`MAX_TCP_FLOWS`] capacity (LRU policy).

use std::collections::HashMap;
use std::net::IpAddr;

use crate::constants::{FLOW_TIMEOUT_SECS, MAX_FLOW_BUFFER_BYTES, MAX_TCP_FLOWS};
use crate::domain::DomainRecord;
use crate::tls;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Identifies one direction of a TCP connection.
///
/// The key is direction-sensitive: `(src, dst, sport, dport)` and its reverse
/// are treated as distinct flows.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source TCP port.
    pub src_port: u16,
    /// Destination TCP port.
    pub dst_port: u16,
}

/// Result returned by [`TcpReassembler::process_segment`].
#[derive(Debug)]
pub enum ReassemblyResult {
    /// A complete TLS ClientHello was parsed and an SNI domain was extracted.
    Complete(DomainRecord),
    /// The ClientHello is incomplete — more segments are needed.
    NeedMore,
    /// The segment does not belong to a TLS ClientHello flow.
    NotRelevant,
}

// ---------------------------------------------------------------------------
// Private types
// ---------------------------------------------------------------------------

/// Reassembly buffer for one TCP flow direction.
struct FlowBuffer {
    /// Accumulated payload bytes.
    data: Vec<u8>,
    /// Unix timestamp (seconds) of the most recent segment seen.
    last_seen: u64,
    /// When known from the TLS record length field, the total byte count
    /// required before a parse attempt is made.
    expected_len: Option<usize>,
}

// ---------------------------------------------------------------------------
// TcpReassembler
// ---------------------------------------------------------------------------

/// Stateful reassembler that buffers TCP payloads per flow and extracts SNI
/// hostnames from TLS ClientHello messages.
///
/// # Resource limits
///
/// * At most [`MAX_TCP_FLOWS`] concurrent flows are tracked.  When the table is
///   full the least-recently-used flow (the one with the smallest `last_seen`
///   timestamp) is evicted before inserting a new one.
/// * Each individual flow buffer is capped at [`MAX_FLOW_BUFFER_BYTES`].
/// * Flows that have not received a segment within [`FLOW_TIMEOUT_SECS`] are
///   removed on the next call to [`process_segment`].
pub struct TcpReassembler {
    /// Active flow buffers keyed by [`FlowKey`].
    flows: HashMap<FlowKey, FlowBuffer>,
}

impl TcpReassembler {
    /// Creates a new reassembler with pre-allocated capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: HashMap::with_capacity(256),
        }
    }

    /// Processes one TCP segment for the given flow.
    ///
    /// Returns:
    /// - [`ReassemblyResult::Complete`] — an SNI was extracted.
    /// - [`ReassemblyResult::NeedMore`] — the flow is being tracked but the
    ///   ClientHello is not yet complete.
    /// - [`ReassemblyResult::NotRelevant`] — the payload is not a TLS
    ///   ClientHello and the flow is not already tracked.
    ///
    /// `now_secs` should be a monotonically increasing Unix timestamp used for
    /// timeout accounting.
    pub fn process_segment(
        &mut self,
        key: FlowKey,
        tcp_payload: &[u8],
        now_secs: u64,
    ) -> ReassemblyResult {
        if tcp_payload.is_empty() {
            if self.flows.contains_key(&key) {
                return ReassemblyResult::NeedMore;
            }
            return ReassemblyResult::NotRelevant;
        }

        // Evict timed-out flows before doing anything else.
        self.evict_expired(now_secs);

        // ----------------------------------------------------------------
        // Case 1 — Existing flow: append data and check for completion.
        // ----------------------------------------------------------------
        if self.flows.contains_key(&key) {
            let buf = self.flows.get_mut(&key).expect("key must be present");
            buf.last_seen = now_secs;

            // Enforce per-flow buffer limit.
            let remaining_capacity = MAX_FLOW_BUFFER_BYTES.saturating_sub(buf.data.len());
            let bytes_to_append = tcp_payload.len().min(remaining_capacity);
            buf.data.extend_from_slice(&tcp_payload[..bytes_to_append]);

            // Check whether we have accumulated the expected number of bytes.
            let ready = match buf.expected_len {
                Some(expected) => buf.data.len() >= expected,
                // No expected length recorded yet — try to derive it now.
                None => {
                    if let Some(expected) = tls_record_total_len(&buf.data) {
                        buf.expected_len = Some(expected);
                        buf.data.len() >= expected
                    } else {
                        false
                    }
                }
            };

            if ready {
                let data = buf.data.clone();
                self.remove_flow(&key);
                return extract_domain_from_hello(&data);
            }

            // Buffer exhausted without completing — give up on this flow.
            if buf.data.len() >= MAX_FLOW_BUFFER_BYTES {
                self.remove_flow(&key);
                return ReassemblyResult::NotRelevant;
            }

            return ReassemblyResult::NeedMore;
        }

        // ----------------------------------------------------------------
        // Case 2 — New flow: only track if it looks like a ClientHello.
        // ----------------------------------------------------------------
        if !tls::is_tls_client_hello_start(tcp_payload) {
            return ReassemblyResult::NotRelevant;
        }

        // Fast path: the entire ClientHello fits in the first segment.
        if let Some(record) = tls::extract_sni(tcp_payload) {
            let tls_version = tls::extract_tls_version(tcp_payload);
            return ReassemblyResult::Complete(record.with_tls_version(tls_version));
        }

        // Need more segments — start buffering.

        // Evict LRU if at capacity.
        if self.flows.len() >= MAX_TCP_FLOWS {
            self.evict_lru();
        }

        let expected_len = tls_record_total_len(tcp_payload);

        let mut data = Vec::with_capacity(tcp_payload.len().min(MAX_FLOW_BUFFER_BYTES));
        let bytes_to_copy = tcp_payload.len().min(MAX_FLOW_BUFFER_BYTES);
        data.extend_from_slice(&tcp_payload[..bytes_to_copy]);

        let buf = FlowBuffer {
            data,
            last_seen: now_secs,
            expected_len,
        };

        self.flows.insert(key, buf);

        ReassemblyResult::NeedMore
    }

    /// Removes all flows whose last-seen timestamp is older than
    /// `now_secs - FLOW_TIMEOUT_SECS`.
    pub fn evict_expired(&mut self, now_secs: u64) {
        let cutoff = now_secs.saturating_sub(FLOW_TIMEOUT_SECS);
        self.flows.retain(|_k, buf| buf.last_seen >= cutoff);
    }

    /// Evicts the least-recently-used flow.
    ///
    /// Finds the entry with the smallest `last_seen` timestamp and removes it.
    /// This is O(n) in the number of active flows, but eviction only occurs
    /// when the table is at capacity, which is an infrequent event.
    pub fn evict_lru(&mut self) {
        let oldest_key = self
            .flows
            .iter()
            .min_by_key(|(_k, buf)| buf.last_seen)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            self.flows.remove(&key);
        }
    }

    /// Removes the flow identified by `key` from the flow table.
    pub fn remove_flow(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    /// Returns the number of currently tracked flows.
    #[must_use]
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Returns an approximate count of heap bytes consumed by all flow buffers.
    ///
    /// Does not include the overhead of the `HashMap` or `Vec` control
    /// structures themselves.
    #[must_use]
    pub fn memory_usage_bytes(&self) -> usize {
        self.flows.values().map(|b| b.data.len()).sum()
    }

}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Computes the total byte length expected for the TLS record whose header
/// begins at `data[0]`.  Returns `None` if `data` is too short to contain
/// the 5-byte TLS record header.
///
/// The returned value is `5 + record_payload_length`.
#[must_use]
fn tls_record_total_len(data: &[u8]) -> Option<usize> {
    if data.len() < 5 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    Some(5 + payload_len)
}

/// Attempts to extract a [`DomainRecord`] from a fully-assembled TLS
/// ClientHello buffer.
///
/// When SNI extraction succeeds, `extract_tls_version` is also called on the
/// same buffer and the result is attached to the record via `with_tls_version`.
fn extract_domain_from_hello(data: &[u8]) -> ReassemblyResult {
    match tls::extract_sni(data) {
        Some(record) => {
            let tls_version = tls::extract_tls_version(data);
            ReassemblyResult::Complete(record.with_tls_version(tls_version))
        }
        None => ReassemblyResult::NotRelevant,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::build_test_client_hello;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_key(src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
        }
    }

    // -----------------------------------------------------------------------
    // Single-segment ClientHello -> Complete
    // -----------------------------------------------------------------------

    #[test]
    fn single_segment_client_hello_returns_complete() {
        let hello = build_test_client_hello("example.com");
        let mut reassembler = TcpReassembler::new();
        let key = make_key(12345, 443);

        let result = reassembler.process_segment(key, &hello, 1000);

        match result {
            ReassemblyResult::Complete(record) => {
                assert_eq!(record.domain, "example.com");
                assert_eq!(record.source, crate::domain::DetectionSource::Sni);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Non-TLS payload -> NotRelevant
    // -----------------------------------------------------------------------

    #[test]
    fn non_tls_payload_returns_not_relevant() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reassembler = TcpReassembler::new();
        let key = make_key(54321, 80);

        let result = reassembler.process_segment(key, payload, 1000);

        assert!(
            matches!(result, ReassemblyResult::NotRelevant),
            "non-TLS payload must yield NotRelevant"
        );
        assert_eq!(reassembler.active_flow_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Flow eviction at capacity
    // -----------------------------------------------------------------------

    #[test]
    fn lru_eviction_at_capacity() {
        let mut reassembler = TcpReassembler::new();

        // A partial ClientHello — 6 bytes is enough to pass is_tls_client_hello_start
        // (needs bytes 0, 1, and 5) but not enough to extract the SNI, so the
        // flow stays buffered.
        let hello = build_test_client_hello("evict.example.com");
        let partial = &hello[..6];

        // Fill the table to exactly MAX_TCP_FLOWS using the same timestamp so
        // that no timeout eviction occurs during the fill phase.
        let fill_time: u64 = 1_000_000;
        for i in 0..MAX_TCP_FLOWS as u16 {
            let key = make_key(i, 443);
            let _ = reassembler.process_segment(key, partial, fill_time);
        }

        assert_eq!(reassembler.active_flow_count(), MAX_TCP_FLOWS);

        // Insert one more at the same timestamp — one existing flow must be
        // evicted to stay within MAX_TCP_FLOWS (no timeout eviction at this
        // timestamp because all flows share fill_time).
        let new_key = make_key(u16::MAX, 443);
        let _ = reassembler.process_segment(new_key.clone(), partial, fill_time);

        assert!(
            reassembler.active_flow_count() <= MAX_TCP_FLOWS,
            "flow count {} exceeds MAX_TCP_FLOWS {}",
            reassembler.active_flow_count(),
            MAX_TCP_FLOWS
        );
        // Exactly one flow must have been evicted (all had the same timestamp,
        // so one was chosen arbitrarily by the LRU scan).
        assert_eq!(
            reassembler.active_flow_count(),
            MAX_TCP_FLOWS,
            "flow count must be exactly MAX_TCP_FLOWS after eviction + insert"
        );
        assert!(
            reassembler.flows.contains_key(&new_key),
            "newly inserted flow must be present"
        );
    }

    // -----------------------------------------------------------------------
    // Timeout eviction
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_eviction_removes_stale_flows() {
        let hello = build_test_client_hello("stale.example.com");
        let partial = &hello[..6];

        let mut reassembler = TcpReassembler::new();

        // Insert a flow at t=0.
        let key = make_key(9000, 443);
        let _ = reassembler.process_segment(key.clone(), partial, 0);
        assert_eq!(reassembler.active_flow_count(), 1);

        // Advance time past the timeout threshold and feed an unrelated segment
        // to trigger the eviction sweep.
        let other_key = make_key(9001, 80);
        let now = FLOW_TIMEOUT_SECS + 1;
        let _ = reassembler.process_segment(other_key, b"not tls data!", now);

        assert_eq!(
            reassembler.active_flow_count(),
            0,
            "stale flow must be evicted after timeout"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-segment reassembly
    // -----------------------------------------------------------------------

    #[test]
    fn multi_segment_client_hello_reassembled() {
        let hello = build_test_client_hello("multi.example.com");
        let mid = hello.len() / 2;

        let mut reassembler = TcpReassembler::new();
        let key = make_key(11111, 443);

        let r1 = reassembler.process_segment(key.clone(), &hello[..mid], 1000);
        assert!(
            matches!(r1, ReassemblyResult::NeedMore),
            "first half must return NeedMore, got {r1:?}"
        );

        let r2 = reassembler.process_segment(key, &hello[mid..], 1001);
        match r2 {
            ReassemblyResult::Complete(record) => {
                assert_eq!(record.domain, "multi.example.com");
            }
            other => panic!("expected Complete after second segment, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Utility methods
    // -----------------------------------------------------------------------

    #[test]
    fn memory_usage_bytes_reflects_buffered_data() {
        let hello = build_test_client_hello("mem.example.com");
        let partial = &hello[..6];
        let mut reassembler = TcpReassembler::new();

        let _ = reassembler.process_segment(make_key(7777, 443), partial, 1000);
        assert!(
            reassembler.memory_usage_bytes() > 0,
            "memory_usage_bytes must be positive after buffering"
        );
    }

    #[test]
    fn active_flow_count_is_zero_after_complete() {
        let hello = build_test_client_hello("count.example.com");
        let mut reassembler = TcpReassembler::new();

        let _ = reassembler.process_segment(make_key(8888, 443), &hello, 1000);
        assert_eq!(
            reassembler.active_flow_count(),
            0,
            "completed flows must be removed from the table"
        );
    }
}
