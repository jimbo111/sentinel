//! DNS response rewriting — ECH stripping from SVCB / HTTPS resource records.
//!
//! Encrypted Client Hello (ECH) configuration blobs embedded in HTTPS and SVCB
//! DNS records let servers advertise TLS ECH support.  Stripping the `ech=`
//! SvcParam prevents clients on the local network from using ECH, which would
//! otherwise hide the SNI from the packet engine.
//!
//! The rewriter only modifies packets that contain HTTPS/SVCB records with an
//! ECH SvcParam; all other packets are returned as-is.

use crate::constants::DNS_HEADER_SIZE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DNS RR type for SVCB (RFC 9460).
const DNS_TYPE_SVCB: u16 = 64;

/// DNS RR type for HTTPS (RFC 9460).
const DNS_TYPE_HTTPS: u16 = 65;

/// SvcParamKey for ECH (RFC 9460 §14.3.2).
const SVCPARAM_KEY_ECH: u16 = 5;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of running [`filter_ech_from_dns_response`].
#[derive(Debug, PartialEq, Eq)]
pub enum FilterResult {
    /// The packet was not a DNS response (QR bit = 0) or was too short.
    NotDnsResponse,
    /// The packet is a valid DNS response but required no modification.
    Unmodified,
    /// The packet contained HTTPS/SVCB records with ECH params that were
    /// stripped.  The inner `Vec<u8>` is the rewritten UDP payload.
    Modified(Vec<u8>),
}

/// Inspects a raw UDP payload and, if it is a DNS response containing
/// HTTPS or SVCB records that advertise ECH, rewrites it to remove those
/// SvcParams.
///
/// The function is designed to be zero-copy when no modification is needed:
/// only [`FilterResult::Modified`] allocates a new buffer.
///
/// # Behaviour
///
/// * Non-responses (QR=0) return [`FilterResult::NotDnsResponse`].
/// * Responses with no HTTPS/SVCB answers return [`FilterResult::Unmodified`].
/// * Responses whose HTTPS/SVCB answers contain no ECH SvcParam return
///   [`FilterResult::Unmodified`].
/// * Responses where ECH stripping succeeds return
///   [`FilterResult::Modified`].
/// * Any parse error during rewriting causes a safe fallback to
///   [`FilterResult::Unmodified`] — the original packet is forwarded intact.
#[must_use]
pub fn filter_ech_from_dns_response(udp_payload: &[u8]) -> FilterResult {
    if udp_payload.len() < DNS_HEADER_SIZE {
        return FilterResult::NotDnsResponse;
    }

    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);

    // Only process responses (QR bit = 1).
    if flags & 0x8000 == 0 {
        return FilterResult::NotDnsResponse;
    }

    let qd_count = u16::from_be_bytes([udp_payload[4], udp_payload[5]]);
    let an_count = u16::from_be_bytes([udp_payload[6], udp_payload[7]]);
    let ns_count = u16::from_be_bytes([udp_payload[8], udp_payload[9]]);
    let ar_count = u16::from_be_bytes([udp_payload[10], udp_payload[11]]);

    if an_count == 0 {
        return FilterResult::Unmodified;
    }

    // Quick scan — skip the full rewrite if no HTTPS/SVCB RR is present.
    if !quick_scan_for_https_rr(udp_payload, qd_count, an_count) {
        return FilterResult::Unmodified;
    }

    // Full rewrite pass.
    match rewrite_dns_response(udp_payload, qd_count, an_count, ns_count, ar_count) {
        Some(rewritten) => FilterResult::Modified(rewritten),
        None => FilterResult::Unmodified,
    }
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

/// Performs a fast scan through the question and answer sections to determine
/// whether any answer RR has type HTTPS (65) or SVCB (64).
///
/// Returns `true` if such a record is found, `false` otherwise (including on
/// any parse error).
#[must_use]
pub fn quick_scan_for_https_rr(data: &[u8], qd_count: u16, an_count: u16) -> bool {
    let mut offset = DNS_HEADER_SIZE;

    // Skip question section.
    for _ in 0..qd_count {
        if skip_dns_name(data, &mut offset).is_none() {
            return false;
        }
        // QTYPE + QCLASS = 4 bytes.
        if offset + 4 > data.len() {
            return false;
        }
        offset += 4;
    }

    // Scan answer section for HTTPS/SVCB types.
    for _ in 0..an_count {
        if skip_dns_name(data, &mut offset).is_none() {
            return false;
        }
        // Need TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
        if offset + 10 > data.len() {
            return false;
        }
        let rr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 8; // skip TYPE + CLASS + TTL
        let rd_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if rr_type == DNS_TYPE_HTTPS || rr_type == DNS_TYPE_SVCB {
            return true;
        }

        offset = match offset.checked_add(rd_len) {
            Some(v) if v <= data.len() => v,
            _ => return false,
        };
    }

    false
}

/// Rewrites a DNS response by walking all RR sections and stripping the ECH
/// SvcParam from any HTTPS/SVCB record whose RDATA contains it.
///
/// Returns `Some(new_payload)` when at least one ECH param was stripped,
/// `None` when no modification was necessary or on any parse error.
#[must_use]
pub fn rewrite_dns_response(
    data: &[u8],
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut modified = false;

    // Copy DNS header verbatim.
    if data.len() < DNS_HEADER_SIZE {
        return None;
    }
    out.extend_from_slice(&data[..DNS_HEADER_SIZE]);
    let mut offset = DNS_HEADER_SIZE;

    // Copy question section verbatim.
    for _ in 0..qd_count {
        let name_start = offset;
        skip_dns_name(data, &mut offset)?;
        // QTYPE + QCLASS
        if offset + 4 > data.len() {
            return None;
        }
        offset += 4;
        out.extend_from_slice(&data[name_start..offset]);
    }

    // Process answer, authority, and additional sections.
    let total_rr = (an_count as usize)
        .checked_add(ns_count as usize)?
        .checked_add(ar_count as usize)?;

    for _ in 0..total_rr {
        let rr_start = offset;

        // Owner name.
        skip_dns_name(data, &mut offset)?;
        let name_end = offset;

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if offset + 10 > data.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 8; // TYPE + CLASS + TTL
        let rd_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let rdata_start = offset;
        let rdata_end = rdata_start.checked_add(rd_len)?;
        if rdata_end > data.len() {
            return None;
        }

        if rr_type == DNS_TYPE_HTTPS || rr_type == DNS_TYPE_SVCB {
            let rdata = &data[rdata_start..rdata_end];
            match strip_ech_from_svcb_rdata(rdata, data) {
                Some(new_rdata) => {
                    // Write owner name.
                    out.extend_from_slice(&data[rr_start..name_end]);
                    // Write TYPE + CLASS + TTL.
                    out.extend_from_slice(&data[name_end..rdata_start - 2]);
                    // Write updated RDLENGTH.
                    let new_rd_len = new_rdata.len() as u16;
                    out.extend_from_slice(&new_rd_len.to_be_bytes());
                    // Write updated RDATA.
                    out.extend_from_slice(&new_rdata);
                    modified = true;
                }
                None => {
                    // No ECH in this record — copy verbatim.
                    out.extend_from_slice(&data[rr_start..rdata_end]);
                }
            }
        } else {
            out.extend_from_slice(&data[rr_start..rdata_end]);
        }

        offset = rdata_end;
    }

    if modified {
        Some(out)
    } else {
        None
    }
}

/// Strips the ECH SvcParam from an SVCB/HTTPS RDATA blob.
///
/// RDATA layout (RFC 9460):
/// ```text
/// SvcPriority (2) | TargetName (DNS name) | SvcParams (key=2, len=2, value)*
/// ```
///
/// Returns `Some(new_rdata)` when the ECH param was removed, `None` when
/// either no ECH param exists or the RDATA is malformed.
///
/// `full_msg` is the complete DNS message buffer, needed to resolve DNS name
/// compression pointers inside TargetName.
#[must_use]
pub fn strip_ech_from_svcb_rdata(rdata: &[u8], full_msg: &[u8]) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }

    // SvcPriority (2 bytes).
    let mut pos = 2usize;

    // TargetName — DNS wire-format name, potentially compressed.
    skip_dns_name_in_rdata(rdata, &mut pos)?;

    // Walk SvcParams looking for the ECH key.
    let params_start = pos;
    let mut found_ech = false;
    let mut scan = params_start;
    while scan + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[scan], rdata[scan + 1]]);
        let val_len = u16::from_be_bytes([rdata[scan + 2], rdata[scan + 3]]) as usize;
        scan += 4;
        let val_end = scan.checked_add(val_len)?;
        if val_end > rdata.len() {
            return None;
        }
        if key == SVCPARAM_KEY_ECH {
            found_ech = true;
        }
        scan = val_end;
    }

    if !found_ech {
        return None;
    }

    // Rebuild RDATA without the ECH param.
    let mut new_rdata: Vec<u8> = Vec::with_capacity(rdata.len());
    // SvcPriority + TargetName.
    new_rdata.extend_from_slice(&rdata[..params_start]);

    let mut scan = params_start;
    while scan + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[scan], rdata[scan + 1]]);
        let val_len = u16::from_be_bytes([rdata[scan + 2], rdata[scan + 3]]) as usize;
        let val_end = scan.checked_add(4)?.checked_add(val_len)?;
        if val_end > rdata.len() {
            return None;
        }
        if key != SVCPARAM_KEY_ECH {
            new_rdata.extend_from_slice(&rdata[scan..val_end]);
        }
        scan = val_end;
    }

    // Suppress unused-variable warning; full_msg is available for pointer
    // resolution if a future implementation needs it.
    let _ = full_msg;

    Some(new_rdata)
}

/// Advances `offset` past a DNS wire-format name in `data`.
///
/// Handles both plain label sequences and compression pointers (0xC0 prefix).
/// The offset is always updated to the position in `data` *after* the name
/// (i.e. after the zero-length root label or the 2-byte pointer).
///
/// Returns `Some(())` on success, `None` on any parse error.
#[must_use]
pub fn skip_dns_name(data: &[u8], offset: &mut usize) -> Option<()> {
    let mut pos = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;
    const MAX_JUMPS: usize = 16;

    loop {
        if pos >= data.len() {
            return None;
        }
        let byte = data[pos];

        if byte == 0x00 {
            // End of name.  Only update the caller's offset when we have not
            // already advanced it past a compression pointer.
            if !jumped {
                *offset = pos + 1;
            }
            return Some(());
        }

        if byte & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total.
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                // Advance the caller's offset past the pointer.
                *offset = pos + 2;
            }
            jumped = true;
            let ptr = (((byte & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            pos = ptr;
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
            continue;
        }

        if byte & 0xC0 != 0x00 {
            // Reserved label type — treat as malformed.
            return None;
        }

        // Regular label: skip length byte + label bytes.
        let label_len = byte as usize;
        let next = pos.checked_add(1)?.checked_add(label_len)?;
        if next > data.len() {
            return None;
        }
        pos = next;
    }
}

/// Advances `offset` past a DNS wire-format name contained *within RDATA*.
///
/// SVCB TargetName is stored in the RDATA slice (a sub-slice of the full
/// message), so compression pointers would resolve relative to the *full*
/// message.  For the purposes of this function we only handle uncompressed
/// names; a compression pointer causes the offset to skip the 2-byte pointer
/// and the function returns `Some(())` immediately (the pointed-to labels are
/// not inspected here because we only need to advance past the field).
#[must_use]
pub fn skip_dns_name_in_rdata(rdata: &[u8], offset: &mut usize) -> Option<()> {
    let mut pos = *offset;

    loop {
        if pos >= rdata.len() {
            return None;
        }
        let byte = rdata[pos];

        if byte == 0x00 {
            *offset = pos + 1;
            return Some(());
        }

        if byte & 0xC0 == 0xC0 {
            // Compression pointer — treat as a 2-byte terminal.
            if pos + 1 >= rdata.len() {
                return None;
            }
            *offset = pos + 2;
            return Some(());
        }

        if byte & 0xC0 != 0x00 {
            return None;
        }

        let label_len = byte as usize;
        let next = pos.checked_add(1)?.checked_add(label_len)?;
        if next > rdata.len() {
            return None;
        }
        pos = next;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Wire-format helpers
    // -----------------------------------------------------------------------

    /// Encodes a dotted domain name into DNS wire format (length-prefixed labels
    /// terminated by a zero byte).
    fn encode_name(domain: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in domain.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0x00);
        out
    }

    /// Builds a minimal DNS header.
    fn dns_header(flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&[0x00, 0x01]); // ID
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&an.to_be_bytes());
        h.extend_from_slice(&ns.to_be_bytes());
        h.extend_from_slice(&ar.to_be_bytes());
        h
    }

    /// Builds an SVCB/HTTPS RDATA blob.
    ///
    /// `params` is a slice of `(key, value)` pairs.
    fn build_svcb_rdata(priority: u16, target: &str, params: &[(u16, &[u8])]) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&encode_name(target));
        for (key, val) in params {
            rdata.extend_from_slice(&key.to_be_bytes());
            rdata.extend_from_slice(&(val.len() as u16).to_be_bytes());
            rdata.extend_from_slice(val);
        }
        rdata
    }

    /// Builds a complete DNS response containing a single HTTPS answer RR.
    fn build_https_response(domain: &str, svcb_rdata: &[u8]) -> Vec<u8> {
        // Flags: QR=1, AA=1
        let mut pkt = dns_header(0x8400, 1, 1, 0, 0);

        // Question section.
        pkt.extend_from_slice(&encode_name(domain));
        pkt.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes()); // QTYPE=HTTPS
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        // Answer RR: compression pointer to offset 12.
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes()); // TYPE
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        pkt.extend_from_slice(&(svcb_rdata.len() as u16).to_be_bytes()); // RDLENGTH
        pkt.extend_from_slice(svcb_rdata);

        pkt
    }

    // -----------------------------------------------------------------------
    // filter_ech_from_dns_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn dns_query_returns_not_dns_response() {
        // QR=0 => query.
        let mut pkt = dns_header(0x0100, 1, 0, 0, 0);
        pkt.extend_from_slice(&encode_name("example.com"));
        pkt.extend_from_slice(&[0x00, 0x41, 0x00, 0x01]); // QTYPE=HTTPS, QCLASS=IN

        assert_eq!(
            filter_ech_from_dns_response(&pkt),
            FilterResult::NotDnsResponse
        );
    }

    #[test]
    fn response_with_no_https_rr_returns_unmodified() {
        // Build a response with a single A record (type 1) answer.
        let domain_wire = encode_name("example.com");
        let mut pkt = dns_header(0x8180, 1, 1, 0, 0);

        // Question
        pkt.extend_from_slice(&domain_wire);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN

        // Answer
        pkt.extend_from_slice(&[0xC0, 0x0C]); // ptr
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        pkt.extend_from_slice(&[93, 184, 216, 34]); // RDATA

        assert_eq!(
            filter_ech_from_dns_response(&pkt),
            FilterResult::Unmodified
        );
    }

    #[test]
    fn https_rr_without_ech_returns_unmodified() {
        // HTTPS record with only alpn= (key 1), no ECH.
        let rdata = build_svcb_rdata(1, "example.com", &[(1, b"h2")]);
        let pkt = build_https_response("example.com", &rdata);

        assert_eq!(
            filter_ech_from_dns_response(&pkt),
            FilterResult::Unmodified
        );
    }

    #[test]
    fn https_rr_with_ech_returns_modified() {
        // HTTPS record with alpn= and ech= params.
        let fake_ech = b"\x00\x01\x02\x03\x04";
        let rdata = build_svcb_rdata(1, "example.com", &[(1, b"h2"), (SVCPARAM_KEY_ECH, fake_ech)]);
        let pkt = build_https_response("example.com", &rdata);

        let result = filter_ech_from_dns_response(&pkt);
        assert!(
            matches!(result, FilterResult::Modified(_)),
            "HTTPS RR with ECH must return Modified"
        );
    }

    #[test]
    fn ech_param_absent_in_rewritten_packet() {
        let fake_ech = b"\xde\xad\xbe\xef";
        let rdata = build_svcb_rdata(1, "example.com", &[(1, b"h2"), (SVCPARAM_KEY_ECH, fake_ech)]);
        let pkt = build_https_response("example.com", &rdata);

        if let FilterResult::Modified(rewritten) = filter_ech_from_dns_response(&pkt) {
            // The rewritten packet must not contain the raw ECH bytes.
            let ech_in_rewritten = rewritten
                .windows(fake_ech.len())
                .any(|w| w == fake_ech);
            assert!(
                !ech_in_rewritten,
                "ECH value bytes must be absent from the rewritten packet"
            );
        } else {
            panic!("expected Modified result");
        }
    }

    #[test]
    fn truncated_packet_returns_safe_fallback() {
        // Feed a 3-byte slice — below DNS_HEADER_SIZE.
        let pkt = [0x81u8, 0x80, 0x00];
        assert_eq!(
            filter_ech_from_dns_response(&pkt),
            FilterResult::NotDnsResponse
        );
    }

    #[test]
    fn malformed_rdata_returns_unmodified() {
        // Build a packet where the HTTPS RDATA is only 1 byte (malformed).
        let mut pkt = dns_header(0x8400, 1, 1, 0, 0);

        let domain_wire = encode_name("example.com");
        pkt.extend_from_slice(&domain_wire);
        pkt.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        pkt.extend_from_slice(&[0xC0, 0x0C]); // ptr
        pkt.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        pkt.extend_from_slice(&[0x00, 0x01]); // RDLENGTH=1
        pkt.push(0xFF); // 1 byte of junk RDATA

        // strip_ech_from_svcb_rdata will return None, so the result must be
        // Unmodified (safe fallback).
        let result = filter_ech_from_dns_response(&pkt);
        assert!(
            matches!(result, FilterResult::Unmodified),
            "malformed RDATA must return Unmodified, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // strip_ech_from_svcb_rdata unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn strip_ech_removes_only_ech_param() {
        let fake_ech = b"\x01\x02\x03";
        let rdata = build_svcb_rdata(1, "example.com", &[(1, b"h2"), (SVCPARAM_KEY_ECH, fake_ech), (3, b"\x00\x05")]);
        let full_msg = vec![0u8; 64]; // placeholder

        let stripped = strip_ech_from_svcb_rdata(&rdata, &full_msg)
            .expect("ECH stripping should succeed");

        // ECH param (key=5) must be absent.
        let mut scan = 0usize;
        // Skip SvcPriority (2) + TargetName.
        scan += 2;
        let _ = {
            let mut pos = scan;
            let _ = skip_dns_name_in_rdata(&stripped, &mut pos);
            scan = pos;
        };

        while scan + 4 <= stripped.len() {
            let key = u16::from_be_bytes([stripped[scan], stripped[scan + 1]]);
            assert_ne!(key, SVCPARAM_KEY_ECH, "ECH param must be absent after stripping");
            let val_len = u16::from_be_bytes([stripped[scan + 2], stripped[scan + 3]]) as usize;
            scan += 4 + val_len;
        }
    }

    #[test]
    fn strip_ech_returns_none_when_no_ech_present() {
        let rdata = build_svcb_rdata(1, "example.com", &[(1, b"h2")]);
        let full_msg = vec![0u8; 64];

        assert!(
            strip_ech_from_svcb_rdata(&rdata, &full_msg).is_none(),
            "must return None when no ECH param is present"
        );
    }
}
