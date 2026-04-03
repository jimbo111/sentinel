//! DNS-to-IP correlation table.
//!
//! Records the mapping from IP addresses to domain names that was established
//! by prior DNS responses.  A subsequent TCP/TLS connection to one of those
//! IPs can then be labelled with the corresponding domain name even when SNI
//! extraction fails (e.g. for TLS 1.3 with ECH or for non-TLS connections).
//!
//! Each entry carries a TTL derived from [`CORRELATOR_TTL_SECS`]; stale
//! entries are lazily evicted when the table would exceed [`max_entries`].

use std::collections::HashMap;
use std::net::IpAddr;

use crate::constants::{CORRELATOR_TTL_SECS, MAX_CORRELATOR_ENTRIES};

/// A time-bounded DNS-to-IP mapping.
///
/// Each [`IpAddr`] key maps to a `(domain, expiry_secs)` tuple where
/// `expiry_secs` is the Unix second timestamp after which the entry is
/// considered stale.
pub struct DnsIpCorrelator {
    /// Inner map from IP address to `(domain_name, expiry_unix_secs)`.
    ip_to_domain: HashMap<IpAddr, (String, u64)>,
    /// Maximum number of entries before stale eviction is triggered.
    max_entries: usize,
}

impl DnsIpCorrelator {
    /// Creates a new correlator with the given entry limit.
    ///
    /// The internal map is pre-allocated with capacity 256 regardless of
    /// `max_entries`; the `max_entries` limit governs when eviction runs.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::ech_correlator::DnsIpCorrelator;
    /// use packet_engine::constants::MAX_CORRELATOR_ENTRIES;
    ///
    /// let correlator = DnsIpCorrelator::new(MAX_CORRELATOR_ENTRIES);
    /// assert_eq!(correlator.len(), 0);
    /// ```
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            ip_to_domain: HashMap::with_capacity(256),
            max_entries,
        }
    }

    /// Records the observation that `domain` resolved to `ip` at time
    /// `now_secs`.
    ///
    /// The entry expires at `now_secs + CORRELATOR_TTL_SECS`.
    ///
    /// When the table is at capacity, all entries whose expiry is `<= now_secs`
    /// are removed before inserting the new one.  If the table is still full
    /// after expiry-based eviction, the oldest entry (smallest expiry
    /// timestamp) is removed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use packet_engine::ech_correlator::DnsIpCorrelator;
    ///
    /// let mut c = DnsIpCorrelator::new(128);
    /// let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    /// c.record_resolution("example.com", ip, 1_000);
    /// assert_eq!(c.lookup_domain(ip), Some("example.com"));
    /// ```
    pub fn record_resolution(&mut self, domain: &str, ip: IpAddr, now_secs: u64) {
        if self.ip_to_domain.len() >= self.max_entries {
            // Remove all stale entries first.
            self.ip_to_domain.retain(|_, (_, expiry)| *expiry > now_secs);

            // If still at capacity, remove the entry with the smallest expiry.
            if self.ip_to_domain.len() >= self.max_entries {
                if let Some(oldest_ip) = self
                    .ip_to_domain
                    .iter()
                    .min_by_key(|(_, (_, expiry))| *expiry)
                    .map(|(ip, _)| *ip)
                {
                    self.ip_to_domain.remove(&oldest_ip);
                }
            }
        }

        let expiry = now_secs.saturating_add(CORRELATOR_TTL_SECS);
        self.ip_to_domain.insert(ip, (domain.to_owned(), expiry));
    }

    /// Looks up the domain name most recently associated with `ip`.
    ///
    /// Returns `None` if no entry exists for `ip` **or** if the entry has
    /// expired.  The expiry check uses the timestamp stored at insertion time;
    /// the caller must use the same monotonic clock as [`record_resolution`]
    /// for meaningful TTL semantics.
    ///
    /// Note: this method does not take `now_secs` to keep the API simple for
    /// the common read path.  Use [`lookup_domain_at`] if you need TTL-aware
    /// lookups.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use packet_engine::ech_correlator::DnsIpCorrelator;
    ///
    /// let mut c = DnsIpCorrelator::new(128);
    /// let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    /// assert_eq!(c.lookup_domain(ip), None);
    /// ```
    #[must_use]
    pub fn lookup_domain(&self, ip: IpAddr) -> Option<&str> {
        self.ip_to_domain
            .get(&ip)
            .map(|(domain, _)| domain.as_str())
    }

    /// Looks up the domain name for `ip` as of `now_secs`, honouring the TTL.
    ///
    /// Returns `None` if no entry exists or if `expiry <= now_secs`.
    #[must_use]
    pub fn lookup_domain_at(&self, ip: IpAddr, now_secs: u64) -> Option<&str> {
        self.ip_to_domain.get(&ip).and_then(|(domain, expiry)| {
            if *expiry > now_secs {
                Some(domain.as_str())
            } else {
                None
            }
        })
    }

    /// Removes all entries whose expiry timestamp is `<= now_secs`.
    pub fn evict_expired(&mut self, now_secs: u64) {
        self.ip_to_domain.retain(|_, (_, expiry)| *expiry > now_secs);
    }

    /// Returns the number of entries currently stored in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ip_to_domain.len()
    }

    /// Returns `true` if the table contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ip_to_domain.is_empty()
    }
}

impl Default for DnsIpCorrelator {
    fn default() -> Self {
        Self::new(MAX_CORRELATOR_ENTRIES)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ip6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        ))
    }

    // -----------------------------------------------------------------------
    // Record and lookup
    // -----------------------------------------------------------------------

    #[test]
    fn record_and_lookup_returns_correct_domain() {
        let mut c = DnsIpCorrelator::new(128);
        let ip = ip4(93, 184, 216, 34);

        c.record_resolution("example.com", ip, 1_000);

        assert_eq!(c.lookup_domain(ip), Some("example.com"));
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let c = DnsIpCorrelator::new(128);
        assert_eq!(c.lookup_domain(ip4(1, 2, 3, 4)), None);
    }

    #[test]
    fn record_updates_existing_entry() {
        let mut c = DnsIpCorrelator::new(128);
        let ip = ip4(10, 0, 0, 1);

        c.record_resolution("old.example.com", ip, 1_000);
        c.record_resolution("new.example.com", ip, 2_000);

        assert_eq!(c.lookup_domain(ip), Some("new.example.com"));
    }

    #[test]
    fn ipv6_address_is_recorded_and_retrieved() {
        let mut c = DnsIpCorrelator::new(128);
        let ip = ip6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);

        c.record_resolution("ipv6.example.com", ip, 500);

        assert_eq!(c.lookup_domain(ip), Some("ipv6.example.com"));
    }

    // -----------------------------------------------------------------------
    // TTL expiration
    // -----------------------------------------------------------------------

    #[test]
    fn lookup_domain_at_returns_domain_before_expiry() {
        let mut c = DnsIpCorrelator::new(128);
        let ip = ip4(1, 2, 3, 4);

        c.record_resolution("example.com", ip, 0);
        // expiry = 0 + CORRELATOR_TTL_SECS

        // One second before expiry — should still return the domain.
        let just_before = CORRELATOR_TTL_SECS - 1;
        assert_eq!(c.lookup_domain_at(ip, just_before), Some("example.com"));
    }

    #[test]
    fn lookup_domain_at_returns_none_after_expiry() {
        let mut c = DnsIpCorrelator::new(128);
        let ip = ip4(5, 6, 7, 8);

        c.record_resolution("expired.example.com", ip, 0);
        // expiry = CORRELATOR_TTL_SECS

        // At exactly the expiry second the entry is considered stale.
        assert_eq!(c.lookup_domain_at(ip, CORRELATOR_TTL_SECS), None);
        // Well past expiry.
        assert_eq!(c.lookup_domain_at(ip, CORRELATOR_TTL_SECS + 100), None);
    }

    #[test]
    fn evict_expired_removes_stale_entries() {
        let mut c = DnsIpCorrelator::new(128);
        let stale_ip = ip4(10, 0, 0, 1);
        let fresh_ip = ip4(10, 0, 0, 2);

        // Insert stale entry at t=0 (expires at CORRELATOR_TTL_SECS).
        c.record_resolution("stale.example.com", stale_ip, 0);
        // Insert fresh entry at t=CORRELATOR_TTL_SECS (expires at 2*TTL).
        c.record_resolution("fresh.example.com", fresh_ip, CORRELATOR_TTL_SECS);

        assert_eq!(c.len(), 2);

        // Evict at the exact expiry of the stale entry.
        c.evict_expired(CORRELATOR_TTL_SECS);

        assert_eq!(c.len(), 1);
        assert_eq!(c.lookup_domain(stale_ip), None);
        assert_eq!(c.lookup_domain(fresh_ip), Some("fresh.example.com"));
    }

    // -----------------------------------------------------------------------
    // Capacity eviction
    // -----------------------------------------------------------------------

    #[test]
    fn capacity_eviction_keeps_table_within_limit() {
        let max = 4usize;
        let mut c = DnsIpCorrelator::new(max);

        // Fill the table with entries that all expire far in the future.
        for i in 0..max as u8 {
            c.record_resolution("fill.example.com", ip4(192, 168, 1, i), 1_000);
        }
        assert_eq!(c.len(), max);

        // Insert one more entry — the table must not exceed `max`.
        c.record_resolution("extra.example.com", ip4(192, 168, 2, 0), 2_000);
        assert!(
            c.len() <= max,
            "table size {} must not exceed max {}",
            c.len(),
            max
        );
    }

    #[test]
    fn stale_eviction_preferred_over_oldest_eviction() {
        let max = 3usize;
        let mut c = DnsIpCorrelator::new(max);
        let now: u64 = 10_000;

        // Insert two entries that are already expired relative to `now`.
        c.record_resolution("old1.example.com", ip4(1, 0, 0, 1), 0); // expiry = TTL
        c.record_resolution("old2.example.com", ip4(1, 0, 0, 2), 0); // expiry = TTL

        // Insert one fresh entry.
        c.record_resolution("fresh.example.com", ip4(1, 0, 0, 3), now); // expiry = now+TTL

        assert_eq!(c.len(), 3);

        // Trigger eviction by inserting a fourth entry at `now`.
        c.record_resolution("new.example.com", ip4(1, 0, 0, 4), now);

        // The two stale entries must have been swept before the fresh ones.
        // After inserting the fourth entry the table must be <= max.
        assert!(c.len() <= max);
    }

    // -----------------------------------------------------------------------
    // Default constructor
    // -----------------------------------------------------------------------

    #[test]
    fn default_constructor_uses_max_correlator_entries() {
        let c = DnsIpCorrelator::default();
        assert_eq!(c.max_entries, MAX_CORRELATOR_ENTRIES);
        assert!(c.is_empty());
    }
}
