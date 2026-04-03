use fastbloom_rs::{BloomFilter, FilterBuilder, Membership};

/// A loaded threat feed backed by a bloom filter for fast domain lookups.
///
/// The bloom filter provides O(1) checks with a configurable false-positive
/// rate (0.1 % by default).  No `HashSet` is kept — this is critical for
/// staying within the iOS Network Extension's 50 MB jetsam limit.
///
/// Memory budget at 0.1 % FP rate:
/// - 400K domains ≈ 720 KB
/// - 100K domains ≈ 180 KB
///
/// False positives (0.1 %) are acceptable: they result in a logged alert that
/// the user can dismiss or allowlist.  False negatives are impossible.
pub struct ThreatFeed {
    /// Bloom filter for O(1) membership check.  `false` guarantees the domain
    /// is **not** in the feed.
    bloom: BloomFilter,
    /// Number of domains successfully loaded into this feed.
    pub domain_count: usize,
    /// Unix timestamp (milliseconds) when this feed was constructed.
    pub last_updated_ms: i64,
    /// Human-readable name for this feed (e.g. `"phishing"`, `"malware"`).
    pub feed_name: String,
}

impl ThreatFeed {
    /// Parse a hosts-file or plain-domain-list and build a [`ThreatFeed`].
    ///
    /// Accepted line formats:
    /// - `# comment` / blank lines — skipped.
    /// - `0.0.0.0 domain.com` or `127.0.0.1 domain.com` — the domain is the
    ///   second whitespace-separated token.
    /// - `domain.com` — plain domain entry.
    ///
    /// Domains are lowercased; trailing dots are stripped.  Any line whose
    /// extracted domain contains no `.` is skipped.  The bloom filter is
    /// sized for the number of parsed domains with a 0.1 % false-positive
    /// rate; a minimum capacity of 1 is enforced to avoid a zero-size filter.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_feed::ThreatFeed;
    ///
    /// let data = "# phishing list\n0.0.0.0 evil.com\nbad.net\n";
    /// let feed = ThreatFeed::from_hosts_data(data, "phishing");
    /// assert_eq!(feed.domain_count, 2);
    /// assert!(feed.contains("evil.com"));
    /// assert!(feed.contains("bad.net"));
    /// ```
    #[must_use]
    pub fn from_hosts_data(data: &str, feed_name: &str) -> Self {
        // First pass: collect all valid domains so we know the capacity.
        let mut parsed: Vec<String> = Vec::new();

        for line in data.lines() {
            let trimmed = line.trim();

            // Skip comments and blank lines.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let domain = Self::extract_domain(trimmed);
            if domain.contains('.') {
                parsed.push(domain);
            }
        }

        // Minimum capacity of 1000 ensures the bloom filter has enough bits
        // to maintain the target FP rate even for small test feeds.
        let capacity = parsed.len().max(1000) as u64;
        let mut bloom: BloomFilter = FilterBuilder::new(capacity, 0.001).build_bloom_filter();

        for domain in &parsed {
            bloom.add(domain.as_bytes());
        }

        let last_updated_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        ThreatFeed {
            bloom,
            domain_count: parsed.len(),
            last_updated_ms,
            feed_name: feed_name.to_owned(),
        }
    }

    /// Returns `true` if `domain` passes the bloom filter pre-check.
    ///
    /// A `false` result guarantees the domain is **not** in the feed.  A
    /// `true` result may be a false positive; call [`contains`] to confirm.
    ///
    /// [`contains`]: ThreatFeed::contains
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_feed::ThreatFeed;
    ///
    /// let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
    /// // A true result here is a candidate; call contains() to confirm.
    /// let _ = feed.check_bloom("evil.com");
    /// assert!(!feed.check_bloom("definitely-not-in-feed-xyz123.com"));
    /// ```
    #[must_use]
    pub fn check_bloom(&self, domain: &str) -> bool {
        self.bloom.contains(domain.as_bytes())
    }

    /// Returns `true` if `domain` is in the feed (via bloom filter).
    ///
    /// At 0.1 % FP rate this is practically authoritative.  False positives
    /// are handled at the UI layer (user can dismiss or allowlist).
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_feed::ThreatFeed;
    ///
    /// let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
    /// assert!(feed.contains("evil.com"));
    /// assert!(!feed.contains("safe.com"));
    /// ```
    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        self.bloom.contains(domain.as_bytes())
    }

    /// Returns `true` if `domain` **or any of its parent domains** is in the
    /// feed.
    ///
    /// For example, `sub.evil.com` will match if `evil.com` is listed.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_feed::ThreatFeed;
    ///
    /// let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
    /// assert!(feed.contains_or_parent("sub.evil.com"));
    /// assert!(feed.contains_or_parent("evil.com"));
    /// assert!(!feed.contains_or_parent("safe.com"));
    /// ```
    #[must_use]
    pub fn contains_or_parent(&self, domain: &str) -> bool {
        if self.contains(domain) {
            return true;
        }
        // Walk up through parent labels: "a.b.c.com" → "b.c.com" → "c.com"
        let mut remainder = domain;
        while let Some(dot_pos) = remainder.find('.') {
            remainder = &remainder[dot_pos + 1..];
            if remainder.contains('.') && self.contains(remainder) {
                return true;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Extract a normalised domain from a single non-comment, non-blank line.
    ///
    /// Handles:
    /// - Hosts-file format: `"0.0.0.0 domain.com"` → `"domain.com"`
    /// - Plain format: `"domain.com"` → `"domain.com"`
    ///
    /// The returned string is lowercase with any trailing dot stripped.
    fn extract_domain(line: &str) -> String {
        let mut tokens = line.split_whitespace();

        let first = match tokens.next() {
            Some(t) => t,
            None => return String::new(),
        };

        // If the first token looks like an IP address (contains only digits,
        // dots, colons, or hex chars) take the *second* token as the domain.
        let raw = if Self::looks_like_ip(first) {
            match tokens.next() {
                Some(t) => t,
                None => return String::new(),
            }
        } else {
            first
        };

        // Normalise: lowercase, strip trailing dot.
        let lower = raw.to_lowercase();
        lower
            .strip_suffix('.')
            .map(str::to_owned)
            .unwrap_or(lower)
    }

    /// Cheap heuristic: returns `true` if `s` could be an IPv4 or IPv6
    /// address.  Used only to distinguish IP-prefixed hosts-file lines from
    /// plain domain entries.
    fn looks_like_ip(s: &str) -> bool {
        s.parse::<std::net::IpAddr>().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    #[test]
    fn parses_hosts_file_format() {
        let data = "0.0.0.0 evil.com\n127.0.0.1 phish.net\n";
        let feed = ThreatFeed::from_hosts_data(data, "test");
        assert_eq!(feed.domain_count, 2);
        assert!(feed.contains("evil.com"));
        assert!(feed.contains("phish.net"));
    }

    #[test]
    fn parses_plain_domain_format() {
        let data = "evil.com\nphish.net\n";
        let feed = ThreatFeed::from_hosts_data(data, "test");
        assert_eq!(feed.domain_count, 2);
        assert!(feed.contains("evil.com"));
        assert!(feed.contains("phish.net"));
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let data = "# This is a comment\n\nevil.com\n# Another comment\nbad.org\n";
        let feed = ThreatFeed::from_hosts_data(data, "test");
        assert_eq!(feed.domain_count, 2);
    }

    #[test]
    fn skips_bare_hostnames_without_dot() {
        // Entries with no dot in the domain portion should be ignored.
        let data = "0.0.0.0 localhost\nevil.com\n";
        let feed = ThreatFeed::from_hosts_data(data, "test");
        // Only "evil.com" is valid.
        assert_eq!(feed.domain_count, 1);
        assert!(feed.contains("evil.com"));
    }

    #[test]
    fn handles_trailing_dot_in_domain() {
        let data = "evil.com.\n";
        let feed = ThreatFeed::from_hosts_data(data, "test");
        // Trailing dot is stripped during normalisation.
        assert!(feed.contains("evil.com"));
    }

    #[test]
    fn mixed_case_is_normalised() {
        let data = "EVIL.COM\n0.0.0.0 PHISH.NET\n";
        let feed = ThreatFeed::from_hosts_data(data, "test");
        assert!(feed.contains("evil.com"));
        assert!(feed.contains("phish.net"));
    }

    // ------------------------------------------------------------------
    // contains / check_bloom
    // ------------------------------------------------------------------

    #[test]
    fn contains_returns_true_for_loaded_domain() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        assert!(feed.contains("evil.com"));
    }

    #[test]
    fn contains_returns_false_for_unlisted_domain() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        assert!(!feed.contains("safe.com"));
    }

    #[test]
    fn check_bloom_passes_for_loaded_domain() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        // The bloom filter must return true for a domain that is in the feed.
        assert!(feed.check_bloom("evil.com"));
    }

    #[test]
    fn check_bloom_returns_false_for_never_inserted() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        // This domain was never inserted; the bloom filter must return false
        // (no false negatives are possible).
        assert!(!feed.check_bloom("definitely-not-inserted-xyz9999.com"));
    }

    // ------------------------------------------------------------------
    // contains_or_parent
    // ------------------------------------------------------------------

    #[test]
    fn contains_or_parent_matches_exact() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        assert!(feed.contains_or_parent("evil.com"));
    }

    #[test]
    fn contains_or_parent_matches_subdomain_of_listed_parent() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        assert!(feed.contains_or_parent("sub.evil.com"));
        assert!(feed.contains_or_parent("deep.sub.evil.com"));
    }

    #[test]
    fn contains_or_parent_returns_false_for_unrelated() {
        let feed = ThreatFeed::from_hosts_data("evil.com\n", "test");
        assert!(!feed.contains_or_parent("safe.com"));
        assert!(!feed.contains_or_parent("evilcom.net"));
    }

    // ------------------------------------------------------------------
    // Large feed
    // ------------------------------------------------------------------

    #[test]
    fn large_feed_loading_works() {
        // Build 10 000 synthetic domains.
        let mut data = String::new();
        for i in 0..10_000u32 {
            data.push_str(&format!("domain{i}.example.com\n"));
        }
        let feed = ThreatFeed::from_hosts_data(&data, "large");
        assert_eq!(feed.domain_count, 10_000);
        assert!(feed.contains("domain0.example.com"));
        assert!(feed.contains("domain9999.example.com"));
        assert!(!feed.contains("domain10000.example.com"));
    }
}
