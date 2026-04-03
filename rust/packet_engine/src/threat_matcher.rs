use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::threat_feed::ThreatFeed;

// ═══════════════════════════════════════════════════════════
// ThreatType
// ═══════════════════════════════════════════════════════════

/// Category of a detected threat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    /// Credential-phishing domain.
    Phishing,
    /// Malware distribution / dropper domain.
    Malware,
    /// Command-and-control (C2) infrastructure.
    Command,
    /// Pervasive tracking / fingerprinting domain.
    Tracking,
    /// Feed-detected but unclassified threat.
    Unknown,
}

impl ThreatType {
    /// Returns a stable lowercase string identifier for this variant.
    ///
    /// Used when persisting alerts to SQLite.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatType;
    ///
    /// assert_eq!(ThreatType::Phishing.as_str(), "phishing");
    /// assert_eq!(ThreatType::Command.as_str(), "c2");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatType::Phishing => "phishing",
            ThreatType::Malware => "malware",
            ThreatType::Command => "c2",
            ThreatType::Tracking => "tracking",
            ThreatType::Unknown => "unknown",
        }
    }

    /// Infer a [`ThreatType`] from a feed name.
    ///
    /// The heuristic is a case-insensitive substring search so that feed names
    /// like `"StevenBlack-phishing"` or `"abuse-ch-malware"` resolve
    /// correctly.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatType;
    ///
    /// assert_eq!(ThreatType::from_feed_name("phishing-domains"), ThreatType::Phishing);
    /// assert_eq!(ThreatType::from_feed_name("malware"), ThreatType::Malware);
    /// assert_eq!(ThreatType::from_feed_name("c2-feed"), ThreatType::Command);
    /// assert_eq!(ThreatType::from_feed_name("tracking"), ThreatType::Tracking);
    /// assert_eq!(ThreatType::from_feed_name("blocklist"), ThreatType::Unknown);
    /// ```
    #[must_use]
    pub fn from_feed_name(feed_name: &str) -> Self {
        let lower = feed_name.to_lowercase();
        if lower.contains("phish") {
            ThreatType::Phishing
        } else if lower.contains("malware") || lower.contains("malicious") {
            ThreatType::Malware
        } else if lower.contains("c2")
            || lower.contains("command")
            || lower.contains("control")
            || lower.contains("botnet")
        {
            ThreatType::Command
        } else if lower.contains("track") || lower.contains("adware") || lower.contains("ads") {
            ThreatType::Tracking
        } else {
            ThreatType::Unknown
        }
    }
}

// ═══════════════════════════════════════════════════════════
// ThreatMatch
// ═══════════════════════════════════════════════════════════

/// A confirmed threat detection result.
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    /// The domain that triggered the match.
    pub domain: String,
    /// Threat category inferred from the feed name.
    pub threat_type: ThreatType,
    /// Name of the feed that identified the domain as a threat.
    pub feed_name: String,
    /// Confidence score in `[0.0, 1.0]`.  Currently `1.0` for exact matches
    /// and `0.8` for parent-domain matches.
    pub confidence: f32,
    /// Unix timestamp in milliseconds when the match occurred.
    pub timestamp_ms: i64,
}

// ═══════════════════════════════════════════════════════════
// ThreatMatcher
// ═══════════════════════════════════════════════════════════

/// Checks observed domains against one or more loaded [`ThreatFeed`]s.
///
/// Designed to be used from a single thread (the Network Extension packet
/// loop); no interior mutability or locking is required.
pub struct ThreatMatcher {
    feeds: Vec<ThreatFeed>,
    allowlist: HashSet<String>,
    /// Total number of domains blocked (not in allowlist, matched a feed).
    pub threats_blocked: u64,
    /// Total number of allowed bypasses (domain was in allowlist *and* in a
    /// feed).
    pub threats_allowed: u64,
}

impl ThreatMatcher {
    /// Create an empty [`ThreatMatcher`] with no feeds loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatMatcher;
    ///
    /// let matcher = ThreatMatcher::new();
    /// assert_eq!(matcher.total_threat_domains(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        ThreatMatcher {
            feeds: Vec::new(),
            allowlist: HashSet::new(),
            threats_blocked: 0,
            threats_allowed: 0,
        }
    }

    /// Parse `data` as a hosts-format list and add it as a new feed.
    ///
    /// The `feed_name` string is used to infer the [`ThreatType`] for any
    /// matches produced by this feed (see [`ThreatType::from_feed_name`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatMatcher;
    ///
    /// let mut matcher = ThreatMatcher::new();
    /// matcher.load_feed("evil.com\n", "phishing");
    /// assert_eq!(matcher.total_threat_domains(), 1);
    /// ```
    pub fn load_feed(&mut self, data: &str, feed_name: &str) {
        let feed = ThreatFeed::from_hosts_data(data, feed_name);
        self.feeds.push(feed);
    }

    /// Add `domain` to the user allowlist.
    ///
    /// Allowlisted domains always pass [`check_domain`] regardless of feed
    /// matches.
    ///
    /// [`check_domain`]: ThreatMatcher::check_domain
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatMatcher;
    ///
    /// let mut matcher = ThreatMatcher::new();
    /// matcher.load_feed("safe-but-listed.com\n", "phishing");
    /// matcher.add_allowlist("safe-but-listed.com");
    /// assert!(matcher.check_domain("safe-but-listed.com").is_none());
    /// ```
    pub fn add_allowlist(&mut self, domain: &str) {
        self.allowlist.insert(domain.to_lowercase());
    }

    /// Remove `domain` from the user allowlist.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatMatcher;
    ///
    /// let mut matcher = ThreatMatcher::new();
    /// matcher.add_allowlist("example.com");
    /// matcher.remove_allowlist("example.com");
    /// // After removal the domain is no longer allowlisted.
    /// ```
    pub fn remove_allowlist(&mut self, domain: &str) {
        self.allowlist.remove(&domain.to_lowercase());
    }

    /// Check `domain` against all loaded feeds.
    ///
    /// Returns `None` if the domain is clean or allowlisted.  Returns
    /// `Some(ThreatMatch)` on the first confirmed feed hit.
    ///
    /// The allowlist is checked first: if the domain is allowlisted and a feed
    /// would have matched, `threats_allowed` is incremented and `None` is
    /// returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatMatcher;
    ///
    /// let mut matcher = ThreatMatcher::new();
    /// matcher.load_feed("evil.com\n", "phishing");
    ///
    /// let result = matcher.check_domain("evil.com");
    /// assert!(result.is_some());
    ///
    /// let result = matcher.check_domain("safe.com");
    /// assert!(result.is_none());
    /// ```
    pub fn check_domain(&mut self, domain: &str) -> Option<ThreatMatch> {
        let normalised = domain.to_lowercase();

        for feed in &self.feeds {
            if feed.contains_or_parent(&normalised) {
                // Determine confidence: exact match = 1.0, parent match = 0.8.
                let confidence = if feed.contains(&normalised) { 1.0_f32 } else { 0.8_f32 };

                // Check allowlist before incrementing the blocked counter.
                if self.allowlist.contains(&normalised) {
                    self.threats_allowed += 1;
                    return None;
                }

                self.threats_blocked += 1;

                let timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);

                return Some(ThreatMatch {
                    domain: normalised,
                    threat_type: ThreatType::from_feed_name(&feed.feed_name),
                    feed_name: feed.feed_name.clone(),
                    confidence,
                    timestamp_ms,
                });
            }
        }

        None
    }

    /// Returns the total number of distinct threat domains across all loaded
    /// feeds.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::threat_matcher::ThreatMatcher;
    ///
    /// let mut matcher = ThreatMatcher::new();
    /// matcher.load_feed("a.com\nb.com\n", "malware");
    /// matcher.load_feed("c.com\n", "phishing");
    /// assert_eq!(matcher.total_threat_domains(), 3);
    /// ```
    #[must_use]
    pub fn total_threat_domains(&self) -> usize {
        self.feeds.iter().map(|f| f.domain_count).sum()
    }

    /// Returns the number of domains currently on the allowlist.
    #[must_use]
    pub fn allowlist_count(&self) -> usize {
        self.allowlist.len()
    }

    /// Returns the number of feeds currently loaded.
    #[must_use]
    pub fn feeds_loaded(&self) -> usize {
        self.feeds.len()
    }
}

impl Default for ThreatMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // ThreatType
    // ------------------------------------------------------------------

    #[test]
    fn threat_type_from_feed_name_phishing() {
        assert_eq!(ThreatType::from_feed_name("phishing-domains"), ThreatType::Phishing);
        assert_eq!(ThreatType::from_feed_name("PHISH"), ThreatType::Phishing);
    }

    #[test]
    fn threat_type_from_feed_name_malware() {
        assert_eq!(ThreatType::from_feed_name("malware"), ThreatType::Malware);
        assert_eq!(ThreatType::from_feed_name("malicious-hosts"), ThreatType::Malware);
    }

    #[test]
    fn threat_type_from_feed_name_c2() {
        assert_eq!(ThreatType::from_feed_name("c2-feed"), ThreatType::Command);
        assert_eq!(ThreatType::from_feed_name("botnet"), ThreatType::Command);
        assert_eq!(ThreatType::from_feed_name("command-and-control"), ThreatType::Command);
    }

    #[test]
    fn threat_type_from_feed_name_tracking() {
        assert_eq!(ThreatType::from_feed_name("tracking"), ThreatType::Tracking);
        assert_eq!(ThreatType::from_feed_name("adware"), ThreatType::Tracking);
    }

    #[test]
    fn threat_type_from_feed_name_unknown() {
        assert_eq!(ThreatType::from_feed_name("blocklist"), ThreatType::Unknown);
    }

    #[test]
    fn threat_type_as_str() {
        assert_eq!(ThreatType::Phishing.as_str(), "phishing");
        assert_eq!(ThreatType::Malware.as_str(), "malware");
        assert_eq!(ThreatType::Command.as_str(), "c2");
        assert_eq!(ThreatType::Tracking.as_str(), "tracking");
        assert_eq!(ThreatType::Unknown.as_str(), "unknown");
    }

    // ------------------------------------------------------------------
    // ThreatMatcher::check_domain
    // ------------------------------------------------------------------

    #[test]
    fn clean_domain_returns_none() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("evil.com\n", "phishing");
        assert!(matcher.check_domain("safe.com").is_none());
    }

    #[test]
    fn threat_domain_returns_some_with_correct_type() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("evil.com\n", "phishing");
        let result = matcher.check_domain("evil.com");
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.domain, "evil.com");
        assert_eq!(m.threat_type, ThreatType::Phishing);
        assert_eq!(m.feed_name, "phishing");
        assert!((m.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn subdomain_match_has_lower_confidence() {
        let mut matcher = ThreatMatcher::new();
        // Only the parent is in the feed.
        matcher.load_feed("evil.com\n", "malware");
        let result = matcher.check_domain("sub.evil.com");
        assert!(result.is_some());
        let m = result.unwrap();
        assert!((m.confidence - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn allowlisted_domain_returns_none_even_if_in_feed() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("evil.com\n", "phishing");
        matcher.add_allowlist("evil.com");
        assert!(matcher.check_domain("evil.com").is_none());
        // threats_allowed must have been incremented.
        assert_eq!(matcher.threats_allowed, 1);
        // threats_blocked must stay zero.
        assert_eq!(matcher.threats_blocked, 0);
    }

    #[test]
    fn multiple_feeds_are_checked() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("phish.com\n", "phishing");
        matcher.load_feed("malware.org\n", "malware");

        assert!(matcher.check_domain("phish.com").is_some());
        assert!(matcher.check_domain("malware.org").is_some());
        assert!(matcher.check_domain("safe.io").is_none());
    }

    #[test]
    fn stats_accumulate_correctly() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("evil.com\nmalware.net\n", "malware");
        matcher.add_allowlist("malware.net");

        matcher.check_domain("evil.com");   // blocked
        matcher.check_domain("malware.net"); // allowed (in feed + allowlist)
        matcher.check_domain("safe.io");     // clean, no effect

        assert_eq!(matcher.threats_blocked, 1);
        assert_eq!(matcher.threats_allowed, 1);
    }

    #[test]
    fn remove_allowlist_re_enables_blocking() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("evil.com\n", "phishing");
        matcher.add_allowlist("evil.com");
        assert!(matcher.check_domain("evil.com").is_none());

        matcher.remove_allowlist("evil.com");
        assert!(matcher.check_domain("evil.com").is_some());
    }

    // ------------------------------------------------------------------
    // total_threat_domains
    // ------------------------------------------------------------------

    #[test]
    fn total_threat_domains_sums_across_feeds() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("a.com\nb.com\n", "malware");
        matcher.load_feed("c.com\n", "phishing");
        assert_eq!(matcher.total_threat_domains(), 3);
    }

    #[test]
    fn empty_matcher_has_zero_domains() {
        let matcher = ThreatMatcher::new();
        assert_eq!(matcher.total_threat_domains(), 0);
    }

    // ------------------------------------------------------------------
    // Case normalisation
    // ------------------------------------------------------------------

    #[test]
    fn uppercase_domain_is_normalised_before_check() {
        let mut matcher = ThreatMatcher::new();
        matcher.load_feed("evil.com\n", "phishing");
        // Feed stores lowercase; query with uppercase must still match.
        assert!(matcher.check_domain("EVIL.COM").is_some());
    }
}
