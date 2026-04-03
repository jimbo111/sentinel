use std::borrow::Cow;

/// Known CDN / supporting domain associations.
///
/// Each entry is `(cdn_suffix, parent_site)`. The lookup uses the same
/// suffix-matching rule as `is_noise_domain`: an entry matches if
/// `domain == cdn_suffix` OR `domain` ends with `".<cdn_suffix>"`.
///
/// Domains that are themselves registrable (e.g. `google.com`, `youtube.com`)
/// are intentionally absent — they resolve correctly via the eTLD+1 fallback.
const KNOWN_ASSOCIATIONS: &[(&str, &str)] = &[
    // YouTube
    ("ytimg.com", "youtube.com"),
    ("googlevideo.com", "youtube.com"),
    ("ggpht.com", "youtube.com"),
    // Meta — Facebook
    ("fbcdn.net", "facebook.com"),
    ("fbsbx.com", "facebook.com"),
    // Meta — Instagram
    ("cdninstagram.com", "instagram.com"),
    // Twitter / X
    ("twimg.com", "x.com"),
    ("t.co", "x.com"),
    // Netflix
    ("nflxvideo.net", "netflix.com"),
    ("nflxext.com", "netflix.com"),
    ("nflximg.net", "netflix.com"),
    // Amazon
    ("images-amazon.com", "amazon.com"),
    ("ssl-images-amazon.com", "amazon.com"),
    ("media-amazon.com", "amazon.com"),
    // Coupang
    ("coupangcdn.com", "coupang.com"),
    ("coupang.io", "coupang.com"),
    // TikTok
    ("tiktokcdn.com", "tiktok.com"),
    ("tiktokv.com", "tiktok.com"),
    ("musical.ly", "tiktok.com"),
    // Reddit
    ("redditmedia.com", "reddit.com"),
    ("redditstatic.com", "reddit.com"),
    ("redd.it", "reddit.com"),
    // Discord
    ("discordapp.com", "discord.com"),
    ("discordapp.net", "discord.com"),
    ("discord.gg", "discord.com"),
    ("discord.media", "discord.com"),
    // Spotify
    ("spotifycdn.com", "spotify.com"),
    ("scdn.co", "spotify.com"),
    ("spotify.design", "spotify.com"),
    // GitHub
    ("github.io", "github.com"),
    ("githubusercontent.com", "github.com"),
    ("githubassets.com", "github.com"),
    // LinkedIn
    ("licdn.com", "linkedin.com"),
    ("linkedin.cn", "linkedin.com"),
    // Pinterest
    ("pinimg.com", "pinterest.com"),
    // Snapchat
    ("snapchat.com", "snapchat.com"),
    ("snap.com", "snapchat.com"),
    ("sc-cdn.net", "snapchat.com"),
    ("bitmoji.com", "snapchat.com"),
    // Twitch
    ("twitchcdn.net", "twitch.tv"),
    ("twitchsvc.net", "twitch.tv"),
    ("jtvnw.net", "twitch.tv"),
    // Telegram
    ("telegram.me", "telegram.org"),
    ("t.me", "telegram.org"),
    ("telegram.dog", "telegram.org"),
    // WhatsApp
    ("whatsapp.net", "whatsapp.com"),
    ("whatsapp.com", "whatsapp.com"),
    // Naver
    ("naver.net", "naver.com"),
    ("navercorp.com", "naver.com"),
    ("pstatic.net", "naver.com"),
    // Kakao
    ("kakaocdn.net", "kakao.com"),
    ("kakao.co.kr", "kakao.com"),
    ("daum.net", "kakao.com"),
    ("daumcdn.net", "kakao.com"),
    // Apple
    ("apple.com", "apple.com"),
    ("icloud.com", "apple.com"),
    ("mzstatic.com", "apple.com"),
    ("apple-dns.net", "apple.com"),
    // Microsoft
    ("live.com", "microsoft.com"),
    ("microsoftonline.com", "microsoft.com"),
    ("msedge.net", "microsoft.com"),
    ("msftconnecttest.com", "microsoft.com"),
    // Zoom
    ("zoom.us", "zoom.us"),
    ("zoomcdn.com", "zoom.us"),
    // Stripe
    ("stripecdn.com", "stripe.com"),
    ("stripe.network", "stripe.com"),
    // Slack
    ("slack-edge.com", "slack.com"),
    ("slack-imgs.com", "slack.com"),
    // Dropbox
    ("dropboxstatic.com", "dropbox.com"),
    ("dropbox.tech", "dropbox.com"),
    // Airbnb
    ("airbnbcdn.com", "airbnb.com"),
    ("muscache.com", "airbnb.com"),
    // Uber
    ("ubercdn.net", "uber.com"),
];

/// Shared CDN / analytics / tracking infrastructure that cannot be attributed
/// to a single first-party site.
///
/// Domains matching any of these suffixes are mapped to the sentinel value
/// `"_infra"`.
const INFRA_DOMAINS: &[&str] = &[
    // Google infrastructure
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
    "gvt1.com",
    "gvt2.com",
    // CDN providers
    "cloudfront.net",
    "akamaiedge.net",
    "akamaihd.net",
    "akadns.net",
    "akamaized.net",
    "cloudflare.com",
    "fastly.net",
    "edgecastcdn.net",
    "azureedge.net",
    "jsdelivr.net",
    // Analytics / telemetry
    "1e100.net",
    "nr-data.net",
    "newrelic.com",
    "segment.io",
];

/// Two-part TLD suffixes that require three labels to form a registrable domain.
///
/// For example, `"www.bbc.co.uk"` → `"bbc.co.uk"` (three labels).
const MULTI_PART_TLDS: &[&str] = &[
    ".co.uk",
    ".co.kr",
    ".co.jp",
    ".com.au",
    ".com.br",
    ".com.cn",
    ".com.tw",
    ".com.sg",
    ".com.hk",
    ".com.mx",
    ".co.in",
    ".co.za",
    ".co.nz",
    ".co.id",
    ".co.th",
    ".or.kr",
    ".or.jp",
    ".ne.jp",
    ".ac.uk",
    ".org.uk",
    // Government domains
    ".gov.uk",
    ".gov.au",
    ".gov.br",
    ".go.jp",
    ".go.kr",
    // Education domains
    ".edu.au",
    ".ac.jp",
    ".ac.kr",
    // Network/org domains
    ".net.au",
    ".org.au",
    ".net.br",
    ".org.br",
    ".net.cn",
    ".org.cn",
];

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `domain` is an exact match for `suffix` or is a
/// subdomain of it (i.e. ends with `".<suffix>"`).
///
/// This is the same zero-allocation suffix-matching logic used in
/// `is_noise_domain` in `domain.rs`.
#[inline]
fn suffix_matches(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    let slen = suffix.len();
    domain.len() > slen
        && domain.ends_with(suffix)
        && domain.as_bytes()[domain.len() - slen - 1] == b'.'
}

/// Extracts the registrable domain (eTLD+1) from a fully qualified `domain`.
///
/// - If `domain` ends with a known two-part TLD (e.g. `.co.uk`), the three
///   rightmost labels are returned.
/// - Otherwise the two rightmost labels are returned.
/// - If fewer labels than required are present the full `domain` is returned
///   unchanged.
///
/// The returned slice always borrows from `domain` — no allocation occurs.
fn extract_etld_plus_one(domain: &str) -> &str {
    if domain.is_empty() {
        return domain;
    }

    // Determine how many labels we need on the right-hand side.
    let labels_needed: usize = if MULTI_PART_TLDS
        .iter()
        .any(|tld| domain.ends_with(tld))
    {
        3
    } else {
        2
    };

    // Walk backwards through the string counting dots.
    // We need to find the dot that bounds the left edge of the registrable
    // domain, i.e. the `labels_needed`-th dot from the right.
    //
    // Example (labels_needed = 2, domain = "www.example.com"):
    //   dots from right: 1st = between "example" and "com"
    //                    2nd = between "www" and "example"  <- split here
    //   → return "example.com" (everything after that dot)
    let bytes = domain.as_bytes();
    let mut dots_seen: usize = 0;
    let mut i = bytes.len();

    while i > 0 {
        i -= 1;
        if bytes[i] == b'.' {
            dots_seen += 1;
            if dots_seen == labels_needed {
                // Everything after this dot is the registrable domain.
                return &domain[i + 1..];
            }
        }
    }

    // Fewer dots than required — the whole domain is the registrable domain.
    domain
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a (lowercase, no-trailing-dot) domain name to its canonical "site"
/// identifier using a three-layer lookup.
///
/// **Layer 1 — known associations**: suffix-matches against [`KNOWN_ASSOCIATIONS`].
/// Returns `Cow::Borrowed(parent_site)` on the first hit.
///
/// **Layer 2 — shared infrastructure**: suffix-matches against [`INFRA_DOMAINS`].
/// Returns `Cow::Borrowed("_infra")` on any hit.
///
/// **Layer 3 — eTLD+1 fallback**: extracts the registrable domain (e.g.
/// `"api.v2.stripe.com"` → `"stripe.com"`). Returns a zero-allocation
/// `Cow::Borrowed` slice of the input.
///
/// The function never allocates — all returned values are either `'static`
/// string literals or slices of the `domain` argument.
///
/// # Examples
///
/// ```
/// use packet_engine::site_mapper::map_to_site;
///
/// assert_eq!(map_to_site("i.ytimg.com"), "youtube.com");
/// assert_eq!(map_to_site("d123.cloudfront.net"), "_infra");
/// assert_eq!(map_to_site("www.example.com"), "example.com");
/// assert_eq!(map_to_site("www.bbc.co.uk"), "bbc.co.uk");
/// ```
#[must_use]
pub fn map_to_site(domain: &str) -> Cow<'_, str> {
    // Layer 1: known associations.
    for (suffix, parent) in KNOWN_ASSOCIATIONS {
        if suffix_matches(domain, suffix) {
            return Cow::Borrowed(parent);
        }
    }

    // Layer 2: shared infrastructure.
    for infra in INFRA_DOMAINS {
        if suffix_matches(domain, infra) {
            return Cow::Borrowed("_infra");
        }
    }

    // Layer 3: eTLD+1 fallback — zero allocation.
    Cow::Borrowed(extract_etld_plus_one(domain))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Layer 1: known associations ──────────────────────────────────────────

    #[test]
    fn ytimg_subdomain_maps_to_youtube() {
        assert_eq!(map_to_site("i.ytimg.com"), "youtube.com");
    }

    #[test]
    fn ytimg_exact_maps_to_youtube() {
        // Exact suffix match (no subdomain prefix).
        assert_eq!(map_to_site("ytimg.com"), "youtube.com");
    }

    #[test]
    fn fbcdn_maps_to_facebook() {
        assert_eq!(map_to_site("fbcdn.net"), "facebook.com");
        assert_eq!(map_to_site("static.fbcdn.net"), "facebook.com");
    }

    #[test]
    fn twimg_maps_to_x() {
        assert_eq!(map_to_site("video.twimg.com"), "x.com");
    }

    #[test]
    fn nflxvideo_maps_to_netflix() {
        assert_eq!(map_to_site("cdn.nflxvideo.net"), "netflix.com");
    }

    #[test]
    fn tiktokcdn_maps_to_tiktok() {
        assert_eq!(map_to_site("p16-sign.tiktokcdn.com"), "tiktok.com");
    }

    #[test]
    fn discord_variants_map_to_discord() {
        assert_eq!(map_to_site("cdn.discordapp.com"), "discord.com");
        assert_eq!(map_to_site("gateway.discordapp.net"), "discord.com");
        assert_eq!(map_to_site("discord.gg"), "discord.com");
    }

    #[test]
    fn githubusercontent_maps_to_github() {
        assert_eq!(map_to_site("raw.githubusercontent.com"), "github.com");
        assert_eq!(map_to_site("user.github.io"), "github.com");
    }

    #[test]
    fn pinimg_maps_to_pinterest() {
        assert_eq!(map_to_site("i.pinimg.com"), "pinterest.com");
    }

    #[test]
    fn kakao_variants_map_to_kakao() {
        assert_eq!(map_to_site("t1.daumcdn.net"), "kakao.com");
        assert_eq!(map_to_site("kakao.co.kr"), "kakao.com");
    }

    // ── Layer 2: infrastructure ───────────────────────────────────────────────

    #[test]
    fn cloudfront_maps_to_infra() {
        assert_eq!(map_to_site("d123.cloudfront.net"), "_infra");
    }

    #[test]
    fn googleapis_maps_to_infra() {
        assert_eq!(map_to_site("fonts.googleapis.com"), "_infra");
    }

    #[test]
    fn doubleclick_maps_to_infra() {
        assert_eq!(map_to_site("stats.doubleclick.net"), "_infra");
    }

    #[test]
    fn fastly_maps_to_infra() {
        assert_eq!(map_to_site("cache.fastly.net"), "_infra");
    }

    // ── Layer 3: eTLD+1 fallback (standard TLD) ───────────────────────────────

    #[test]
    fn www_example_com_maps_to_example_com() {
        assert_eq!(map_to_site("www.example.com"), "example.com");
    }

    #[test]
    fn deep_subdomain_extracts_registrable() {
        assert_eq!(map_to_site("api.v2.stripe.com"), "stripe.com");
    }

    #[test]
    fn already_registrable_domain_unchanged() {
        let result = map_to_site("example.com");
        assert_eq!(result, "example.com");
        // Must borrow from the input — no allocation.
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // ── Layer 3: eTLD+1 fallback (multi-part TLD) ─────────────────────────────

    #[test]
    fn co_uk_uses_three_labels() {
        assert_eq!(map_to_site("www.bbc.co.uk"), "bbc.co.uk");
    }

    #[test]
    fn co_kr_uses_three_labels() {
        assert_eq!(map_to_site("news.naver.co.kr"), "naver.co.kr");
    }

    #[test]
    fn com_au_uses_three_labels() {
        assert_eq!(map_to_site("shop.woolworths.com.au"), "woolworths.com.au");
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn single_label_returned_unchanged() {
        assert_eq!(map_to_site("localhost"), "localhost");
    }

    #[test]
    fn empty_string_returned_unchanged() {
        assert_eq!(map_to_site(""), "");
    }

    #[test]
    fn domain_equal_to_tld_returned_unchanged() {
        // e.g. bare "com" — only one label, no dot
        assert_eq!(map_to_site("com"), "com");
    }

    #[test]
    fn known_association_not_confused_with_different_suffix() {
        // "notytimg.com" must NOT match the "ytimg.com" association because
        // the character before the suffix is not a dot.
        assert_eq!(map_to_site("notytimg.com"), "notytimg.com");
    }
}
