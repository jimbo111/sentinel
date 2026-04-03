import Foundation

final class CategoriesService {
    static let shared = CategoriesService()

    private init() {
        buildMap()
    }

    struct CategoryResult {
        let key: String
        let label: String
        let icon: String
        let siteCount: Int
        let totalVisits: Int
    }

    typealias CategoryInfo = (key: String, label: String, icon: String)

    private var domainToCategory: [String: CategoryInfo] = [:]

    /// Memoization cache: domain → resolved category (nil = confirmed uncategorized).
    /// Avoids repeated 4-step fallback for the same domain across renders.
    private var cache: [String: CategoryInfo?] = [:]

    // MARK: - Category Definitions

    private static let categories: [(key: String, label: String, icon: String, domains: [String])] = [
        ("social_media", "Social Media", "person.2.fill", [
            // Global
            "facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com",
            "reddit.com", "snapchat.com", "linkedin.com", "pinterest.com", "threads.net",
            "tumblr.com", "mastodon.social", "bluesky.social", "lemon8-app.com",
            // Korean
            "band.us", "weverse.io", "cafe.naver.com",
        ]),
        ("shopping", "Shopping", "cart.fill", [
            // Global
            "amazon.com", "ebay.com", "walmart.com", "aliexpress.com", "etsy.com",
            "shein.com", "temu.com", "target.com", "bestbuy.com", "costco.com",
            "ikea.com", "zara.com", "nike.com", "adidas.com", "uniqlo.com",
            "asos.com", "nordstrom.com", "macys.com", "newegg.com", "shopify.com",
            // Korean
            "coupang.com", "gmarket.co.kr", "11st.co.kr", "musinsa.com", "kurly.com",
            "ssg.com", "lotteon.com", "interpark.com", "tmon.com", "wemakeprice.com",
            "oliveyoung.co.kr", "29cm.co.kr", "zigzag.kr", "wconcept.co.kr",
            "ohou.se", "brandi.co.kr", "ably.kr", "balaan.co.kr",
            "auction.co.kr", "danawa.com", "enuri.com",
        ]),
        ("entertainment", "Entertainment", "play.circle.fill", [
            // Global
            "youtube.com", "netflix.com", "spotify.com", "twitch.tv", "hulu.com",
            "disneyplus.com", "max.com", "soundcloud.com", "vimeo.com",
            "bilibili.com", "crunchyroll.com", "primevideo.com", "peacocktv.com",
            "paramountplus.com", "dazn.com", "applemusic.com", "tidal.com",
            // Korean
            "tving.com", "wavve.com", "melon.com", "afreecatv.com", "soop.co.kr",
            "bugs.co.kr", "genie.co.kr", "laftel.net", "watcha.com",
            "coupangplay.com", "flo.com", "vibe.naver.com",
        ]),
        ("news", "News", "newspaper.fill", [
            // Global
            "cnn.com", "bbc.com", "bbc.co.uk", "nytimes.com", "reuters.com",
            "bloomberg.com", "theguardian.com", "washingtonpost.com", "apnews.com",
            "aljazeera.com", "wsj.com", "ft.com", "techcrunch.com", "theverge.com",
            "arstechnica.com", "wired.com", "forbes.com", "cnbc.com",
            // Korean
            "chosun.com", "donga.com", "joongang.co.kr", "hani.co.kr",
            "yna.co.kr", "mk.co.kr", "sedaily.com", "hankyung.com",
            "kmib.co.kr", "khan.co.kr", "sbs.co.kr", "kbs.co.kr",
            "mbc.co.kr", "jtbc.co.kr", "ytn.co.kr", "newsis.com",
            "edaily.co.kr", "mt.co.kr", "news.naver.com", "v.daum.net",
        ]),
        ("search", "Search", "magnifyingglass", [
            // Global
            "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com",
            "ecosia.org", "brave.com", "yandex.com",
            // Korean
            "naver.com", "daum.net", "zum.com",
        ]),
        ("communication", "Communication", "bubble.left.and.bubble.right.fill", [
            // Global
            "whatsapp.com", "telegram.org", "discord.com", "zoom.us", "slack.com",
            "signal.org", "skype.com", "teams.microsoft.com", "webex.com",
            "meet.google.com",
            // Korean
            "kakao.com", "kakaocorp.com", "line.me",
        ]),
        ("finance", "Finance", "dollarsign.circle.fill", [
            // Global
            "paypal.com", "stripe.com", "coinbase.com", "binance.com", "robinhood.com",
            "chase.com", "wise.com", "revolut.com", "venmo.com", "cashapp.com",
            "schwab.com", "fidelity.com", "etrade.com", "kraken.com",
            // Korean
            "toss.im", "kakaobank.com", "upbit.com", "kakaopay.com",
            "kbstar.com", "shinhan.com", "hanabank.com", "wooribank.com",
            "ibk.co.kr", "nhbank.com", "samsungcard.com", "bithumb.com",
            "banksalad.com", "kbcard.com", "hyundaicard.com",
            "truefriend.com", "samsungpay.com",
        ]),
        ("productivity", "Productivity", "hammer.fill", [
            // Global
            "github.com", "gitlab.com", "notion.so", "figma.com", "canva.com",
            "trello.com", "atlassian.com", "dropbox.com", "monday.com", "linear.app",
            "asana.com", "miro.com", "airtable.com", "clickup.com",
            "docs.google.com", "drive.google.com", "office.com",
            // Korean
            "dooray.com", "jandi.com", "flex.team",
        ]),
        ("gaming", "Gaming", "gamecontroller.fill", [
            // Global
            "steampowered.com", "epicgames.com", "roblox.com", "riot.com",
            "battle.net", "ea.com", "playstation.com", "xbox.com",
            "nintendo.com", "ubisoft.com",
            // Korean
            "nexon.com", "ncsoft.com", "netmarble.com", "smilegate.com",
            "krafton.com", "kakaogames.com", "hangame.com", "pmang.com",
            "inven.co.kr", "fmkorea.com",
        ]),
        ("education", "Education", "book.fill", [
            // Global
            "wikipedia.org", "stackoverflow.com", "coursera.org", "udemy.com",
            "duolingo.com", "medium.com", "khanacademy.org", "edx.org",
            "skillshare.com", "codecademy.com", "leetcode.com", "w3schools.com",
            // Korean
            "inflearn.com", "class101.net", "megastudy.net", "etoos.com",
            "ebsi.co.kr", "fastcampus.co.kr", "nomadcoders.co", "programmers.co.kr",
        ]),
        ("food_delivery", "Food & Delivery", "takeoutbag.and.cup.and.straw.fill", [
            // Global
            "doordash.com", "ubereats.com", "grubhub.com", "instacart.com",
            "deliveroo.com", "hellofresh.com", "postmates.com",
            // Korean
            "baemin.com", "yogiyo.co.kr", "coupangeats.com",
            "mangoplate.com", "catchtable.co.kr", "sikhye.com",
        ]),
        ("health", "Health", "heart.fill", [
            // Global
            "webmd.com", "healthline.com", "strava.com", "myfitnesspal.com",
            "headspace.com", "calm.com", "fitbit.com", "peloton.com",
            "noom.com", "whoop.com",
            // Korean
            "goodoc.co.kr", "ddocdoc.com", "hidoc.co.kr",
            "pilates.co.kr", "kakaocare.com",
        ]),
        ("travel", "Travel", "airplane", [
            // Global
            "airbnb.com", "booking.com", "expedia.com", "tripadvisor.com",
            "skyscanner.com", "agoda.com", "kayak.com", "hotels.com",
            "vrbo.com", "hostelworld.com",
            // Korean
            "koreanair.com", "yanolja.com", "goodchoice.kr",
            "jejuair.net", "flyasiana.com", "hanatour.com",
            "modetour.com", "myrealtrip.com", "klook.com",
        ]),
        ("technology", "Technology", "cpu", [
            // Global
            "cloudflare.com", "vercel.com", "netlify.com", "render.com",
            "apple.com", "samsung.com", "microsoft.com", "aws.amazon.com",
            "digitalocean.com", "heroku.com",
            // Korean
            "ncloud.com", "gabia.com", "cafe24.com",
        ]),
        ("ai_tools", "AI Tools", "brain.head.profile", [
            "chatgpt.com", "openai.com", "claude.ai", "anthropic.com",
            "perplexity.ai", "midjourney.com", "character.ai", "huggingface.co",
            "copilot.microsoft.com", "gemini.google.com", "poe.com",
            "stability.ai", "runway.ml", "replicate.com", "cursor.com",
            "v0.dev", "bolt.new", "replit.com",
            // Korean
            "wrtn.ai", "askup.com", "clova.ai",
        ]),
        ("dating", "Dating", "heart.circle", [
            // Global
            "tinder.com", "bumble.com", "hinge.co", "match.com",
            "okcupid.com", "badoo.com", "coffeemeetsbagel.com",
            // Korean
            "wippy.kr", "amanda.co.kr", "glam.am",
            "noondate.com", "skypeople.co.kr",
        ]),
        ("sports", "Sports", "sportscourt", [
            // Global
            "espn.com", "nfl.com", "nba.com", "mlb.com", "fifa.com",
            "premierleague.com", "livescore.com", "flashscore.com",
            "transfermarkt.com", "theathletic.com",
            // Korean
            "kleague.com", "kbo.or.kr", "sports.news.naver.com",
            "spotvnow.co.kr", "tfreeca.com",
        ]),
        ("weather", "Weather", "cloud.sun.fill", [
            // Global
            "weather.com", "accuweather.com", "wunderground.com", "windy.com",
            "weather.gov",
            // Korean
            "weather.naver.com", "kma.go.kr",
        ]),
        ("government", "Government", "building.columns.fill", [
            // Korean
            "gov.kr", "mois.go.kr", "nts.go.kr", "nhis.or.kr",
            "wetax.go.kr", "hometax.go.kr", "minwon.go.kr",
            "bokjiro.go.kr", "work.go.kr", "safekorea.go.kr",
            // Global
            "usa.gov", "gov.uk", "irs.gov",
        ]),
        ("transportation", "Transportation", "car.fill", [
            // Korean
            "kakaomobility.com", "tmap.co.kr", "odsay.com",
            "korail.com", "letskorail.com", "subway.or.kr",
            "bus.go.kr", "kakaomap.com",
            // Global
            "uber.com", "lyft.com", "maps.google.com",
        ]),
    ]

    // MARK: - Map Building

    private func buildMap() {
        for cat in Self.categories {
            for domain in cat.domains {
                domainToCategory[domain] = (key: cat.key, label: cat.label, icon: cat.icon)
            }
        }
    }

    // MARK: - Categorization

    /// Categorize a domain with memoized 4-step fallback:
    /// exact match → strip prefix → parent domain walk → suffix match.
    /// Results are cached so repeated lookups (same domain across renders) are O(1).
    func categorize(_ siteDomain: String) -> CategoryInfo? {
        // Check memoization cache first (covers both hits and confirmed misses)
        if let cached = cache[siteDomain] {
            return cached
        }

        let result = resolveCategoryUncached(siteDomain)
        cache[siteDomain] = result
        return result
    }

    /// The actual 4-step resolution. Only called once per unique domain.
    private func resolveCategoryUncached(_ siteDomain: String) -> CategoryInfo? {
        // 1. Exact match (fastest path)
        if let result = domainToCategory[siteDomain] {
            return result
        }

        // 2. Strip common prefixes and retry (no allocation if no prefix found)
        let stripped = stripPrefix(siteDomain)
        if stripped != siteDomain, let result = domainToCategory[stripped] {
            return result
        }

        // 3. Walk up parent domains without String allocation:
        //    "news.naver.com" → try "naver.com"
        //    Uses Substring slicing instead of joined(separator:)
        var searchDomain = stripped[stripped.startIndex...]
        while let dotIndex = searchDomain.firstIndex(of: ".") {
            let afterDot = searchDomain[searchDomain.index(after: dotIndex)...]
            // Need at least one more dot for a valid domain (e.g., "naver.com")
            guard afterDot.contains(".") else { break }
            searchDomain = afterDot
            if let result = domainToCategory[String(searchDomain)] {
                return result
            }
        }

        // 4. Suffix match for government TLDs
        if siteDomain.hasSuffix(".go.kr") || siteDomain.hasSuffix(".or.kr") {
            return domainToCategory["gov.kr"]
        }
        if siteDomain.hasSuffix(".gov") {
            return domainToCategory["usa.gov"]
        }

        return nil
    }

    /// Strip common non-meaningful prefixes. Returns the original string if no prefix found.
    private func stripPrefix(_ domain: String) -> String {
        for prefix in Self.strippablePrefixes {
            if domain.hasPrefix(prefix) {
                return String(domain.dropFirst(prefix.count))
            }
        }
        return domain
    }

    private static let strippablePrefixes = ["www.", "m.", "mobile.", "app.", "api.", "static.", "cdn.", "edge."]

    // MARK: - Bulk Categorization

    /// Single-pass categorization: buckets sites and counts uncategorized in one iteration.
    func categorizeSites(_ sites: [SiteRecord]) -> [CategoryResult] {
        var buckets: [String: (label: String, icon: String, sites: Int, visits: Int)] = [:]
        var uncategorizedCount = 0
        var uncategorizedVisits = 0

        for site in sites {
            if let cat = categorize(site.siteDomain) {
                var bucket = buckets[cat.key] ?? (label: cat.label, icon: cat.icon, sites: 0, visits: 0)
                bucket.sites += 1
                bucket.visits += site.totalVisits
                buckets[cat.key] = bucket
            } else {
                uncategorizedCount += 1
                uncategorizedVisits += site.totalVisits
            }
        }

        if uncategorizedCount > 0 {
            buckets["uncategorized"] = (label: "Other", icon: "questionmark.circle", sites: uncategorizedCount, visits: uncategorizedVisits)
        }

        return buckets
            .map { CategoryResult(key: $0.key, label: $0.value.label, icon: $0.value.icon, siteCount: $0.value.sites, totalVisits: $0.value.visits) }
            .sorted { $0.totalVisits > $1.totalVisits }
    }
}
