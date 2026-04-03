import Foundation
import SQLite3
import os.log

// MARK: - Supporting Types

struct DatabaseStats: Sendable {
    let totalDomains: Int
    let totalVisits: Int
    let domainsToday: Int
}

struct VisitRecord: Identifiable, Sendable {
    let id: Int64
    let domainId: Int64
    let timestampMs: Int64
    let source: String

    var date: Date {
        Date(timeIntervalSince1970: TimeInterval(timestampMs) / 1000)
    }
}

// MARK: - DatabaseReader

/// Manages the shared SQLite database written by the Rust packet engine.
///
/// Uses the C SQLite3 API directly (no third-party dependencies). Primarily
/// read-only, but includes admin write operations (truncateAllData,
/// cleanupOldVisits). Opened with READWRITE for WAL compatibility.
/// Returns empty results gracefully when the database file does not yet exist.
final class DatabaseReader {

    static let shared = DatabaseReader()

    // MARK: - Private State

    private var db: OpaquePointer?
    private var schemaValid = false
    private let queue = DispatchQueue(label: "com.jimmykim.ring.dbreader", qos: .userInitiated)
    private let log = OSLog(subsystem: "com.jimmykim.ring", category: "DatabaseReader")

    // MARK: - Init / Deinit

    private init() {
        // Open database inside the serial queue — openDatabase() uses
        // SQLITE_OPEN_NOMUTEX so all access must be serialized. (audit fix)
        queue.sync { openDatabase() }
    }

    deinit {
        closeDatabase()
    }

    // MARK: - Connection Management

    private var loggedNotFound = false

    private func openDatabase() {
        let path = AppGroupConfig.databasePath

        guard FileManager.default.fileExists(atPath: path) else {
            if !loggedNotFound {
                print("[Ring DB] Not found at \(path), waiting for tunnel to create it")
                loggedNotFound = true
            }
            db = nil
            return
        }
        loggedNotFound = false

        var handle: OpaquePointer?
        // Use READWRITE so we can read WAL databases properly.
        // The Rust engine is the only writer; we only read.
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX
        let rc = sqlite3_open_v2(path, &handle, flags, nil)

        if rc == SQLITE_OK {
            db = handle
            sqlite3_busy_timeout(db, 5000)
            self.ensureSentinelTables()
            print("[Ring DB] Opened successfully at \(path)")
        } else {
            let errMsg = String(cString: sqlite3_errmsg(handle))
            print("[Ring DB] Open FAILED: rc=\(rc) err=\(errMsg)")
            sqlite3_close(handle)
            db = nil
        }
    }

    private func closeDatabase() {
        if let db = db {
            sqlite3_close(db)
            self.db = nil
            self.schemaValid = false
        }
    }

    /// Create sentinel tables if they don't exist yet.
    /// Called on database open so the app can query threat data even if the
    /// Network Extension hasn't run yet.
    private func ensureSentinelTables() {
        guard let db = db else { return }
        let sql = "CREATE TABLE IF NOT EXISTS sentinel_alerts ("
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            + "domain TEXT NOT NULL,"
            + "threat_type TEXT NOT NULL,"
            + "feed_name TEXT NOT NULL,"
            + "confidence REAL NOT NULL,"
            + "timestamp_ms INTEGER NOT NULL,"
            + "dismissed INTEGER NOT NULL DEFAULT 0);"
            + "CREATE INDEX IF NOT EXISTS idx_sentinel_alerts_timestamp ON sentinel_alerts(timestamp_ms);"
            + "CREATE INDEX IF NOT EXISTS idx_sentinel_alerts_domain ON sentinel_alerts(domain);"
            + "CREATE TABLE IF NOT EXISTS sentinel_allowlist ("
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            + "domain TEXT NOT NULL UNIQUE,"
            + "added_ms INTEGER NOT NULL DEFAULT 0);"
        var errMsg: UnsafeMutablePointer<CChar>?
        sqlite3_exec(db, sql, nil, nil, &errMsg)
        if let errMsg = errMsg {
            print("[Ring DB] sentinel tables creation note: \(String(cString: errMsg))")
            sqlite3_free(errMsg)
        }
    }

    /// Truncate all domain and visit data without deleting the database file.
    /// Safe to call while the Network Extension has the DB open — SQLite
    /// handles concurrent access via WAL. The extension's next write will
    /// simply create new rows.
    func truncateAllData() {
        queue.sync {
            ensureOpen()
            guard let db = db else { return }
            sqlite3_exec(db, "DELETE FROM visits", nil, nil, nil)
            sqlite3_exec(db, "DELETE FROM domains", nil, nil, nil)
            print("[Ring DB] All data truncated")
        }
    }

    private var schemaRetryCount = 0

    /// Re-open the database if it was nil at launch (file didn't exist yet).
    private func ensureOpen() {
        if db == nil {
            openDatabase()
        }
        // Validate schema — the extension may still be creating tables,
        // so just close and retry on the next call. NEVER delete the file
        // because the extension may have it open.
        if let db = db, !schemaValid {
            if validateSchema(db) {
                schemaValid = true
                schemaRetryCount = 0
                print("[Ring DB] Schema validated OK")
            } else {
                schemaRetryCount += 1
                if schemaRetryCount <= 3 {
                    print("[Ring DB] Schema not ready yet (attempt \(schemaRetryCount)), will retry")
                }
                closeDatabase()
                // Do NOT delete — the extension may still be creating tables
            }
        }
    }

    /// Check that the domains table has the columns we expect.
    private func validateSchema(_ db: OpaquePointer) -> Bool {
        var stmt: OpaquePointer?
        // PRAGMA table_info returns one row per column
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(domains)", -1, &stmt, nil) == SQLITE_OK else {
            return false
        }
        defer { sqlite3_finalize(stmt) }

        var columns: Set<String> = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let name = sqlite3_column_text(stmt, 1) {
                columns.insert(String(cString: name))
            }
        }

        // These are the columns the Rust engine creates
        let required: Set<String> = ["id", "domain", "first_seen", "last_seen", "visit_count", "source"]
        return required.isSubset(of: columns)
    }

    // MARK: - Public API

    /// Most recent domains, ordered by `last_seen DESC`.
    func recentDomains(limit: Int = 100) -> [DomainRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source,
                       tls_version, bytes_in, bytes_out
                FROM domains
                ORDER BY last_seen DESC
                LIMIT ?
                """
            let legacySQL = """
                SELECT id, domain, first_seen, last_seen, visit_count, source
                FROM domains
                ORDER BY last_seen DESC
                LIMIT ?
                """
            return queryDomains(db: db, sql: sql, legacySQL: legacySQL, bind: { stmt in
                sqlite3_bind_int(stmt, 1, Int32(limit))
            })
        }
    }

    /// Domains whose name contains `query` (case-insensitive).
    func searchDomains(query: String) -> [DomainRecord] {
        // Escape LIKE wildcards so searching for "100%" or "_test" matches literally
        let escaped = query.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "%", with: "\\%")
            .replacingOccurrences(of: "_", with: "\\_")
        let pattern = "%\(escaped)%"
        return queue.sync { () -> [DomainRecord] in
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source,
                       tls_version, bytes_in, bytes_out
                FROM domains
                WHERE domain LIKE ? ESCAPE '\\'
                ORDER BY last_seen DESC
                LIMIT 200
                """
            let legacySQL = """
                SELECT id, domain, first_seen, last_seen, visit_count, source
                FROM domains
                WHERE domain LIKE ? ESCAPE '\\'
                ORDER BY last_seen DESC
                LIMIT 200
                """
            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            return queryDomains(db: db, sql: sql, legacySQL: legacySQL, bind: { stmt in
                _ = pattern.withCString { cStr in
                    sqlite3_bind_text(stmt, 1, cStr, -1, transient)
                }
            })
        }
    }

    /// Top domains by visit count.
    func topDomains(limit: Int = 20) -> [DomainRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source,
                       tls_version, bytes_in, bytes_out
                FROM domains
                ORDER BY visit_count DESC
                LIMIT ?
                """
            let legacySQL = """
                SELECT id, domain, first_seen, last_seen, visit_count, source
                FROM domains
                ORDER BY visit_count DESC
                LIMIT ?
                """
            return queryDomains(db: db, sql: sql, legacySQL: legacySQL, bind: { stmt in
                sqlite3_bind_int(stmt, 1, Int32(limit))
            })
        }
    }

    /// Aggregate statistics.
    func stats() -> DatabaseStats {
        queue.sync {
            ensureOpen()
            guard let db = db else {
                return DatabaseStats(totalDomains: 0, totalVisits: 0, domainsToday: 0)
            }

            let totalDomains = scalarInt(db: db, sql: "SELECT COUNT(*) FROM domains")
            let totalVisits = scalarInt(db: db, sql: "SELECT COUNT(*) FROM visits")

            let startOfTodayMs = Self.startOfTodayMs()
            let domainsToday = scalarInt(
                db: db,
                sql: "SELECT COUNT(DISTINCT domain_id) FROM visits WHERE timestamp >= ?",
                bind: { stmt in sqlite3_bind_int64(stmt, 1, startOfTodayMs) }
            )

            return DatabaseStats(
                totalDomains: totalDomains,
                totalVisits: totalVisits,
                domainsToday: domainsToday
            )
        }
    }

    /// Unique domain counts grouped by calendar day for the last `days` days.
    func dailyDomainCounts(days: Int = 7) -> [(date: Date, count: Int)] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            // Build the lower bound timestamp.
            let calendar = Calendar.current
            guard let startDate = calendar.date(byAdding: .day, value: -(days - 1), to: calendar.startOfDay(for: Date())) else {
                return []
            }
            let startMs = Int64(startDate.timeIntervalSince1970 * 1000)

            // Group visit timestamps into calendar days by dividing ms by ms-per-day.
            let sql = """
                SELECT (timestamp / 86400000) AS day_bucket,
                       COUNT(DISTINCT domain_id) AS cnt
                FROM visits
                WHERE timestamp >= ?
                GROUP BY day_bucket
                ORDER BY day_bucket ASC
                """

            var results: [Int64: Int] = [:]
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int64(stmt, 1, startMs)

            while sqlite3_step(stmt) == SQLITE_ROW {
                let bucket = sqlite3_column_int64(stmt, 0)
                let count = Int(sqlite3_column_int(stmt, 1))
                results[bucket] = count
            }

            // Fill in zero-count days so the chart always has `days` entries.
            var output: [(date: Date, count: Int)] = []
            for offset in 0..<days {
                guard let dayDate = calendar.date(byAdding: .day, value: offset, to: startDate) else { continue }
                let bucket = Int64(dayDate.timeIntervalSince1970 * 1000) / 86400000
                let count = results[bucket] ?? 0
                output.append((date: dayDate, count: count))
            }

            return output
        }
    }

    /// Visit history for a specific domain.
    func visits(forDomainId domainId: Int64, limit: Int = 50) -> [VisitRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain_id, timestamp, source
                FROM visits
                WHERE domain_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int64(stmt, 1, domainId)
            sqlite3_bind_int(stmt, 2, Int32(limit))

            var records: [VisitRecord] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                let record = VisitRecord(
                    id: sqlite3_column_int64(stmt, 0),
                    domainId: sqlite3_column_int64(stmt, 1),
                    timestampMs: sqlite3_column_int64(stmt, 2),
                    source: columnText(stmt, index: 3)
                )
                records.append(record)
            }
            return records
        }
    }

    /// Most recent sites (grouped by site_domain), ordered by `last_seen DESC`.
    func recentSites(limit: Int = 100) -> [SiteRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            return querySites(
                db: db,
                whereClause: "site_domain IS NOT NULL AND site_domain != '_infra'",
                bind: { stmt in sqlite3_bind_int(stmt, 1, Int32(limit)) },
                limit: "LIMIT ?"
            )
        }
    }

    /// Sites whose site_domain or constituent domains contain `query` (case-insensitive).
    func searchSites(query: String) -> [SiteRecord] {
        let escaped = query.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "%", with: "\\%")
            .replacingOccurrences(of: "_", with: "\\_")
        let pattern = "%\(escaped)%"
        return queue.sync { () -> [SiteRecord] in
            ensureOpen()
            guard let db = db else { return [] }

            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            return querySites(
                db: db,
                whereClause: "site_domain IS NOT NULL AND site_domain != '_infra' AND (site_domain LIKE ?1 ESCAPE '\\' OR domain LIKE ?1 ESCAPE '\\')",
                bind: { stmt in
                    _ = pattern.withCString { cStr in
                        sqlite3_bind_text(stmt, 1, cStr, -1, transient)
                    }
                },
                limit: "LIMIT 200"
            )
        }
    }

    /// Shared implementation for site aggregate queries with graceful column fallback.
    ///
    /// When `bytes_in`/`bytes_out` columns don't yet exist on the `domains` table
    /// (older DB before Rust migration runs), the first prepare will fail and we
    /// retry with a legacy SELECT that omits those columns.
    private func querySites(
        db: OpaquePointer,
        whereClause: String,
        bind: (OpaquePointer) -> Void,
        limit: String
    ) -> [SiteRecord] {
        let fullSQL = """
            SELECT site_domain,
                   COUNT(*) AS domain_count,
                   SUM(visit_count) AS total_visits,
                   MAX(last_seen) AS last_seen,
                   MIN(first_seen) AS first_seen,
                   COALESCE(SUM(bytes_in), 0) AS total_bytes_in,
                   COALESCE(SUM(bytes_out), 0) AS total_bytes_out
            FROM domains
            WHERE \(whereClause)
            GROUP BY site_domain
            ORDER BY last_seen DESC
            \(limit)
            """

        let legacySQL = """
            SELECT site_domain,
                   COUNT(*) AS domain_count,
                   SUM(visit_count) AS total_visits,
                   MAX(last_seen) AS last_seen,
                   MIN(first_seen) AS first_seen
            FROM domains
            WHERE \(whereClause)
            GROUP BY site_domain
            ORDER BY last_seen DESC
            \(limit)
            """

        func buildRecords(stmt: OpaquePointer, hasBytes: Bool) -> [SiteRecord] {
            var records: [SiteRecord] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                records.append(SiteRecord(
                    siteDomain: columnText(stmt, index: 0),
                    domainCount: Int(sqlite3_column_int(stmt, 1)),
                    totalVisits: Int(sqlite3_column_int(stmt, 2)),
                    firstSeenMs: sqlite3_column_int64(stmt, 4),
                    lastSeenMs: sqlite3_column_int64(stmt, 3),
                    totalBytesIn: hasBytes ? sqlite3_column_int64(stmt, 5) : Int64(0),
                    totalBytesOut: hasBytes ? sqlite3_column_int64(stmt, 6) : Int64(0)
                ))
            }
            return records
        }

        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, fullSQL, -1, &stmt, nil) == SQLITE_OK {
            defer { sqlite3_finalize(stmt) }
            bind(stmt!)
            return buildRecords(stmt: stmt!, hasBytes: true)
        }

        // bytes_in/bytes_out not present yet — fall back to legacy query.
        guard sqlite3_prepare_v2(db, legacySQL, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        bind(stmt!)
        return buildRecords(stmt: stmt!, hasBytes: false)
    }

    /// All domains belonging to a specific site, ordered by visit count descending.
    func domainsForSite(_ siteDomain: String) -> [DomainRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, first_seen, last_seen, visit_count, source, site_domain,
                       tls_version, bytes_in, bytes_out
                FROM domains WHERE site_domain = ?
                ORDER BY visit_count DESC
                """
            let legacySQL = """
                SELECT id, domain, first_seen, last_seen, visit_count, source, site_domain
                FROM domains WHERE site_domain = ?
                ORDER BY visit_count DESC
                """

            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            return queryDomains(db: db, sql: sql, legacySQL: legacySQL, bind: { stmt in
                _ = siteDomain.withCString { cStr in
                    sqlite3_bind_text(stmt, 1, cStr, -1, transient)
                }
            }, hasSiteDomain: true)
        }
    }

    /// IP addresses observed for a domain, ordered by most recently seen.
    ///
    /// Returns an empty array when the `domain_ips` table does not yet exist
    /// (i.e. the Rust migration hasn't run yet on this device).
    func ipsForDomain(_ domain: String) -> [(ip: String, firstSeen: Int64, lastSeen: Int64)] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT ip, first_seen, last_seen
                FROM domain_ips
                WHERE domain = ?
                ORDER BY last_seen DESC
                LIMIT 10
                """

            var stmt: OpaquePointer?
            // If the table doesn't exist yet, prepare will fail — return empty.
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            _ = domain.withCString { cStr in
                sqlite3_bind_text(stmt, 1, cStr, -1, transient)
            }

            var results: [(ip: String, firstSeen: Int64, lastSeen: Int64)] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                results.append((
                    ip: columnText(stmt, index: 0),
                    firstSeen: sqlite3_column_int64(stmt, 1),
                    lastSeen: sqlite3_column_int64(stmt, 2)
                ))
            }
            return results
        }
    }

    /// DNS query types observed for a domain, ordered by most frequent.
    ///
    /// Returns an empty array when the `dns_query_types` table does not yet exist.
    func queryTypesForDomain(_ domain: String) -> [(queryType: Int, name: String, count: Int, lastSeen: Int64)] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT query_type, query_type_name, query_count, last_seen
                FROM dns_query_types
                WHERE domain = ?
                ORDER BY query_count DESC
                """

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            _ = domain.withCString { cStr in
                sqlite3_bind_text(stmt, 1, cStr, -1, transient)
            }

            var results: [(queryType: Int, name: String, count: Int, lastSeen: Int64)] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                results.append((
                    queryType: Int(sqlite3_column_int(stmt, 0)),
                    name: columnText(stmt, index: 1),
                    count: Int(sqlite3_column_int(stmt, 2)),
                    lastSeen: sqlite3_column_int64(stmt, 3)
                ))
            }
            return results
        }
    }

    // MARK: - Threat Queries

    /// Most recent threat alerts, ordered by timestamp descending.
    func fetchRecentAlerts(limit: Int = 50) -> [ThreatRecord] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT id, domain, threat_type, feed_name, confidence, timestamp_ms, dismissed
                FROM sentinel_alerts
                ORDER BY timestamp_ms DESC
                LIMIT ?
                """

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int(stmt, 1, Int32(limit))

            var records: [ThreatRecord] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                records.append(ThreatRecord(
                    id: sqlite3_column_int64(stmt, 0),
                    domain: columnText(stmt, index: 1),
                    threatType: columnText(stmt, index: 2),
                    feedName: columnText(stmt, index: 3),
                    confidence: sqlite3_column_double(stmt, 4),
                    timestampMs: sqlite3_column_int64(stmt, 5),
                    dismissed: sqlite3_column_int(stmt, 6) != 0
                ))
            }
            return records
        }
    }

    /// Total number of threat alerts.
    func fetchAlertCount() -> Int {
        queue.sync {
            ensureOpen()
            guard let db = db else { return 0 }
            return scalarInt(db: db, sql: "SELECT COUNT(*) FROM sentinel_alerts")
        }
    }

    /// Number of threat alerts since a given date.
    func fetchAlertCountSince(_ date: Date) -> Int {
        queue.sync {
            ensureOpen()
            guard let db = db else { return 0 }
            let ms = Int64(date.timeIntervalSince1970 * 1000)
            return scalarInt(
                db: db,
                sql: "SELECT COUNT(*) FROM sentinel_alerts WHERE timestamp_ms >= ?",
                bind: { stmt in sqlite3_bind_int64(stmt, 1, ms) }
            )
        }
    }

    /// Threat counts grouped by type.
    func fetchThreatsByType() -> [(type: String, count: Int)] {
        queue.sync {
            ensureOpen()
            guard let db = db else { return [] }

            let sql = """
                SELECT threat_type, COUNT(*) as cnt
                FROM sentinel_alerts
                GROUP BY threat_type
                ORDER BY cnt DESC
                """

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }

            var results: [(type: String, count: Int)] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                results.append((
                    type: columnText(stmt, index: 0),
                    count: Int(sqlite3_column_int(stmt, 1))
                ))
            }
            return results
        }
    }

    /// Mark an alert as dismissed.
    func dismissAlert(id: Int64) {
        queue.sync {
            ensureOpen()
            guard let db = db else { return }

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(
                db, "UPDATE sentinel_alerts SET dismissed = 1 WHERE id = ?", -1, &stmt, nil
            ) == SQLITE_OK else { return }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int64(stmt, 1, id)
            sqlite3_step(stmt)
        }
    }

    // MARK: - Allowlist Queries

    /// All domains on the threat allowlist (read from shared UserDefaults).
    func fetchAllowlist() -> [String] {
        Self.allowlistFromDefaults().sorted()
    }

    /// Add a domain to the threat allowlist.
    ///
    /// Uses UserDefaults in the App Group as IPC — avoids SQLite write locks
    /// from the main app process which would cause 0xDEAD10CC on suspension.
    /// The Network Extension reads this on next packet to sync its in-memory
    /// allowlist.
    func addToAllowlist(domain: String) {
        var list = Self.allowlistFromDefaults()
        let lower = domain.lowercased()
        if !list.contains(lower) {
            list.append(lower)
            AppGroupConfig.sharedDefaults.set(list, forKey: "sentinel_allowlist")
        }
    }

    /// Remove a domain from the threat allowlist.
    func removeFromAllowlist(domain: String) {
        var list = Self.allowlistFromDefaults()
        let lower = domain.lowercased()
        list.removeAll { $0 == lower }
        AppGroupConfig.sharedDefaults.set(list, forKey: "sentinel_allowlist")
    }

    /// Check if a domain is on the allowlist.
    func isAllowlisted(domain: String) -> Bool {
        Self.allowlistFromDefaults().contains(domain.lowercased())
    }

    /// Read the current allowlist from shared UserDefaults.
    static func allowlistFromDefaults() -> [String] {
        AppGroupConfig.sharedDefaults.stringArray(forKey: "sentinel_allowlist") ?? []
    }

    // MARK: - Helpers

    /// Runs a query that returns `DomainRecord` rows.
    ///
    /// Expected column layout (matches all callers):
    ///   0: id, 1: domain, 2: first_seen, 3: last_seen, 4: visit_count, 5: source
    ///   hasSiteDomain=false: 6: tls_version, 7: bytes_in, 8: bytes_out
    ///   hasSiteDomain=true:  6: site_domain, 7: tls_version, 8: bytes_in, 9: bytes_out
    ///
    /// If the new columns are absent (older DB), prepare fails and we fall back to
    /// the legacy SELECT so existing functionality is preserved.
    private func queryDomains(
        db: OpaquePointer,
        sql: String,
        legacySQL: String,
        bind: ((OpaquePointer) -> Void)? = nil,
        hasSiteDomain: Bool = false
    ) -> [DomainRecord] {
        var stmt: OpaquePointer?

        // Primary attempt: full SELECT including new columns.
        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
            defer { sqlite3_finalize(stmt) }
            bind?(stmt!)

            let tlsCol: Int32 = hasSiteDomain ? 7 : 6
            let bytesInCol: Int32 = hasSiteDomain ? 8 : 7
            let bytesOutCol: Int32 = hasSiteDomain ? 9 : 8

            var records: [DomainRecord] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                let siteDomain: String? = hasSiteDomain ? columnOptionalText(stmt, index: 6) : nil
                records.append(DomainRecord(
                    id: sqlite3_column_int64(stmt, 0),
                    domain: columnText(stmt, index: 1),
                    firstSeenMs: sqlite3_column_int64(stmt, 2),
                    lastSeenMs: sqlite3_column_int64(stmt, 3),
                    visitCount: Int(sqlite3_column_int(stmt, 4)),
                    source: columnText(stmt, index: 5),
                    siteDomain: siteDomain,
                    tlsVersion: columnOptionalText(stmt, index: tlsCol),
                    bytesIn: sqlite3_column_int64(stmt, bytesInCol),
                    bytesOut: sqlite3_column_int64(stmt, bytesOutCol)
                ))
            }
            return records
        }

        // Fallback: columns not yet added by Rust migration.
        guard sqlite3_prepare_v2(db, legacySQL, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        bind?(stmt!)

        var records: [DomainRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let siteDomain: String? = hasSiteDomain ? columnOptionalText(stmt, index: 6) : nil
            records.append(DomainRecord(
                id: sqlite3_column_int64(stmt, 0),
                domain: columnText(stmt, index: 1),
                firstSeenMs: sqlite3_column_int64(stmt, 2),
                lastSeenMs: sqlite3_column_int64(stmt, 3),
                visitCount: Int(sqlite3_column_int(stmt, 4)),
                source: columnText(stmt, index: 5),
                siteDomain: siteDomain,
                tlsVersion: nil,
                bytesIn: 0,
                bytesOut: 0
            ))
        }
        return records
    }

    /// Read a non-null TEXT column as a Swift String (empty string fallback).
    private func columnText(_ stmt: OpaquePointer?, index: Int32) -> String {
        guard let cStr = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: cStr)
    }

    /// Read a nullable TEXT column.
    private func columnOptionalText(_ stmt: OpaquePointer?, index: Int32) -> String? {
        guard sqlite3_column_type(stmt, index) != SQLITE_NULL,
              let cStr = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: cStr)
    }

    /// Execute a scalar `SELECT COUNT(*)` style query, returning an Int.
    private func scalarInt(
        db: OpaquePointer,
        sql: String,
        bind: ((OpaquePointer) -> Void)? = nil
    ) -> Int {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        if let bind = bind { bind(stmt!) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Delete visit rows older than `days` days. Called on app launch to
    /// enforce the user's retention setting.
    func cleanupOldVisits(olderThanDays days: Int) {
        queue.sync {
            ensureOpen()
            guard let db = db else { return }
            let cutoffMs = Int64(Date().timeIntervalSince1970 * 1000) - Int64(days) * 86_400_000
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "DELETE FROM visits WHERE timestamp < ?", -1, &stmt, nil) == SQLITE_OK else { return }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, cutoffMs)
            sqlite3_step(stmt)
        }
    }

    /// Millisecond timestamp at the start of today (midnight, local time zone).
    private static func startOfTodayMs() -> Int64 {
        let startOfDay = Calendar.current.startOfDay(for: Date())
        return Int64(startOfDay.timeIntervalSince1970 * 1000)
    }
}
