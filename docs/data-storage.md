# Data Storage

## Overview

All domain browsing data is stored locally in a single SQLite database file shared between the Network Extension (writer) and the main app (reader) via the App Group container. No browsing data ever leaves the device.

---

## Database File

| Property | Value |
|----------|-------|
| Path | `{AppGroupContainer}/domains.sqlite` |
| Journal mode | WAL (Write-Ahead Logging) |
| Synchronous | NORMAL |
| Page size | 4096 (default) |
| Auto-vacuum | INCREMENTAL |
| Encoding | UTF-8 |

---

## Schema

### Table: `domains`

The primary table storing all observed domain visits.

```sql
CREATE TABLE IF NOT EXISTS domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT    NOT NULL,
    first_seen_ms   INTEGER NOT NULL,  -- Unix timestamp in milliseconds
    last_seen_ms    INTEGER NOT NULL,  -- Updated on subsequent visits
    visit_count     INTEGER NOT NULL DEFAULT 1,
    source          TEXT    NOT NULL DEFAULT 'dns',  -- 'dns' or 'sni'
    dst_ip          TEXT,              -- Destination IP (if available)
    is_blocked      INTEGER NOT NULL DEFAULT 0,  -- User-blocked domain
    category        TEXT               -- Optional: 'social', 'shopping', etc.
);

-- Index for fast lookups by domain name (dedup check on insert)
CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_name ON domains(domain);

-- Index for UI: recent domains sorted by time
CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains(last_seen_ms DESC);

-- Index for stats queries
CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains(first_seen_ms);
```

### Table: `visits`

Granular visit log for timeline/detail views. Each row is one observation event.

```sql
CREATE TABLE IF NOT EXISTS visits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id       INTEGER NOT NULL REFERENCES domains(id),
    timestamp_ms    INTEGER NOT NULL,  -- When this specific visit occurred
    source          TEXT    NOT NULL,   -- 'dns' or 'sni'
    dst_ip          TEXT               -- Resolved IP for this visit
);

-- Index for querying visits by domain
CREATE INDEX IF NOT EXISTS idx_visits_domain ON visits(domain_id, timestamp_ms DESC);

-- Index for time-range queries (stats, cleanup)
CREATE INDEX IF NOT EXISTS idx_visits_time ON visits(timestamp_ms);
```

### Table: `settings`

Key-value store for engine configuration (accessible from both Rust and Swift).

```sql
CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
```

---

## Rust Storage Module (`storage.rs`)

```rust
use rusqlite::{Connection, params};
use crate::domain::DomainRecord;
use crate::errors::EngineError;

/// Handles all SQLite writes from the Rust packet engine.
///
/// This is the ONLY writer to the database. The Swift side only reads.
pub struct DomainStorage {
    conn: Connection,
}

impl DomainStorage {
    /// Open the database and initialize schema.
    pub fn new(db_path: &str) -> Result<Self, EngineError> {
        let conn = Connection::open(db_path)
            .map_err(EngineError::DatabaseOpen)?;

        // Configure for performance + cross-process safety
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -2000;  -- 2MB cache
            PRAGMA auto_vacuum = INCREMENTAL;
            PRAGMA busy_timeout = 5000;  -- Wait up to 5s if DB is locked
        ").map_err(EngineError::DatabaseOpen)?;

        // Create tables
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS domains (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT    NOT NULL,
                first_seen_ms   INTEGER NOT NULL,
                last_seen_ms    INTEGER NOT NULL,
                visit_count     INTEGER NOT NULL DEFAULT 1,
                source          TEXT    NOT NULL DEFAULT 'dns',
                dst_ip          TEXT,
                is_blocked      INTEGER NOT NULL DEFAULT 0,
                category        TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_name
                ON domains(domain);
            CREATE INDEX IF NOT EXISTS idx_domains_last_seen
                ON domains(last_seen_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_domains_first_seen
                ON domains(first_seen_ms);

            CREATE TABLE IF NOT EXISTS visits (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id       INTEGER NOT NULL REFERENCES domains(id),
                timestamp_ms    INTEGER NOT NULL,
                source          TEXT    NOT NULL,
                dst_ip          TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_visits_domain
                ON visits(domain_id, timestamp_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_visits_time
                ON visits(timestamp_ms);

            CREATE TABLE IF NOT EXISTS settings (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL
            );
        ").map_err(EngineError::DatabaseOpen)?;

        Ok(DomainStorage { conn })
    }

    /// Insert a batch of domain records.
    ///
    /// Uses UPSERT: if the domain already exists, update last_seen and
    /// increment visit_count. Also inserts a row into the visits table.
    ///
    /// Wrapped in a single transaction for atomicity and performance.
    pub fn batch_insert(&mut self, records: &[DomainRecord]) -> Result<(), EngineError> {
        let tx = self.conn.transaction()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        {
            let mut upsert_stmt = tx.prepare_cached("
                INSERT INTO domains (domain, first_seen_ms, last_seen_ms, visit_count, source)
                VALUES (?1, ?2, ?2, 1, ?3)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen_ms = ?2,
                    visit_count = visit_count + 1,
                    source = CASE
                        WHEN excluded.source = 'sni' THEN 'sni'
                        ELSE domains.source
                    END
            ").map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            let mut visit_stmt = tx.prepare_cached("
                INSERT INTO visits (domain_id, timestamp_ms, source)
                VALUES (
                    (SELECT id FROM domains WHERE domain = ?1),
                    ?2,
                    ?3
                )
            ").map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            for record in records {
                upsert_stmt.execute(params![
                    record.domain,
                    record.timestamp_ms,
                    record.source.as_str(),
                ]).map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

                visit_stmt.execute(params![
                    record.domain,
                    record.timestamp_ms,
                    record.source.as_str(),
                ]).map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
            }
        }

        tx.commit().map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        Ok(())
    }

    /// Get the total number of unique domains.
    pub fn domain_count(&self) -> Result<i64, EngineError> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM domains",
            [],
            |row| row.get(0),
        ).map_err(|e| EngineError::DatabaseWrite(e.to_string()))
    }

    /// Cleanup: delete visits older than the given threshold.
    pub fn cleanup_old_visits(&self, older_than_ms: i64) -> Result<usize, EngineError> {
        self.conn.execute(
            "DELETE FROM visits WHERE timestamp_ms < ?1",
            params![older_than_ms],
        ).map_err(|e| EngineError::DatabaseWrite(e.to_string()))
    }
}
```

---

## Swift Database Reader (`DatabaseReader.swift`)

```swift
import Foundation
import GRDB

/// Read-only access to the shared domain database from the main app.
///
/// Uses GRDB's ValueObservation for reactive UI updates.
class DatabaseReader {

    private let dbQueue: DatabaseQueue

    init() throws {
        let dbPath = AppGroupConfig.databasePath

        // Open in read-only mode with WAL
        var config = Configuration()
        config.readonly = true
        config.prepareDatabase { db in
            // WAL mode allows concurrent read while extension writes
            // (read-only connections can still read WAL)
        }

        dbQueue = try DatabaseQueue(path: dbPath, configuration: config)
    }

    // MARK: - Domain Queries

    /// Fetch recent domains, sorted by last seen (newest first).
    func recentDomains(limit: Int = 100, offset: Int = 0) throws -> [DomainRow] {
        try dbQueue.read { db in
            try DomainRow.fetchAll(db, sql: """
                SELECT id, domain, first_seen_ms, last_seen_ms,
                       visit_count, source, category
                FROM domains
                WHERE is_blocked = 0
                ORDER BY last_seen_ms DESC
                LIMIT ? OFFSET ?
                """,
                arguments: [limit, offset]
            )
        }
    }

    /// Search domains by name.
    func searchDomains(query: String) throws -> [DomainRow] {
        try dbQueue.read { db in
            try DomainRow.fetchAll(db, sql: """
                SELECT id, domain, first_seen_ms, last_seen_ms,
                       visit_count, source, category
                FROM domains
                WHERE domain LIKE ?
                ORDER BY visit_count DESC
                LIMIT 50
                """,
                arguments: ["%\(query)%"]
            )
        }
    }

    /// Get top domains by visit count.
    func topDomains(limit: Int = 20) throws -> [DomainRow] {
        try dbQueue.read { db in
            try DomainRow.fetchAll(db, sql: """
                SELECT id, domain, first_seen_ms, last_seen_ms,
                       visit_count, source, category
                FROM domains
                WHERE is_blocked = 0
                ORDER BY visit_count DESC
                LIMIT ?
                """,
                arguments: [limit]
            )
        }
    }

    /// Get visit history for a specific domain.
    func visits(forDomainId id: Int64, limit: Int = 50) throws -> [VisitRow] {
        try dbQueue.read { db in
            try VisitRow.fetchAll(db, sql: """
                SELECT id, domain_id, timestamp_ms, source, dst_ip
                FROM visits
                WHERE domain_id = ?
                ORDER BY timestamp_ms DESC
                LIMIT ?
                """,
                arguments: [id, limit]
            )
        }
    }

    /// Get aggregate stats.
    func stats() throws -> DomainStats {
        try dbQueue.read { db in
            let totalDomains = try Int.fetchOne(db, sql:
                "SELECT COUNT(*) FROM domains") ?? 0

            let totalVisits = try Int.fetchOne(db, sql:
                "SELECT COUNT(*) FROM visits") ?? 0

            let todayStart = Calendar.current.startOfDay(for: Date())
                .timeIntervalSince1970 * 1000

            let domainsToday = try Int.fetchOne(db, sql: """
                SELECT COUNT(DISTINCT domain) FROM visits
                WHERE timestamp_ms >= ?
                """, arguments: [Int64(todayStart)]) ?? 0

            return DomainStats(
                totalDomains: totalDomains,
                totalVisits: totalVisits,
                domainsToday: domainsToday
            )
        }
    }

    // MARK: - Reactive Observation

    /// Observe recent domains reactively.
    /// Returns a DatabaseCancellable that must be retained.
    func observeRecentDomains(
        limit: Int = 100,
        onChange: @escaping ([DomainRow]) -> Void
    ) -> DatabaseCancellable {
        let observation = ValueObservation.tracking { db in
            try DomainRow.fetchAll(db, sql: """
                SELECT id, domain, first_seen_ms, last_seen_ms,
                       visit_count, source, category
                FROM domains
                WHERE is_blocked = 0
                ORDER BY last_seen_ms DESC
                LIMIT ?
                """,
                arguments: [limit]
            )
        }

        return observation.start(
            in: dbQueue,
            scheduling: .async(onQueue: .main),
            onError: { error in
                print("Domain observation error: \(error)")
            },
            onChange: onChange
        )
    }
}

// MARK: - Row Types

struct DomainRow: FetchableRecord, Codable {
    let id: Int64
    let domain: String
    let firstSeenMs: Int64
    let lastSeenMs: Int64
    let visitCount: Int
    let source: String
    let category: String?

    enum CodingKeys: String, CodingKey {
        case id
        case domain
        case firstSeenMs = "first_seen_ms"
        case lastSeenMs = "last_seen_ms"
        case visitCount = "visit_count"
        case source
        case category
    }
}

struct VisitRow: FetchableRecord, Codable {
    let id: Int64
    let domainId: Int64
    let timestampMs: Int64
    let source: String
    let dstIp: String?

    enum CodingKeys: String, CodingKey {
        case id
        case domainId = "domain_id"
        case timestampMs = "timestamp_ms"
        case source
        case dstIp = "dst_ip"
    }
}

struct DomainStats {
    let totalDomains: Int
    let totalVisits: Int
    let domainsToday: Int
}
```

---

## Data Lifecycle & Cleanup

### Automatic Cleanup

The visits table grows continuously. Implement periodic cleanup:

```rust
// In engine.rs, called periodically (e.g., every hour or on app launch)
impl PacketEngine {
    pub fn cleanup_old_data(&self, retention_days: i64) -> Result<usize, EngineError> {
        let cutoff_ms = Self::now_millis() - (retention_days * 86_400_000);
        self.storage.cleanup_old_visits(cutoff_ms)
    }
}
```

### Retention Policy

| Data | Default Retention | User Configurable |
|------|------------------|-------------------|
| `domains` rows | Indefinite (unique domains) | Yes — "Clear all data" |
| `visits` rows | 30 days | Yes — 7/14/30/90 days |
| Database file size | ~10-50 MB typical | Auto-compact via INCREMENTAL vacuum |

### Storage Estimates

| Usage Pattern | Unique Domains | Visits/Day | DB Size (30 days) |
|--------------|---------------|------------|-------------------|
| Light user | ~200 | ~2,000 | ~5 MB |
| Average user | ~500 | ~10,000 | ~20 MB |
| Heavy user | ~1,000 | ~50,000 | ~80 MB |

---

## Cross-Process Concurrency

SQLite's WAL mode allows one writer and multiple readers concurrently. Our setup:

| Process | Role | Library | Access |
|---------|------|---------|--------|
| Network Extension | Writer | rusqlite | `Connection::open()` (read-write) |
| Main App | Reader | GRDB.swift | `DatabaseQueue` with `readonly = true` |

WAL mode guarantees:
- The reader (Swift) always sees a consistent snapshot, even while the writer (Rust) is mid-transaction
- The writer never blocks the reader, and vice versa
- No explicit locking needed from our code

The `busy_timeout = 5000` pragma handles the rare case where both processes try to checkpoint the WAL simultaneously.
