use rusqlite::{params, Connection};

use crate::domain::DomainRecord;
use crate::errors::EngineError;
use crate::site_mapper;

/// SQLite-backed persistent store for observed domain records and visit history.
pub struct DomainStorage {
    conn: Connection,
}

impl DomainStorage {
    /// Opens (or creates) the SQLite database at `db_path` and applies the
    /// required schema and PRAGMA configuration.
    ///
    /// Pass `":memory:"` for an in-process ephemeral database (useful in
    /// tests).
    ///
    /// PRAGMAs applied:
    /// - `journal_mode = WAL` — concurrent readers do not block the writer.
    /// - `synchronous = NORMAL` — durable enough for non-critical data.
    /// - `cache_size = -2000` — approximately 2 MB page cache.
    /// - `auto_vacuum = INCREMENTAL` — reclaim free pages incrementally.
    /// - `busy_timeout = 5000` — wait up to 5 s before returning SQLITE_BUSY.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseOpen`] if the database cannot be opened
    /// or if schema creation fails.
    pub fn new(db_path: &str) -> Result<Self, EngineError> {
        let conn = Connection::open(db_path)?;

        // Apply recommended PRAGMA settings before creating the schema.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -2000;
             PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA busy_timeout = 5000;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS domains (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                domain       TEXT    NOT NULL,
                first_seen   INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                source       TEXT    NOT NULL,
                visit_count  INTEGER NOT NULL DEFAULT 1,
                site_domain  TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain
                ON domains(domain);

            CREATE TABLE IF NOT EXISTS visits (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id  INTEGER NOT NULL REFERENCES domains(id),
                timestamp  INTEGER NOT NULL,
                source     TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_visits_timestamp
                ON visits(timestamp);
            CREATE INDEX IF NOT EXISTS idx_visits_domain_id
                ON visits(domain_id);

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );",
        )?;

        // Migration: add site_domain column if it doesn't exist (for databases
        // created before this feature was introduced).
        //
        // The ALTER TABLE is wrapped in a match to handle the race condition
        // where both the app and the Network Extension open the database
        // simultaneously after an update — the second process would see
        // "duplicate column name" and fail without this guard.
        let has_site_domain: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('domains') WHERE name = 'site_domain'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .unwrap_or(false);

        if !has_site_domain {
            match conn.execute_batch("ALTER TABLE domains ADD COLUMN site_domain TEXT;") {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("duplicate column name") {
                        return Err(e.into());
                    }
                    // Column was added by another process — safe to continue.
                }
            }
        }

        // Always backfill rows with NULL site_domain — covers both fresh
        // migrations and crash-recovery where a previous backfill was
        // interrupted before completing.
        {
            let mut select_stmt =
                conn.prepare("SELECT id, domain FROM domains WHERE site_domain IS NULL")?;
            let rows: Vec<(i64, String)> = select_stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .filter_map(|r| r.ok())
                .collect();
            drop(select_stmt);

            for (id, domain) in &rows {
                let site = site_mapper::map_to_site(domain);
                conn.execute(
                    "UPDATE domains SET site_domain = ?1 WHERE id = ?2",
                    params![site.as_ref(), id],
                )?;
            }
        }

        // Ensure the index exists for both fresh installs and migrated databases.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_domains_site_domain ON domains(site_domain);",
        )?;

        // Migration: add tls_version column if it doesn't exist.
        let has_tls_version: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('domains') WHERE name = 'tls_version'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .unwrap_or(false);

        if !has_tls_version {
            match conn.execute_batch("ALTER TABLE domains ADD COLUMN tls_version TEXT;") {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("duplicate column name") {
                        return Err(e.into());
                    }
                    // Column was added by another process — safe to continue.
                }
            }
        }

        // Migration: add bytes_in column if it doesn't exist.
        let has_bytes_in: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('domains') WHERE name = 'bytes_in'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .unwrap_or(false);

        if !has_bytes_in {
            match conn.execute_batch(
                "ALTER TABLE domains ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0;",
            ) {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("duplicate column name") {
                        return Err(e.into());
                    }
                }
            }
        }

        // Migration: add bytes_out column if it doesn't exist.
        let has_bytes_out: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('domains') WHERE name = 'bytes_out'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .unwrap_or(false);

        if !has_bytes_out {
            match conn.execute_batch(
                "ALTER TABLE domains ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0;",
            ) {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("duplicate column name") {
                        return Err(e.into());
                    }
                }
            }
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS domain_ips (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain     TEXT    NOT NULL,
                ip         TEXT    NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL,
                UNIQUE(domain, ip)
            );
            CREATE INDEX IF NOT EXISTS idx_domain_ips_domain ON domain_ips(domain);

            CREATE TABLE IF NOT EXISTS dns_query_types (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT    NOT NULL,
                query_type      INTEGER NOT NULL,
                query_type_name TEXT    NOT NULL,
                first_seen      INTEGER NOT NULL,
                last_seen       INTEGER NOT NULL,
                query_count     INTEGER NOT NULL DEFAULT 1,
                UNIQUE(domain, query_type)
            );
            CREATE INDEX IF NOT EXISTS idx_dns_query_types_domain ON dns_query_types(domain);",
        )?;

        Ok(Self { conn })
    }

    /// Inserts or updates a batch of [`DomainRecord`]s inside a single
    /// transaction.
    ///
    /// For each record:
    /// - The `domains` row is upserted: on a domain conflict the `last_seen`
    ///   timestamp, `source`, and `visit_count` are updated.
    /// - A new row is always appended to the `visits` table.
    ///
    /// The entire batch is committed atomically; if any step fails the
    /// transaction is rolled back.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if any SQL operation fails.
    pub fn batch_insert(&mut self, records: &[DomainRecord]) -> Result<(), EngineError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        for record in records {
            let site = site_mapper::map_to_site(&record.domain);

            tx.execute(
                "INSERT INTO domains (domain, first_seen, last_seen, source, visit_count, site_domain, tls_version)
                 VALUES (?1, ?2, ?2, ?3, 1, ?4, ?5)
                 ON CONFLICT(domain) DO UPDATE SET
                     last_seen   = excluded.last_seen,
                     visit_count = visit_count + 1,
                     source      = CASE
                         WHEN excluded.source = 'sni' THEN 'sni'
                         WHEN excluded.source = 'dns_correlation' THEN
                             CASE WHEN domains.source = 'sni' THEN 'sni'
                                  ELSE excluded.source
                             END
                         ELSE domains.source
                     END,
                     tls_version = COALESCE(excluded.tls_version, domains.tls_version)",
                params![
                    record.domain,
                    record.timestamp_ms,
                    record.source.as_str(),
                    site.as_ref(),
                    record.tls_version.as_deref(),
                ],
            )
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            // Fetch the domain's row id for the visit foreign key.
            let domain_id: i64 = tx
                .query_row(
                    "SELECT id FROM domains WHERE domain = ?1",
                    params![record.domain],
                    |row| row.get(0),
                )
                .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            tx.execute(
                "INSERT INTO visits (domain_id, timestamp, source)
                 VALUES (?1, ?2, ?3)",
                params![domain_id, record.timestamp_ms, record.source.as_str()],
            )
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        Ok(())
    }

    /// Returns the number of distinct domains stored in the database.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if the query fails.
    pub fn domain_count(&self) -> Result<i64, EngineError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM domains", [], |row| row.get(0))
            .map_err(|e| EngineError::DatabaseWrite(format!("Failed to read from database: {e}")))
    }

    /// Inserts or updates a batch of `(domain, ip, timestamp_ms)` triples in
    /// the `domain_ips` table inside a single transaction.
    ///
    /// On a `(domain, ip)` conflict the `last_seen` timestamp is updated while
    /// `first_seen` is preserved.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if any SQL operation fails.
    pub fn batch_upsert_domain_ips(
        &mut self,
        entries: &[(String, String, i64)],
    ) -> Result<(), EngineError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO domain_ips (domain, ip, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?3)
                     ON CONFLICT(domain, ip) DO UPDATE SET last_seen = excluded.last_seen",
                )
                .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            for (domain, ip, ts) in entries {
                stmt.execute(params![domain, ip, ts])
                    .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
            }
        }

        tx.commit()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        Ok(())
    }

    /// Inserts or updates a batch of `(domain, query_type, query_type_name,
    /// timestamp_ms)` tuples in the `dns_query_types` table inside a single
    /// transaction.
    ///
    /// On a `(domain, query_type)` conflict the `last_seen` timestamp is
    /// updated and `query_count` is incremented by one; `first_seen` is
    /// preserved.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if any SQL operation fails.
    pub fn batch_upsert_query_types(
        &mut self,
        entries: &[(String, u16, String, i64)],
    ) -> Result<(), EngineError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO dns_query_types
                         (domain, query_type, query_type_name, first_seen, last_seen, query_count)
                     VALUES (?1, ?2, ?3, ?4, ?4, 1)
                     ON CONFLICT(domain, query_type) DO UPDATE SET
                         last_seen   = excluded.last_seen,
                         query_count = dns_query_types.query_count + 1",
                )
                .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

            for (domain, query_type, query_type_name, ts) in entries {
                stmt.execute(params![domain, query_type, query_type_name, ts])
                    .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
            }
        }

        tx.commit()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;

        Ok(())
    }

    /// Accumulates byte counts for a batch of domains inside a single transaction.
    ///
    /// For each `(domain, bytes_in, bytes_out)` triple the corresponding row in
    /// `domains` has its counters incremented by the given amounts.  Rows that
    /// do not yet exist in `domains` are silently skipped (UPDATE affects zero
    /// rows).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if any SQL operation fails.
    pub fn batch_update_domain_bytes(
        &mut self,
        entries: &[(String, u64, u64)],
    ) -> Result<(), EngineError> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "UPDATE domains
                     SET bytes_in  = bytes_in  + ?2,
                         bytes_out = bytes_out + ?3
                     WHERE domain = ?1",
                )
                .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
            for (domain, bytes_in, bytes_out) in entries {
                stmt.execute(params![domain, bytes_in, bytes_out])
                    .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| EngineError::DatabaseWrite(e.to_string()))?;
        Ok(())
    }

    /// Deletes all visit rows with a timestamp strictly older than
    /// `older_than_ms` (Unix milliseconds).
    ///
    /// Returns the number of rows removed.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DatabaseWrite`] if the DELETE fails.
    pub fn cleanup_old_visits(&self, older_than_ms: i64) -> Result<usize, EngineError> {
        let rows_deleted = self
            .conn
            .execute(
                "DELETE FROM visits WHERE timestamp < ?1",
                params![older_than_ms],
            )
            .map_err(|e| EngineError::DatabaseWrite(format!("Failed to read from database: {e}")))?;

        Ok(rows_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DetectionSource, DomainRecord};

    /// Creates an in-memory [`DomainStorage`] and panics on failure.
    fn in_memory_storage() -> DomainStorage {
        DomainStorage::new(":memory:").expect("in-memory DB should open")
    }

    /// Builds a [`DomainRecord`] with a specific timestamp, bypassing the
    /// noise and validation filters used in `from_raw_name`.
    fn make_record(domain: &str, timestamp_ms: i64, source: DetectionSource) -> DomainRecord {
        DomainRecord {
            domain: domain.to_owned(),
            timestamp_ms,
            source,
            tls_version: None,
        }
    }

    #[test]
    fn in_memory_db_tables_exist() {
        let storage = in_memory_storage();

        // Query sqlite_master to verify the expected tables were created.
        let count: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table'
                   AND name IN ('domains', 'visits', 'settings')",
                [],
                |row| row.get(0),
            )
            .expect("sqlite_master query should succeed");

        assert_eq!(count, 3, "domains, visits, and settings tables must exist");
    }

    #[test]
    fn insert_three_records_domain_count_is_three() {
        let mut storage = in_memory_storage();

        let records = vec![
            make_record("example.com", 1_000, DetectionSource::Dns),
            make_record("github.com", 2_000, DetectionSource::Sni),
            make_record("rust-lang.org", 3_000, DetectionSource::DnsCorrelation),
        ];

        storage.batch_insert(&records).expect("batch_insert should succeed");

        assert_eq!(
            storage.domain_count().expect("domain_count should succeed"),
            3
        );
    }

    #[test]
    fn insert_same_domain_twice_count_stays_one_visit_increments() {
        let mut storage = in_memory_storage();

        let first = make_record("example.com", 1_000, DetectionSource::Dns);
        storage
            .batch_insert(&[first])
            .expect("first insert should succeed");

        let second = make_record("example.com", 2_000, DetectionSource::Sni);
        storage
            .batch_insert(&[second])
            .expect("second insert should succeed");

        // Domain count must still be 1.
        assert_eq!(
            storage.domain_count().expect("domain_count should succeed"),
            1,
            "duplicate domain must not create a second domains row"
        );

        // visit_count on the domains row must be 2.
        let visit_count: i64 = storage
            .conn
            .query_row(
                "SELECT visit_count FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("visit_count query should succeed");

        assert_eq!(visit_count, 2, "visit_count must be incremented on upsert");

        // The visits table must have 2 rows.
        let visits_rows: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(*) FROM visits",
                [],
                |row| row.get(0),
            )
            .expect("visits count query should succeed");

        assert_eq!(visits_rows, 2, "each visit must produce a visits row");
    }

    #[test]
    fn cleanup_old_visits_removes_old_entries() {
        let mut storage = in_memory_storage();

        let records = vec![
            make_record("old.example.com", 500, DetectionSource::Dns),
            make_record("also-old.example.com", 900, DetectionSource::Dns),
            make_record("new.example.com", 2_000, DetectionSource::Dns),
        ];
        storage.batch_insert(&records).expect("batch_insert should succeed");

        // Verify that 3 visit rows exist before cleanup.
        let before: i64 = storage
            .conn
            .query_row("SELECT COUNT(*) FROM visits", [], |row| row.get(0))
            .expect("count query should succeed");
        assert_eq!(before, 3);

        // Remove visits older than timestamp 1_000.
        let removed = storage
            .cleanup_old_visits(1_000)
            .expect("cleanup should succeed");

        assert_eq!(removed, 2, "two old visit rows should have been removed");

        let after: i64 = storage
            .conn
            .query_row("SELECT COUNT(*) FROM visits", [], |row| row.get(0))
            .expect("count query should succeed");
        assert_eq!(after, 1, "one recent visit row should remain");
    }

    #[test]
    fn upsert_preserves_sni_source_over_dns() {
        let mut storage = in_memory_storage();

        // First visit via SNI
        let sni_record = make_record("example.com", 1_000, DetectionSource::Sni);
        storage.batch_insert(&[sni_record]).expect("insert should succeed");

        let source: String = storage
            .conn
            .query_row(
                "SELECT source FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(source, "sni", "initial source must be sni");

        // Second visit via DNS — must NOT overwrite sni
        let dns_record = make_record("example.com", 2_000, DetectionSource::Dns);
        storage.batch_insert(&[dns_record]).expect("insert should succeed");

        let source_after: String = storage
            .conn
            .query_row(
                "SELECT source FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(
            source_after, "sni",
            "source must remain 'sni' after a dns upsert — sni is higher fidelity"
        );
    }

    #[test]
    fn upsert_upgrades_dns_to_sni() {
        let mut storage = in_memory_storage();

        // First visit via DNS
        let dns_record = make_record("example.com", 1_000, DetectionSource::Dns);
        storage.batch_insert(&[dns_record]).expect("insert should succeed");

        // Second visit via SNI — must upgrade
        let sni_record = make_record("example.com", 2_000, DetectionSource::Sni);
        storage.batch_insert(&[sni_record]).expect("insert should succeed");

        let source: String = storage
            .conn
            .query_row(
                "SELECT source FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(
            source, "sni",
            "source must be upgraded to 'sni' when sni is observed"
        );
    }

    #[test]
    fn upsert_preserves_sni_over_dns_correlation() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::Sni)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::DnsCorrelation)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "sni", "sni must not be overwritten by dns_correlation");
    }

    #[test]
    fn upsert_upgrades_dns_to_dns_correlation() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::Dns)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::DnsCorrelation)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "dns_correlation", "dns should be upgraded to dns_correlation");
    }

    #[test]
    fn upsert_preserves_dns_correlation_over_dns() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::DnsCorrelation)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::Dns)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "dns_correlation", "dns_correlation must not be overwritten by dns");
    }

    #[test]
    fn upsert_upgrades_dns_correlation_to_sni() {
        let mut storage = in_memory_storage();
        storage.batch_insert(&[make_record("example.com", 1_000, DetectionSource::DnsCorrelation)]).unwrap();
        storage.batch_insert(&[make_record("example.com", 2_000, DetectionSource::Sni)]).unwrap();

        let source: String = storage.conn
            .query_row("SELECT source FROM domains WHERE domain = 'example.com'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "sni", "dns_correlation should be upgraded to sni");
    }

    #[test]
    fn cleanup_old_visits_with_no_old_entries_returns_zero() {
        let mut storage = in_memory_storage();

        let records = vec![make_record("example.com", 5_000, DetectionSource::Dns)];
        storage.batch_insert(&records).expect("batch_insert should succeed");

        let removed = storage
            .cleanup_old_visits(1_000)
            .expect("cleanup should succeed");

        assert_eq!(removed, 0, "no rows should be removed when all are newer");
    }

    // ── site_domain integration tests ────────────────────────────────────────

    #[test]
    fn site_domain_populated_on_insert() {
        let mut storage = in_memory_storage();

        storage
            .batch_insert(&[make_record("i.ytimg.com", 1_000, DetectionSource::Dns)])
            .expect("batch_insert should succeed");

        let site: String = storage
            .conn
            .query_row(
                "SELECT site_domain FROM domains WHERE domain = 'i.ytimg.com'",
                [],
                |row| row.get(0),
            )
            .expect("site_domain query should succeed");

        assert_eq!(site, "youtube.com", "ytimg subdomain must map to youtube.com");
    }

    #[test]
    fn site_domain_correct_for_unmapped() {
        let mut storage = in_memory_storage();

        storage
            .batch_insert(&[make_record("www.example.com", 1_000, DetectionSource::Dns)])
            .expect("batch_insert should succeed");

        let site: String = storage
            .conn
            .query_row(
                "SELECT site_domain FROM domains WHERE domain = 'www.example.com'",
                [],
                |row| row.get(0),
            )
            .expect("site_domain query should succeed");

        assert_eq!(site, "example.com", "eTLD+1 fallback must yield example.com");
    }

    #[test]
    fn infra_domain_gets_infra() {
        let mut storage = in_memory_storage();

        storage
            .batch_insert(&[make_record("fonts.googleapis.com", 1_000, DetectionSource::Dns)])
            .expect("batch_insert should succeed");

        let site: String = storage
            .conn
            .query_row(
                "SELECT site_domain FROM domains WHERE domain = 'fonts.googleapis.com'",
                [],
                |row| row.get(0),
            )
            .expect("site_domain query should succeed");

        assert_eq!(site, "_infra", "googleapis must be classified as _infra");
    }

    #[test]
    fn migration_backfills_existing_rows() {
        // Write a "legacy" database that has no site_domain column by creating a
        // fresh storage (which includes the column), then manually nulling it
        // out and dropping the column index to simulate a pre-migration state.
        // The simplest approach: use a temp file so we can reopen the DB.
        let tmp = tempfile::NamedTempFile::new().expect("temp file should be created");
        let db_path = tmp.path().to_str().expect("path must be valid UTF-8").to_owned();

        // Step 1: create a DB in the legacy state (no site_domain column).
        {
            let conn =
                rusqlite::Connection::open(&db_path).expect("should open for legacy setup");
            conn.execute_batch(
                "CREATE TABLE domains (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT NOT NULL,
                    first_seen  INTEGER NOT NULL,
                    last_seen   INTEGER NOT NULL,
                    source      TEXT NOT NULL,
                    visit_count INTEGER NOT NULL DEFAULT 1
                );
                CREATE UNIQUE INDEX idx_domains_domain ON domains(domain);
                CREATE TABLE visits (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER NOT NULL REFERENCES domains(id),
                    timestamp INTEGER NOT NULL,
                    source    TEXT NOT NULL
                );
                CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
                INSERT INTO domains (domain, first_seen, last_seen, source, visit_count)
                VALUES ('i.ytimg.com', 1000, 1000, 'dns', 1);",
            )
            .expect("legacy schema setup should succeed");
        }

        // Step 2: open via DomainStorage — migration should detect the missing
        // column, add it, and backfill the existing row.
        let storage = DomainStorage::new(&db_path).expect("DomainStorage::new should succeed");

        let site: Option<String> = storage
            .conn
            .query_row(
                "SELECT site_domain FROM domains WHERE domain = 'i.ytimg.com'",
                [],
                |row| row.get(0),
            )
            .expect("site_domain query should succeed");

        assert_eq!(
            site.as_deref(),
            Some("youtube.com"),
            "migration must backfill site_domain for existing rows"
        );
    }

    #[test]
    fn site_domain_unchanged_on_upsert() {
        let mut storage = in_memory_storage();

        // First insert: establishes site_domain = "youtube.com".
        storage
            .batch_insert(&[make_record("i.ytimg.com", 1_000, DetectionSource::Dns)])
            .expect("first insert should succeed");

        // Second insert (upsert): visit_count increments, site_domain must stay.
        storage
            .batch_insert(&[make_record("i.ytimg.com", 2_000, DetectionSource::Sni)])
            .expect("second insert should succeed");

        let (site, visit_count): (String, i64) = storage
            .conn
            .query_row(
                "SELECT site_domain, visit_count FROM domains WHERE domain = 'i.ytimg.com'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("query should succeed");

        assert_eq!(site, "youtube.com", "site_domain must not change on upsert");
        assert_eq!(visit_count, 2, "visit_count must be incremented on upsert");
    }

    // ── domain_ips tests ──────────────────────────────────────────────────────

    #[test]
    fn test_domain_ips_upsert_and_update() {
        let mut storage = in_memory_storage();

        let domain = "example.com".to_owned();
        let ip = "93.184.216.34".to_owned();
        let first_ts: i64 = 1_000;
        let second_ts: i64 = 5_000;

        // Initial insert.
        storage
            .batch_upsert_domain_ips(&[(domain.clone(), ip.clone(), first_ts)])
            .expect("first upsert should succeed");

        let (first_seen, last_seen): (i64, i64) = storage
            .conn
            .query_row(
                "SELECT first_seen, last_seen FROM domain_ips
                 WHERE domain = ?1 AND ip = ?2",
                params![domain, ip],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row should exist after first upsert");

        assert_eq!(first_seen, first_ts, "first_seen must be set on initial insert");
        assert_eq!(last_seen, first_ts, "last_seen must match first_seen on initial insert");

        // Second upsert with a newer timestamp.
        storage
            .batch_upsert_domain_ips(&[(domain.clone(), ip.clone(), second_ts)])
            .expect("second upsert should succeed");

        let (first_seen2, last_seen2): (i64, i64) = storage
            .conn
            .query_row(
                "SELECT first_seen, last_seen FROM domain_ips
                 WHERE domain = ?1 AND ip = ?2",
                params![domain, ip],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row should still exist after second upsert");

        assert_eq!(
            first_seen2, first_ts,
            "first_seen must be preserved across upserts"
        );
        assert_eq!(
            last_seen2, second_ts,
            "last_seen must be updated to the newer timestamp"
        );

        // Verify only one row exists (no duplicate on conflict).
        let row_count: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(*) FROM domain_ips WHERE domain = ?1 AND ip = ?2",
                params![domain, ip],
                |row| row.get(0),
            )
            .expect("count query should succeed");

        assert_eq!(row_count, 1, "conflict must not create a duplicate row");
    }

    // ── dns_query_types tests ─────────────────────────────────────────────────

    #[test]
    fn test_dns_query_types_storage() {
        let mut storage = in_memory_storage();

        let domain = "example.com".to_owned();
        let qtype: u16 = 28; // AAAA
        let qtype_name = "AAAA".to_owned();
        let ts1: i64 = 1_000;
        let ts2: i64 = 3_000;

        // First insert.
        storage
            .batch_upsert_query_types(&[(domain.clone(), qtype, qtype_name.clone(), ts1)])
            .expect("first upsert should succeed");

        let (count, first_seen): (i64, i64) = storage
            .conn
            .query_row(
                "SELECT query_count, first_seen FROM dns_query_types
                 WHERE domain = ?1 AND query_type = ?2",
                params![domain, qtype],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row should exist after first upsert");

        assert_eq!(count, 1, "query_count must start at 1");
        assert_eq!(first_seen, ts1, "first_seen must be set on initial insert");

        // Second upsert — query_count must increment to 2, last_seen must update.
        storage
            .batch_upsert_query_types(&[(domain.clone(), qtype, qtype_name.clone(), ts2)])
            .expect("second upsert should succeed");

        let (count2, first_seen2, last_seen2): (i64, i64, i64) = storage
            .conn
            .query_row(
                "SELECT query_count, first_seen, last_seen FROM dns_query_types
                 WHERE domain = ?1 AND query_type = ?2",
                params![domain, qtype],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("row should still exist after second upsert");

        assert_eq!(count2, 2, "query_count must be incremented on conflict");
        assert_eq!(first_seen2, ts1, "first_seen must be preserved across upserts");
        assert_eq!(last_seen2, ts2, "last_seen must be updated on conflict");

        // Verify only one row exists.
        let row_count: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dns_query_types WHERE domain = ?1 AND query_type = ?2",
                params![domain, qtype],
                |row| row.get(0),
            )
            .expect("count query should succeed");

        assert_eq!(row_count, 1, "conflict must not create a duplicate row");
    }

    // ── tls_version tests ─────────────────────────────────────────────────────

    #[test]
    fn test_bytes_columns_default_zero() {
        let mut storage = in_memory_storage();

        storage
            .batch_insert(&[make_record("example.com", 1_000, DetectionSource::Dns)])
            .expect("insert should succeed");

        let (bytes_in, bytes_out): (i64, i64) = storage
            .conn
            .query_row(
                "SELECT bytes_in, bytes_out FROM domains WHERE domain = 'example.com'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("bytes column query should succeed");

        assert_eq!(bytes_in, 0, "bytes_in must default to 0");
        assert_eq!(bytes_out, 0, "bytes_out must default to 0");
    }

    #[test]
    fn test_batch_update_bytes_accumulates() {
        let mut storage = in_memory_storage();

        storage
            .batch_insert(&[make_record("example.com", 1_000, DetectionSource::Dns)])
            .expect("insert should succeed");

        // First accumulation.
        storage
            .batch_update_domain_bytes(&[("example.com".to_owned(), 100, 200)])
            .expect("first byte update should succeed");

        // Second accumulation — values must add up.
        storage
            .batch_update_domain_bytes(&[("example.com".to_owned(), 50, 75)])
            .expect("second byte update should succeed");

        let (bytes_in, bytes_out): (i64, i64) = storage
            .conn
            .query_row(
                "SELECT bytes_in, bytes_out FROM domains WHERE domain = 'example.com'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("bytes column query should succeed");

        assert_eq!(bytes_in, 150, "bytes_in must accumulate across updates");
        assert_eq!(bytes_out, 275, "bytes_out must accumulate across updates");
    }

    #[test]
    fn tls_version_stored_on_insert() {
        let mut storage = in_memory_storage();

        let record = DomainRecord {
            domain: "example.com".to_owned(),
            timestamp_ms: 1_000,
            source: DetectionSource::Sni,
            tls_version: Some("1.3".to_owned()),
        };
        storage.batch_insert(&[record]).expect("insert should succeed");

        let tls_version: Option<String> = storage
            .conn
            .query_row(
                "SELECT tls_version FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("tls_version query should succeed");

        assert_eq!(
            tls_version.as_deref(),
            Some("1.3"),
            "tls_version must be stored on insert"
        );
    }

    #[test]
    fn tls_version_not_overwritten_by_null_on_upsert() {
        let mut storage = in_memory_storage();

        // First insert: establishes tls_version = "1.3".
        let first = DomainRecord {
            domain: "example.com".to_owned(),
            timestamp_ms: 1_000,
            source: DetectionSource::Sni,
            tls_version: Some("1.3".to_owned()),
        };
        storage.batch_insert(&[first]).expect("first insert should succeed");

        // Second insert with no tls_version — must NOT overwrite the existing value.
        storage
            .batch_insert(&[make_record("example.com", 2_000, DetectionSource::Dns)])
            .expect("second insert should succeed");

        let tls_version: Option<String> = storage
            .conn
            .query_row(
                "SELECT tls_version FROM domains WHERE domain = 'example.com'",
                [],
                |row| row.get(0),
            )
            .expect("tls_version query should succeed");

        assert_eq!(
            tls_version.as_deref(),
            Some("1.3"),
            "tls_version must not be overwritten by a NULL on upsert"
        );
    }
}
