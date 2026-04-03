/// Maximum number of concurrent TCP flows tracked for reassembly.
pub const MAX_TCP_FLOWS: usize = 1024;

/// Maximum bytes buffered per TCP flow for reassembly.
pub const MAX_FLOW_BUFFER_BYTES: usize = 16_384;

/// Flow timeout in seconds.
pub const FLOW_TIMEOUT_SECS: u64 = 10;

/// Batch insert threshold.
pub const BATCH_INSERT_SIZE: usize = 50;

/// Batch flush interval in milliseconds.
pub const BATCH_FLUSH_INTERVAL_MS: u64 = 500;

/// DNS standard port
pub const DNS_PORT: u16 = 53;

/// HTTPS standard port
pub const HTTPS_PORT: u16 = 443;

/// Maximum DNS query name length (per RFC 1035)
pub const MAX_DNS_NAME_LENGTH: usize = 253;

/// DNS header size in bytes
pub const DNS_HEADER_SIZE: usize = 12;

/// Maximum entries in DNS/IP correlator
pub const MAX_CORRELATOR_ENTRIES: usize = 4096;

/// DNS/IP correlation TTL in seconds
pub const CORRELATOR_TTL_SECS: u64 = 300;
