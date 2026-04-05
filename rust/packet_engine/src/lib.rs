pub mod engine;
pub mod ip;
pub mod dns;
pub mod tls;
pub mod tcp_reassembly;
pub mod domain;
pub mod storage;
pub mod errors;
pub mod constants;
pub mod dns_filter;
pub mod ech_correlator;
pub mod site_mapper;
pub mod threat_feed;
pub mod threat_matcher;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic;
use std::ptr;
use std::sync::Mutex;

use engine::{PacketEngine, ProcessResult};

/// Global last error message (shared across threads, protected by Mutex).
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(msg: String) {
    if let Ok(mut err) = LAST_ERROR.lock() {
        *err = Some(msg);
    }
}

// ═══════════════════════════════════════════════════════════
// FFI Stats Struct
// ═══════════════════════════════════════════════════════════

/// Stats struct returned to Swift.
#[repr(C)]
pub struct EngineStatsFFI {
    pub packets_processed: u64,
    pub dns_domains_found: u64,
    pub sni_domains_found: u64,
    pub packets_skipped: u64,
    pub active_tcp_flows: u64,
    pub reassembly_memory_bytes: u64,
    pub ech_configs_stripped: u64,
    pub ech_connections_detected: u64,
    pub ech_resolved_via_dns: u64,
    pub ech_unresolved: u64,
}

// ═══════════════════════════════════════════════════════════
// Lifecycle Functions
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_init(
    db_path: *const c_char,
) -> *mut PacketEngine {
    let result = panic::catch_unwind(|| {
        if db_path.is_null() {
            set_last_error("db_path is null".into());
            return ptr::null_mut();
        }

        let path = match CStr::from_ptr(db_path).to_str() {
            Ok(s) => s,
            Err(e) => {
                set_last_error(format!("Invalid UTF-8 in db_path: {}", e));
                return ptr::null_mut();
            }
        };

        match PacketEngine::new(path) {
            Ok(engine) => Box::into_raw(Box::new(engine)),
            Err(e) => {
                set_last_error(format!("Engine init failed: {}", e));
                ptr::null_mut()
            }
        }
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_last_error("Panic during engine init".into());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_destroy(engine: *mut PacketEngine) {
    if !engine.is_null() {
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = Box::from_raw(engine);
        }));
    }
}

// ═══════════════════════════════════════════════════════════
// Packet Processing
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_process(
    engine: *mut PacketEngine,
    packet_data: *const u8,
    packet_len: usize,
    out_buf: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> c_int {
    if engine.is_null() || packet_data.is_null() || packet_len == 0 {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        let packet = std::slice::from_raw_parts(packet_data, packet_len);

        let engine_result = engine.process_packet(packet);
        match engine_result {
            ProcessResult::Forward => {
                if !out_len.is_null() {
                    *out_len = 0;
                }
                0
            }
            ProcessResult::Replace(ref new_packet) | ProcessResult::Block(ref new_packet) => {
                let is_block = matches!(engine_result, ProcessResult::Block(_));
                if out_buf.is_null() || out_capacity < new_packet.len() {
                    return 0;
                }
                let out_slice = std::slice::from_raw_parts_mut(out_buf, out_capacity);
                out_slice[..new_packet.len()].copy_from_slice(new_packet);
                if !out_len.is_null() {
                    *out_len = new_packet.len();
                }
                // 1 = replace (ECH downgrade), 2 = block (DNS sinkhole)
                if is_block { 2 } else { 1 }
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during packet processing".into());
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_process_batch(
    engine: *mut PacketEngine,
    packets: *const *const u8,
    lengths: *const usize,
    count: usize,
) -> c_int {
    if engine.is_null() || packets.is_null() || lengths.is_null() || count == 0 {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        let mut total = 0i32;

        for i in 0..count {
            let pkt_ptr = *packets.add(i);
            let pkt_len = *lengths.add(i);

            if !pkt_ptr.is_null() && pkt_len > 0 {
                let packet = std::slice::from_raw_parts(pkt_ptr, pkt_len);
                let _ = engine.process_packet(packet);
                total += 1;
            }
        }

        total as c_int
    }));

    match result {
        Ok(count) => count,
        Err(_) => {
            set_last_error("Panic during batch processing".into());
            -1
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Control Functions
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_flush(engine: *mut PacketEngine) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.flush();
        0 as c_int
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during flush".into());
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_set_noise_filter(
    engine: *mut PacketEngine,
    enabled: bool,
) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.noise_filter_enabled = enabled;
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_set_ech_downgrade(
    engine: *mut PacketEngine,
    enabled: bool,
) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.ech_downgrade_enabled = enabled;
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}

/// Set the protection level: 0 = relaxed, 1 = balanced, 2 = strict.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_set_protection_level(
    engine: *mut PacketEngine,
    level: u8,
) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.protection_level = level.min(2);
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}

// ═══════════════════════════════════════════════════════════
// Diagnostics
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_get_stats(
    engine: *const PacketEngine,
) -> EngineStatsFFI {
    let zero = EngineStatsFFI {
        packets_processed: 0,
        dns_domains_found: 0,
        sni_domains_found: 0,
        packets_skipped: 0,
        active_tcp_flows: 0,
        reassembly_memory_bytes: 0,
        ech_configs_stripped: 0,
        ech_connections_detected: 0,
        ech_resolved_via_dns: 0,
        ech_unresolved: 0,
    };

    if engine.is_null() {
        return zero;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &*engine;
        let stats = engine.stats();
        EngineStatsFFI {
            packets_processed: stats.packets_processed,
            dns_domains_found: stats.dns_domains_found,
            sni_domains_found: stats.sni_domains_found,
            packets_skipped: stats.packets_skipped,
            active_tcp_flows: engine.reassembly_flow_count() as u64,
            reassembly_memory_bytes: engine.reassembly_memory_bytes() as u64,
            ech_configs_stripped: stats.ech_configs_stripped,
            ech_connections_detected: stats.ech_connections,
            ech_resolved_via_dns: stats.ech_resolved_via_dns,
            ech_unresolved: stats.ech_unresolved,
        }
    }));

    result.unwrap_or(zero)
}

// ═══════════════════════════════════════════════════════════
// Threat Detection FFI
// ═══════════════════════════════════════════════════════════

/// Threat statistics returned to Swift.
#[repr(C)]
pub struct ThreatStatsFFI {
    pub threats_blocked: u64,
    pub threats_allowed: u64,
    pub feed_domain_count: u64,
    pub feeds_loaded: u64,
}

/// Load a threat feed from hosts-format data.
///
/// `data` and `feed_name` must be valid, non-null UTF-8 C strings.
///
/// Returns `0` on success, `-1` on error.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_load_threat_feed(
    engine: *mut PacketEngine,
    data: *const c_char,
    feed_name: *const c_char,
) -> c_int {
    if engine.is_null() || data.is_null() || feed_name.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let data_str = match CStr::from_ptr(data).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("Invalid UTF-8 in data".into());
                return -1;
            }
        };
        let name_str = match CStr::from_ptr(feed_name).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("Invalid UTF-8 in feed_name".into());
                return -1;
            }
        };
        let engine = &mut *engine;
        engine.load_threat_feed(data_str, name_str);
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during load_threat_feed".into());
            -1
        }
    }
}

/// Add a domain to the user allowlist.
///
/// Returns `0` on success, `-1` on error.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_add_allowlist(
    engine: *mut PacketEngine,
    domain: *const c_char,
) -> c_int {
    if engine.is_null() || domain.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let domain_str = match CStr::from_ptr(domain).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("Invalid UTF-8 in domain".into());
                return -1;
            }
        };
        let engine = &mut *engine;
        engine.add_allowlist_domain(domain_str);
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during add_allowlist".into());
            -1
        }
    }
}

/// Remove a domain from the user allowlist.
///
/// Returns `0` on success, `-1` on error.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_remove_allowlist(
    engine: *mut PacketEngine,
    domain: *const c_char,
) -> c_int {
    if engine.is_null() || domain.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let domain_str = match CStr::from_ptr(domain).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("Invalid UTF-8 in domain".into());
                return -1;
            }
        };
        let engine = &mut *engine;
        engine.remove_allowlist_domain(domain_str);
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during remove_allowlist".into());
            -1
        }
    }
}

/// Get threat detection statistics.
///
/// Returns a zeroed struct if the engine pointer is null.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_get_threat_stats(
    engine: *const PacketEngine,
) -> ThreatStatsFFI {
    let zero = ThreatStatsFFI {
        threats_blocked: 0,
        threats_allowed: 0,
        feed_domain_count: 0,
        feeds_loaded: 0,
    };

    if engine.is_null() {
        return zero;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &*engine;
        let stats = engine.threat_stats();
        ThreatStatsFFI {
            threats_blocked: stats.threats_blocked,
            threats_allowed: stats.threats_allowed,
            feed_domain_count: stats.feed_domain_count as u64,
            feeds_loaded: stats.feeds_loaded as u64,
        }
    }));

    result.unwrap_or(zero)
}

// ═══════════════════════════════════════════════════════════
// Error Reporting
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_last_error() -> *mut c_char {
    match LAST_ERROR.lock() {
        Ok(mut err) => match err.take() {
            Some(msg) => CString::new(msg).unwrap_or_default().into_raw(),
            None => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}
