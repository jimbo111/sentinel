# Cross-Platform Bindings (Rust ↔ Swift FFI)

## Overview

The Rust packet engine compiles to a static C library (`libpacket_engine.a`). Swift calls into it via C-ABI functions exposed through an auto-generated header (`packet_engine.h`). This document specifies every FFI function, the memory ownership model, and the Swift-side wrapper.

---

## Design Principles

1. **C ABI only** — No C++ name mangling, no Objective-C runtime. Pure `extern "C"` functions.
2. **Opaque pointer pattern** — Swift holds a `*mut PacketEngine` as an opaque `OpaquePointer`. It never inspects the struct's internals.
3. **Caller owns buffers** — iOS allocates packet buffers; Rust borrows them. Rust never allocates buffers that Swift must free (except for string returns, which use a paired free function).
4. **No panics across FFI** — Every `extern "C"` function catches panics via `std::panic::catch_unwind`. A panic across the FFI boundary is undefined behavior.
5. **Error codes** — Functions return `i32` status codes: 0 = success, negative = error. Error details available via `packet_engine_last_error()`.

---

## Rust FFI Functions (`lib.rs`)

```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic;
use std::ptr;
use std::sync::Mutex;

mod engine;
mod ip;
mod dns;
mod tls;
mod tcp_reassembly;
mod domain;
mod storage;
mod errors;
mod constants;

use engine::PacketEngine;

/// Thread-local last error message.
/// (The extension is single-threaded, but this is good practice.)
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(msg: String) {
    if let Ok(mut err) = LAST_ERROR.lock() {
        *err = Some(msg);
    }
}

// ═══════════════════════════════════════════════════════════
// Lifecycle Functions
// ═══════════════════════════════════════════════════════════

/// Initialize the packet engine.
///
/// # Parameters
/// - `db_path`: Null-terminated C string path to the SQLite database file.
///   This should be in the App Group shared container.
///
/// # Returns
/// - Non-null opaque pointer on success (the engine handle)
/// - Null pointer on failure (call `packet_engine_last_error()` for details)
///
/// # Safety
/// - `db_path` must be a valid, null-terminated UTF-8 string
/// - The returned pointer must eventually be passed to `packet_engine_destroy()`
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

/// Destroy the packet engine and free all resources.
///
/// This flushes any pending domain records to SQLite before destroying.
///
/// # Safety
/// - `engine` must be a pointer previously returned by `packet_engine_init()`
/// - After this call, the pointer is invalid and must not be used
/// - Calling with a null pointer is safe (no-op)
#[no_mangle]
pub unsafe extern "C" fn packet_engine_destroy(engine: *mut PacketEngine) {
    if !engine.is_null() {
        let _ = panic::catch_unwind(|| {
            let _ = Box::from_raw(engine); // Drop runs PacketEngine::drop → flush
        });
    }
}

// ═══════════════════════════════════════════════════════════
// Packet Processing
// ═══════════════════════════════════════════════════════════

/// Process a single raw IP packet. May return a modified packet (ECH downgrade).
///
/// This is the hot-path function called for every packet the VPN tunnel receives.
///
/// # Parameters
/// - `engine`: Engine handle from `packet_engine_init()`
/// - `packet_data`: Pointer to the raw IP packet bytes
/// - `packet_len`: Length of the packet in bytes
/// - `out_buf`: Buffer for the replacement packet (if the engine modifies it)
/// - `out_capacity`: Size of `out_buf` in bytes
/// - `out_len`: On return, the number of bytes written to `out_buf` (if modified)
///
/// # Returns
/// - 0: Forward the original packet unchanged (the common case, ~99.9%)
/// - 1: Forward the replacement packet from `out_buf` instead
///       (DNS response was rewritten to strip ECH config)
/// - -1: Error (null engine or null data)
///
/// # Safety
/// - `engine` must be a valid engine pointer
/// - `packet_data` must point to at least `packet_len` readable bytes
/// - `out_buf` must point to at least `out_capacity` writable bytes
/// - This function borrows the packet buffer — it does not take ownership
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

        match engine.process_packet(packet) {
            ProcessResult::Forward => 0,
            ProcessResult::Replace(new_packet) => {
                if out_buf.is_null() || out_capacity < new_packet.len() {
                    return 0; // Buffer too small, forward original
                }
                let out_slice = std::slice::from_raw_parts_mut(out_buf, out_capacity);
                out_slice[..new_packet.len()].copy_from_slice(&new_packet);
                if !out_len.is_null() {
                    *out_len = new_packet.len();
                }
                1
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

/// Process a batch of packets at once.
///
/// More efficient than calling `packet_engine_process` in a loop because
/// it amortizes the FFI call overhead.
///
/// NOTE: The batch API does NOT support packet replacement (ECH downgrade).
/// For packets that need modification, the single-packet API must be used.
/// In practice, this is fine: DNS responses are a tiny fraction of traffic,
/// and the per-packet API is used in the main loop (see system-integration.md).
///
/// # Parameters
/// - `engine`: Engine handle
/// - `packets`: Array of pointers to packet data
/// - `lengths`: Array of packet lengths (parallel to `packets`)
/// - `count`: Number of packets in the batch
///
/// # Returns
/// - Total number of new domains found across all packets
/// - -1 on error
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
                // Note: batch mode ignores Replace results.
                // Use single-packet API for ECH downgrade support.
                let _ = engine.process_packet(packet);
                total += 1; // Count processed (not domains found)
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

/// Force-flush any pending domain records to SQLite.
///
/// Call this:
/// - When the VPN tunnel is stopping (before `packet_engine_destroy`)
/// - When the app requests immediate data refresh
///
/// # Returns
/// - 0 on success
/// - -1 on error
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

// ═══════════════════════════════════════════════════════════
// Diagnostics
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
}

/// Get engine statistics.
///
/// # Returns
/// - EngineStatsFFI struct (passed by value)
/// - All zeros if engine is null
#[no_mangle]
pub unsafe extern "C" fn packet_engine_get_stats(
    engine: *const PacketEngine,
) -> EngineStatsFFI {
    if engine.is_null() {
        return EngineStatsFFI {
            packets_processed: 0,
            dns_domains_found: 0,
            sni_domains_found: 0,
            packets_skipped: 0,
            active_tcp_flows: 0,
            reassembly_memory_bytes: 0,
        };
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
        }
    }));

    result.unwrap_or(EngineStatsFFI {
        packets_processed: 0,
        dns_domains_found: 0,
        sni_domains_found: 0,
        packets_skipped: 0,
        active_tcp_flows: 0,
        reassembly_memory_bytes: 0,
    })
}

// ═══════════════════════════════════════════════════════════
// Error Reporting
// ═══════════════════════════════════════════════════════════

/// Get the last error message.
///
/// # Returns
/// - Pointer to a null-terminated UTF-8 string, or null if no error.
/// - The returned string is owned by Rust. Call `packet_engine_free_string()`
///   to free it.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_last_error() -> *mut c_char {
    match LAST_ERROR.lock() {
        Ok(mut err) => {
            match err.take() {
                Some(msg) => {
                    CString::new(msg).unwrap_or_default().into_raw()
                }
                None => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string previously returned by `packet_engine_last_error()`.
///
/// # Safety
/// - `s` must be a pointer returned by `packet_engine_last_error()`, or null.
#[no_mangle]
pub unsafe extern "C" fn packet_engine_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// ═══════════════════════════════════════════════════════════
// ECH Downgrade Control
// ═══════════════════════════════════════════════════════════

/// Enable or disable active ECH downgrade (HTTPS RR ech= stripping).
///
/// When enabled, DNS responses containing HTTPS/SVCB records with ech=
/// SvcParams will be rewritten to remove the ECH config. This prevents
/// browsers from activating Encrypted Client Hello, ensuring TLS SNI
/// remains in plaintext.
///
/// Default: disabled. Enable via remote feature flag.
///
/// See ech-fallback.md for full technical specification.
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
        log::info!("ECH downgrade {}", if enabled { "enabled" } else { "disabled" });
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}
```

---

## Generated C Header (`packet_engine.h`)

This is auto-generated by `cbindgen` from the Rust source. The expected output:

```c
#ifndef PACKET_ENGINE_H
#define PACKET_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque engine handle
typedef struct PacketEngine PacketEngine;

/// Engine statistics
typedef struct {
    uint64_t packets_processed;
    uint64_t dns_domains_found;
    uint64_t sni_domains_found;
    uint64_t packets_skipped;
    uint64_t active_tcp_flows;
    uint64_t reassembly_memory_bytes;
    uint64_t ech_configs_stripped;
    uint64_t ech_connections_detected;
    uint64_t ech_resolved_via_dns;
    uint64_t ech_unresolved;
} EngineStatsFFI;

// ── Lifecycle ──
PacketEngine* packet_engine_init(const char* db_path);
void packet_engine_destroy(PacketEngine* engine);

// ── Packet Processing ──
// Returns: 0 = forward original, 1 = forward replacement (out_buf), -1 = error
int packet_engine_process(PacketEngine* engine,
                          const uint8_t* packet_data,
                          size_t packet_len,
                          uint8_t* out_buf,
                          size_t out_capacity,
                          size_t* out_len);

int packet_engine_process_batch(PacketEngine* engine,
                                const uint8_t* const* packets,
                                const size_t* lengths,
                                size_t count);

// ── Control ──
int packet_engine_flush(PacketEngine* engine);

// ── ECH Downgrade ──
int packet_engine_set_ech_downgrade(PacketEngine* engine, bool enabled);

// ── Diagnostics ──
EngineStatsFFI packet_engine_get_stats(const PacketEngine* engine);

// ── Error Reporting ──
char* packet_engine_last_error(void);
void packet_engine_free_string(char* s);

#ifdef __cplusplus
}
#endif

#endif // PACKET_ENGINE_H
```

---

## cbindgen Configuration (`cbindgen.toml`)

```toml
language = "C"
header = "/* Auto-generated by cbindgen. Do not edit. */"
include_guard = "PACKET_ENGINE_H"
autogen_warning = "/* Warning: this file is auto-generated by cbindgen. Do not modify. */"
tab_width = 4
style = "Both"

[export]
include = ["EngineStatsFFI"]

[export.rename]
# Keep Rust naming in C header
```

---

## build.rs (Header Generation)

```rust
fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = format!("{}/target", crate_dir);

    let config = cbindgen::Config::from_file("cbindgen.toml")
        .unwrap_or_default();

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(format!("{}/packet_engine.h", output_dir));
}
```

---

## Swift Bridging Header

**File**: `PacketTunnelExtension-Bridging-Header.h`

```c
#import "Bridge/packet_engine.h"
```

---

## Swift Wrapper (`RustBridge.swift`)

This is the Swift-side type-safe wrapper around the raw C functions.

```swift
import Foundation

/// Type-safe wrapper around the Rust packet engine C API.
///
/// This class manages the lifecycle of the Rust engine and provides
/// Swift-native interfaces for packet processing.
///
/// IMPORTANT: This class is NOT thread-safe. It must only be used
/// from the Network Extension's packet processing thread.
final class RustPacketEngine {

    /// Opaque pointer to the Rust PacketEngine instance
    private var engine: OpaquePointer?

    /// Whether the engine has been initialized successfully
    var isInitialized: Bool { engine != nil }

    // MARK: - Lifecycle

    /// Initialize the Rust packet engine.
    ///
    /// - Parameter dbPath: Absolute path to the SQLite database file
    ///   (must be in the App Group shared container)
    /// - Throws: `RustEngineError.initFailed` if initialization fails
    init(dbPath: String) throws {
        let ptr = dbPath.withCString { cPath in
            packet_engine_init(cPath)
        }

        guard let ptr = ptr else {
            let error = Self.consumeLastError() ?? "Unknown error"
            throw RustEngineError.initFailed(error)
        }

        self.engine = OpaquePointer(ptr)
    }

    deinit {
        shutdown()
    }

    /// Shut down the engine and free all Rust resources.
    ///
    /// This flushes pending domains to SQLite before destroying.
    /// Safe to call multiple times.
    func shutdown() {
        guard let engine = self.engine else { return }
        packet_engine_destroy(UnsafeMutablePointer(engine))
        self.engine = nil
    }

    // MARK: - Packet Processing

    /// Result of processing a single packet.
    enum ProcessResult {
        /// Forward the original packet unchanged (common case)
        case forward
        /// Forward a modified packet (e.g., DNS response with ECH stripped)
        case replace(Data)
    }

    /// Process a single raw IP packet. May return a modified packet.
    ///
    /// - Parameter packetData: The raw IP packet bytes from `packetFlow.readPackets()`
    /// - Returns: `.forward` to pass original, `.replace(data)` to use modified version
    func processPacket(_ packetData: Data) -> ProcessResult {
        guard let engine = self.engine else { return .forward }

        // Allocate output buffer (same size as input + margin)
        var outBuffer = Data(count: packetData.count + 64)
        var outLen: Int = 0

        let result = packetData.withUnsafeBytes { inBuf -> Int32 in
            outBuffer.withUnsafeMutableBytes { outBuf -> Int32 in
                guard let inBase = inBuf.baseAddress,
                      let outBase = outBuf.baseAddress else { return -1 }

                return packet_engine_process(
                    UnsafeMutablePointer(engine),
                    inBase.assumingMemoryBound(to: UInt8.self),
                    inBuf.count,
                    outBase.assumingMemoryBound(to: UInt8.self),
                    outBuf.count,
                    &outLen
                )
            }
        }

        switch result {
        case 1:
            return .replace(outBuffer.prefix(outLen))
        default:
            return .forward
        }
    }

    /// Process a batch of raw IP packets.
    ///
    /// More efficient than calling `processPacket` in a loop.
    ///
    /// - Parameter packets: Array of raw IP packet data
    /// - Returns: Total number of new domains found
    func processPacketBatch(_ packets: [Data]) -> Int {
        guard let engine = self.engine, !packets.isEmpty else { return 0 }

        // We need to pin the Data buffers and create arrays of pointers + lengths
        var pointers: [UnsafePointer<UInt8>?] = []
        var lengths: [Int] = []

        // Use ContiguousArray for better performance
        var pinnedData: [Data] = packets // keep references alive

        for data in pinnedData {
            data.withUnsafeBytes { buffer in
                if let base = buffer.baseAddress {
                    pointers.append(base.assumingMemoryBound(to: UInt8.self))
                    lengths.append(buffer.count)
                }
            }
        }

        guard pointers.count == packets.count else { return 0 }

        let result = pointers.withUnsafeBufferPointer { ptrBuf in
            lengths.withUnsafeBufferPointer { lenBuf in
                packet_engine_process_batch(
                    UnsafeMutablePointer(engine),
                    ptrBuf.baseAddress,
                    lenBuf.baseAddress,
                    packets.count
                )
            }
        }

        return Int(result)
    }

    // MARK: - Control

    /// Force-flush any pending domain records to SQLite.
    func flush() {
        guard let engine = self.engine else { return }
        packet_engine_flush(UnsafeMutablePointer(engine))
    }

    // MARK: - ECH Downgrade Control

    /// Enable or disable active ECH downgrade.
    ///
    /// When enabled, DNS responses containing HTTPS/SVCB records with
    /// ech= parameters are rewritten to strip the ECH config, preventing
    /// browsers from using Encrypted Client Hello.
    func setEchDowngrade(enabled: Bool) {
        guard let engine = self.engine else { return }
        packet_engine_set_ech_downgrade(UnsafeMutablePointer(engine), enabled)
    }

    // MARK: - Diagnostics

    /// Engine processing statistics.
    struct Stats {
        let packetsProcessed: UInt64
        let dnsDomainsFound: UInt64
        let sniDomainsFound: UInt64
        let packetsSkipped: UInt64
        let activeTcpFlows: UInt64
        let reassemblyMemoryBytes: UInt64
        // ECH metrics
        let echConfigsStripped: UInt64
        let echConnectionsDetected: UInt64
        let echResolvedViaDns: UInt64
        let echUnresolved: UInt64
    }

    /// Get current engine statistics.
    func getStats() -> Stats {
        guard let engine = self.engine else {
            return Stats(packetsProcessed: 0, dnsDomainsFound: 0,
                        sniDomainsFound: 0, packetsSkipped: 0,
                        activeTcpFlows: 0, reassemblyMemoryBytes: 0,
                        echConfigsStripped: 0, echConnectionsDetected: 0,
                        echResolvedViaDns: 0, echUnresolved: 0)
        }

        let raw = packet_engine_get_stats(UnsafePointer(engine))

        return Stats(
            packetsProcessed: raw.packets_processed,
            dnsDomainsFound: raw.dns_domains_found,
            sniDomainsFound: raw.sni_domains_found,
            packetsSkipped: raw.packets_skipped,
            activeTcpFlows: raw.active_tcp_flows,
            reassemblyMemoryBytes: raw.reassembly_memory_bytes,
            echConfigsStripped: raw.ech_configs_stripped,
            echConnectionsDetected: raw.ech_connections_detected,
            echResolvedViaDns: raw.ech_resolved_via_dns,
            echUnresolved: raw.ech_unresolved
        )
    }

    // MARK: - Error Handling

    /// Consume and return the last Rust error message.
    private static func consumeLastError() -> String? {
        let errorPtr = packet_engine_last_error()
        guard let errorPtr = errorPtr else { return nil }

        let message = String(cString: errorPtr)
        packet_engine_free_string(errorPtr)
        return message
    }
}

// MARK: - Errors

enum RustEngineError: LocalizedError {
    case initFailed(String)
    case processingFailed(String)

    var errorDescription: String? {
        switch self {
        case .initFailed(let msg): return "Rust engine init failed: \(msg)"
        case .processingFailed(let msg): return "Rust engine error: \(msg)"
        }
    }
}
```

---

## Memory Ownership Summary

```
┌────────────────────────────────────────────────────────────┐
│                   Memory Ownership Rules                    │
├────────────────────┬───────────────────────────────────────┤
│ Input packets      │ iOS allocates, Rust borrows (&[u8])   │
│                    │ Rust NEVER stores packet pointers      │
├────────────────────┼───────────────────────────────────────┤
│ Output buffer      │ Swift allocates (Data), passes ptr    │
│ (ECH replacement)  │ Rust writes into it (copy_from_slice) │
│                    │ Swift owns — no Rust-side free needed  │
├────────────────────┼───────────────────────────────────────┤
│ PacketEngine*      │ Rust allocates (Box::into_raw)        │
│                    │ Swift holds as OpaquePointer            │
│                    │ Rust frees (Box::from_raw in destroy)  │
├────────────────────┼───────────────────────────────────────┤
│ Error strings      │ Rust allocates (CString::into_raw)    │
│                    │ Swift reads and calls free_string()    │
├────────────────────┼───────────────────────────────────────┤
│ EngineStatsFFI     │ Passed by value (on stack)            │
│                    │ No heap allocation, no free needed     │
├────────────────────┼───────────────────────────────────────┤
│ db_path string     │ Swift owns the String                 │
│                    │ Rust borrows via CStr::from_ptr        │
│                    │ Only used during init, not stored      │
└────────────────────┴───────────────────────────────────────┘
```

---

## Performance Notes

The FFI boundary adds approximately **2-5 nanoseconds** per call on ARM64. Given that the actual packet parsing takes 1-10 microseconds, the FFI overhead is negligible (<0.5%).

However, the `processPacketBatch` function exists to amortize the cost when processing many packets at once. The `readPackets()` API on `NEPacketTunnelProvider` returns an array of packets, so batching is natural.
