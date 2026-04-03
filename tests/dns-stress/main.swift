#!/usr/bin/env swift
//
// Ring DNS Stress Test Lab
//
// Simulates the exact DNS forwarding patterns the on-device VPN encounters:
// - Burst sends (20-50 queries in <100ms)
// - Sustained load (continuous queries over 30s)
// - Retry behavior (same txnID re-sent)
// - Timeout measurement
// - Response rate and latency tracking
//
// Usage:
//   swift tests/dns-stress/main.swift [--burst N] [--sustained N] [--server IP]
//

import Foundation

// MARK: - Configuration

struct TestConfig {
    var dnsServer: String = "8.8.8.8"
    var dnsPort: UInt16 = 53
    var burstSize: Int = 30
    var sustainedCount: Int = 100
    var sustainedIntervalMs: Int = 50
    var timeoutSeconds: Double = 10.0
    var retryCount: Int = 3
    var retryIntervalMs: Int = 2000

    static func fromArgs() -> TestConfig {
        var config = TestConfig()
        let args = CommandLine.arguments
        for i in 0..<args.count {
            switch args[i] {
            case "--burst": if i + 1 < args.count { config.burstSize = Int(args[i + 1]) ?? 30 }
            case "--sustained": if i + 1 < args.count { config.sustainedCount = Int(args[i + 1]) ?? 100 }
            case "--server": if i + 1 < args.count { config.dnsServer = args[i + 1] }
            case "--timeout": if i + 1 < args.count { config.timeoutSeconds = Double(args[i + 1]) ?? 10.0 }
            case "--interval": if i + 1 < args.count { config.sustainedIntervalMs = Int(args[i + 1]) ?? 50 }
            default: break
            }
        }
        return config
    }
}

// MARK: - Test Domains

let testDomains: [String] = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "twitter.com",
    "instagram.com", "linkedin.com", "reddit.com", "netflix.com", "github.com",
    "stackoverflow.com", "apple.com", "microsoft.com", "wikipedia.org", "yahoo.com",
    "naver.com", "coupang.com", "kakao.com", "tiktok.com", "spotify.com",
    "discord.com", "twitch.tv", "pinterest.com", "ebay.com", "walmart.com",
    "cnn.com", "bbc.com", "nytimes.com", "bloomberg.com", "reuters.com",
    "i.ytimg.com", "yt3.ggpht.com", "googlevideo.com", "fbcdn.net", "cdninstagram.com",
    "ssl-images-amazon.com", "pstatic.net", "daumcdn.net", "twimg.com", "redditmedia.com",
    "cloudflare.com", "googleapis.com", "gstatic.com", "akamaiedge.net", "fastly.net",
    "stripe.com", "zoom.us", "slack.com", "notion.so", "figma.com",
]

// MARK: - DNS Query Builder

func buildDNSQuery(domain: String, txnID: UInt16) -> Data {
    var query = Data()
    query.append(UInt8(txnID >> 8))
    query.append(UInt8(txnID & 0xFF))
    query.append(contentsOf: [0x01, 0x00])
    query.append(contentsOf: [0x00, 0x01])
    query.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in domain.split(separator: ".") {
        query.append(UInt8(label.count))
        query.append(contentsOf: label.utf8)
    }
    query.append(0x00)
    query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
    return query
}

// MARK: - Query Result

struct QueryResult {
    let txnID: UInt16
    let domain: String
    let sentAt: CFAbsoluteTime
    var receivedAt: CFAbsoluteTime?
    var timedOut: Bool = false
    var error: String?

    var latencyMs: Double? {
        guard let received = receivedAt, !timedOut else { return nil }
        return (received - sentAt) * 1000
    }
}

// MARK: - DNS Test Runner

class DNSTestRunner {
    let config: TestConfig
    private var socket: Int32 = -1
    private var results: [UInt16: QueryResult] = [:]
    private let lock = NSLock()
    private var nextTxnID: UInt16 = 0x1000

    init(config: TestConfig) {
        self.config = config
    }

    private func createSocket() -> Bool {
        socket = Darwin.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard socket >= 0 else {
            print("Failed to create UDP socket: errno=\(errno)")
            return false
        }
        var tv = timeval(tv_sec: Int(config.timeoutSeconds), tv_usec: 0)
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        return true
    }

    private func closeSocket() {
        if socket >= 0 { Darwin.close(socket); socket = -1 }
    }

    private func sendQuery(domain: String, overrideTxnID: UInt16? = nil) -> UInt16 {
        let txnID = overrideTxnID ?? nextTxnID
        if overrideTxnID == nil { nextTxnID &+= 1 }

        let query = buildDNSQuery(domain: domain, txnID: txnID)

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = config.dnsPort.bigEndian
        inet_pton(AF_INET, config.dnsServer, &addr.sin_addr)

        let sent = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                sendto(socket, [UInt8](query), query.count, 0, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        lock.lock()
        if results[txnID] == nil {
            results[txnID] = QueryResult(txnID: txnID, domain: domain, sentAt: CFAbsoluteTimeGetCurrent())
        }
        if sent < 0 { results[txnID]?.error = "send errno=\(errno)" }
        lock.unlock()

        return txnID
    }

    private func receiveResponses(durationSeconds: Double) {
        let deadline = CFAbsoluteTimeGetCurrent() + durationSeconds
        var buf = [UInt8](repeating: 0, count: 4096)

        while CFAbsoluteTimeGetCurrent() < deadline {
            let n = recv(socket, &buf, buf.count, 0)
            if n > 2 {
                let now = CFAbsoluteTimeGetCurrent()
                let txnID = UInt16(buf[0]) << 8 | UInt16(buf[1])
                lock.lock()
                if results[txnID] != nil && results[txnID]?.receivedAt == nil {
                    results[txnID]?.receivedAt = now
                }
                lock.unlock()
            } else if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
                break
            }

            lock.lock()
            let allDone = results.values.allSatisfy { $0.receivedAt != nil || $0.error != nil }
            lock.unlock()
            if allDone { break }
        }

        lock.lock()
        for (id, result) in results where result.receivedAt == nil && result.error == nil {
            results[id]?.timedOut = true
        }
        lock.unlock()
    }

    // MARK: - Test Cases

    func runBurstTest() -> TestReport {
        printHeader("BURST TEST: \(config.burstSize) queries to \(config.dnsServer)")
        results.removeAll()
        nextTxnID = 0x1000
        guard createSocket() else { return TestReport(name: "burst", results: []) }

        let domains = (0..<config.burstSize).map { testDomains[$0 % testDomains.count] }

        print("  Sending \(config.burstSize) queries in burst...")
        let t0 = CFAbsoluteTimeGetCurrent()
        for domain in domains { _ = sendQuery(domain: domain) }
        let burstMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        print("  Burst sent in \(String(format: "%.1f", burstMs))ms")

        print("  Waiting for responses (timeout: \(config.timeoutSeconds)s)...")
        receiveResponses(durationSeconds: config.timeoutSeconds + 1)
        closeSocket()
        return makeReport("burst")
    }

    func runSustainedTest() -> TestReport {
        printHeader("SUSTAINED TEST: \(config.sustainedCount) queries, \(config.sustainedIntervalMs)ms interval")
        results.removeAll()
        nextTxnID = 0x2000
        guard createSocket() else { return TestReport(name: "sustained", results: []) }

        print("  Sending \(config.sustainedCount) queries at \(config.sustainedIntervalMs)ms intervals...")
        for i in 0..<config.sustainedCount {
            let domain = testDomains[i % testDomains.count]
            _ = sendQuery(domain: domain)
            if (i + 1) % 25 == 0 { print("  Sent \(i + 1)/\(config.sustainedCount)") }
            usleep(UInt32(config.sustainedIntervalMs) * 1000)
        }

        print("  Waiting for responses...")
        receiveResponses(durationSeconds: config.timeoutSeconds + 2)
        closeSocket()
        return makeReport("sustained")
    }

    func runRetryTest() -> TestReport {
        printHeader("RETRY TEST: \(config.burstSize) queries, \(config.retryCount) retries")
        results.removeAll()
        nextTxnID = 0x3000
        guard createSocket() else { return TestReport(name: "retry", results: []) }

        let domains = (0..<config.burstSize).map { testDomains[$0 % testDomains.count] }

        print("  Sending initial burst of \(config.burstSize) queries...")
        var txnIDs: [UInt16] = []
        for domain in domains { txnIDs.append(sendQuery(domain: domain)) }

        for retry in 1...config.retryCount {
            usleep(UInt32(config.retryIntervalMs) * 1000)
            print("  Retry \(retry)/\(config.retryCount) - re-sending \(txnIDs.count) queries with same txnIDs...")
            for (i, txnID) in txnIDs.enumerated() {
                _ = sendQuery(domain: domains[i], overrideTxnID: txnID)
            }
        }

        print("  Waiting for responses...")
        receiveResponses(durationSeconds: config.timeoutSeconds + 1)
        closeSocket()
        return makeReport("retry")
    }

    // MARK: - Helpers

    private func printHeader(_ title: String) {
        print("\n" + String(repeating: "=", count: 60))
        print("  \(title)")
        print(String(repeating: "=", count: 60))
    }

    private func makeReport(_ name: String) -> TestReport {
        lock.lock()
        let allResults = Array(results.values)
        lock.unlock()
        let report = TestReport(name: name, results: allResults)
        report.display()
        return report
    }
}

// MARK: - Test Report

struct TestReport {
    let name: String
    let results: [QueryResult]
    let timestamp = Date()

    var total: Int { results.count }
    var succeeded: Int { results.filter { $0.receivedAt != nil && !$0.timedOut && $0.error == nil }.count }
    var timedOut: Int { results.filter { $0.timedOut }.count }
    var errored: Int { results.filter { $0.error != nil }.count }
    var successRate: Double { total > 0 ? Double(succeeded) / Double(total) * 100 : 0 }

    var latencies: [Double] { results.compactMap { $0.latencyMs } }
    var avgLatency: Double { latencies.isEmpty ? 0 : latencies.reduce(0, +) / Double(latencies.count) }
    var minLatency: Double { latencies.min() ?? 0 }
    var maxLatency: Double { latencies.max() ?? 0 }

    func percentile(_ p: Double) -> Double {
        let sorted = latencies.sorted()
        guard !sorted.isEmpty else { return 0 }
        return sorted[min(Int(Double(sorted.count - 1) * p), sorted.count - 1)]
    }

    func display() {
        let icon = successRate >= 95 ? "PASS" : successRate >= 80 ? "WARN" : "FAIL"
        print("\n--- \(name.uppercased()) RESULTS [\(icon)] ---")
        print("  Success: \(succeeded)/\(total) (\(String(format: "%.1f", successRate))%)")
        print("  Timeout: \(timedOut)  Errors: \(errored)")
        if !latencies.isEmpty {
            print("  Latency (ms): avg=\(f(avgLatency)) min=\(f(minLatency)) p50=\(f(percentile(0.5))) p95=\(f(percentile(0.95))) p99=\(f(percentile(0.99))) max=\(f(maxLatency))")
        }
    }

    private func f(_ v: Double) -> String { String(format: "%.1f", v) }

    func save(dir: String) {
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let path = "\(dir)/\(name)_\(df.string(from: timestamp)).txt"

        var s = "Ring DNS Stress Test: \(name)\nDate: \(timestamp)\nServer: 8.8.8.8:53\n\n"
        s += "Total: \(total)  Success: \(succeeded) (\(String(format: "%.1f", successRate))%)  Timeout: \(timedOut)  Errors: \(errored)\n"
        if !latencies.isEmpty {
            s += "Latency (ms): avg=\(f(avgLatency)) min=\(f(minLatency)) p50=\(f(percentile(0.5))) p95=\(f(percentile(0.95))) max=\(f(maxLatency))\n"
        }
        s += "\nPer-query:\n"
        for r in results.sorted(by: { $0.txnID < $1.txnID }) {
            let st = r.timedOut ? "TIMEOUT" : (r.error != nil ? "ERROR(\(r.error!))" : "OK")
            let lat = r.latencyMs.map { String(format: "%.1fms", $0) } ?? "-"
            s += "  0x\(String(r.txnID, radix: 16)): \(r.domain) -> \(st) \(lat)\n"
        }
        try? s.write(toFile: path, atomically: true, encoding: .utf8)
        print("  Saved: \(path)")
    }
}

// MARK: - Main

let config = TestConfig.fromArgs()
let runner = DNSTestRunner(config: config)
let resultsDir = URL(fileURLWithPath: #file)
    .deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("results").path

try? FileManager.default.createDirectory(atPath: resultsDir, withIntermediateDirectories: true)

print("Ring DNS Stress Test Lab")
print("  Server: \(config.dnsServer):\(config.dnsPort)")
print("  Burst: \(config.burstSize)  Sustained: \(config.sustainedCount)@\(config.sustainedIntervalMs)ms")
print("  Timeout: \(config.timeoutSeconds)s  Retries: \(config.retryCount)")

let burst = runner.runBurstTest()
burst.save(dir: resultsDir)

let sustained = runner.runSustainedTest()
sustained.save(dir: resultsDir)

let retry = runner.runRetryTest()
retry.save(dir: resultsDir)

print("\n" + String(repeating: "=", count: 60))
print("  SUMMARY")
print(String(repeating: "=", count: 60))
print("  Burst:     \(burst.succeeded)/\(burst.total) (\(String(format: "%.0f", burst.successRate))%) avg=\(String(format: "%.0f", burst.avgLatency))ms")
print("  Sustained: \(sustained.succeeded)/\(sustained.total) (\(String(format: "%.0f", sustained.successRate))%) avg=\(String(format: "%.0f", sustained.avgLatency))ms")
print("  Retry:     \(retry.succeeded)/\(retry.total) (\(String(format: "%.0f", retry.successRate))%) avg=\(String(format: "%.0f", retry.avgLatency))ms")

let pass = burst.successRate >= 95 && sustained.successRate >= 95 && retry.successRate >= 80
print("\n  Overall: \(pass ? "PASS" : "FAIL")")
