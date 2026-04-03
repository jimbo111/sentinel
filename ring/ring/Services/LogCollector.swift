import Foundation

/// Collects structured logs from both the app and the Network Extension
/// via a shared file in the App Group container. The extension writes
/// tunnel/DNS events; the app writes UI/service events. DiagnosticsView
/// reads and displays them.
final class LogCollector {
    static let shared = LogCollector()

    private let fileURL: URL
    private let queue = DispatchQueue(label: "com.jimmykim.ring.logcollector")
    private static let maxFileSize = 512 * 1024 // 512 KB

    private init() {
        fileURL = AppGroupConfig.containerURL.appendingPathComponent("ring_debug.log")
    }

    func log(_ message: String, source: String = "app") {
        queue.async { [self] in
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let line = "[\(timestamp)] [\(source)] \(message)\n"
            appendToFile(line)
        }
    }

    func readAll() -> String {
        queue.sync {
            (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
        }
    }

    func clear() {
        queue.sync {
            try? "".write(to: fileURL, atomically: true, encoding: .utf8)
        }
    }

    /// Also reads the legacy tunnel_status.txt breadcrumbs.
    func readTunnelStatus() -> String {
        let statusPath = AppGroupConfig.containerURL.appendingPathComponent("tunnel_status.txt").path
        return (try? String(contentsOfFile: statusPath, encoding: .utf8)) ?? ""
    }

    private func appendToFile(_ line: String) {
        let data = Data(line.utf8)

        if FileManager.default.fileExists(atPath: fileURL.path) {
            // Truncate if file is too large
            if let attrs = try? FileManager.default.attributesOfItem(atPath: fileURL.path),
               let size = attrs[.size] as? Int, size > Self.maxFileSize {
                // Keep the last half
                if var content = try? String(contentsOf: fileURL, encoding: .utf8) {
                    let halfIndex = content.index(content.startIndex, offsetBy: content.count / 2)
                    content = String(content[halfIndex...])
                    try? content.write(to: fileURL, atomically: true, encoding: .utf8)
                }
            }

            if let handle = try? FileHandle(forWritingTo: fileURL) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            }
        } else {
            try? data.write(to: fileURL)
        }
    }
}
