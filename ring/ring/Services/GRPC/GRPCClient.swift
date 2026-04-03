import Foundation

/// Ring gRPC client — future replacement for REST communication.
///
/// This is a shell/placeholder. To activate:
/// 1. Add `grpc-swift` SPM package in Xcode (github.com/grpc/grpc-swift)
/// 2. Add `swift-protobuf` SPM package (github.com/apple/swift-protobuf)
/// 3. Generate Swift stubs from proto/ring.proto using protoc + grpc-swift plugin
/// 4. Replace the placeholder types below with generated types
/// 5. Uncomment the implementation
///
/// Proto file: proto/ring.proto (in both frontend/ and backend/ repos)
/// Backend gRPC port: 50051 (separate from REST on 3000)
///
/// All 6 RPCs defined:
/// - SendConsent (unary)
/// - SendTelemetry (unary)
/// - GetAssociations (unary, with ETag caching)
/// - GetInsights (unary, per-device)
/// - HealthCheck (unary)
/// - StreamDomains (server-streaming, real-time domain events)

final class RingGRPCClient {
    static let shared = RingGRPCClient()

    private let host = "ring-backend-gccf.onrender.com"
    private let port = 50051

    private init() {}

    // MARK: - Connection Setup
    //
    // Once grpc-swift is added:
    //
    // import GRPC
    // import NIO
    //
    // private lazy var group = PlatformSupport.makeEventLoopGroup(loopCount: 1)
    // private lazy var channel = try! GRPCChannelPool.with(
    //     target: .host(host, port: port),
    //     transportSecurity: .tls,
    //     eventLoopGroup: group
    // )
    // private lazy var client = Ring_RingServiceNIOClient(channel: channel)

    // MARK: - Consent

    /// gRPC equivalent of ConsentService.sendConsent()
    func sendConsent(deviceId: String, dns: Bool, analytics: Bool, crashes: Bool) async {
        // let request = Ring_ConsentRequest.with {
        //     $0.deviceID = deviceId
        //     $0.consents = .with {
        //         $0.dnsTelemetry = dns
        //         $0.usageAnalytics = analytics
        //         $0.crashReports = crashes
        //     }
        //     $0.appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        //     $0.osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        // }
        // let response = try await client.sendConsent(request)
        // print("[gRPC] Consent: success=\(response.success)")
        print("[gRPC] sendConsent not yet wired — use REST")
    }

    // MARK: - Telemetry

    /// gRPC equivalent of TelemetryService.syncTelemetry()
    func sendTelemetry(deviceId: String, sessionId: String, events: [[String: Any]]) async {
        // let request = Ring_TelemetryRequest.with {
        //     $0.deviceID = deviceId
        //     $0.sessionID = sessionId
        //     $0.mappingVersion = Int32(events.first?["mapping_version"] as? Int ?? 0)
        //     $0.durationSec = Int32(events.first?["duration_sec"] as? Int ?? 0)
        //     $0.domainEvents = events.map { e in
        //         Ring_DomainEventEntry.with {
        //             $0.siteDomain = e["site_domain"] as? String ?? ""
        //             $0.layer = Int32(e["layer"] as? Int ?? 0)
        //             $0.visitCount = Int32(e["visit_count"] as? Int ?? 0)
        //             $0.domainCount = Int32(e["domain_count"] as? Int ?? 0)
        //         }
        //     }
        //     $0.unmappedDomains = (events.first?["unmapped"] as? [[String: Any]] ?? []).map { u in
        //         Ring_UnmappedDomain.with {
        //             $0.domain = u["domain"] as? String ?? ""
        //             $0.siteDomain = u["site_domain"] as? String ?? ""
        //             $0.visitCount = Int32(u["visit_count"] as? Int ?? 0)
        //         }
        //     }
        //     // query_volume populated from events metadata
        // }
        // let response = try await client.sendTelemetry(request)
        // print("[gRPC] Telemetry: accepted=\(response.accepted)")
        print("[gRPC] sendTelemetry not yet wired — use REST")
    }

    // MARK: - Associations Config

    /// gRPC equivalent of ConfigService.fetchUpdatedMappings()
    func getAssociations(etag: String? = nil) async -> [String: String]? {
        // let request = Ring_AssociationsRequest.with { $0.etag = etag ?? "" }
        // let response = try await client.getAssociations(request)
        // if response.notModified { return nil }
        // return Dictionary(uniqueKeysWithValues: response.associations.map { ($0.key, $0.value) })
        print("[gRPC] getAssociations not yet wired — use REST")
        return nil
    }

    // MARK: - Insights

    /// gRPC equivalent of InsightsService.fetchInsights()
    func getInsights(deviceId: String) async -> InsightsResponse? {
        // let request = Ring_InsightsRequest.with { $0.deviceID = deviceId }
        // let response = try await client.getInsights(request)
        // return InsightsResponse(
        //     totalVisits: Int(response.totalVisits),
        //     categoryCount: Int(response.categoryCount),
        //     insights: response.insights.map { cat in
        //         InsightsCategory(
        //             category: cat.category, label: cat.label,
        //             siteCount: Int(cat.siteCount), totalVisits: Int(cat.totalVisits),
        //             totalDomains: Int(cat.totalDomains), percentage: Int(cat.percentage),
        //             sites: cat.sites.map { s in
        //                 InsightsSite(domain: s.domain, visits: Int(s.visits), domains: Int(s.domains))
        //             }
        //         )
        //     }
        // )
        print("[gRPC] getInsights not yet wired — use REST")
        return nil
    }

    // MARK: - Health Check

    func healthCheck() async -> Bool {
        // let response = try await client.healthCheck(Ring_HealthRequest())
        // return response.status == "ok"
        print("[gRPC] healthCheck not yet wired — use REST")
        return false
    }

    // MARK: - Domain Streaming (Future)

    /// Server-streaming RPC — subscribes to real-time domain events.
    /// Call this when the VPN connects, receive events as they happen.
    func streamDomains(deviceId: String, onEvent: @escaping (String, String, String) -> Void) async {
        // let request = Ring_StreamDomainsRequest.with { $0.deviceID = deviceId }
        // let stream = client.streamDomains(request)
        // for try await event in stream {
        //     onEvent(event.domain, event.siteDomain, event.categoryLabel)
        // }
        print("[gRPC] streamDomains not yet wired — future feature")
    }

    // MARK: - Cleanup

    func shutdown() {
        // try? channel.close().wait()
        // try? group.syncShutdownGracefully()
    }
}
