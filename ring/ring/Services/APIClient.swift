import Foundation

// MARK: - APIClient

/// HTTP client for the Ring cloud backend.
///
/// Responsibilities:
/// - Persists access and refresh tokens in the Keychain across launches.
/// - Automatically attaches `Authorization: Bearer …` headers to every
///   authenticated request.
/// - Exposes typed async throwing methods for each backend endpoint.
///
/// All mutable state (`accessToken`, `refreshToken`) is protected by the
/// `actor` isolation boundary; callers never need additional synchronisation.
actor APIClient {

    // MARK: Shared instance

    /// The process-wide singleton. Use this from SwiftUI views and view models.
    static let shared = APIClient()

    // MARK: Private state

    private let baseURL: URL
    private let session: URLSession
    private var accessToken: String?
    private var refreshToken: String?

    // MARK: Init

    private init(baseURL: URL = URL(string: "https://api.ring.jimmykim.com")!) {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        self.session = URLSession(configuration: config)
        // Restore persisted credentials from the Keychain on first access.
        self.accessToken = KeychainHelper.load(key: "ring.accessToken")
        self.refreshToken = KeychainHelper.load(key: "ring.refreshToken")
    }

    // MARK: - Auth

    /// Exchanges an Apple identity token and authorization code for Ring
    /// access/refresh tokens, then persists them to the Keychain.
    ///
    /// - Parameters:
    ///   - identityToken: The JWT identity token from `ASAuthorizationAppleIDCredential`.
    ///   - authCode: The single-use authorization code from Sign in with Apple.
    ///   - fullName: The user's name components, provided only on the first sign-in.
    /// - Returns: The server's `AuthResponse` containing tokens and basic user info.
    func signInWithApple(
        identityToken: String,
        authCode: String,
        fullName: PersonNameComponents?
    ) async throws -> AuthResponse {
        let body: [String: Any] = [
            "identityToken": identityToken,
            "authorizationCode": authCode,
            "fullName": [
                "givenName": fullName?.givenName ?? "",
                "familyName": fullName?.familyName ?? ""
            ]
        ]
        let response: AuthResponse = try await post("/auth/apple", body: body)
        persistTokens(access: response.accessToken, refresh: response.refreshToken)
        return response
    }

    /// Exchanges the stored refresh token for a new access/refresh token pair.
    ///
    /// Throws `APIError.unauthorized` if no refresh token is available locally.
    func refreshTokens() async throws {
        guard let rt = refreshToken else { throw APIError.unauthorized }
        let body: [String: Any] = ["refreshToken": rt]
        let response: AuthResponse = try await post("/auth/refresh", body: body)
        persistTokens(access: response.accessToken, refresh: response.refreshToken)
    }

    /// Sends a DELETE to `/auth/account`, then wipes all local credentials.
    ///
    /// The deletion request is sent with the current access token. On success
    /// both in-memory tokens and Keychain entries are cleared.
    func deleteAccount() async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent("/auth/account"))
        request.httpMethod = "DELETE"
        attachBearerToken(to: &request)

        let (_, response) = try await session.data(for: request)
        try validateResponse(response)

        clearTokens()
    }

    // MARK: - Config

    /// Fetches the current remote configuration from the server.
    ///
    /// The returned `RemoteConfig` contains feature flags, the minimum
    /// supported app version, and the global kill-switch state.
    func fetchConfig() async throws -> RemoteConfig {
        try await get("/config")
    }

    // MARK: - Analytics

    /// Batches and ships `events` to the analytics endpoint.
    ///
    /// Device metadata (anonymous ID, app version, OS version) is added
    /// automatically. Individual event serialisation is handled by
    /// `AnalyticsEvent.toDictionary()`.
    ///
    /// - Parameter events: The events to ship. An empty array is a no-op
    ///   server-side but still performs a network round-trip — callers should
    ///   guard against sending empty batches.
    func sendEvents(_ events: [AnalyticsEvent]) async throws {
        let appVersion = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String ?? "1.0"

        // ProcessInfo is available without UIKit and does not require await.
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString

        let body: [String: Any] = [
            "deviceId": DeviceIdentifier.anonymousId,
            "appVersion": appVersion,
            "osVersion": osVersion,
            "events": events.map { $0.toDictionary() }
        ]
        let _: EmptyResponse = try await post("/analytics/events", body: body)
    }

    // MARK: - HTTP Helpers

    /// Performs an authenticated GET and decodes the response body as `T`.
    private func get<T: Decodable>(_ path: String) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        attachBearerToken(to: &request)

        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Performs an authenticated JSON POST and decodes the response body as `T`.
    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        attachBearerToken(to: &request)
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Adds `Authorization: Bearer <token>` to `request` when a token is available.
    private func attachBearerToken(to request: inout URLRequest) {
        guard let token = accessToken else { return }
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    }

    /// Validates the HTTP status code, mapping error codes to typed `APIError` values.
    ///
    /// - Throws: `APIError.invalidResponse` for non-HTTP responses,
    ///   `APIError.unauthorized` for 401, `APIError.rateLimited` for 429, and
    ///   `APIError.serverError` for any other non-2xx status.
    private func validateResponse(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        switch http.statusCode {
        case 200...299:
            return
        case 401:
            throw APIError.unauthorized
        case 429:
            throw APIError.rateLimited
        default:
            throw APIError.serverError(http.statusCode)
        }
    }

    // MARK: - Token Management

    /// Writes both tokens to memory and the Keychain atomically.
    private func persistTokens(access: String, refresh: String) {
        self.accessToken = access
        self.refreshToken = refresh
        KeychainHelper.save(key: "ring.accessToken", value: access)
        KeychainHelper.save(key: "ring.refreshToken", value: refresh)
    }

    /// Clears both tokens from memory and the Keychain.
    private func clearTokens() {
        accessToken = nil
        refreshToken = nil
        KeychainHelper.delete(key: "ring.accessToken")
        KeychainHelper.delete(key: "ring.refreshToken")
    }
}

// MARK: - Models

/// Token pair and basic user info returned by the auth endpoints.
struct AuthResponse: Codable {
    let accessToken: String
    let refreshToken: String
    let user: UserInfo
}

/// Minimal user record returned by the server after authentication.
struct UserInfo: Codable {
    let id: String
    let email: String?
    let createdAt: String
}

/// Remote configuration fetched from `/config`.
struct RemoteConfig: Codable {
    let version: Int
    let features: FeatureFlags
    let minimumAppVersion: String
    /// When `true` the app should disable all VPN functionality immediately.
    let killSwitch: Bool
}

/// Server-controlled feature flags embedded in `RemoteConfig`.
struct FeatureFlags: Codable {
    let echFallbackEnabled: Bool
    let maxRetentionDays: Int
    let noiseFilterVersion: Int
}

/// A single analytics event ready for shipping to the backend.
struct AnalyticsEvent {
    let name: String
    let timestamp: Date
    let properties: [String: Any]?

    private static let iso8601Formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        return formatter
    }()

    /// Serialises the event to a JSON-compatible dictionary.
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "name": name,
            "timestamp": Self.iso8601Formatter.string(from: timestamp)
        ]
        if let props = properties {
            dict["properties"] = props
        }
        return dict
    }
}

/// Used as the decoded response type for endpoints that return an empty body.
struct EmptyResponse: Codable {}

// MARK: - APIError

/// Typed errors produced by `APIClient`.
enum APIError: LocalizedError {
    case invalidResponse
    case unauthorized
    case rateLimited
    case serverError(Int)

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Invalid server response"
        case .unauthorized:
            return "Authentication required"
        case .rateLimited:
            return "Too many requests"
        case .serverError(let code):
            return "Server error (\(code))"
        }
    }
}

// MARK: - KeychainHelper

/// Thin wrapper around the Security framework for storing small string values.
///
/// All operations are scoped to `kSecAttrService = "com.jimmykim.ring"` to
/// prevent collisions with other apps that use the same account key names.
enum KeychainHelper {

    private static let service = "com.jimmykim.ring"

    /// Saves `value` under `key`, overwriting any existing entry.
    static func save(key: String, value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    /// Returns the string stored under `key`, or `nil` if absent.
    static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Removes the entry stored under `key`. A no-op if the key is absent.
    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - DeviceIdentifier

/// Provides a stable anonymous device identifier persisted in `UserDefaults`.
///
/// The ID is created on first access and never rotates, giving the backend a
/// consistent device handle without linking to any personal identifier.
enum DeviceIdentifier {

    /// A UUID string that is stable across app launches for this install.
    static var anonymousId: String {
        let key = "ring.anonymousDeviceId"
        if let existing = UserDefaults.standard.string(forKey: key) {
            return existing
        }
        let newId = UUID().uuidString
        UserDefaults.standard.set(newId, forKey: key)
        return newId
    }
}
