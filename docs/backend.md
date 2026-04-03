# Cloud Backend

## Overview

The backend is a lightweight REST API handling standard SaaS concerns only. **Zero browsing data ever touches the server.** The backend exists for user management, feature configuration, and operational telemetry.

For MVP at <10K users, this is a single Node.js service with PostgreSQL.

---

## Architecture

```
┌─────────────┐        HTTPS/JSON         ┌─────────────────────┐
│  iOS App     │ ──────────────────────── │  API Server          │
│  (APIClient) │                           │  Node.js + Express   │
└─────────────┘                           │                       │
                                           │  /auth/*              │
                                           │  /config/*            │
                                           │  /analytics/*         │
                                           │  /subscription/*      │
                                           ├───────────────────────┤
                                           │  PostgreSQL           │
                                           │  (users, config)      │
                                           └───────────────────────┘
```

---

## API Specification

### Authentication

#### POST `/auth/apple`

Validate a Sign in with Apple identity token and issue a JWT.

**Request:**
```json
{
  "identityToken": "<Apple-issued JWT>",
  "authorizationCode": "<one-time code>",
  "fullName": {
    "givenName": "Jimmy",
    "familyName": "Kim"
  }
}
```

**Response (200):**
```json
{
  "accessToken": "<JWT, 1 hour expiry>",
  "refreshToken": "<opaque token, 30 day expiry>",
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "createdAt": "2026-01-15T00:00:00Z"
  }
}
```

**JWT Claims:**
```json
{
  "sub": "usr_abc123",
  "iat": 1710000000,
  "exp": 1710003600,
  "iss": "domainguard-api"
}
```

#### POST `/auth/refresh`

Exchange a refresh token for a new access token.

**Request:**
```json
{
  "refreshToken": "<opaque token>"
}
```

**Response (200):**
```json
{
  "accessToken": "<new JWT>",
  "refreshToken": "<new refresh token>"
}
```

#### DELETE `/auth/account`

Delete user account and all server-side data. (Required by App Store guidelines.)

**Headers:** `Authorization: Bearer <accessToken>`

**Response (204):** No content.

---

### Remote Configuration

#### GET `/config`

Fetch feature flags and remote configuration. Called on app launch.

**Headers:** `Authorization: Bearer <accessToken>` (optional — works without auth for basic config)

**Response (200):**
```json
{
  "version": 3,
  "features": {
    "echFallbackEnabled": false,
    "maxRetentionDays": 90,
    "noiseFilterVersion": 2
  },
  "noiseFilterDomains": [
    "apple.com",
    "icloud.com",
    "mzstatic.com"
  ],
  "minimumAppVersion": "1.0.0",
  "killSwitch": false,
  "announcement": null
}
```

**Caching:** Response includes `ETag` and `Cache-Control: max-age=3600`. The iOS client caches and only re-fetches if stale.

---

### Anonymous Analytics

#### POST `/analytics/events`

Submit anonymous usage events. No PII, no browsing data.

**Headers:** `Authorization: Bearer <accessToken>` (optional)

**Request:**
```json
{
  "deviceId": "<random UUID, generated on first launch, NOT IDFA>",
  "appVersion": "1.0.0",
  "osVersion": "17.4",
  "events": [
    {
      "name": "vpn_connected",
      "timestamp": "2026-03-19T10:30:00Z",
      "properties": {
        "sessionDuration": 3600
      }
    },
    {
      "name": "app_launched",
      "timestamp": "2026-03-19T10:00:00Z"
    }
  ]
}
```

**Allowed event names:** `app_launched`, `vpn_connected`, `vpn_disconnected`, `domains_viewed`, `settings_changed`, `data_exported`, `data_cleared`.

**Response (202):** Accepted.

**Privacy rules:**
- No domain names, URLs, or browsing data in events
- `deviceId` is a random UUID, not Apple's IDFA
- No IP logging (strip `X-Forwarded-For` at the load balancer)

---

### Subscription Validation

#### POST `/subscription/verify`

Validate an App Store receipt for premium features (if applicable).

**Request:**
```json
{
  "receiptData": "<base64-encoded App Store receipt>",
  "productId": "com.yourcompany.domainguard.premium"
}
```

**Response (200):**
```json
{
  "valid": true,
  "expiresAt": "2027-03-19T00:00:00Z",
  "productId": "com.yourcompany.domainguard.premium"
}
```

---

## Database Schema (PostgreSQL)

```sql
CREATE TABLE users (
    id          TEXT PRIMARY KEY,        -- "usr_" + nanoid
    apple_sub   TEXT UNIQUE,             -- Apple's "sub" claim from identity token
    email       TEXT,                    -- From Sign in with Apple (may be relay address)
    given_name  TEXT,
    family_name TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ             -- Soft delete
);

CREATE TABLE refresh_tokens (
    id          TEXT PRIMARY KEY,        -- nanoid
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  TEXT NOT NULL,           -- bcrypt hash of the token
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

CREATE TABLE feature_flags (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE analytics_events (
    id          BIGSERIAL PRIMARY KEY,
    device_id   TEXT NOT NULL,
    event_name  TEXT NOT NULL,
    properties  JSONB,
    app_version TEXT,
    os_version  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition analytics by month for easy cleanup
CREATE INDEX idx_analytics_created ON analytics_events(created_at);
CREATE INDEX idx_analytics_event ON analytics_events(event_name);
```

---

## Project Structure (Backend)

```
backend/
├── src/
│   ├── index.ts                  # Express app entry point
│   ├── routes/
│   │   ├── auth.ts               # /auth/* endpoints
│   │   ├── config.ts             # /config endpoint
│   │   ├── analytics.ts          # /analytics/* endpoints
│   │   └── subscription.ts       # /subscription/* endpoints
│   ├── middleware/
│   │   ├── auth.ts               # JWT verification middleware
│   │   ├── rateLimiter.ts        # Rate limiting
│   │   └── errorHandler.ts       # Global error handler
│   ├── services/
│   │   ├── appleAuth.ts          # Apple identity token validation
│   │   ├── jwtService.ts         # JWT sign/verify
│   │   ├── userService.ts        # User CRUD
│   │   └── configService.ts      # Feature flag management
│   ├── db/
│   │   ├── connection.ts         # PostgreSQL connection pool
│   │   └── migrations/           # SQL migration files
│   └── config.ts                 # Environment configuration
├── package.json
├── tsconfig.json
├── Dockerfile
└── docker-compose.yml            # Local dev: API + PostgreSQL
```

---

## Security

| Concern | Mitigation |
|---------|-----------|
| JWT signing | RS256 with 2048-bit RSA key pair. Public key available at `/auth/.well-known/jwks.json` |
| Refresh token storage | Stored as bcrypt hash, never plain text |
| Rate limiting | 100 req/min per IP for auth endpoints, 1000 req/min for config/analytics |
| HTTPS | TLS 1.2+ enforced. HSTS header. |
| Input validation | Zod schemas for all request bodies |
| SQL injection | Parameterized queries only (via `pg` library) |
| CORS | Restricted to iOS app bundle ID |
| Logging | No PII in logs. Request bodies not logged. |

---

## Deployment (Small Scale)

For <10K users, a single instance is sufficient:

| Component | Service | Cost (approx.) |
|-----------|---------|-----------------|
| API Server | Fly.io (1 shared CPU, 256MB) | ~$5/mo |
| Database | Fly.io Postgres (1GB) | ~$7/mo |
| Monitoring | Sentry (free tier) | $0 |
| CI/CD | GitHub Actions | $0 |
| **Total** | | **~$12/mo** |

### Dockerfile

```dockerfile
FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build

FROM node:20-slim
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

---

## iOS API Client (`APIClient.swift`)

```swift
import Foundation

/// HTTP client for the cloud backend.
///
/// Handles auth token management, automatic refresh, and request/response serialization.
actor APIClient {
    private let baseURL: URL
    private let session: URLSession
    private var accessToken: String?
    private var refreshToken: String?

    init(baseURL: URL = URL(string: "https://api.domainguard.app")!) {
        self.baseURL = baseURL
        self.session = URLSession(configuration: .default)

        // Load tokens from Keychain
        self.accessToken = KeychainHelper.load(key: "accessToken")
        self.refreshToken = KeychainHelper.load(key: "refreshToken")
    }

    // MARK: - Auth

    func signInWithApple(identityToken: String, authCode: String,
                         fullName: PersonNameComponents?) async throws -> AuthResponse {
        let body: [String: Any] = [
            "identityToken": identityToken,
            "authorizationCode": authCode,
            "fullName": [
                "givenName": fullName?.givenName ?? "",
                "familyName": fullName?.familyName ?? ""
            ]
        ]

        let response: AuthResponse = try await post("/auth/apple", body: body)

        self.accessToken = response.accessToken
        self.refreshToken = response.refreshToken
        KeychainHelper.save(key: "accessToken", value: response.accessToken)
        KeychainHelper.save(key: "refreshToken", value: response.refreshToken)

        return response
    }

    // MARK: - Config

    func fetchConfig() async throws -> RemoteConfig {
        try await get("/config")
    }

    // MARK: - Analytics

    func sendEvents(_ events: [AnalyticsEvent]) async throws {
        let body: [String: Any] = [
            "deviceId": DeviceIdentifier.anonymousId,
            "appVersion": Bundle.main.appVersion,
            "osVersion": UIDevice.current.systemVersion,
            "events": events.map { $0.toDictionary() }
        ]

        let _: EmptyResponse = try await post("/analytics/events", body: body)
    }

    // MARK: - HTTP Helpers

    private func get<T: Decodable>(_ path: String) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        if let token = accessToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = accessToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func validateResponse(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }

        switch http.statusCode {
        case 200...299: return
        case 401: throw APIError.unauthorized
        case 429: throw APIError.rateLimited
        default: throw APIError.serverError(http.statusCode)
        }
    }
}

// MARK: - Models

struct AuthResponse: Codable {
    let accessToken: String
    let refreshToken: String
    let user: UserInfo
}

struct UserInfo: Codable {
    let id: String
    let email: String?
    let createdAt: String
}

struct RemoteConfig: Codable {
    let version: Int
    let features: FeatureFlags
    let minimumAppVersion: String
    let killSwitch: Bool
}

struct FeatureFlags: Codable {
    let echFallbackEnabled: Bool
    let maxRetentionDays: Int
    let noiseFilterVersion: Int
}

enum APIError: LocalizedError {
    case invalidResponse
    case unauthorized
    case rateLimited
    case serverError(Int)

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Invalid server response"
        case .unauthorized: return "Authentication required"
        case .rateLimited: return "Too many requests"
        case .serverError(let code): return "Server error (\(code))"
        }
    }
}
```
