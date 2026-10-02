import Foundation

struct AdGuardQueryEntry: Identifiable, Sendable, Hashable {
    let id: String
    let time: String
    let domain: String
    let client: String
    let blocked: Bool
    let rule: String
}

struct AdGuardSnapshot: Sendable {
    var available = false
    var version = "—"
    var totalQueries = 0
    var blockedQueries = 0
    var averageProcessingTime = 0.0
    var topQueried: [String] = []
    var topBlocked: [String] = []
    var topClients: [String] = []
    var filters: [String] = []
    var queryLog: [AdGuardQueryEntry] = []
    var lastUpdated: Date?
    var error: String?

    var blockedPercentage: Double {
        guard totalQueries > 0 else { return 0 }
        return Double(blockedQueries) / Double(totalQueries) * 100
    }
}

actor AdGuardAPIService {
    func load(baseURL: String, username: String, password: String) async -> AdGuardSnapshot {
        var snapshot = AdGuardSnapshot()
        do {
            let status = try await json(path: "/control/status", baseURL: baseURL, username: username, password: password)
            snapshot.available = true
            snapshot.version = status["version"] as? String ?? "available"

            let stats = try await json(path: "/control/stats", baseURL: baseURL, username: username, password: password)
            snapshot.totalQueries = Self.intValue(stats["num_dns_queries"])
            snapshot.blockedQueries = Self.intValue(stats["num_blocked_filtering"])
            snapshot.averageProcessingTime = Self.doubleValue(stats["avg_processing_time"])
            snapshot.topQueried = Self.names(stats["top_queried_domains"])
            snapshot.topBlocked = Self.names(stats["top_blocked_domains"])
            snapshot.topClients = Self.names(stats["top_clients"])

            let filtering = try await json(path: "/control/filtering/status", baseURL: baseURL, username: username, password: password)
            snapshot.filters = (filtering["filters"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }

            let log = try await json(path: "/control/querylog", baseURL: baseURL, username: username, password: password)
            snapshot.queryLog = Self.parseQueryLog(log)
            snapshot.lastUpdated = Date()
            snapshot.error = nil
        } catch {
            snapshot.error = SecretRedactor.redact(error.localizedDescription)
        }
        return snapshot
    }

    static func parseQueryLog(_ payload: [String: Any]) -> [AdGuardQueryEntry] {
        let data = payload["data"] as? [[String: Any]] ?? []
        return data.enumerated().compactMap { index, item -> AdGuardQueryEntry? in
            guard let question = item["question"] as? [String: Any],
                  let domain = question["name"] as? String,
                  !domain.isEmpty else { return nil }

            let time = item["time"] as? String ?? "—"
            let client = item["client"] as? String ?? "—"
            let reason = item["reason"] as? String ?? ""
            let lowered = reason.lowercased()
            let blocked = lowered.hasPrefix("filtered") || lowered.contains("blocked")

            let ruleText = (item["rules"] as? [[String: Any]])?
                .compactMap { $0["text"] as? String ?? $0["rule"] as? String }
                .first
            let rule = ruleText?.nonEmpty ?? reason.nonEmpty ?? "—"
            let id = "\(time)|\(client)|\(domain)|\(index)"
            return AdGuardQueryEntry(id: id, time: time, domain: domain, client: client, blocked: blocked, rule: rule)
        }
    }

    private func json(path: String, baseURL: String, username: String, password: String) async throws -> [String: Any] {
        guard let url = URL(string: baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path) else {
            throw URLError(.badURL)
        }
        var request = URLRequest(url: url, timeoutInterval: 8)
        let credential = Data("\(username):\(password)".utf8).base64EncodedString()
        request.setValue("Basic \(credential)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw NSError(domain: "TunnelDeck.AdGuard", code: -1, userInfo: [NSLocalizedDescriptionKey: "AdGuard API returned an invalid HTTP response"])
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = http.statusCode == 401
                ? "AdGuard rejected the username or password (HTTP 401)"
                : "AdGuard API returned HTTP \(http.statusCode)"
            throw NSError(domain: "TunnelDeck.AdGuard", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: message])
        }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    private static func names(_ value: Any?) -> [String] {
        (value as? [[String: Any]] ?? []).compactMap { $0.keys.first }
    }

    private static func intValue(_ value: Any?) -> Int {
        if let value = value as? Int { return value }
        if let value = value as? NSNumber { return value.intValue }
        return 0
    }

    private static func doubleValue(_ value: Any?) -> Double {
        if let value = value as? Double { return value }
        if let value = value as? NSNumber { return value.doubleValue }
        return 0
    }
}