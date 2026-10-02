import Foundation

struct AdGuardSnapshot: Sendable {
    var available = false; var version = "—"; var totalQueries = 0; var blockedQueries = 0; var averageProcessingTime = 0.0
    var topQueried: [String] = []; var topBlocked: [String] = []; var topClients: [String] = []; var filters: [String] = []; var queryLog: [String] = []; var error: String?
}

actor AdGuardAPIService {
    func load(baseURL: String, username: String, password: String) async -> AdGuardSnapshot {
        var snapshot = AdGuardSnapshot()
        do {
            let status = try await json(path: "/control/status", baseURL: baseURL, username: username, password: password)
            snapshot.available = true; snapshot.version = status["version"] as? String ?? "available"
            let stats = try await json(path: "/control/stats", baseURL: baseURL, username: username, password: password)
            snapshot.totalQueries = stats["num_dns_queries"] as? Int ?? 0; snapshot.blockedQueries = stats["num_blocked_filtering"] as? Int ?? 0; snapshot.averageProcessingTime = stats["avg_processing_time"] as? Double ?? 0
            snapshot.topQueried = Self.names(stats["top_queried_domains"]); snapshot.topBlocked = Self.names(stats["top_blocked_domains"]); snapshot.topClients = Self.names(stats["top_clients"])
            let filtering = try await json(path: "/control/filtering/status", baseURL: baseURL, username: username, password: password)
            snapshot.filters = (filtering["filters"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
            let log = try await json(path: "/control/querylog?limit=50", baseURL: baseURL, username: username, password: password)
            snapshot.queryLog = (log["data"] as? [[String: Any]] ?? []).compactMap { item in (item["question"] as? [String: Any])?["name"] as? String }
        } catch { snapshot.error = SecretRedactor.redact(error.localizedDescription) }
        return snapshot
    }

    private func json(path: String, baseURL: String, username: String, password: String) async throws -> [String: Any] {
        guard let url = URL(string: baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path) else { throw URLError(.badURL) }
        var request = URLRequest(url: url, timeoutInterval: 8)
        let credential = Data("\(username):\(password)".utf8).base64EncodedString()
        request.setValue("Basic \(credential)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw NSError(domain: "TunnelDeck.AdGuard", code: (response as? HTTPURLResponse)?.statusCode ?? -1, userInfo: [NSLocalizedDescriptionKey: "AdGuard API rejected the request"]) }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    private static func names(_ value: Any?) -> [String] {
        (value as? [[String: Any]] ?? []).compactMap { $0.keys.first }
    }
}
