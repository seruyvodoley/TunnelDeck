import Foundation

enum PeerHistoryAnalytics {
    static func trafficDelta(points: [PeerHistorySample]) -> UInt64 {
        let sorted = points.sorted { $0.timestamp < $1.timestamp }
        guard sorted.count >= 2 else { return 0 }
        var total: UInt64 = 0
        for pair in zip(sorted, sorted.dropFirst()) {
            total += counterDelta(previous: pair.0.receivedBytes, current: pair.1.receivedBytes)
            total += counterDelta(previous: pair.0.sentBytes, current: pair.1.sentBytes)
        }
        return total
    }

    private static func counterDelta(previous: UInt64, current: UInt64) -> UInt64 {
        current >= previous ? current - previous : current
    }
}

enum AdGuardHistoryAnalytics {
    static func queryDelta(_ points: [AdGuardHistorySample]) -> Int {
        counterDelta(points.sorted { $0.timestamp < $1.timestamp }.map(\.totalQueries))
    }

    static func blockedDelta(_ points: [AdGuardHistorySample]) -> Int {
        counterDelta(points.sorted { $0.timestamp < $1.timestamp }.map(\.blockedQueries))
    }

    private static func counterDelta(_ values: [Int]) -> Int {
        guard values.count >= 2 else { return 0 }
        var total = 0
        for pair in zip(values, values.dropFirst()) {
            total += pair.1 >= pair.0 ? pair.1 - pair.0 : pair.1
        }
        return total
    }
}

actor TelemetryHistoryStore {
    private let folder: URL
    private let retention: TimeInterval = 7 * 24 * 60 * 60
    private let minimumPeerInterval: TimeInterval = 30
    private let minimumAdGuardInterval: TimeInterval = 30

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        folder = base.appendingPathComponent("TunnelDeck/Telemetry", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    func loadPeers(host: String) -> [PeerHistorySample] {
        decode([PeerHistorySample].self, from: peerURL(host)) ?? []
    }

    func loadAdGuard(host: String) -> [AdGuardHistorySample] {
        decode([AdGuardHistorySample].self, from: adGuardURL(host)) ?? []
    }

    func recordPeers(host: String, peers: [WireGuardPeer], timestamp: Date) -> [PeerHistorySample] {
        var history = loadPeers(host: host)
        let latestTimestamp = history.map(\.timestamp).max()

        if let latestTimestamp, timestamp.timeIntervalSince(latestTimestamp) < minimumPeerInterval {
            history.removeAll { abs($0.timestamp.timeIntervalSince(latestTimestamp)) < 0.001 }
        }

        history.append(contentsOf: peers.map { peer in
            PeerHistorySample(
                id: UUID(),
                timestamp: timestamp,
                peerID: peer.id,
                name: peer.name,
                vpnIP: peer.vpnIP,
                status: peer.status,
                receivedBytes: peer.receivedBytes,
                sentBytes: peer.sentBytes,
                latestHandshake: peer.latestHandshake
            )
        })

        let cutoff = timestamp.addingTimeInterval(-retention)
        history = history.filter { $0.timestamp >= cutoff }
        if history.count > 20_000 { history = Array(history.suffix(20_000)) }
        encode(history, to: peerURL(host))
        return history
    }

    func recordAdGuard(host: String, snapshot: AdGuardSnapshot, timestamp: Date) -> [AdGuardHistorySample] {
        var history = loadAdGuard(host: host)
        let sample = AdGuardHistorySample(
            id: UUID(),
            timestamp: timestamp,
            totalQueries: snapshot.totalQueries,
            blockedQueries: snapshot.blockedQueries,
            blockedPercentage: snapshot.blockedPercentage,
            averageProcessingTime: snapshot.averageProcessingTime
        )

        if let last = history.last, timestamp.timeIntervalSince(last.timestamp) < minimumAdGuardInterval {
            history[history.count - 1] = sample
        } else {
            history.append(sample)
        }

        let cutoff = timestamp.addingTimeInterval(-retention)
        history = history.filter { $0.timestamp >= cutoff }
        if history.count > 10_000 { history = Array(history.suffix(10_000)) }
        encode(history, to: adGuardURL(host))
        return history
    }

    private func safeKey(_ host: String) -> String {
        let value = host.isEmpty ? "unconfigured" : host
        return String(value.map {
            ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") ? $0 : "_"
        }.prefix(120))
    }

    private func peerURL(_ host: String) -> URL {
        folder.appendingPathComponent("peers-\(safeKey(host)).json")
    }

    private func adGuardURL(_ host: String) -> URL {
        folder.appendingPathComponent("adguard-\(safeKey(host)).json")
    }

    private func decode<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    private func encode<T: Encodable>(_ value: T, to url: URL) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
