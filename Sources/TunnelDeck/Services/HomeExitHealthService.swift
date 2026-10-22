import Foundation

struct HomeExitHealthSample: Codable, Sendable, Equatable {
    let host: String
    let checkedAt: Date
    let interfaceUp: Bool?
    let routeCorrect: Bool?
    let homeExitDataOK: Bool?
    let vpsFallbackDataOK: Bool?
    let handshakeAgeSeconds: TimeInterval?
    let reason: String

    var pathHealthy: Bool? {
        guard let interfaceUp, let routeCorrect, let homeExitDataOK else { return nil }
        return interfaceUp && routeCorrect && homeExitDataOK
    }
}

enum HomeExitRecommendation: String, Codable, Sendable {
    case noChange = "No change"
    case repeatProbe = "Repeat the read-only probe"
    case inspectHomePeer = "Inspect the Xiaomi/home peer"
    case vpsFallbackAvailable = "VPS egress is reachable; fallback is inactive"
    case homeExitRecovered = "HomeExit recovered; keep observing"
}

struct HomeExitHealthSnapshot: Sendable, Equatable {
    let checkedAt: Date
    let host: String
    let state: HealthState
    let interfaceUp: Bool?
    let handshakeAgeSeconds: TimeInterval?
    let receivedBytes: UInt64?
    let sentBytes: UInt64?
    let receivedDeltaBytes: UInt64?
    let sentDeltaBytes: UInt64?
    let routeCorrect: Bool?
    let ruAddressSetContainsProbe: Bool?
    let dnsAddress: String?
    let homeExitDataPassed: Bool?
    let homeExitHTTPStatus: Int?
    let homeExitLatencySeconds: Double?
    let vpsFallbackDataPassed: Bool?
    let vpsFallbackHTTPStatus: Int?
    let vpsFallbackLatencySeconds: Double?
    let consecutiveFailures: Int
    let lastFailureAt: Date?
    let currentOutageSeconds: TimeInterval?
    let recommendation: HomeExitRecommendation
    let reason: String
    let automaticRouteChangesEnabled: Bool

    static let notChecked = HomeExitHealthSnapshot(
        checkedAt: .distantPast, host: "Not checked", state: .unknown,
        interfaceUp: nil, handshakeAgeSeconds: nil, receivedBytes: nil, sentBytes: nil,
        receivedDeltaBytes: nil, sentDeltaBytes: nil,
        routeCorrect: nil, ruAddressSetContainsProbe: nil, dnsAddress: nil,
        homeExitDataPassed: nil,
        homeExitHTTPStatus: nil, homeExitLatencySeconds: nil,
        vpsFallbackDataPassed: nil,
        vpsFallbackHTTPStatus: nil, vpsFallbackLatencySeconds: nil,
        consecutiveFailures: 0, lastFailureAt: nil, currentOutageSeconds: nil,
        recommendation: .noChange, reason: "No probe has run in this app session.",
        automaticRouteChangesEnabled: false
    )

    static func parse(
        _ output: String,
        succeeded: Bool,
        history: [HomeExitHealthSample] = [],
        now: Date = Date()
    ) -> HomeExitHealthSnapshot {
        let sections = TaggedDiscoveryOutput.sections(output)
        let host = firstLine(sections["HOST"]) ?? "Unknown"

        guard succeeded,
              let link = firstLine(sections["LINK"]),
              let transfer = parseTransfer(firstLine(sections["TRANSFER"])),
              let rules = sections["RULES"],
              let table = sections["RU_TABLE"],
              let lookup = firstLine(sections["RU_LOOKUP"]),
              let dnsValue = firstLine(sections["DNS"]),
              let homeProbe = firstLine(sections["HOMEEXIT_DATA"]),
              let fallbackProbe = firstLine(sections["VPS_FALLBACK_DATA"]) else {
            let failedSample = HomeExitHealthSample(
                host: host, checkedAt: now, interfaceUp: nil, routeCorrect: nil,
                homeExitDataOK: nil, vpsFallbackDataOK: nil,
                handshakeAgeSeconds: nil, reason: "SSH or probe output is incomplete; no route or service change was made."
            )
            let decision = HomeExitResiliencePolicy.evaluate(history: history + [failedSample], now: now)
            return HomeExitHealthSnapshot(
                checkedAt: now, host: host, state: .unknown, interfaceUp: nil,
                handshakeAgeSeconds: nil, receivedBytes: nil, sentBytes: nil,
                receivedDeltaBytes: nil, sentDeltaBytes: nil,
                routeCorrect: nil, ruAddressSetContainsProbe: nil, dnsAddress: nil,
                homeExitDataPassed: nil,
                homeExitHTTPStatus: nil, homeExitLatencySeconds: nil,
                vpsFallbackDataPassed: nil,
                vpsFallbackHTTPStatus: nil, vpsFallbackLatencySeconds: nil,
                consecutiveFailures: decision.consecutiveFailures,
                lastFailureAt: decision.lastFailureAt,
                currentOutageSeconds: decision.currentOutageSeconds,
                recommendation: decision.recommendation,
                reason: failedSample.reason, automaticRouteChangesEnabled: false
            )
        }

        let linkUp = link == "up"
        let markRule = rules.contains("fwmark 0x67") && rules.contains("lookup 167")
        let correctTable = table.split(whereSeparator: \.isNewline).contains { $0.contains("default") && $0.contains("dev homeexit") }
        let routeCorrect = markRule && correctTable && lookup.contains("dev homeexit") && lookup.contains("table 167")
        let ruSet = firstLine(sections["RU_SET"]) == "member"
        let handshakeEpoch = UInt64(firstLine(sections["HANDSHAKE"]) ?? "")
        let handshakeAge = handshakeEpoch.map { max(0, now.timeIntervalSince1970 - Double($0)) }
        let transferAfter = parseTransfer(firstLine(sections["TRANSFER_AFTER"]))
        let homeHTTP = httpStatus(in: homeProbe)
        let fallbackHTTP = httpStatus(in: fallbackProbe)
        let homeLatency = metric("total", in: homeProbe)
        let fallbackLatency = metric("total", in: fallbackProbe)
        let dnsAddress = dnsValue == "DNS_FAILED" || dnsValue.isEmpty ? nil : dnsValue
        let homeDataOK = dnsAddress != nil && successfulHTTP(homeProbe)
        let fallbackDataOK = dnsAddress != nil && successfulHTTP(fallbackProbe)
        let pathHealthy = linkUp && routeCorrect && ruSet && homeDataOK
        let reason: String
        if pathHealthy {
            reason = "Marked RU lookup, RU-set membership and a pinned HTTPS request through homeexit all passed. Handshake age is informational because the data-plane probe passed."
        } else if !markRule || !correctTable || !lookup.contains("dev homeexit") {
            reason = "The fwmark 0x67 route no longer proves table 167 → homeexit. Do not repair routes automatically."
        } else if !linkUp {
            reason = "The homeexit interface is absent or down."
        } else if !ruSet {
            reason = "The probe destination is missing from the VPS RU address set."
        } else if dnsAddress == nil {
            reason = "The VPS could not resolve the RU probe hostname; the data-plane result is inconclusive."
        } else if (handshakeAge ?? 0) > 180 {
            reason = "The pinned HTTPS data-plane probe failed and the homeexit peer has no recent handshake."
        } else {
            reason = "The pinned HTTPS data-plane probe failed despite a recent handshake; handshake alone does not establish service health."
        }

        let sample = HomeExitHealthSample(
            host: host, checkedAt: now, interfaceUp: linkUp, routeCorrect: routeCorrect && ruSet,
            homeExitDataOK: homeDataOK, vpsFallbackDataOK: fallbackDataOK,
            handshakeAgeSeconds: handshakeAge, reason: reason
        )
        let decision = HomeExitResiliencePolicy.evaluate(history: history + [sample], now: now)
        let state: HealthState
        if pathHealthy {
            state = .online
        } else if decision.consecutiveFailures >= HomeExitResiliencePolicy.failureThreshold && homeDataOK == false {
            state = .offline
        } else {
            state = .warning
        }

        return HomeExitHealthSnapshot(
            checkedAt: now, host: host, state: state, interfaceUp: linkUp,
            handshakeAgeSeconds: handshakeAge, receivedBytes: transfer.received,
            sentBytes: transfer.sent,
            receivedDeltaBytes: transferAfter.map { $0.received >= transfer.received ? $0.received - transfer.received : 0 },
            sentDeltaBytes: transferAfter.map { $0.sent >= transfer.sent ? $0.sent - transfer.sent : 0 },
            routeCorrect: routeCorrect,
            ruAddressSetContainsProbe: ruSet, dnsAddress: dnsAddress,
            homeExitDataPassed: homeDataOK,
            homeExitHTTPStatus: homeHTTP, homeExitLatencySeconds: homeLatency,
            vpsFallbackDataPassed: fallbackDataOK,
            vpsFallbackHTTPStatus: fallbackHTTP, vpsFallbackLatencySeconds: fallbackLatency,
            consecutiveFailures: decision.consecutiveFailures,
            lastFailureAt: decision.lastFailureAt,
            currentOutageSeconds: decision.currentOutageSeconds,
            recommendation: decision.recommendation, reason: reason,
            automaticRouteChangesEnabled: false
        )
    }

    var historySample: HomeExitHealthSample {
        HomeExitHealthSample(
            host: host, checkedAt: checkedAt, interfaceUp: interfaceUp,
            routeCorrect: routeCorrect.map { $0 && ruAddressSetContainsProbe == true },
            homeExitDataOK: homeExitDataPassed, vpsFallbackDataOK: vpsFallbackDataPassed,
            handshakeAgeSeconds: handshakeAgeSeconds, reason: reason
        )
    }

    private static func firstLine(_ value: String?) -> String? {
        value?.split(whereSeparator: \.isNewline).first.map(String.init)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func parseTransfer(_ value: String?) -> (received: UInt64, sent: UInt64)? {
        let fields = value?.split(whereSeparator: \.isWhitespace) ?? []
        guard fields.count == 2, let received = UInt64(fields[0]), let sent = UInt64(fields[1]) else { return nil }
        return (received, sent)
    }

    private static func httpStatus(in value: String) -> Int? {
        guard let match = value.range(of: #"http=(\d{3})"#, options: .regularExpression) else { return nil }
        return Int(value[match].dropFirst(5))
    }

    private static func successfulHTTP(_ value: String) -> Bool {
        guard let status = httpStatus(in: value), (200..<400).contains(status),
              let tls = metric("tls", in: value) else { return false }
        return tls > 0
    }

    private static func metric(_ name: String, in value: String) -> Double? {
        guard let field = value.split(whereSeparator: \.isWhitespace).first(where: { $0.hasPrefix("\(name)=") }) else { return nil }
        return Double(field.dropFirst(name.count + 1))
    }
}

struct HomeExitResilienceDecision: Sendable, Equatable {
    let recommendation: HomeExitRecommendation
    let consecutiveFailures: Int
    let lastFailureAt: Date?
    let currentOutageSeconds: TimeInterval?
}

enum HomeExitResiliencePolicy {
    static let failureThreshold = 2
    static let recoverySuccessThreshold = 3
    static let minimumStableRecovery: TimeInterval = 300
    static let maximumSampleGap: TimeInterval = 600

    static func evaluate(history: [HomeExitHealthSample], now: Date = Date()) -> HomeExitResilienceDecision {
        let ordered = history.sorted { $0.checkedAt < $1.checkedAt }
        guard let latest = ordered.last, now.timeIntervalSince(latest.checkedAt) <= maximumSampleGap,
              let healthy = latest.pathHealthy else {
            return HomeExitResilienceDecision(recommendation: .noChange, consecutiveFailures: 0, lastFailureAt: nil, currentOutageSeconds: nil)
        }

        var consecutive = 0
        for sample in ordered.reversed() {
            guard now.timeIntervalSince(sample.checkedAt) <= maximumSampleGap,
                  let sampleHealthy = sample.pathHealthy,
                  sampleHealthy == healthy else { break }
            consecutive += 1
        }

        let lastFailure = ordered.last(where: { $0.pathHealthy == false })?.checkedAt
        if healthy {
            let recoveryStable = consecutive >= recoverySuccessThreshold &&
                (latest.checkedAt.timeIntervalSince(ordered[max(0, ordered.count - recoverySuccessThreshold)].checkedAt) >= minimumStableRecovery)
            let recommendation: HomeExitRecommendation = recoveryStable && lastFailure != nil ? .homeExitRecovered : .noChange
            return HomeExitResilienceDecision(recommendation: recommendation, consecutiveFailures: 0, lastFailureAt: lastFailure, currentOutageSeconds: nil)
        }

        var outageStart = latest.checkedAt
        for sample in ordered.reversed() {
            guard now.timeIntervalSince(sample.checkedAt) <= maximumSampleGap, sample.pathHealthy == false else { break }
            outageStart = sample.checkedAt
        }
        let fallbackAvailable = latest.vpsFallbackDataOK == true
        let recommendation: HomeExitRecommendation
        if consecutive < failureThreshold {
            recommendation = .repeatProbe
        } else if fallbackAvailable {
            recommendation = .vpsFallbackAvailable
        } else {
            recommendation = .inspectHomePeer
        }
        return HomeExitResilienceDecision(
            recommendation: recommendation, consecutiveFailures: consecutive,
            lastFailureAt: lastFailure, currentOutageSeconds: max(0, now.timeIntervalSince(outageStart))
        )
    }
}

actor HomeExitHealthHistoryStore {
    private let url: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let folder = base.appendingPathComponent("TunnelDeck", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        url = folder.appendingPathComponent("homeexit-health.json")
    }

    func load() -> [HomeExitHealthSample] {
        (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode([HomeExitHealthSample].self, from: $0) } ?? []
    }

    func append(_ sample: HomeExitHealthSample) {
        var values = load()
        values.append(sample)
        if let data = try? JSONEncoder().encode(Array(values.suffix(500))) {
            try? data.write(to: url, options: .atomic)
        }
    }
}
