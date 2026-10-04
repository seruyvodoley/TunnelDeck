import Foundation

enum ObservationFreshnessState: String, Codable, Sendable { case live, stale, unknown }

struct ObservationFreshness: Equatable, Sendable {
    let lastObservedAt: Date?
    let now: Date
    let staleAfter: TimeInterval

    var age: TimeInterval? { lastObservedAt.map { max(0, now.timeIntervalSince($0)) } }
    var state: ObservationFreshnessState {
        guard let age else { return .unknown }
        return age <= staleAfter ? .live : .stale
    }
    var isStale: Bool { state == .stale }
}

enum MonitoringHistory {
    static let retention: TimeInterval = 7 * 86_400

    static func cutoff(hours: Int, now: Date = Date()) -> Date {
        now.addingTimeInterval(-Double(hours) * 3_600)
    }

    static func filtered<T>(_ values: [T], hours: Int, now: Date = Date(), timestamp: (T) -> Date) -> [T] {
        let start = cutoff(hours: hours, now: now)
        return values.filter { timestamp($0) >= start }
    }

    static func segments<T>(_ values: [T], expectedInterval: TimeInterval, timestamp: (T) -> Date) -> [[T]] {
        let ordered = values.sorted { timestamp($0) < timestamp($1) }
        guard !ordered.isEmpty else { return [] }
        let gapLimit = max(expectedInterval * 3, 120)
        return ordered.dropFirst().reduce(into: [[ordered[0]]]) { result, value in
            if let previous = result.last?.last, timestamp(value).timeIntervalSince(timestamp(previous)) > gapLimit {
                result.append([value])
            } else {
                result[result.count - 1].append(value)
            }
        }
    }
}

struct MonitoringPresentation: Sendable {
    let samples: [MonitoringSample]
    let sampleSegments: [[MonitoringSample]]
    let pingSegments: [[MonitoringSample]]
    let peerGroups: [(id: String, samples: [PeerHistorySample])]
    let adGuard: [AdGuardHistorySample]
    let adGuardSegments: [[AdGuardHistorySample]]

    static func build(samples: [MonitoringSample], peers: [PeerHistorySample], adGuard: [AdGuardHistorySample], hours: Int, expectedInterval: TimeInterval, now: Date = Date(), chartPointLimit: Int = 1_200) -> MonitoringPresentation {
        let cutoff = MonitoringHistory.cutoff(hours: hours, now: now)
        let windowSamples = samples.filter { $0.timestamp >= cutoff }
        let segments = MonitoringHistory.segments(windowSamples, expectedInterval: expectedInterval, timestamp: \MonitoringSample.timestamp)
            .map { ChartDownsampler.monitoring($0, maxPoints: chartPointLimit) }
        let pingSegments = segments.map { $0.filter { $0.pingMilliseconds != nil } }.filter { !$0.isEmpty }
        let grouped = Dictionary(grouping: peers.lazy.filter { $0.timestamp >= cutoff }, by: \PeerHistorySample.peerID)
            .map { (id: $0.key, samples: $0.value.sorted { $0.timestamp < $1.timestamp }) }
            .sorted { $0.id < $1.id }
        let adGuardWindow = adGuard.filter { $0.timestamp >= cutoff }.sorted { $0.timestamp < $1.timestamp }
        let adGuardSegments = MonitoringHistory.segments(adGuardWindow, expectedInterval: max(expectedInterval, 60), timestamp: \AdGuardHistorySample.timestamp)
            .map { ChartDownsampler.adGuard($0, maxPoints: chartPointLimit) }
        return MonitoringPresentation(samples: windowSamples, sampleSegments: segments, pingSegments: pingSegments, peerGroups: grouped, adGuard: adGuardWindow, adGuardSegments: adGuardSegments)
    }
}

@MainActor
final class CPUDeltaTracker {
    private var previous: (idle: Double, total: Double)?

    func reset() { previous = nil }
    func percentage(idle: Double, total: Double, fallback: Double) -> Double {
        defer { previous = (idle, total) }
        guard let previous else { return 0 }
        let totalDelta = total - previous.total
        guard totalDelta > 0 else { return fallback }
        return max(0, min(100, (1 - (idle - previous.idle) / totalDelta) * 100))
    }
}

enum ChartDownsampler {
    /// Bucketed min/max sampling preserves endpoints and spikes without changing persisted history.
    static func monitoring(_ values: [MonitoringSample], maxPoints: Int) -> [MonitoringSample] {
        guard maxPoints >= 2, values.count > maxPoints else { return values }
        guard maxPoints >= 10 else { return [values[0], values[values.count - 1]] }
        let interiorBudget = max(1, maxPoints - 2), bucketCount = max(1, interiorBudget / 8)
        let interior = Array(values.dropFirst().dropLast())
        let bucketSize = max(1, Int(ceil(Double(interior.count) / Double(bucketCount))))
        var selected = Set<Int>(); selected.insert(0); selected.insert(values.count - 1)
        for start in stride(from: 0, to: interior.count, by: bucketSize) {
            let end = min(interior.count, start + bucketSize), range = start..<end
            let metrics: [(MonitoringSample) -> Double] = [{ $0.cpuPercent }, { $0.memoryPercent }, { $0.diskPercent }, { $0.pingMilliseconds ?? -.infinity }]
            for metric in metrics {
                if let minimum = range.min(by: { metric(interior[$0]) < metric(interior[$1]) }) { selected.insert(minimum + 1) }
                if let maximum = range.max(by: { metric(interior[$0]) < metric(interior[$1]) }) { selected.insert(maximum + 1) }
            }
        }
        return selected.sorted().prefix(maxPoints).map { values[$0] }
    }

    static func adGuard(_ values: [AdGuardHistorySample], maxPoints: Int) -> [AdGuardHistorySample] {
        guard maxPoints >= 4, values.count > maxPoints else { return values }
        let bucketCount = max(1, (maxPoints - 2) / 2), interior = Array(values.dropFirst().dropLast())
        let bucketSize = max(1, Int(ceil(Double(interior.count) / Double(bucketCount))))
        var selected: Set<Int> = [0, values.count - 1]
        for start in stride(from: 0, to: interior.count, by: bucketSize) {
            let range = start..<min(interior.count, start + bucketSize)
            if let minimum = range.min(by: { interior[$0].blockedPercentage < interior[$1].blockedPercentage }) { selected.insert(minimum + 1) }
            if let maximum = range.max(by: { interior[$0].blockedPercentage < interior[$1].blockedPercentage }) { selected.insert(maximum + 1) }
        }
        return selected.sorted().prefix(maxPoints).map { values[$0] }
    }
}

@MainActor
final class NodeOperationGuard {
    private(set) var generation = 0
    func advance() { generation += 1 }
    func capture(nodeID: UUID?) -> (UUID?, Int) { (nodeID, generation) }
    func accepts(nodeID: UUID?, generation: Int, activeNodeID: UUID?) -> Bool { self.generation == generation && nodeID == activeNodeID }
}

struct NodeOperationContext: Sendable {
    let nodeID: UUID?
    let generation: Int
    let configuration: SSHConfiguration
    let host: String
}

@MainActor
final class InFlightOperationState {
    private var token: UUID?
    var isActive: Bool { token != nil }
    func begin() -> UUID { let value=UUID();token=value;return value }
    func cancel() { token=nil }
    func finish(_ value:UUID)->Bool{guard token==value else{return false};token=nil;return true}
}

@MainActor
final class PollingCoordinator {
    private(set) var generation = 0
    private var task: Task<Void, Never>?

    var isRunning: Bool { task != nil }

    func stop() { task?.cancel(); task = nil }
    func start(interval: @escaping @MainActor () -> TimeInterval, operation: @escaping @MainActor () async -> Void) {
        stop(); generation += 1
        task = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval()))
                guard !Task.isCancelled else { return }
                await operation()
            }
        }
    }
}

@MainActor
final class RefreshCadenceController {
    private var lastRun: [String: Date] = [:]

    func shouldRun(_ tier: String, every interval: TimeInterval, now: Date = Date()) -> Bool {
        guard lastRun[tier].map({ now.timeIntervalSince($0) < interval }) != true else { return false }
        lastRun[tier] = now
        return true
    }

    func reset() { lastRun.removeAll() }
}
