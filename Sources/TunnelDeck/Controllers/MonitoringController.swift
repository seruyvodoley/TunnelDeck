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

@MainActor
final class PollingCoordinator {
    private(set) var generation = 0
    private var task: Task<Void, Never>?

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
