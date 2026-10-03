import Foundation

struct AgentEnvelope<Item: Decodable & Sendable>: Decodable, Sendable {
    let schemaVersion: Int
    let agentVersion: String
    let items: [Item]?
    let nextCursor: Int64?
}

struct AgentTelemetryItem<Payload: Decodable & Sendable>: Decodable, Sendable {
    let rowid: Int64
    let id: String
    let timestamp: String
    let payload: Payload
}

struct AgentStatus: Decodable, Sendable { let schemaVersion: Int; let agentVersion: String; let status: String; let agentHealth:String?;let telemetryLag:Double?;let lastAgentSampleAt:String? }
struct AgentMonitoringPayload: Decodable, Sendable {
    let cpuPercent: Double; let memoryPercent: Double; let diskPercent: Double; let pingMilliseconds: Double?
    let vpsState: HealthState; let wireGuardState: HealthState; let adGuardState: HealthState; let antiZapretState: HealthState
    let publicDNSExposed: Bool; let publicListeners: [String]
}
struct AgentEventPayload: Decodable, Sendable { let from:String?;let to:String?;let event:String? }
struct AgentPeerPayload: Decodable, Sendable { let publicIdentifier:String;let latestHandshake:Int64;let rx:UInt64;let tx:UInt64 }
struct AgentAdGuardPayload: Decodable, Sendable { let totalQueries:Int;let blockedQueries:Int;let blockedPercentage:Double;let averageProcessingTime:Double }

enum AgentHistoryKind: String, Sendable, CaseIterable { case samples, events, peers, adguard }

enum AgentReadCommand: Sendable {
    static let sudoPath = "/usr/bin/sudo"
    static let agentUser = "tunneldeck-agent"
    static let agentPath = "/usr/local/libexec/tunneldeck-agent"
    case status
    case history(kind:AgentHistoryKind,cursor: Int64, limit: Int)

    var arguments: [String] {
        let prefix = [Self.sudoPath, "-n", "-u", Self.agentUser, Self.agentPath]
        switch self {
        case .status: return prefix + ["agent-status"]
        case .history(let kind,let cursor, let limit): return prefix + ["telemetry-\(kind.rawValue)", "--cursor", String(max(0, cursor)), "--limit", String(max(1, min(limit, 10_000)))]
        }
    }
}

actor AgentService: AgentHistorySource {
    private let ssh: SSHService
    init(ssh: SSHService) { self.ssh = ssh }

    func status(configuration: SSHConfiguration) async throws -> AgentStatus {
        let result = try await ssh.executeAgent(.status, configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Agent", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(AgentStatus.self, from: Data(result.stdout.utf8))
    }

    func samples(cursor: Int64, limit:Int, configuration: SSHConfiguration) async throws -> AgentEnvelope<AgentTelemetryItem<AgentMonitoringPayload>> {
        let result = try await ssh.executeAgent(.history(kind:.samples,cursor: cursor, limit: limit), configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Agent", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(AgentEnvelope<AgentTelemetryItem<AgentMonitoringPayload>>.self, from: Data(result.stdout.utf8))
    }
    func events(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentEventPayload>>{try await history(.events,cursor,limit,configuration)}
    func peers(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentPeerPayload>>{try await history(.peers,cursor,limit,configuration)}
    func adGuard(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentAdGuardPayload>>{try await history(.adguard,cursor,limit,configuration)}
    private func history<T:Decodable & Sendable>(_ kind:AgentHistoryKind,_ cursor:Int64,_ limit:Int,_ configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<T>>{let result=try await ssh.executeAgent(.history(kind:kind,cursor:cursor,limit:limit),configuration:configuration);guard result.succeeded else{throw NSError(domain:"TunnelDeck.Agent",code:Int(result.exitCode),userInfo:[NSLocalizedDescriptionKey:result.stderr])};return try JSONDecoder().decode(AgentEnvelope<AgentTelemetryItem<T>>.self,from:Data(result.stdout.utf8))}
}
