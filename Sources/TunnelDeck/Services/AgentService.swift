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

enum AgentReadCommand: Sendable {
    case status
    case history(kind:String,cursor: Int64, limit: Int)

    var arguments: [String] {
        switch self {
        case .status: return ["/usr/local/libexec/tunneldeck-agent", "agent-status"]
        case .history(let kind,let cursor, let limit): return ["/usr/local/libexec/tunneldeck-agent", "telemetry-\(kind)", "--cursor", String(max(0, cursor)), "--limit", String(max(1, min(limit, 10_000)))]
        }
    }
}

actor AgentService {
    private let ssh: SSHService
    init(ssh: SSHService) { self.ssh = ssh }

    func status(configuration: SSHConfiguration) async throws -> AgentStatus {
        let result = try await ssh.executeAgent(.status, configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Agent", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(AgentStatus.self, from: Data(result.stdout.utf8))
    }

    func samples(cursor: Int64, configuration: SSHConfiguration) async throws -> AgentEnvelope<AgentTelemetryItem<AgentMonitoringPayload>> {
        let result = try await ssh.executeAgent(.history(kind:"samples",cursor: cursor, limit: 2_000), configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Agent", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(AgentEnvelope<AgentTelemetryItem<AgentMonitoringPayload>>.self, from: Data(result.stdout.utf8))
    }
    func events(cursor:Int64,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentEventPayload>>{try await history("events",cursor,configuration)}
    func peers(cursor:Int64,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentPeerPayload>>{try await history("peers",cursor,configuration)}
    func adGuard(cursor:Int64,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentAdGuardPayload>>{try await history("adguard",cursor,configuration)}
    private func history<T:Decodable & Sendable>(_ kind:String,_ cursor:Int64,_ configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<T>>{guard ["events","peers","adguard"].contains(kind)else{throw CommandPolicyError.deniedCommand};let result=try await ssh.executeAgent(.history(kind:kind,cursor:cursor,limit:2_000),configuration:configuration);guard result.succeeded else{throw NSError(domain:"TunnelDeck.Agent",code:Int(result.exitCode),userInfo:[NSLocalizedDescriptionKey:result.stderr])};return try JSONDecoder().decode(AgentEnvelope<AgentTelemetryItem<T>>.self,from:Data(result.stdout.utf8))}
}
