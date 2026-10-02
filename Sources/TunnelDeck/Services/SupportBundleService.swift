import Foundation

struct SupportBundleInput: Sendable {
    let applicationVersion: String; let helperVersion: String?; let node: InfrastructureNode?; let health: HealthReport?; let security: SecuritySnapshot; let exposure: [NetworkEndpoint]; let samples: [MonitoringSample]; let incidents: [Incident]; let events: [MonitoringEvent]; let drift: [ConfigurationDrift]; let logs: [LogEntry]
}

enum SupportBundleService {
    static func create(_ input: SupportBundleInput, destinationFolder: URL? = nil) throws -> URL {
        let manager = FileManager.default; let output = destinationFolder ?? manager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TunnelDeck/SupportBundles", isDirectory: true); try manager.createDirectory(at: output, withIntermediateDirectories: true, attributes: [.posixPermissions:0o700]); let temporary = manager.temporaryDirectory.appendingPathComponent("TunnelDeck-Support-\(UUID().uuidString)", isDirectory:true); try manager.createDirectory(at:temporary,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]); defer { try? manager.removeItem(at:temporary) }
        let files = try sanitizedFiles(input)
        for (name, content) in files { try content.write(to:temporary.appendingPathComponent(name),atomically:true,encoding:.utf8) }
        let formatter=DateFormatter(); formatter.dateFormat="yyyy-MM-dd_HH-mm-ss"; let archive=output.appendingPathComponent("TunnelDeck-Support-\(formatter.string(from:Date())).zip"); let process=Process(); process.executableURL=URL(fileURLWithPath:"/usr/bin/ditto"); process.arguments=["-c","-k","--sequesterRsrc","--keepParent",temporary.path,archive.path]; try process.run(); process.waitUntilExit(); guard process.terminationStatus == 0 else { throw NSError(domain:"TunnelDeck.SupportBundle",code:Int(process.terminationStatus)) }; try manager.setAttributes([.posixPermissions:0o600],ofItemAtPath:archive.path); return archive
    }
    static func renderedFiles(_ input: SupportBundleInput) throws -> [String:String] {
        let encoder=JSONEncoder(); encoder.outputFormatting=[.prettyPrinted,.sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        func json<T:Encodable>(_ value:T)->String { (try? String(data:encoder.encode(value),encoding:.utf8)) ?? "null" }
        let metadata:[String:String] = ["applicationVersion":input.applicationVersion,"helperVersion":input.helperVersion ?? "unavailable","nodeID":input.node?.id.uuidString ?? "unconfigured","nodeName":input.node?.name ?? "unconfigured","nodeRole":input.node?.role.rawValue ?? "unknown"]
        let logText=input.logs.suffix(500).map { "\($0.timestamp.ISO8601Format()) [\($0.subsystem)] \($0.command) exit=\($0.exitCode)\n\($0.stdout)\n\($0.stderr)" }.joined(separator:"\n")
        return ["metadata.json":json(metadata),"health-report.json":json(input.health),"security-audit.json":json(SupportSecuritySnapshot(input.security)),"exposure-matrix.json":json(input.exposure),"monitoring-summary.json":json(Array(input.samples.suffix(500))),"recent-incidents.json":json(Array(input.incidents.suffix(100))),"recent-events.json":json(Array(input.events.suffix(500))),"configuration-drift.json":json(input.drift),"redacted.log":logText]
    }
    static func sanitizedFiles(_ input:SupportBundleInput) throws -> [String:String] { let files=try renderedFiles(input); return try Dictionary(uniqueKeysWithValues:files.map { name,content in let redacted=SecretRedactor.redact(content); guard !containsForbiddenSecret(redacted) else { throw NSError(domain:"TunnelDeck.SupportBundle",code:2,userInfo:[NSLocalizedDescriptionKey:"Redaction verification failed for \(name)"]) }; return (name,redacted) }) }
    static func containsForbiddenSecret(_ text:String)->Bool { let patterns=[#"(?im)^\s*(PrivateKey|PresharedKey)\s*=\s*(?!\[REDACTED\])\S+"#,#"(?i)Authorization\s*:\s*(?!\[REDACTED\])\S+"#,#"(?i)Cookie\s*:\s*(?!\[REDACTED\])\S+"#,#"(?i)(password|token)\s*[=:]\s*(?!\[REDACTED\])\S+"#]; return patterns.contains { text.range(of:$0,options:.regularExpression) != nil } }
}

private struct SupportSecuritySnapshot: Encodable { let state:HealthState; let publicListeners:[SecurityListener]; let privateListeners:[SecurityListener]; let ssh:SupportSSH; let lastUpdated:Date?; init(_ value:SecuritySnapshot){state=value.state;publicListeners=value.publicListeners;privateListeners=value.privateListeners;ssh=SupportSSH(value.ssh);lastUpdated=value.lastUpdated} }
private struct SupportSSH: Encodable { let state:HealthState; let port,passwordAuthentication,keyboardInteractiveAuthentication,pubkeyAuthentication,permitRootLogin:String; let findings:[String]; init(_ value:SSHSecuritySnapshot){state=value.state;port=value.port;passwordAuthentication=value.passwordAuthentication;keyboardInteractiveAuthentication=value.keyboardInteractiveAuthentication;pubkeyAuthentication=value.pubkeyAuthentication;permitRootLogin=value.permitRootLogin;findings=value.findings} }
