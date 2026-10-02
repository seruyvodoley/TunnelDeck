import Foundation

enum EmergencyKitService {
    static func create(health: HealthReport?, server: ServerProfile?, profiles: [LocalProfile], backups: [BackupRecord], includeClientCredentials: Bool) throws -> URL {
        guard !includeClientCredentials else { throw NSError(domain: "TunnelDeck.EmergencyKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "Encrypted secret containers are unavailable; client credentials were not included."]) }
        let manager = FileManager.default
        let support = manager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TunnelDeck/EmergencyKits", isDirectory: true)
        try manager.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temporary = manager.temporaryDirectory.appendingPathComponent("TunnelDeck-Emergency-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: temporary, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? manager.removeItem(at: temporary) }
        _ = profiles
        let publicInfo: [String: String] = ["name": server?.name ?? "Current VPS", "host": server?.host ?? "", "role": server?.role ?? "", "latestBackupManifest": backups.first?.path ?? ""]
        try JSONSerialization.data(withJSONObject: publicInfo, options: .prettyPrinted).write(to: temporary.appendingPathComponent("server-public.json"), options: .atomic)
        if let health { try JSONEncoder().encode(health).write(to: temporary.appendingPathComponent("health-report.json"), options: .atomic) }
        try "TunnelDeck Emergency Kit\n\nUse an independent VPS console if SSH or WireGuard is unavailable. Review backup manifests before restoring. Never replace a server private key during recovery.\n".write(to: temporary.appendingPathComponent("RECOVERY.txt"), atomically: true, encoding: .utf8)
        let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let archive = support.appendingPathComponent("TunnelDeck-Emergency-\(formatter.string(from: Date())).zip")
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto"); process.arguments = ["-c", "-k", "--sequesterRsrc", "--keepParent", temporary.path, archive.path]
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw NSError(domain: "TunnelDeck.EmergencyKit", code: Int(process.terminationStatus)) }
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: archive.path)
        return archive
    }
}
