import Foundation
import SwiftUI

@MainActor
final class AppViewModel: ObservableObject {
    @Published var settings: AppSettings
    @Published var system = SystemSnapshot()
    @Published var wireGuard = WireGuardSnapshot()
    @Published var units: [UnitStatus] = []
    @Published var listeners: [Listener] = []
    @Published var profiles: [ProfileMetadata] = []
    @Published var antiZapretSettings: [String: String] = [:]
    @Published var logs: [LogEntry] = []
    @Published var diagnostics: [DiagnosticResult] = []
    @Published var isRefreshing = false
    @Published var lastRefresh: Date?
    @Published var selectedSection: SidebarSection = .dashboard
    @Published var showOnboarding: Bool
    @Published var statusMessage = "Read-only mode"
    @Published var helperVersion: String?
    @Published var helperError: AppError?
    @Published var backups: [BackupRecord] = []
    @Published var presentedError: AppError?
    @Published var localProfiles: [LocalProfile] = []
    @Published var managedPeers: [HelperPeer] = []
    @Published var healthReport: HealthReport?
    @Published var activity: [ActivityRecord] = []
    @Published var lastSuccessfulHealthCheck: Date?
    @Published var isRunningHealthCheck = false
    @Published var servers: [ServerProfile] = []
    @Published var activeServerID: UUID?
    @Published var configurationDrift: [String] = []
    @Published var restorePreview: RestorePreview?
    @Published var approvedListenerIDs = Set<String>()
    @Published var ignoredPeerIDs = Set<String>()
    @Published var adGuard = AdGuardSnapshot()
    @Published var dnsPath = DNSPathSnapshot()
    @Published var isRunningDNSPathTest = false
    @Published var security = SecuritySnapshot()
    @Published var isRefreshingSecurity = false

    let ssh = SSHService()
    let adGuardAPI = AdGuardAPIService()
    let localDNS = LocalDNSService()
    lazy var helper = HelperService(ssh: ssh)
    private let history = DiagnosticHistoryStore()
    private let activityStore = ActivityStore()
    private var pollTask: Task<Void, Never>?
    private var previousCPUTicks: (idle: Double, total: Double)?

    init() {
        let decoded = UserDefaults.standard.data(forKey: "settings").flatMap { try? JSONDecoder().decode(AppSettings.self, from: $0) }
        var initialSettings = decoded ?? AppSettings()
        if let storedPath = KeychainService.load(account: "ssh-key-path"), !storedPath.isEmpty { initialSettings.keyPath = storedPath }
        settings = initialSettings
        showOnboarding = !initialSettings.completedOnboarding
        system.macLANIP = LocalNetworkService.lanIPv4()
        localProfiles = ProfileStore.list()
        Task { diagnostics = await history.load() }
        Task { activity = await activityStore.load() }
        if let data = UserDefaults.standard.data(forKey: "servers") { servers = (try? JSONDecoder().decode([ServerProfile].self, from: data)) ?? [] }
        activeServerID = UserDefaults.standard.string(forKey: "activeServerID").flatMap(UUID.init)
        loadServerScopedState()
    }

    var configuration: SSHConfiguration { SSHConfiguration(host: settings.host, username: settings.username, keyPath: NSString(string: settings.keyPath).expandingTildeInPath, timeout: 8, port: settings.port) }

    func saveSettings() {
        try? KeychainService.save(settings.keyPath, account: "ssh-key-path")
        var persisted = settings; persisted.keyPath = ""
        if let data = try? JSONEncoder().encode(persisted) { UserDefaults.standard.set(data, forKey: "settings") }
        configurePolling()
    }

    func saveCurrentServer(name: String = "Primary VPS", role: String = "Primary") {
        let profile = ServerProfile(id: activeServerID ?? UUID(), name: name, host: settings.host, port: settings.port, username: settings.username, keyPath: settings.keyPath, role: role)
        servers.removeAll { $0.id == profile.id }; servers.append(profile); activeServerID = profile.id
        if let data = try? JSONEncoder().encode(servers) { UserDefaults.standard.set(data, forKey: "servers") }
        UserDefaults.standard.set(profile.id.uuidString, forKey: "activeServerID"); saveSettings()
    }

    func selectServer(_ id: UUID) {
        guard let server = servers.first(where: { $0.id == id }) else { return }
        activeServerID = id; UserDefaults.standard.set(id.uuidString, forKey: "activeServerID"); settings.host = server.host; settings.port = server.port; settings.username = server.username; settings.keyPath = server.keyPath
        system = SystemSnapshot(); wireGuard = WireGuardSnapshot(); units = []; listeners = []; healthReport = nil; security = SecuritySnapshot(); loadServerScopedState()
        saveSettings(); Task { await refresh() }
    }

    func completeOnboarding() { settings.completedOnboarding = true; showOnboarding = false; saveSettings() }

    func configurePolling() {
        pollTask?.cancel()
        guard settings.pollingEnabled else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(self?.settings.pollingInterval ?? 5))
                await self?.refresh()
            }
        }
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true; defer { isRefreshing = false }
        system.macLANIP = LocalNetworkService.lanIPv4()
        async let hostname = execute(.hostname, subsystem: "System")
        async let cpu = execute(.cpu, subsystem: "System")
        async let macPublicIP = LocalNetworkService.publicIPv4()
        async let os = execute(.osRelease, subsystem: "System")
        async let uname = execute(.uname, subsystem: "System")
        async let uptime = execute(.uptime, subsystem: "System")
        async let memory = execute(.memory, subsystem: "System")
        async let disk = execute(.disk, subsystem: "System")
        async let ipv4 = execute(.publicIPv4, subsystem: "Network")
        async let ipv6 = execute(.publicIPv6, subsystem: "Network")
        async let wg = execute(.wireGuard, subsystem: "WireGuard")
        async let wgAddress = execute(.wireGuardAddress, subsystem: "WireGuard")
        async let wgLink = execute(.wireGuardLink, subsystem: "WireGuard")
        async let serviceUnits = execute(.units, subsystem: "systemd")
        async let socketListeners = execute(.listeners, subsystem: "DNS")
        async let azSettings = execute(.antiZapretSettings, subsystem: "AntiZapret")
        async let profileList = execute(.profiles, subsystem: "Profiles")
        let values = await (hostname, os, uname, uptime, memory, disk, ipv4, ipv6, wg, wgAddress, wgLink, serviceUnits, socketListeners, azSettings, profileList, cpu, macPublicIP)
        system.hostname = values.0.stdout.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "—"
        system.osVersion = parseOS(values.1.stdout)
        system.kernel = values.2.stdout.split(separator: " ").dropFirst(2).first.map(String.init) ?? "—"
        system.uptime = values.3.stdout.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "—"
        system.loadAverage = parseLoad(values.3.stdout)
        system.memoryPercent = parseMemory(values.4.stdout)
        system.diskPercent = parseDisk(values.5.stdout)
        system.publicIPv4 = values.6.stdout.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "—"
        system.publicIPv6 = values.7.stdout.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "—"
        system.cpuPercent = parseCPU(values.15.stdout)
        system.macPublicIP = values.16
        system.sshAvailable = values.0.succeeded
        system.health = values.0.succeeded ? .online : .offline
        wireGuard = WireGuardParser.parse(values.8.stdout, timeout: settings.handshakeTimeout)
        wireGuard.address = parseWireGuardAddress(values.9.stdout)
        if let mtuRange = values.10.stdout.range(of: #"mtu\s+(\d+)"#, options: .regularExpression) { wireGuard.mtu = values.10.stdout[mtuRange].split(separator: " ").last.map(String.init) ?? "—" }
        units = SystemctlParser.parse(values.11.stdout)
        listeners = SSParser.parse(values.12.stdout)
        antiZapretSettings = Dictionary(uniqueKeysWithValues: values.13.stdout.split(separator: "\n").compactMap { line in
            let pair = line.split(separator: "=", maxSplits: 1).map(String.init); return pair.count == 2 ? (pair[0], pair[1]) : nil
        })
        profiles = ProfileParser.parseListing(values.14.stdout)
        lastRefresh = Date(); statusMessage = values.0.succeeded ? "Updated" : "SSH unavailable"
        if values.0.succeeded { await refreshHelper() }
        await evaluateMonitoringState()
        await performScheduledBackupIfNeeded()
    }

    func refreshHelper() async {
        switch await helper.version(configuration: configuration) {
        case .success(let version):
            helperVersion = version; helperError = nil
            backups = (try? await helper.listBackups(configuration: configuration)) ?? []
            managedPeers = (try? await helper.peers(configuration: configuration)) ?? []
        case .failure(let error):
            helperVersion = nil; helperError = error
        }
    }

    func suggestedPeerIP() -> String {
        guard let address = wireGuard.address.split(separator: "/").first else { return "" }
        let octets = address.split(separator: ".")
        guard octets.count == 4 else { return "" }
        let prefix = octets.prefix(3).joined(separator: ".")
        let used = Set(managedPeers.map(\.ip) + wireGuard.peers.map { $0.vpnIP.replacingOccurrences(of: "/32", with: "") })
        return (2...254).map { "\(prefix).\($0)" }.first { !used.contains($0) } ?? ""
    }

    func addPeer(name: String, ip: String, dns: String, mtu: Int, allowedIPs: String, endpoint: String) async -> Bool {
        guard settings.writeModeEnabled, helperVersion == HelperService.localVersion else {
            presentedError = AppError(title: "Write operation unavailable", message: "Write Mode and a matching server helper are required.", technicalDetails: "helper=\(helperVersion ?? "missing")", recommendedAction: "Enable Write Mode after installing helper version \(HelperService.localVersion).")
            return false
        }
        do {
            _ = try await helper.addPeer(name: name, ip: ip, dns: dns, mtu: mtu, allowedIPs: allowedIPs, endpoint: endpoint, configuration: configuration)
            let config = try await ssh.fetchClientConfig(name: name, configuration: configuration)
            _ = try ProfileStore.saveConfiguration(config, name: name)
            localProfiles = ProfileStore.list()
            await refresh()
            return true
        } catch {
            presentedError = AppError(title: "WireGuard peer creation failed", message: "The peer was not created successfully. The helper performs rollback when validation fails.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Review the safe log and verify wg0/helper health before retrying.")
            return false
        }
    }

    func removePeer(publicKey: String, deleteClient: Bool, allowExisting: Bool) async -> Bool {
        guard settings.writeModeEnabled, helperVersion == HelperService.localVersion else { return false }
        do {
            _ = try await helper.removePeer(publicKey: publicKey, deleteClient: deleteClient, allowExisting: allowExisting, configuration: configuration)
            await refresh(); return true
        } catch {
            presentedError = AppError(title: "WireGuard peer removal failed", message: "The peer could not be removed safely.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Do not edit wg0.conf manually; inspect the backup and helper health output.")
            return false
        }
    }

    func performServiceAction(_ action: String, unit: String) async -> Bool {
        guard settings.writeModeEnabled, helperVersion == HelperService.localVersion else { return false }
        do {
            let change = try await helper.service(action: action, unit: unit, configuration: configuration)
            logs.insert(LogEntry(timestamp: Date(), subsystem: "System", command: "helper service \(action) \(unit)", stdout: "state=\(change.state) backup=\(change.backup)", stderr: "", exitCode: 0), at: 0)
            await activityStore.append(operation: "Service \(action)", server: settings.host, preview: unit, result: "state=\(change.state), backup=\(change.backup)")
            activity = await activityStore.load()
            await refresh()
            return true
        } catch {
            presentedError = AppError(title: "Service action failed", message: "\(unit) could not be \(action)ed safely.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Review the helper backup and service journal before retrying.")
            return false
        }
    }

    func runFullHealthCheck() async {
        guard !isRunningHealthCheck else { return }
        isRunningHealthCheck = true
        defer { isRunningHealthCheck = false }

        let commands: [ReadCommand] = [.hostname, .wireGuardService, .wireGuard, .wireGuardAll, .wireGuardAddress, .udpListeners, .ipForward, .natRules, .pingInternet, .dnsTest, .adGuardStatus, .adGuardBinds, .antiZapretStatus, .units, .disk, .memory, .uptime, .listeners, .firewallState, .configurationHashes]
        var results: [ReadCommand: CommandResult] = [:]
        for command in commands {
            results[command] = await execute(command, subsystem: "Doctor")
        }

        var freshWireGuard = WireGuardParser.parse(results[.wireGuard]?.stdout ?? "", timeout: settings.handshakeTimeout)
        freshWireGuard.address = parseWireGuardAddress(results[.wireGuardAddress]?.stdout ?? "")

        var freshSystem = system
        freshSystem.sshAvailable = results[.hostname]?.succeeded == true
        freshSystem.health = freshSystem.sshAvailable ? .online : .offline
        freshSystem.diskPercent = parseDisk(results[.disk]?.stdout ?? "")
        freshSystem.memoryPercent = parseMemory(results[.memory]?.stdout ?? "")

        let freshListeners = SSParser.parse(results[.listeners]?.stdout ?? "")

        loadServerScopedState()
        healthReport = HealthEvaluator.report(
            results: results,
            listeners: freshListeners,
            system: freshSystem,
            wireGuard: freshWireGuard,
            host: settings.host,
            approvedListenerIDs: approvedListenerIDs,
            ignoredPeerIDs: ignoredPeerIDs
        )
        detectConfigurationDrift(results[.configurationHashes]?.stdout ?? "", storeBaseline: healthReport?.state == .online)
        if healthReport?.state == .online { lastSuccessfulHealthCheck = Date() }
        await activityStore.append(operation: "Full Health Check", server: settings.host, preview: "\(commands.count) read-only checks", result: healthReport?.state.rawValue ?? "unknown")
        activity = await activityStore.load()
    }

    func approveListener(for issue: HealthIssue) {
        guard issue.fix == "approve-listener", let listener = listeners.first(where: { issue.id == "unexpected-\($0.id)" }), ![53, 3000].contains(listener.port) else { return }
        approvedListenerIDs.insert(listener.id)
        UserDefaults.standard.set(Array(approvedListenerIDs), forKey: "approvedListeners-\(settings.host)")
        Task { await runFullHealthCheck() }
    }

    func ignorePeer(for issue: HealthIssue) {
        let prefix = "peer-never-"
        guard issue.fix == "ignore-peer", issue.id.hasPrefix(prefix) else { return }
        ignoredPeerIDs.insert(String(issue.id.dropFirst(prefix.count)))
        UserDefaults.standard.set(Array(ignoredPeerIDs), forKey: "ignoredPeers-\(settings.host)")
        Task { await runFullHealthCheck() }
    }

    func resetIgnoredPeers() {
        ignoredPeerIDs.removeAll()
        UserDefaults.standard.removeObject(forKey: "ignoredPeers-\(settings.host)")
        Task { await runFullHealthCheck() }
    }

    private func loadServerScopedState() {
        approvedListenerIDs = Set(UserDefaults.standard.stringArray(forKey: "approvedListeners-\(settings.host)") ?? [])
        ignoredPeerIDs = Set(UserDefaults.standard.stringArray(forKey: "ignoredPeers-\(settings.host)") ?? [])
    }

    func discoveredAdGuardBaseURL() -> String? {
        let serverIP = wireGuard.address.split(separator: "/").first.map(String.init) ?? ""
        guard !serverIP.isEmpty, serverIP != "—" else { return nil }

        let candidates = listeners.filter {
            $0.protocolName.lowercased().hasPrefix("tcp")
                && $0.port != 53
                && $0.process.localizedCaseInsensitiveContains("AdGuardHome")
        }
        guard let listener = candidates.first(where: { $0.address == serverIP })
            ?? candidates.first(where: { $0.isPublic || $0.address == settings.host })
            ?? candidates.first else { return nil }

        let scheme = listener.port == 443 ? "https" : "http"
        let isDefaultPort = (scheme == "http" && listener.port == 80) || (scheme == "https" && listener.port == 443)
        return "\(scheme)://\(serverIP)\(isDefaultPort ? "" : ":\(listener.port)")"
    }

    func saveAdGuardCredentials(baseURL: String, username: String, password: String) async -> Bool {
        let candidate = await adGuardAPI.load(baseURL: baseURL, username: username, password: password)
        guard candidate.available else {
            adGuard = candidate
            presentedError = AppError(
                title: "AdGuard login failed",
                message: candidate.error ?? "TunnelDeck could not authenticate to AdGuard Home.",
                technicalDetails: "Endpoint: \(baseURL)",
                recommendedAction: "Verify the discovered AdGuard URL and credentials. HTTP 401 means the credentials were rejected; connection errors mean the endpoint is not reachable."
            )
            return false
        }

        do {
            try KeychainService.save(baseURL, account: "adguard-url-\(settings.host)")
            try KeychainService.save(username, account: "adguard-user-\(settings.host)")
            try KeychainService.save(password, account: "adguard-password-\(settings.host)")
            adGuard = candidate
            return true
        } catch {
            presentedError = AppError(title: "AdGuard credentials could not be saved", message: "Keychain rejected the credentials.", technicalDetails: error.localizedDescription, recommendedAction: "Check Keychain access and retry.")
            return false
        }
    }

    func refreshAdGuardAPI() async {
        let baseURL = KeychainService.load(account: "adguard-url-\(settings.host)") ?? discoveredAdGuardBaseURL() ?? ""
        let username = KeychainService.load(account: "adguard-user-\(settings.host)") ?? ""
        let password = KeychainService.load(account: "adguard-password-\(settings.host)") ?? ""
        guard !baseURL.isEmpty, !username.isEmpty, !password.isEmpty else {
            adGuard.error = "AdGuard API credentials are not configured"
            return
        }
        adGuard = await adGuardAPI.load(baseURL: baseURL, username: username, password: password)
    }

    func refreshSecurityAudit() async {
        guard !isRefreshingSecurity else { return }
        isRefreshingSecurity = true
        defer { isRefreshingSecurity = false }

        async let freshListeners = execute(.listeners, subsystem: "Security")
        async let allWireGuard = execute(.wireGuardAll, subsystem: "Security")
        async let openVPN = execute(.openVPNBinds, subsystem: "Security")
        async let sshConfig = execute(.sshEffectiveConfig, subsystem: "Security")
        async let authLog = execute(.sshAuthLog24h, subsystem: "Security")

        let values = await (freshListeners, allWireGuard, openVPN, sshConfig, authLog)
        let parsedListeners = SSParser.parse(values.0.stdout)
        let cleanPort = Int(wireGuard.listenPort)
        let classified = SecurityAuditParser.classifyListeners(
            parsedListeners,
            host: settings.host,
            cleanWireGuardPort: cleanPort,
            wireGuardAll: values.1.stdout,
            openVPNBinds: values.2.stdout
        )
        let ssh = SecurityAuditParser.parseSSHConfig(
            values.3.stdout,
            configuredPort: settings.port,
            authLog: values.4.stdout
        )

        let listenerState: HealthState
        if classified.public.contains(where: { $0.state == .critical }) {
            listenerState = .critical
        } else if classified.public.contains(where: { $0.state == .warning }) {
            listenerState = .warning
        } else {
            listenerState = .online
        }

        let state: HealthState
        if listenerState == .critical || ssh.state == .critical {
            state = .critical
        } else if listenerState == .warning || ssh.state == .warning {
            state = .warning
        } else if !parsedListeners.isEmpty || ssh.available {
            state = .online
        } else {
            state = .unknown
        }

        listeners = parsedListeners
        security = SecuritySnapshot(
            state: state,
            publicListeners: classified.public,
            privateListeners: classified.private,
            ssh: ssh,
            lastUpdated: Date()
        )
    }

    func runDNSPathTest() async {
        guard !isRunningDNSPathTest else { return }
        let adGuardIP = wireGuard.address.split(separator: "/").first.map(String.init) ?? ""
        guard !adGuardIP.isEmpty, adGuardIP != "—" else {
            dnsPath = DNSPathSnapshot(ran: true, state: .warning, summary: "WireGuard server address is unavailable.")
            return
        }

        isRunningDNSPathTest = true
        defer { isRunningDNSPathTest = false }
        let snapshot = await localDNS.test(adGuardIP: adGuardIP)
        dnsPath = snapshot

        let result = DiagnosticResult(
            id: UUID(),
            date: Date(),
            name: "DNS Path Test",
            success: snapshot.state == .online,
            summary: snapshot.summary,
            milliseconds: nil
        )
        await history.append(result)
        diagnostics = await history.load()
    }

    private func detectConfigurationDrift(_ output: String, storeBaseline: Bool) {
        let current = Dictionary(uniqueKeysWithValues: output.split(separator: "\n").compactMap { line -> (String, String)? in
            let fields = line.split(whereSeparator: \.isWhitespace); guard fields.count >= 2 else { return nil }; return (String(fields[1]), String(fields[0]))
        })
        let key = "configurationHashes-\(settings.host)"
        let previous = UserDefaults.standard.dictionary(forKey: key) as? [String: String] ?? [:]
        configurationDrift = current.compactMap { path, hash in previous[path].map { $0 == hash ? nil : "\(path): \($0.prefix(12)) → \(hash.prefix(12))" } ?? nil }
        if storeBaseline && configurationDrift.isEmpty { UserDefaults.standard.set(current, forKey: key) }
    }

    func createBackup(operation: String = "scheduled") async -> Bool {
        guard settings.writeModeEnabled, helperVersion == HelperService.localVersion else { return false }
        do {
            let path = try await helper.createBackup(operation: operation, configuration: configuration)
            UserDefaults.standard.set(Date(), forKey: "lastScheduledBackup-\(settings.host)")
            await activityStore.append(operation: "Configuration backup", server: settings.host, preview: operation, result: path)
            activity = await activityStore.load(); await refreshHelper(); return true
        } catch {
            presentedError = AppError(title: "Backup failed", message: "TunnelDeck could not create a verified server backup.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Verify helper version, disk space and Write Mode.")
            return false
        }
    }

    func createEmergencyKit(includeClientCredentials: Bool = false) {
        do {
            let server = servers.first { $0.id == activeServerID } ?? ServerProfile(name: "Current VPS", host: settings.host, port: settings.port, username: settings.username, keyPath: "", role: "Primary")
            let archive = try EmergencyKitService.create(health: healthReport, server: server, profiles: localProfiles, backups: backups, includeClientCredentials: includeClientCredentials)
            Task { await activityStore.append(operation: "Create Emergency Kit", server: settings.host, preview: "Sanitized recovery archive", result: archive.path); activity = await activityStore.load() }
            ProfileStore.revealURL(archive)
        } catch { presentedError = AppError(title: "Emergency Kit failed", message: "The local recovery archive could not be created.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Check Application Support permissions and available disk space.") }
    }

    func downloadBackup(_ backup: BackupRecord) async {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TunnelDeck/Backups", isDirectory: true)
        do {
            try await ssh.downloadBackup(remotePath: backup.path, destination: folder, configuration: configuration)
            await activityStore.append(operation: "Download Backup", server: settings.host, preview: backup.operation, result: folder.path)
            activity = await activityStore.load(); ProfileStore.revealURL(folder.appendingPathComponent((backup.path as NSString).lastPathComponent))
        } catch { presentedError = AppError(title: "Backup download failed", message: "The server backup could not be copied to this Mac.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Check SSH access and local Application Support permissions.") }
    }

    func previewRestore(_ backup: BackupRecord, type: String) async {
        do { restorePreview = try await helper.restorePreview(identifier: (backup.path as NSString).lastPathComponent, type: type, configuration: configuration) }
        catch { presentedError = AppError(title: "Restore preview failed", message: "The backup could not be safely verified for restore.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Do not restore this backup; inspect its manifest and hashes.") }
    }

    func applyRestore() async -> Bool {
        guard settings.writeModeEnabled, helperVersion == HelperService.localVersion, let preview = restorePreview else { return false }
        do {
            let result = try await helper.restoreApply(identifier: preview.backup, type: preview.type, configuration: configuration)
            await activityStore.append(operation: "Restore", server: settings.host, preview: "\(preview.type): \(preview.files.count) verified files", result: "success", rollback: "available: \(result.rollbackBackup)")
            activity = await activityStore.load(); restorePreview = nil; await refresh(); return true
        } catch let failure as RestoreOperationFailure {
            let payload = failure.payload
            await activityStore.append(operation: "Restore", server: settings.host, preview: preview.type, result: "failed: \(payload.originalError)", rollback: payload.rollbackStatus == "success" ? "success" : "failed: \(payload.rollbackError ?? "unknown")")
            activity = await activityStore.load()
            if payload.critical {
                presentedError = AppError(title: "CRITICAL: Restore failed — rollback failed", message: "The \(payload.restoreType) service may be unhealthy. Open the independent VPS console immediately.", technicalDetails: SecretRedactor.redact("Backup: \(payload.backup)\nRollback backup: \(payload.rollbackBackup)\nOriginal error: \(payload.originalError)\nRollback error: \(payload.rollbackError ?? "unknown")"), recommendedAction: "Open the VPS provider console. Do not retry restore until the affected service and rollback backup are inspected.")
            } else {
                presentedError = AppError(title: "Restore failed — rollback succeeded", message: "The previous \(payload.restoreType) configuration was restored and its health check passed.", technicalDetails: SecretRedactor.redact("Original error: \(payload.originalError)\nRollback backup: \(payload.rollbackBackup)"), recommendedAction: "Review the restore preview and service logs before retrying.")
            }
            return false
        } catch {
            await activityStore.append(operation: "Restore", server: settings.host, preview: preview.type, result: "failed", rollback: "status unavailable")
            activity = await activityStore.load(); presentedError = AppError(title: "Restore failed", message: "The helper returned an unstructured restore error.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Review helper health and use the independent VPS console if the service is unavailable."); return false
        }
    }

    private func performScheduledBackupIfNeeded() async {
        guard settings.writeModeEnabled, helperVersion == HelperService.localVersion else { return }
        let last = UserDefaults.standard.object(forKey: "lastScheduledBackup-\(settings.host)") as? Date ?? .distantPast
        if Date().timeIntervalSince(last) >= 86_400 { _ = await createBackup() }
    }

    private func evaluateMonitoringState() async {
        let current = ["vps": system.health.rawValue, "wg0": wireGuard.state.rawValue, "adguard": units.first { $0.name.contains("AdGuardHome") }?.activeState ?? "unknown", "antizapret": units.first { $0.name == "antizapret.service" }?.activeState ?? "unknown", "dnsPublic": String(listeners.contains { ($0.isPublic || $0.address == settings.host) && $0.port == 53 }), "diskCritical": String(system.diskPercent >= 90)]
        let stateKey = "monitoringState-\(settings.host)"
        let previous = UserDefaults.standard.dictionary(forKey: stateKey) as? [String: String] ?? [:]
        if settings.notificationsEnabled {
            for (key, value) in current where previous[key] != nil && previous[key] != value { NotificationService.send(title: "TunnelDeck state changed", body: "\(key): \(previous[key]!) → \(value)", id: "tunneldeck-\(key)-\(value)") }
        }
        UserDefaults.standard.set(current, forKey: stateKey)
    }

    func testSSH() async -> Bool {
        let result = await execute(.uname, subsystem: "SSH Test")
        statusMessage = result.succeeded ? "SSH connection successful" : "SSH failed: \(result.stderr)"
        return result.succeeded
    }

    func runDiagnostic(_ command: ReadCommand, name: String) async {
        let result = await execute(command, subsystem: "Diagnostics")
        let diagnostic = DiagnosticResult(id: UUID(), date: Date(), name: name, success: result.succeeded, summary: (result.stdout.nonEmpty ?? result.stderr).trimmingCharacters(in: .whitespacesAndNewlines), milliseconds: result.duration * 1000)
        diagnostics.append(diagnostic); await history.append(diagnostic)
    }

    func execute(_ command: ReadCommand, subsystem: String) async -> CommandResult {
        do {
            let result = try await ssh.execute(command, configuration: configuration)
            logs.insert(LogEntry(timestamp: Date(), subsystem: subsystem, command: command.rawValue, stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode), at: 0)
            return result
        } catch {
            let message = SecretRedactor.redact(error.localizedDescription)
            logs.insert(LogEntry(timestamp: Date(), subsystem: subsystem, command: command.rawValue, stdout: "", stderr: message, exitCode: -1), at: 0)
            return CommandResult(stdout: "", stderr: message, exitCode: -1, duration: 0)
        }
    }

    private func parseWireGuardAddress(_ value: String) -> String {
        let fields = value.split(whereSeparator: \.isWhitespace)
        guard fields.count >= 3 else { return "—" }
        return String(fields[2])
    }

    private func parseOS(_ value: String) -> String { value.split(separator: "\n").first(where: { $0.hasPrefix("PRETTY_NAME=") }).map { $0.replacingOccurrences(of: "PRETTY_NAME=", with: "").replacingOccurrences(of: "\"", with: "") } ?? "—" }
    private func parseLoad(_ value: String) -> String { value.components(separatedBy: "load average:").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "—" }
    private func parseMemory(_ value: String) -> Double { let line = value.split(separator: "\n").first { $0.hasPrefix("Mem:") }; let fields = line?.split(whereSeparator: \.isWhitespace) ?? []; guard fields.count > 2, let total = Double(fields[1]), let used = Double(fields[2]), total > 0 else { return 0 }; return used / total * 100 }
    private func parseDisk(_ value: String) -> Double { let fields = value.split(separator: "\n").last?.split(whereSeparator: \.isWhitespace) ?? []; return Double(fields.first { $0.hasSuffix("%") }?.dropLast() ?? "0") ?? 0 }
    private func parseCPU(_ value: String) -> Double {
        let values = value.split(whereSeparator: \.isWhitespace).dropFirst().compactMap { Double($0) }
        guard values.count >= 4 else { return system.cpuPercent }
        let idle = values[3] + (values.count > 4 ? values[4] : 0)
        let total = values.reduce(0, +)
        defer { previousCPUTicks = (idle, total) }
        guard let previousCPUTicks else { return 0 }
        let totalDelta = total - previousCPUTicks.total
        guard totalDelta > 0 else { return system.cpuPercent }
        return max(0, min(100, (1 - (idle - previousCPUTicks.idle) / totalDelta) * 100))
    }
}

enum SidebarSection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", doctor = "Doctor", monitoring = "Monitoring", wireGuard = "WireGuard", profiles = "Profiles", dns = "DNS & AdGuard", antiZapret = "AntiZapret", services = "Services", diagnostics = "Diagnostics", security = "Security", backups = "Backups", activity = "Activity", recovery = "Recovery", router = "Router", homeAccess = "Home Access", logs = "Logs", settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self { case .dashboard: "gauge"; case .doctor: "cross.case"; case .monitoring: "waveform.path.ecg"; case .wireGuard: "network"; case .profiles: "doc.text"; case .antiZapret: "shield.lefthalf.filled"; case .dns: "server.rack"; case .services: "gearshape.2"; case .diagnostics: "stethoscope"; case .security: "lock.shield"; case .backups: "externaldrive.badge.timemachine"; case .activity: "clock.arrow.circlepath"; case .recovery: "lifepreserver"; case .router: "wifi.router"; case .homeAccess: "house"; case .logs: "list.bullet.rectangle"; case .settings: "gear" }
    }
}

private extension String { var nonEmpty: String? { isEmpty ? nil : self } }