import Foundation
import AppKit
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
    @Published var selectedSection: SidebarSection = .fleet
    @Published var showOnboarding: Bool
    @Published var statusMessage = "Read-only mode"
    @Published var helperVersion: String?
    @Published var helperCapabilities: HelperCapabilities?
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
    @Published var monitoringSamples: [MonitoringSample] = []
    @Published var monitoringEvents: [MonitoringEvent] = []
    @Published var monitoringWindowHours = 6
    @Published var fleetSummaries: [FleetNodeSummary] = []
    @Published var incidents: [Incident] = []
    @Published var exposureEndpoints: [NetworkEndpoint] = []
    @Published var configurationBaseline: ConfigurationBaseline?
    @Published var baselineDrift: [ConfigurationDrift] = []
    @Published var alertRules: [AlertRule] = []
    @Published var alertStates: [UUID: AlertRuntimeState] = [:]
    @Published var alertEvents: [InfrastructureEvent] = []
    @Published var peerHistory: [PeerHistorySample] = []
    @Published var adGuardHistory: [AdGuardHistorySample] = []
    @Published var lastKnownSamples: [UUID: MonitoringSample] = [:]
    @Published private(set) var lastRefreshDuration: TimeInterval?
    @Published private(set) var lastAgentSyncAt: Date?
    @Published private(set) var persistenceErrorMessage: String?
    @Published private(set) var sqliteSchemaVersion: Int?
    @Published private(set) var agentCursors = AgentSyncCursors()

    let ssh = SSHService()
    let adGuardAPI = AdGuardAPIService()
    let localDNS = LocalDNSService()
    lazy var helper = HelperService(ssh: ssh)
    lazy var agent = AgentService(ssh: ssh)
    private let history = DiagnosticHistoryStore()
    private let activityStore = ActivityStore()
    private let monitoringStore = MonitoringHistoryStore()
    private let fleetController = FleetController()
    private let agentSyncController = AgentSyncController()
    private let pollingCoordinator = PollingCoordinator()
    private let refreshCadence = RefreshCadenceController()
    private let nodeOperations = NodeOperationGuard()
    private let persistenceStore = try? InfrastructureStore()
    private var currentConfigurationHashes: [String: String] = [:]
    private var lastPeerHistorySample: Date?
    private var lastAdGuardHistorySample: Date?
    private var lifecycleObservers: [NSObjectProtocol] = []
    private var wakeTask: Task<Void, Never>?
    private var nodeLoadTask: Task<Void, Never>?
    private var agentSyncTask: Task<AgentSyncResult?, Never>?
    private var agentSyncToken: UUID?
    private var refreshToken: UUID?
    private let securityOperation = InFlightOperationState()
    private var healthCheckTask: Task<Void,Never>?
    private var healthCheckToken: UUID?
    private var alertSaveTask: Task<Void, Never>?
    private var lastAgentSyncAttempt: Date?
    private var isMacSleeping = false
    private let cpuDeltaTracker = CPUDeltaTracker()

    init() {
        let decoded = UserDefaults.standard.data(forKey: "settings").flatMap { try? JSONDecoder().decode(AppSettings.self, from: $0) }
        var initialSettings = decoded ?? AppSettings()
        if let storedPath = KeychainService.load(account: "ssh-key-path"), !storedPath.isEmpty { initialSettings.keyPath = storedPath }
        settings = initialSettings
        showOnboarding = !initialSettings.completedOnboarding
        system.macLANIP = LocalNetworkService.lanIPv4()
        localProfiles = ProfileStore.list()
        if let data = UserDefaults.standard.data(forKey: "servers") { servers = ((try? JSONDecoder().decode([ServerProfile].self, from: data)) ?? []).map { var value=$0;value.keyPath=KeychainService.load(account:"ssh-key-path-\(value.id.uuidString)") ?? "";return value } }
        activeServerID = UserDefaults.standard.string(forKey: "activeServerID").flatMap(UUID.init)
        loadServerScopedState()
        updateFleet()
        configureDefaultAlerts()
        configureLifecycleObservers()
        Task { diagnostics = await history.load() }
        Task { activity = await activityStore.load() }
        nodeLoadTask=Task { [weak self] in guard let self else{return};await self.loadMonitoringHistory();guard !Task.isCancelled else{return};await self.syncAgentHistory();guard !Task.isCancelled else{return};await self.loadMonitoringHistory();await self.loadBaseline() }
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
        try? KeychainService.save(profile.keyPath,account:"ssh-key-path-\(profile.id.uuidString)");let safeServers=servers.map{var value=$0;value.keyPath="";return value};if let data = try? JSONEncoder().encode(safeServers) { UserDefaults.standard.set(data, forKey: "servers") }
        UserDefaults.standard.set(profile.id.uuidString, forKey: "activeServerID"); saveSettings()
        updateFleet()
    }

    func selectServer(_ id: UUID) {
        guard let server = servers.first(where: { $0.id == id }) else { return }
        nodeOperations.advance();refreshCadence.reset();cpuDeltaTracker.reset();securityOperation.cancel();nodeLoadTask?.cancel();wakeTask?.cancel();agentSyncTask?.cancel();alertSaveTask?.cancel();healthCheckTask?.cancel();agentSyncTask=nil;agentSyncToken=nil;refreshToken=nil;healthCheckToken=nil;isRefreshing=false;isRunningHealthCheck=false
        activeServerID = id; UserDefaults.standard.set(id.uuidString, forKey: "activeServerID"); settings.host = server.host; settings.port = server.port; settings.username = server.username; settings.keyPath = server.keyPath;isRefreshingSecurity=false
        system = SystemSnapshot(); wireGuard = WireGuardSnapshot(); units = []; listeners = []; healthReport = nil; security = SecuritySnapshot(); exposureEndpoints=[];monitoringSamples = []; monitoringEvents = []; peerHistory=[];adGuardHistory=[];incidents=[];alertRules=[];alertStates=[:];alertEvents=[];configurationBaseline=nil;baselineDrift=[];lastPeerHistorySample=nil;lastAdGuardHistorySample=nil;loadServerScopedState()
        saveSettings();nodeLoadTask=Task{[weak self] in guard let self else{return};await self.loadMonitoringHistory();guard !Task.isCancelled else{return};await self.syncAgentHistory();guard !Task.isCancelled else{return};await self.loadMonitoringHistory();await self.loadBaseline();guard !Task.isCancelled else{return};await self.refresh()}
        updateFleet()
    }

    func completeOnboarding() { settings.completedOnboarding = true; showOnboarding = false; saveSettings() }

    func configurePolling() {
        pollingCoordinator.stop()
        guard settings.pollingEnabled else { return }
        pollingCoordinator.start(interval: { [weak self] in self?.settings.pollingInterval ?? 5 }) { [weak self] in await self?.refresh() }
    }

    private func configureLifecycleObservers() {
        let center = NSWorkspace.shared.notificationCenter
        lifecycleObservers.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in Task { @MainActor in self?.prepareForSleep() } })
        lifecycleObservers.append(center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in Task { @MainActor in self?.resumeAfterWake() } })
    }

    private func prepareForSleep() { isMacSleeping=true;nodeOperations.advance();cpuDeltaTracker.reset();securityOperation.cancel();wakeTask?.cancel();nodeLoadTask?.cancel();agentSyncTask?.cancel();healthCheckTask?.cancel();agentSyncTask=nil;agentSyncToken=nil;refreshToken=nil;healthCheckToken=nil;isRefreshing=false;isRefreshingSecurity=false;isRunningHealthCheck=false;pollingCoordinator.stop(); statusMessage = "Monitoring paused while Mac sleeps" }

    func resumeAfterWake() {
        isMacSleeping=false
        cpuDeltaTracker.reset()
        wakeTask?.cancel()
        pollingCoordinator.stop()
        wakeTask = Task { [weak self] in
            guard let self else { return }
            await self.loadMonitoringHistory()
            await self.syncAgentHistory()
            await self.loadMonitoringHistory()
            await self.loadBaseline()
            guard !Task.isCancelled else { return }
            await self.refresh()
            self.configurePolling()
        }
    }

    var observationFreshness: ObservationFreshness { ObservationFreshness(lastObservedAt: monitoringSamples.last?.timestamp, now: Date(), staleAfter: max(settings.pollingInterval * 3, 120)) }
    var debugPollingGeneration:Int{pollingCoordinator.generation}
    var debugPollingRunning:Bool{pollingCoordinator.isRunning}

    func refresh() async {
        guard !isRefreshing else { return }
        let context=nodeOperations.capture(nodeID:activeServerID),token=UUID(),capturedConfiguration=configuration,start=Date()
        let discoveryDue=refreshCadence.shouldRun("discovery",every:60)
        refreshToken=token;isRefreshing = true; defer { if refreshToken==token{isRefreshing=false;refreshToken=nil} }
        system.macLANIP = LocalNetworkService.lanIPv4()
        async let hostname = execute(.hostname, subsystem: "System", configuration:capturedConfiguration)
        async let cpu = execute(.cpu, subsystem: "System", configuration:capturedConfiguration)
        let cachedMacPublicIP=system.macPublicIP
        async let macPublicIP = discoveryDue ? LocalNetworkService.publicIPv4() : cachedMacPublicIP
        async let os = executeIf(discoveryDue,.osRelease,subsystem:"System",configuration:capturedConfiguration)
        async let uname = executeIf(discoveryDue,.uname,subsystem:"System",configuration:capturedConfiguration)
        async let uptime = execute(.uptime, subsystem: "System", configuration:capturedConfiguration)
        async let memory = execute(.memory, subsystem: "System", configuration:capturedConfiguration)
        async let disk = execute(.disk, subsystem: "System", configuration:capturedConfiguration)
        async let ipv4 = executeIf(discoveryDue,.publicIPv4,subsystem:"Network",configuration:capturedConfiguration)
        async let ipv6 = executeIf(discoveryDue,.publicIPv6,subsystem:"Network",configuration:capturedConfiguration)
        async let wg = execute(.wireGuard, subsystem: "WireGuard", configuration:capturedConfiguration)
        async let wgAddress = executeIf(discoveryDue,.wireGuardAddress,subsystem:"WireGuard",configuration:capturedConfiguration)
        async let wgLink = executeIf(discoveryDue,.wireGuardLink,subsystem:"WireGuard",configuration:capturedConfiguration)
        async let serviceUnits = executeIf(discoveryDue,.units,subsystem:"systemd",configuration:capturedConfiguration)
        async let socketListeners = executeIf(discoveryDue,.listeners,subsystem:"DNS",configuration:capturedConfiguration)
        async let azSettings = executeIf(discoveryDue,.antiZapretSettings,subsystem:"AntiZapret",configuration:capturedConfiguration)
        async let profileList = executeIf(discoveryDue,.profiles,subsystem:"Profiles",configuration:capturedConfiguration)
        async let monitoringPing = execute(.monitoringPing, subsystem: "Monitoring", configuration:capturedConfiguration)
        let values = await (hostname, os, uname, uptime, memory, disk, ipv4, ipv6, wg, wgAddress, wgLink, serviceUnits, socketListeners, azSettings, profileList, cpu, macPublicIP, monitoringPing)
        guard !isMacSleeping,nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID),refreshToken==token else { return }
        system.hostname = values.0.stdout.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "—"
        if discoveryDue{system.osVersion=parseOS(values.1.stdout);system.kernel=values.2.stdout.split(separator:" ").dropFirst(2).first.map(String.init) ?? "—"}
        system.uptime = values.3.stdout.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "—"
        system.loadAverage = parseLoad(values.3.stdout)
        system.memoryPercent = parseMemory(values.4.stdout)
        system.diskPercent = parseDisk(values.5.stdout)
        if discoveryDue{system.publicIPv4=values.6.stdout.trimmingCharacters(in:.whitespacesAndNewlines).nonEmpty ?? "—";system.publicIPv6=values.7.stdout.trimmingCharacters(in:.whitespacesAndNewlines).nonEmpty ?? "—"}
        system.cpuPercent = parseCPU(values.15.stdout)
        system.macPublicIP = values.16
        system.pingMilliseconds = MonitoringMetricParser.pingMilliseconds(values.17.stdout)
        system.sshAvailable = values.0.succeeded
        system.health = values.0.succeeded ? .online : .offline
        let cachedWGAddress=wireGuard.address,cachedWGMTU=wireGuard.mtu
        wireGuard = WireGuardParser.parse(values.8.stdout, timeout: settings.handshakeTimeout)
        if !discoveryDue{wireGuard.address=cachedWGAddress;wireGuard.mtu=cachedWGMTU}
        if discoveryDue{wireGuard.address=parseWireGuardAddress(values.9.stdout);if let mtuRange=values.10.stdout.range(of:#"mtu\s+(\d+)"#,options:.regularExpression){wireGuard.mtu=values.10.stdout[mtuRange].split(separator:" ").last.map(String.init) ?? "—"};units=SystemctlParser.parse(values.11.stdout);listeners=SSParser.parse(values.12.stdout);antiZapretSettings=Dictionary(uniqueKeysWithValues:values.13.stdout.split(separator:"\n").compactMap{line in let pair=line.split(separator:"=",maxSplits:1).map(String.init);return pair.count==2 ? (pair[0],pair[1]):nil});profiles=ProfileParser.parseListing(values.14.stdout)}
        lastRefresh = Date();lastRefreshDuration=Date().timeIntervalSince(start);statusMessage = values.0.succeeded ? "Updated" : "SSH unavailable"; updateFleet()
        if values.0.succeeded,refreshCadence.shouldRun("helper-api",every:60) { await refreshHelper(); await sampleAdGuardHistoryIfNeeded() }
        await recordMonitoringState()
        await performScheduledBackupIfNeeded()
        scheduleRegularAgentSync()
    }

    func refreshHelper() async {
        let context=nodeOperations.capture(nodeID:activeServerID),capturedConfiguration=configuration
        if let capabilities = await helper.capabilities(configuration: capturedConfiguration) {
            let loadedBackups=(try? await helper.listBackups(configuration:capturedConfiguration)) ?? []
            let loadedPeers=(try? await helper.peers(configuration:capturedConfiguration)) ?? []
            guard nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID) else{return}
            helperCapabilities = capabilities; helperVersion = capabilities.version; helperError = nil
            backups=loadedBackups;managedPeers=loadedPeers
        } else {
            guard nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID) else{return}
            helperCapabilities = nil; helperVersion = nil; helperError = AppError(title: "Helper check failed", message: "TunnelDeck could not negotiate helper capabilities.", technicalDetails: "No compatible helper-info or legacy version response.", recommendedAction: "Verify SSH access and the installed helper.")
        }
    }

    var helperCanUseLegacyWrites: Bool { helperCapabilities?.supports("legacy-safe-writes") == true }

    func suggestedPeerIP() -> String {
        guard let address = wireGuard.address.split(separator: "/").first else { return "" }
        let octets = address.split(separator: ".")
        guard octets.count == 4 else { return "" }
        let prefix = octets.prefix(3).joined(separator: ".")
        let used = Set(managedPeers.map(\.ip) + wireGuard.peers.map { $0.vpnIP.replacingOccurrences(of: "/32", with: "") })
        return (2...254).map { "\(prefix).\($0)" }.first { !used.contains($0) } ?? ""
    }

    func addPeer(name: String, ip: String, dns: String, mtu: Int, allowedIPs: String, endpoint: String) async -> Bool {
        guard settings.writeModeEnabled, helperCanUseLegacyWrites else {
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
        guard settings.writeModeEnabled, helperCanUseLegacyWrites else { return false }
        do {
            _ = try await helper.removePeer(publicKey: publicKey, deleteClient: deleteClient, allowExisting: allowExisting, configuration: configuration)
            await refresh(); return true
        } catch {
            presentedError = AppError(title: "WireGuard peer removal failed", message: "The peer could not be removed safely.", technicalDetails: SecretRedactor.redact(error.localizedDescription), recommendedAction: "Do not edit wg0.conf manually; inspect the backup and helper health output.")
            return false
        }
    }

    func performServiceAction(_ action: String, unit: String) async -> Bool {
        guard settings.writeModeEnabled, helperCanUseLegacyWrites else { return false }
        do {
            let change = try await helper.service(action: action, unit: unit, configuration: configuration)
            appendLog(LogEntry(timestamp: Date(), subsystem: "System", command: "helper service \(action) \(unit)", stdout: "state=\(change.state) backup=\(change.backup)", stderr: "", exitCode: 0))
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
        if let healthCheckTask{await healthCheckTask.value;return}
        let context=nodeOperations.capture(nodeID:activeServerID),configuration=self.configuration,host=settings.host,handshakeTimeout=settings.handshakeTimeout,approved=approvedListenerIDs,ignored=ignoredPeerIDs,token=UUID()
        isRunningHealthCheck=true;healthCheckToken=token
        let task=Task{[weak self] in guard let self else{return};await self.performFullHealthCheck(context:context,configuration:configuration,host:host,handshakeTimeout:handshakeTimeout,approved:approved,ignored:ignored)}
        healthCheckTask=task;await task.value
        if healthCheckToken==token{healthCheckTask=nil;healthCheckToken=nil;isRunningHealthCheck=false}
    }

    private func performFullHealthCheck(context:(UUID?,Int),configuration:SSHConfiguration,host:String,handshakeTimeout:TimeInterval,approved:Set<String>,ignored:Set<String>) async {

        let commands: [ReadCommand] = [.hostname, .wireGuardService, .wireGuard, .wireGuardAll, .wireGuardAddress, .udpListeners, .ipForward, .natRules, .pingInternet, .dnsTest, .adGuardStatus, .adGuardBinds, .antiZapretStatus, .units, .disk, .memory, .uptime, .listeners, .firewallState, .configurationHashes]
        var results: [ReadCommand: CommandResult] = [:]
        for command in commands {
            guard !Task.isCancelled else{return}
            results[command] = await execute(command, subsystem: "Doctor",configuration:configuration)
        }

        guard !Task.isCancelled,nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID) else{return}

        var freshWireGuard = WireGuardParser.parse(results[.wireGuard]?.stdout ?? "", timeout: handshakeTimeout)
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
            host: host,
            approvedListenerIDs: approved,
            ignoredPeerIDs: ignored
        )
        detectConfigurationDrift(results[.configurationHashes]?.stdout ?? "", storeBaseline: healthReport?.state == .online)
        if healthReport?.state == .online { lastSuccessfulHealthCheck = Date() }
        let resultState=healthReport?.state.rawValue ?? "unknown"
        await activityStore.append(operation: "Full Health Check", server: host, preview: "\(commands.count) read-only checks", result: resultState)
        let loadedActivity=await activityStore.load()
        guard !Task.isCancelled,nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID) else{return};activity=loadedActivity
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
        let context=nodeOperations.capture(nodeID:activeServerID),host=settings.host
        let baseURL = KeychainService.load(account: "adguard-url-\(host)") ?? discoveredAdGuardBaseURL() ?? ""
        let username = KeychainService.load(account: "adguard-user-\(host)") ?? ""
        let password = KeychainService.load(account: "adguard-password-\(host)") ?? ""
        guard !baseURL.isEmpty, !username.isEmpty, !password.isEmpty else {
            if nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID){adGuard.error = "AdGuard API credentials are not configured"}
            return
        }
        let loaded=await adGuardAPI.load(baseURL:baseURL,username:username,password:password)
        guard nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID) else{return};adGuard=loaded
    }

    func refreshSecurityAudit() async {
        guard !isRefreshingSecurity else { return }
        let context=nodeOperations.capture(nodeID:activeServerID),capturedConfiguration=configuration,capturedHost=settings.host,capturedPort=settings.port,token=securityOperation.begin()
        isRefreshingSecurity = true
        defer { if securityOperation.finish(token){isRefreshingSecurity=false} }

        async let freshListeners = execute(.listeners, subsystem: "Security",configuration:capturedConfiguration)
        async let allWireGuard = execute(.wireGuardAll, subsystem: "Security",configuration:capturedConfiguration)
        async let openVPN = execute(.openVPNBinds, subsystem: "Security",configuration:capturedConfiguration)
        async let sshConfig = execute(.sshEffectiveConfig, subsystem: "Security",configuration:capturedConfiguration)
        async let authLog = execute(.sshAuthLog24h, subsystem: "Security",configuration:capturedConfiguration)
        async let firewall = execute(.firewallState, subsystem: "Security",configuration:capturedConfiguration)

        let values = await (freshListeners, allWireGuard, openVPN, sshConfig, authLog, firewall)
        guard nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID) else{return}
        let parsedListeners = SSParser.parse(values.0.stdout)
        let cleanPort = Int(wireGuard.listenPort)
        let classified = SecurityAuditParser.classifyListeners(
            parsedListeners,
            host: capturedHost,
            cleanWireGuardPort: cleanPort,
            wireGuardAll: values.1.stdout,
            openVPNBinds: values.2.stdout
        )
        let ssh = SecurityAuditParser.parseSSHConfig(
            values.3.stdout,
            configuredPort: capturedPort,
            authLog: values.4.stdout
        )

        let listenerState: HealthState
        if classified.publicItems.contains(where: { $0.state == .critical }) {
            listenerState = .critical
        } else if classified.publicItems.contains(where: { $0.state == .warning }) {
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
            publicListeners: classified.publicItems,
            privateListeners: classified.privateItems,
            ssh: ssh,
            lastUpdated: Date()
        )
        if let nodeID = activeServerID {
            var names = SecurityAuditParser.wireGuardPorts(values.1.stdout).mapValues { value in value == "wg0" ? "Clean WireGuard" : value.localizedCaseInsensitiveContains("antizapret") ? "AntiZapret WireGuard" : "Full VPN WireGuard" }
            for (port, profile) in SecurityAuditParser.openVPNPorts(values.2.stdout) { names[port] = profile.localizedCaseInsensitiveContains("antizapret") ? "AntiZapret OpenVPN" : "Full VPN OpenVPN" }
            exposureEndpoints = ExposureAnalyzer.analyze(listeners: parsedListeners, nodeID: nodeID, publicAddresses: Set([settings.host, system.publicIPv4, system.publicIPv6].filter { !$0.isEmpty && $0 != "—" }), vpnAddresses: Set([wireGuard.address.split(separator: "/").first.map(String.init) ?? ""].filter { !$0.isEmpty }), firewallEvidence: values.5.stdout, serviceNames: names)
        } else { exposureEndpoints = [] }
        if let configurationBaseline, let nodeID = activeServerID { baselineDrift = BaselineEngine.diff(baseline: configurationBaseline, current: currentBaseline(nodeID)) }
        evaluateAlerts()
        updateFleet()
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
        currentConfigurationHashes = current
        let key = "configurationHashes-\(settings.host)"
        let previous = UserDefaults.standard.dictionary(forKey: key) as? [String: String] ?? [:]
        configurationDrift = current.compactMap { path, hash in previous[path].map { $0 == hash ? nil : "\(path): \($0.prefix(12)) → \(hash.prefix(12))" } ?? nil }
        if storeBaseline && configurationDrift.isEmpty { UserDefaults.standard.set(current, forKey: key) }
    }

    func createBackup(operation: String = "scheduled") async -> Bool {
        guard settings.writeModeEnabled, helperCanUseLegacyWrites else { return false }
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

    func exportSupportBundle() { do { let profile=servers.first{$0.id == activeServerID}; let node=profile.map { LegacyModelAdapter.node(from:$0) }; let input=SupportBundleInput(applicationVersion:Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "2.0-dev",helperVersion:helperVersion,node:node,health:healthReport,security:security,exposure:exposureEndpoints,samples:monitoringSamples,incidents:incidents,events:monitoringEvents,drift:baselineDrift,logs:logs); let archive=try SupportBundleService.create(input); ProfileStore.revealURL(archive) } catch { presentedError=AppError(title:"Support Bundle failed",message:"The sanitized diagnostic archive could not be created.",technicalDetails:SecretRedactor.redact(error.localizedDescription),recommendedAction:"Review local Application Support permissions and retry.") } }

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
        guard settings.writeModeEnabled, helperCanUseLegacyWrites, let preview = restorePreview else { return false }
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
        guard settings.writeModeEnabled, helperCanUseLegacyWrites else { return }
        let last = UserDefaults.standard.object(forKey: "lastScheduledBackup-\(settings.host)") as? Date ?? .distantPast
        if Date().timeIntervalSince(last) >= 86_400 { _ = await createBackup() }
    }

    func loadMonitoringHistory() async {
        let context=nodeOperations.capture(nodeID:activeServerID),cutoff=Date().addingTimeInterval(-MonitoringHistory.retention)
        if let nodeID=context.0,let profile=servers.first(where:{$0.id==nodeID}),let persistenceStore {
            do {
                let node=LegacyModelAdapter.node(from:profile);try await persistenceStore.upsert(node:node);_=try await LegacyMonitoringImporter().importHistory(for:node,into:persistenceStore);try await LegacyTelemetryImporter().importHistory(for:node,into:persistenceStore)
                let samples=try await persistenceStore.samples(nodeID:nodeID,since:cutoff),stored=try await persistenceStore.events(nodeID:nodeID,since:cutoff),peers=try await persistenceStore.peerHistory(nodeID:nodeID,since:cutoff),dns=try await persistenceStore.adGuardHistory(nodeID:nodeID,since:cutoff),saved=try await persistenceStore.alertRules(nodeID:nodeID),states=try await persistenceStore.alertStates(nodeID:nodeID),cursors=try await persistenceStore.agentSyncCursors(nodeID:nodeID),schema=try await persistenceStore.schemaVersion(),latest=try await persistenceStore.latestSamples()
                let legacy=(try? await LegacyAlertImporter().rules(for:node)) ?? [],defaults=AlertEngine.defaultRules(nodeID:nodeID,peerTimeout:settings.handshakeTimeout),imported=saved.isEmpty ? legacy:saved,byKind=Dictionary(uniqueKeysWithValues:imported.map{($0.kind,$0)}),rules=defaults.map{byKind[$0.kind] ?? $0}
                guard nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID),!Task.isCancelled else{return}
                monitoringSamples=samples;monitoringEvents=stored.filter{$0.kind=="monitoring"}.map{MonitoringEvent(id:$0.id,timestamp:$0.timestamp,component:$0.componentID,title:$0.title,detail:$0.detail,state:$0.state,recovered:$0.isRecovery)};alertEvents=Array(stored.filter{$0.kind=="alert"}.suffix(500));peerHistory=peers;adGuardHistory=dns;alertRules=rules;alertStates=states;agentCursors=cursors;sqliteSchemaVersion=schema;lastKnownSamples=latest;persistenceErrorMessage=nil
                if let sample=samples.last{lastKnownSamples[nodeID]=sample};try await persistenceStore.save(alertRules:rules,nodeID:nodeID)
            }catch{guard nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return};persistenceErrorMessage=SecretRedactor.redact(error.localizedDescription)}
        } else { let samples=await monitoringStore.loadSamples(host:settings.host),events=await monitoringStore.loadEvents(host:settings.host);guard nodeOperations.accepts(nodeID:context.0,generation:context.1,activeNodeID:activeServerID)else{return};monitoringSamples=samples;monitoringEvents=events }
        rebuildIncidents(evaluateRules: false)
    }

    private func recordMonitoringState() async {
        guard !isMacSleeping else{return}
        let adGuardState = monitoredUnitState { $0.name.contains("AdGuardHome") }
        let antiZapretState = monitoredUnitState { $0.name == "antizapret.service" }
        let exposedDNS = listeners.contains { ($0.isPublic || $0.address == settings.host) && $0.port == 53 }
        let publicListeners = Array(Set(listeners
            .filter { $0.isPublic || (!settings.host.isEmpty && $0.address == settings.host) }
            .map { "\($0.protocolName.lowercased()):\($0.port)" })).sorted()

        let sample = MonitoringSample(
            nodeID: activeServerID ?? LegacyNodeIdentity.unassigned,
            id: UUID(),
            timestamp: Date(),
            cpuPercent: system.cpuPercent,
            memoryPercent: system.memoryPercent,
            diskPercent: system.diskPercent,
            pingMilliseconds: system.pingMilliseconds,
            vpsState: system.health,
            wireGuardState: wireGuard.state,
            adGuardState: adGuardState,
            antiZapretState: antiZapretState,
            publicDNSExposed: exposedDNS,
            publicListeners: publicListeners
        )

        if let nodeID=activeServerID,let persistenceStore {
            let newEvents=MonitoringEventBuilder.events(from:monitoringSamples.last,to:sample)
            do{try await persistenceStore.insert(sample:sample,nodeID:nodeID);for event in newEvents{try await persistenceStore.insert(event:LegacyModelAdapter.event(from:event,nodeID:nodeID))};let cutoff=sample.timestamp.addingTimeInterval(-MonitoringHistory.retention);monitoringSamples.append(sample);monitoringSamples.removeAll{$0.timestamp<cutoff};monitoringEvents.append(contentsOf:newEvents);monitoringEvents.removeAll{$0.timestamp<cutoff};persistenceErrorMessage=nil}catch{persistenceErrorMessage=SecretRedactor.redact(error.localizedDescription)}
        } else {
            let result=await monitoringStore.record(host:settings.host,sample:sample)
            monitoringSamples=result.samples;monitoringEvents=result.events
        }
        if let nodeID=activeServerID,let persistenceStore,lastPeerHistorySample.map({sample.timestamp.timeIntervalSince($0)>=30}) ?? true { var added:[PeerHistorySample]=[];for peer in wireGuard.peers{let value=PeerHistorySample(nodeID:nodeID,id:UUID(),timestamp:sample.timestamp,peerID:peer.id,name:peer.name,vpnIP:peer.vpnIP,status:peer.status,receivedBytes:peer.receivedBytes,sentBytes:peer.sentBytes,latestHandshake:peer.latestHandshake);if(try? await persistenceStore.insert(peer:value)) != nil{added.append(value)}};peerHistory.append(contentsOf:added);peerHistory.removeAll{$0.timestamp<sample.timestamp.addingTimeInterval(-MonitoringHistory.retention)};lastPeerHistorySample=sample.timestamp }
        rebuildIncidents()

    }

    private func monitoredUnitState(where predicate: (UnitStatus) -> Bool) -> HealthState {
        guard system.health == .online else { return .unknown }
        guard let unit = units.first(where: predicate) else { return .unknown }
        return unit.activeState == "active" ? .online : .offline
    }

    private func rebuildIncidents(evaluateRules:Bool=true) { guard let nodeID = activeServerID else { incidents = []; return }; incidents = IncidentEngine.incidents(events: monitoringEvents, nodeID: nodeID); if evaluateRules{evaluateAlerts()}; updateFleet() }

    private func scheduleRegularAgentSync(){guard agentSyncTask==nil,lastAgentSyncAttempt.map({Date().timeIntervalSince($0)>=60}) ?? true else{return};Task{await syncAgentHistory(force:false)}}

    private func syncAgentHistory(force:Bool=true) async {
        if let agentSyncTask{_ = await agentSyncTask.value;return}
        guard force || lastAgentSyncAttempt.map({Date().timeIntervalSince($0)>=60}) ?? true else{return}
        guard let nodeID=activeServerID,let persistenceStore else{return}
        let context=nodeOperations.capture(nodeID:nodeID)
        lastAgentSyncAttempt=Date()
        let configuration=self.configuration,service=agent,controller=agentSyncController
        let cursors=(try? await persistenceStore.agentSyncCursors(nodeID:nodeID)) ?? AgentSyncCursors()
        let token=UUID(),task=Task{try? await controller.synchronize(nodeID:nodeID,cursors:cursors,service:service,configuration:configuration,store:persistenceStore)}
        agentSyncToken=token;agentSyncTask=task;let result=await task.value;if agentSyncToken==token{agentSyncTask=nil;agentSyncToken=nil}
        guard !Task.isCancelled,nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return}
        lastAgentSyncAt=Date()
        if let result,result.imported>0{statusMessage="Imported \(result.imported) server observations";await loadMonitoringHistory()}
    }

    var activeNodeName: String { servers.first(where: { $0.id == activeServerID })?.name ?? (system.hostname == "—" ? "VPS" : system.hostname) }
    func updateFleet() { if let id=activeServerID,let sample=monitoringSamples.last{lastKnownSamples[id]=sample};fleetSummaries = fleetController.summaries(profiles: servers, activeID: activeServerID, system: system, wireGuard: wireGuard, units: units, security: security, incidents: incidents, lastKnownSamples:lastKnownSamples) }
    func exposureName(_ endpoint: NetworkEndpoint) -> String { ExposureAnalyzer.displayName(endpoint, listeners: listeners) }
    private func currentBaseline(_ nodeID: UUID) -> ConfigurationBaseline { BaselineEngine.capture(nodeID: nodeID, endpoints: exposureEndpoints, units: units, wireGuard: wireGuard, ssh: security.ssh, hashes: currentConfigurationHashes) }
    func setCurrentBaseline() async { guard let nodeID=activeServerID else{return};let context=nodeOperations.capture(nodeID:nodeID),baseline=currentBaseline(nodeID);do{if let profile=servers.first(where:{$0.id==nodeID}),let persistenceStore{try await persistenceStore.upsert(node:LegacyModelAdapter.node(from:profile));try await persistenceStore.save(baseline:baseline)};guard nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return};configurationBaseline=baseline;baselineDrift=[];persistenceErrorMessage=nil;evaluateAlerts()}catch{if nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID){persistenceErrorMessage=SecretRedactor.redact(error.localizedDescription)}} }
    func loadBaseline() async { guard let nodeID=activeServerID,let persistenceStore else{return};let context=nodeOperations.capture(nodeID:nodeID);do{let loaded=try await persistenceStore.latestBaseline(nodeID:nodeID);guard nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return};configurationBaseline=loaded;baselineDrift=loaded.map{BaselineEngine.diff(baseline:$0,current:currentBaseline(nodeID))} ?? [];persistenceErrorMessage=nil}catch{guard nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return};configurationBaseline=nil;baselineDrift=[];persistenceErrorMessage="Baseline data could not be decoded: \(SecretRedactor.redact(error.localizedDescription))"} }
    private func configureDefaultAlerts() { guard let nodeID = activeServerID, alertRules.isEmpty else { return }; alertRules=AlertEngine.defaultRules(nodeID:nodeID,peerTimeout:settings.handshakeTimeout) }
    private func evaluateAlerts() { let conditions:[AlertRuleKind:Bool]=[.nodeOffline:system.health == .offline,.wireGuardOffline:system.health == .online && wireGuard.state == .offline,.adGuardOffline:system.health == .online && monitoredUnitState{$0.name.localizedCaseInsensitiveContains("AdGuardHome")} == .offline,.antiZapretOffline:system.health == .online && monitoredUnitState{$0.name == "antizapret.service"} == .offline,.disk:system.diskPercent >= threshold(.disk,90),.memory:system.memoryPercent >= threshold(.memory,90),.ping:(system.pingMilliseconds ?? 0) >= threshold(.ping,250),.publicDNS:exposureEndpoints.contains{$0.port == 53 && $0.classification == .publicInternet},.newPublicListener:baselineDrift.contains{$0.category == "public-listener" && $0.kind == .added},.peerInactive:wireGuard.peers.contains{$0.status == .offline},.configurationDrift:!baselineDrift.isEmpty];let result=AlertEngine.evaluate(rules:alertRules,conditions:conditions,previous:alertStates);alertStates=result.states;alertEvents.append(contentsOf:result.events);if alertEvents.count>500{alertEvents.removeFirst(alertEvents.count-500)};if settings.notificationsEnabled{for event in result.events{NotificationService.send(title:event.title,body:event.detail,id:"tunneldeck-alert-\(event.id.uuidString)")}};if let nodeID=activeServerID,let persistenceStore{Task{try? await persistenceStore.save(alertStates:result.states,nodeID:nodeID);for event in result.events{try? await persistenceStore.insert(event:event)}}} }
    private func threshold(_ kind:AlertRuleKind,_ fallback:Double)->Double{alertRules.first{$0.kind==kind}?.threshold ?? fallback}
    func saveAlertRules(){guard let nodeID=activeServerID,let persistenceStore else{return};let generation=nodeOperations.capture(nodeID:nodeID).1,rules=alertRules;alertSaveTask?.cancel();alertSaveTask=Task{[weak self] in do{try await Task.sleep(for:.milliseconds(350));try Task.checkCancellation();try await persistenceStore.save(alertRules:rules,nodeID:nodeID);guard let self,self.nodeOperations.accepts(nodeID:nodeID,generation:generation,activeNodeID:self.activeServerID)else{return};self.persistenceErrorMessage=nil}catch is CancellationError{}catch{guard let self,self.nodeOperations.accepts(nodeID:nodeID,generation:generation,activeNodeID:self.activeServerID)else{return};self.persistenceErrorMessage=SecretRedactor.redact(error.localizedDescription)}}}
    func acknowledge(_ id: UUID) { guard var state=alertStates[id] else{return}; state.acknowledgedAt=Date(); alertStates[id]=state;if let nodeID=activeServerID,let persistenceStore{let states=alertStates;Task{try? await persistenceStore.save(alertStates:states,nodeID:nodeID)}} }
    private func sampleAdGuardHistoryIfNeeded()async{let now=Date();guard lastAdGuardHistorySample.map({now.timeIntervalSince($0)>=60}) ?? true else{return};let nodeID=activeServerID,context=nodeOperations.capture(nodeID:nodeID);await refreshAdGuardAPI();guard let nodeID,adGuard.available,let persistenceStore,nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return};let sample=AdGuardHistorySample(nodeID:nodeID,id:UUID(),timestamp:now,totalQueries:adGuard.totalQueries,blockedQueries:adGuard.blockedQueries,blockedPercentage:adGuard.blockedPercentage,averageProcessingTime:adGuard.averageProcessingTime);do{try await persistenceStore.insert(adGuard:sample);guard nodeOperations.accepts(nodeID:nodeID,generation:context.1,activeNodeID:activeServerID)else{return};adGuardHistory.append(sample);adGuardHistory.removeAll{$0.timestamp<now.addingTimeInterval(-MonitoringHistory.retention)};lastAdGuardHistorySample=now}catch{persistenceErrorMessage=SecretRedactor.redact(error.localizedDescription)}}

    func testSSH() async -> Bool {
        let result = await execute(.uname, subsystem: "SSH Test")
        statusMessage = result.succeeded ? "SSH connection successful" : "SSH failed: \(result.stderr)"
        return result.succeeded
    }

    func runDiagnostic(_ command: ReadCommand, name: String) async {
        let result = await execute(command, subsystem: "Diagnostics")
        let diagnostic = DiagnosticResult(id: UUID(), date: Date(), name: name, success: result.succeeded, summary: (result.stdout.nonEmpty ?? result.stderr).trimmingCharacters(in: .whitespacesAndNewlines), milliseconds: result.duration * 1000)
        diagnostics.append(diagnostic);if diagnostics.count>500{diagnostics.removeFirst(diagnostics.count-500)};await history.append(diagnostic)
    }

    func execute(_ command: ReadCommand, subsystem: String, configuration: SSHConfiguration? = nil) async -> CommandResult {
        do {
            let result = try await ssh.execute(command, configuration: configuration ?? self.configuration)
            appendLog(LogEntry(timestamp: Date(), subsystem: subsystem, command: command.rawValue, stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode))
            return result
        } catch {
            let message = SecretRedactor.redact(error.localizedDescription)
            appendLog(LogEntry(timestamp: Date(), subsystem: subsystem, command: command.rawValue, stdout: "", stderr: message, exitCode: -1))
            return CommandResult(stdout: "", stderr: message, exitCode: -1, duration: 0)
        }
    }

    private func executeIf(_ enabled:Bool,_ command:ReadCommand,subsystem:String,configuration:SSHConfiguration)async->CommandResult{guard enabled else{return CommandResult(stdout:"",stderr:"",exitCode:0,duration:0)};return await execute(command,subsystem:subsystem,configuration:configuration)}

    private func appendLog(_ entry: LogEntry) { logs.insert(entry,at:0);if logs.count>1_000{logs.removeLast(logs.count-1_000)} }

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
        return cpuDeltaTracker.percentage(idle:idle,total:total,fallback:system.cpuPercent)
    }
}

enum SidebarSection: String, CaseIterable, Identifiable {
    case fleet = "Fleet Overview", topology = "Topology", dashboard = "Node Dashboard", incidents = "Incidents", exposure = "Exposure", baseline = "Baseline & Drift", alerts = "Alert Rules", doctor = "Doctor", monitoring = "Monitoring", wireGuard = "WireGuard", profiles = "Profiles", dns = "DNS & AdGuard", antiZapret = "AntiZapret", services = "Services", diagnostics = "Diagnostics", security = "Security", backups = "Backups", activity = "Activity", recovery = "Recovery", router = "Router", homeAccess = "Home Access", logs = "Logs", settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self { case .fleet: "server.rack"; case .topology: "point.3.connected.trianglepath.dotted"; case .dashboard: "gauge"; case .incidents: "exclamationmark.triangle"; case .exposure: "network.badge.shield.half.filled"; case .baseline: "scope"; case .alerts: "bell.badge"; case .doctor: "cross.case"; case .monitoring: "waveform.path.ecg"; case .wireGuard: "network"; case .profiles: "doc.text"; case .antiZapret: "shield.lefthalf.filled"; case .dns: "server.rack"; case .services: "gearshape.2"; case .diagnostics: "stethoscope"; case .security: "lock.shield"; case .backups: "externaldrive.badge.timemachine"; case .activity: "clock.arrow.circlepath"; case .recovery: "lifepreserver"; case .router: "wifi.router"; case .homeAccess: "house"; case .logs: "list.bullet.rectangle"; case .settings: "gear" }
    }
}

private extension String { var nonEmpty: String? { isEmpty ? nil : self } }
