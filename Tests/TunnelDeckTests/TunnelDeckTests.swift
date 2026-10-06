import Foundation
import Testing
@testable import TunnelDeck
import CSQLite

@Test func sshOutputParsing() {
    let result = CommandResult(stdout: "one\r\ntwo\n", stderr: "", exitCode: 0, duration: 0.1)
    #expect(SSHOutputParser.lines(result) == ["one", "two"])
    #expect(result.succeeded)
}

@Test func wireGuardParsingAndOnlineThreshold() {
    let input = """
    interface: wg0
      public key: abcdefghijklmnopqrstuvwxyz
      private key: (hidden)
      listening port: 51820

    peer: peer-public-key-123456789
      endpoint: 198.51.100.2:51820
      allowed ips: 10.8.0.2/32
      latest handshake: 2 minutes, 10 seconds ago
      transfer: 1.50 MiB received, 2.00 MiB sent
    """
    let snapshot = WireGuardParser.parse(input, timeout: 180)
    #expect(snapshot.interface == "wg0")
    #expect(snapshot.listenPort == "51820")
    #expect(snapshot.peers.count == 1)
    #expect(snapshot.peers[0].vpnIP == "10.8.0.2/32")
    #expect(snapshot.peers[0].status == .online)
    #expect(snapshot.peers[0].receivedBytes == 1_572_864)
}

@Test func systemctlParsing() {
    let input = "Id=wg-quick@antizapret.service\nActiveState=active\nSubState=exited\n\nId=AdGuardHome.service\nActiveState=inactive\nSubState=dead\n"
    let units = SystemctlParser.parse(input)
    #expect(units.count == 2)
    #expect(units[0].health == .online)
    #expect(units[1].health == .warning)
}

@Test func ssParsingAndPublicWarning() {
    let input = "udp UNCONN 0 0 127.1.1.1:53 0.0.0.0:* users:((\"kresd\",pid=1,fd=2))\ntcp LISTEN 0 128 0.0.0.0:53 0.0.0.0:* users:((\"dns\",pid=2,fd=3))"
    let listeners = SSParser.parse(input)
    #expect(listeners.count == 2)
    #expect(!listeners[0].isPublic)
    #expect(listeners[1].isPublic)
}

@Test func secretRedactor() {
    let safe = SecretRedactor.redact("PrivateKey = secret\nPresharedKey = other\nAuthorization: Basic abc\npassword=hunter2")
    #expect(!safe.contains("secret"))
    #expect(!safe.contains("hunter2"))
    #expect(safe.contains("[REDACTED]"))
}

@Test func commandPolicy() throws {
    #expect(try CommandPolicy.authorize(rawCommand: "uname -a") == "uname -a")
    #expect(throws: CommandPolicyError.self) { try CommandPolicy.authorize(rawCommand: "systemctl restart wg-quick@wg0") }
    #expect(throws: CommandPolicyError.self) { try CommandPolicy.authorize(rawCommand: "rm -rf /") }
    #expect(CommandPolicy.readOnlyMode)
}

@Test func writeCommandValidation() throws {
    let valid = try WriteCommandPolicy.arguments(for: .addPeer(name: "MacBook_01", ip: "10.8.0.3", dns: "10.8.0.1", mtu: 1380, allowedIPs: "0.0.0.0/0", endpoint: "vpn.example.com:51820"))
    #expect(valid.first == WriteCommandPolicy.helperPath)
    #expect(throws: CommandPolicyError.self) { try WriteCommandPolicy.arguments(for: .addPeer(name: "../bad", ip: "10.8.0.3", dns: "1.1.1.1", mtu: 1380, allowedIPs: "0.0.0.0/0", endpoint: "vpn.example.com:51820")) }
    #expect(throws: CommandPolicyError.self) { try WriteCommandPolicy.arguments(for: .service(action: "restart", unit: "ssh")) }
}

@Test func inputValidators() {
    #expect(IPv4Validator.isValid("10.8.0.2"))
    #expect(!IPv4Validator.isValid("10.8.0.999"))
    #expect(EndpointValidator.isValid("vpn.example.com:51820"))
    #expect(!EndpointValidator.isValid("host;reboot:22"))
    #expect(AllowedIPsValidator.isValid("0.0.0.0/0, 10.0.0.0/8"))
}

@Test func profileListingParser() {
    let profiles = ProfileParser.parseListing("/root/wg0.conf|500|2026-01-01T12:00:00\n/root/antizapret/client/a.ovpn|1000|2026-01-02T12:00:00\n/root/unrelated.txt|20|2026-01-03T12:00:00")
    #expect(profiles.count == 2)
    #expect(profiles[0].type == "WireGuard")
    #expect(profiles[1].type == "OpenVPN")
    #expect(profiles[1].category == "AntiZapret")
    #expect(profiles[0].endpoint == "Not downloaded")
}

@Test func wildcardListenerAndHelperCompatibility() {
    let listeners = SSParser.parse("tcp LISTEN 0 4096 *:80 *:* users:((\"AdGuardHome\",pid=1,fd=10))")
    #expect(listeners.count == 1)
    #expect(listeners[0].address == "*")
    #expect(listeners[0].isPublic)
    #expect(HelperService.localVersion == "1.2.1")
}

@Test func doctorDistinguishesCriticalFromOffline() {
    func result(_ stdout: String = "", ok: Bool = true) -> CommandResult {
        CommandResult(stdout: stdout, stderr: ok ? "" : "failed", exitCode: ok ? 0 : 1, duration: 0)
    }
    let results: [ReadCommand: CommandResult] = [
        .hostname: result("vps"),
        .wireGuardService: result("active\n"),
        .udpListeners: result("udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*"),
        .ipForward: result("1\n"),
        .natRules: result("-A POSTROUTING -j MASQUERADE"),
        .pingInternet: result("ok"),
        .dnsTest: result("ok"),
        .adGuardStatus: result("active\n"),
        .antiZapretStatus: result("active\n")
    ]
    var system = SystemSnapshot()
    system.diskPercent = 10
    system.memoryPercent = 10
    var wg = WireGuardSnapshot()
    wg.address = "10.66.66.1/24"
    wg.listenPort = "51820"
    let listener = Listener(protocolName: "tcp", address: "203.0.113.10", port: 53, process: "AdGuardHome")
    let report = HealthEvaluator.report(results: results, listeners: [listener], system: system, wireGuard: wg, host: "203.0.113.10")
    #expect(report.state == .critical)
    #expect(report.state != .offline)
}

@Test func doctorRecognizesDiscoveredVPNListeners() {
    func result(_ stdout: String = "", ok: Bool = true) -> CommandResult {
        CommandResult(stdout: stdout, stderr: ok ? "" : "failed", exitCode: ok ? 0 : 1, duration: 0)
    }
    let results: [ReadCommand: CommandResult] = [
        .hostname: result("vps"),
        .wireGuardService: result("active\n"),
        .wireGuardAll: result("""
        interface: vpn
          listening port: 51080
        interface: antizapret
          listening port: 51443
        interface: wg0
          listening port: 51820
        """),
        .udpListeners: result("udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*"),
        .ipForward: result("1\n"),
        .natRules: result("-A POSTROUTING -j MASQUERADE"),
        .pingInternet: result("ok"),
        .dnsTest: result("ok"),
        .adGuardStatus: result("active\n"),
        .antiZapretStatus: result("active\n"),
        .units: result("""
        Id=openvpn-server@antizapret-udp.service
        ActiveState=active
        SubState=running

        Id=openvpn-server@vpn-udp.service
        ActiveState=active
        SubState=running
        """)
    ]
    var system = SystemSnapshot()
    system.diskPercent = 10
    system.memoryPercent = 10
    var wg = WireGuardSnapshot()
    wg.address = "10.66.66.1/24"
    wg.listenPort = "51820"
    let listeners = [
        Listener(protocolName: "udp", address: "0.0.0.0", port: 51080, process: ""),
        Listener(protocolName: "udp", address: "::", port: 51080, process: ""),
        Listener(protocolName: "udp", address: "0.0.0.0", port: 51443, process: ""),
        Listener(protocolName: "udp", address: "0.0.0.0", port: 50080, process: "openvpn"),
        Listener(protocolName: "udp", address: "0.0.0.0", port: 50443, process: "openvpn")
    ]
    let report = HealthEvaluator.report(results: results, listeners: listeners, system: system, wireGuard: wg, host: "203.0.113.10")
    #expect(!report.issues.contains { $0.id.hasPrefix("unexpected-") })
}

@Test func doctorNamesAndCanIgnoreNeverConnectedPeer() {
    func result(_ stdout: String = "") -> CommandResult {
        CommandResult(stdout: stdout, stderr: "", exitCode: 0, duration: 0)
    }
    let results: [ReadCommand: CommandResult] = [
        .hostname: result("vps"),
        .wireGuardService: result("active\n"),
        .udpListeners: result("udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*"),
        .ipForward: result("1\n"),
        .natRules: result("-A POSTROUTING -j MASQUERADE"),
        .pingInternet: result("ok"),
        .dnsTest: result("ok"),
        .adGuardStatus: result("active\n"),
        .antiZapretStatus: result("active\n")
    ]
    var system = SystemSnapshot()
    system.diskPercent = 10
    system.memoryPercent = 10
    var wg = WireGuardSnapshot()
    wg.address = "10.66.66.1/24"
    wg.listenPort = "51820"
    wg.peers = [
        WireGuardPeer(id: "peer-key", name: "Peer 4", vpnIP: "10.66.66.3/32", publicKey: "peer…key", endpoint: "—", latestHandshake: nil, receivedBytes: 0, sentBytes: 0, status: .offline)
    ]

    let report = HealthEvaluator.report(results: results, listeners: [], system: system, wireGuard: wg, host: "203.0.113.10")
    #expect(report.issues.contains { $0.id == "peer-never-peer-key" && $0.title.contains("10.66.66.3/32") })

    let ignored = HealthEvaluator.report(results: results, listeners: [], system: system, wireGuard: wg, host: "203.0.113.10", ignoredPeerIDs: ["peer-key"])
    #expect(!ignored.issues.contains { $0.id == "peer-never-peer-key" })
}

@Test func adGuardQueryLogParsingAndBlockedPercentage() {
    let payload: [String: Any] = [
        "data": [
            [
                "time": "2026-10-03T04:43:26Z",
                "client": "10.66.66.2",
                "question": ["name": "beacons.gvt2.com"],
                "reason": "FilteredBlackList",
                "rules": [["text": "||gvt2.com^"]]
            ],
            [
                "time": "2026-10-03T04:43:25Z",
                "client": "10.66.66.2",
                "question": ["name": "github.com"],
                "reason": "NotFilteredNotFound"
            ]
        ]
    ]
    let entries = AdGuardAPIService.parseQueryLog(payload)
    #expect(entries.count == 2)
    #expect(entries[0].domain == "beacons.gvt2.com")
    #expect(entries[0].blocked)
    #expect(entries[0].rule == "||gvt2.com^")
    #expect(!entries[1].blocked)

    var snapshot = AdGuardSnapshot()
    snapshot.totalQueries = 200
    snapshot.blockedQueries = 50
    #expect(snapshot.blockedPercentage == 25)
}

@Test func dnsPathEvaluationDetectsRouterBypass() {
    let snapshot = DNSPathEvaluator.evaluate(
        systemResolvers: ["10.66.66.1", "192.168.0.1"],
        router: "192.168.0.1",
        adGuard: "10.66.66.1",
        testDomain: "pagead2.googlesyndication.com",
        systemAnswers: ["0.0.0.0"],
        routerAnswers: ["142.251.14.155"],
        adGuardAnswers: ["0.0.0.0"],
        publicAnswers: ["142.251.14.155"]
    )
    #expect(snapshot.state == .online)
    #expect(snapshot.systemUsesAdGuard)
    #expect(snapshot.adGuardBlocks)
    #expect(snapshot.routerBypasses)
    #expect(snapshot.summary.contains("router DNS still bypasses"))
}

@Test func dnsPathBlockedAnswerRecognition() {
    #expect(DNSPathEvaluator.isBlocked(["0.0.0.0"]))
    #expect(!DNSPathEvaluator.isBlocked([]))
    #expect(!DNSPathEvaluator.isBlocked(["142.251.14.155"]))
}

@Test func sshSecurityAuditFlagsRootPasswordLogin() {
    let config = """
    port 22
    passwordauthentication yes
    kbdinteractiveauthentication no
    pubkeyauthentication yes
    permitrootlogin yes
    permitemptypasswords no
    maxauthtries 6
    maxsessions 10
    x11forwarding yes
    allowtcpforwarding yes
    """
    let log = """
    2026-10-03T01:00:00+00:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.2 port 1234 ssh2
    2026-10-03T02:00:00+00:00 host sshd[2]: Accepted publickey for root from 198.51.100.2 port 4321 ssh2
    """
    let snapshot = SecurityAuditParser.parseSSHConfig(config, configuredPort: 22, authLog: log)
    #expect(snapshot.state == .critical)
    #expect(snapshot.failedLogins24h == 1)
    #expect(snapshot.successfulLogins24h == 1)
    #expect(snapshot.findings.contains("Root password login is effectively allowed."))
}

@Test func securityListenerClassificationGroupsIPv4IPv6AndNamesVPNs() {
    let listeners = [
        Listener(protocolName: "udp", address: "0.0.0.0", port: 51820, process: ""),
        Listener(protocolName: "udp", address: "::", port: 51820, process: ""),
        Listener(protocolName: "udp", address: "0.0.0.0", port: 51443, process: ""),
        Listener(protocolName: "udp", address: "0.0.0.0", port: 50443, process: "users:((\"openvpn\",pid=1,fd=3))"),
        Listener(protocolName: "tcp", address: "0.0.0.0", port: 22, process: "users:((\"sshd\",pid=2,fd=3))"),
        Listener(protocolName: "tcp", address: "10.66.66.1", port: 80, process: "users:((\"AdGuardHome\",pid=3,fd=3))")
    ]
    let wgAll = """
    interface: antizapret
      listening port: 51443
    interface: wg0
      listening port: 51820
    """
    let ovpn = """
    [/etc/openvpn/server/antizapret-udp.conf]
    port 50443
    proto udp4
    """
    let result = SecurityAuditParser.classifyListeners(
        listeners,
        host: "203.0.113.10",
        cleanWireGuardPort: 51820,
        wireGuardAll: wgAll,
        openVPNBinds: ovpn
    )
    #expect(result.publicItems.count == 4)
    #expect(result.publicItems.contains { $0.service == "Clean WireGuard" && $0.addresses.count == 2 })
    #expect(result.publicItems.contains { $0.service == "AntiZapret WireGuard" })
    #expect(result.publicItems.contains { $0.service == "AntiZapret OpenVPN" })
    #expect(result.publicItems.contains { $0.service == "SSH" })
    #expect(result.privateItems.contains { $0.service == "AdGuard Web" && $0.state == .online })
}

@Test func monitoringPingParser() {
    let output = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=56 time=11.7 ms"
    #expect(MonitoringMetricParser.pingMilliseconds(output) == 11.7)
    #expect(MonitoringMetricParser.pingMilliseconds("request timeout") == nil)
}

@Test func monitoringEventsAreTransitionOnlyAndRecoverCleanly() {
    let now = Date()
    let baseline = MonitoringSample(
        id: UUID(), timestamp: now, cpuPercent: 5, memoryPercent: 10, diskPercent: 20, pingMilliseconds: 10,
        vpsState: .online, wireGuardState: .online, adGuardState: .online, antiZapretState: .online,
        publicDNSExposed: false, publicListeners: ["tcp:22", "udp:51820"]
    )
    #expect(MonitoringEventBuilder.events(from: nil, to: baseline).isEmpty)

    let down = MonitoringSample(
        id: UUID(), timestamp: now.addingTimeInterval(30), cpuPercent: 0, memoryPercent: 0, diskPercent: 20, pingMilliseconds: nil,
        vpsState: .offline, wireGuardState: .offline, adGuardState: .unknown, antiZapretState: .unknown,
        publicDNSExposed: false, publicListeners: []
    )
    let downEvents = MonitoringEventBuilder.events(from: baseline, to: down)
    #expect(downEvents.count == 1)
    #expect(downEvents[0].component == "vps")
    #expect(downEvents[0].state == .offline)

    let recovered = MonitoringSample(
        id: UUID(), timestamp: now.addingTimeInterval(60), cpuPercent: 6, memoryPercent: 11, diskPercent: 21, pingMilliseconds: 12,
        vpsState: .online, wireGuardState: .online, adGuardState: .online, antiZapretState: .online,
        publicDNSExposed: false, publicListeners: ["tcp:22", "udp:51820"]
    )
    let recoveryEvents = MonitoringEventBuilder.events(from: down, to: recovered)
    #expect(recoveryEvents.count == 1)
    #expect(recoveryEvents[0].component == "vps")
    #expect(recoveryEvents[0].recovered)
}

@Test func monitoringEventsDetectExposureDiskAndNewListener() {
    let now = Date()
    let before = MonitoringSample(
        id: UUID(), timestamp: now, cpuPercent: 5, memoryPercent: 10, diskPercent: 70, pingMilliseconds: 10,
        vpsState: .online, wireGuardState: .online, adGuardState: .online, antiZapretState: .online,
        publicDNSExposed: false, publicListeners: ["tcp:22"]
    )
    let after = MonitoringSample(
        id: UUID(), timestamp: now.addingTimeInterval(30), cpuPercent: 6, memoryPercent: 11, diskPercent: 85, pingMilliseconds: 12,
        vpsState: .online, wireGuardState: .online, adGuardState: .online, antiZapretState: .online,
        publicDNSExposed: true, publicListeners: ["tcp:22", "tcp:8080"]
    )
    let events = MonitoringEventBuilder.events(from: before, to: after)
    #expect(events.contains { $0.component == "dnsPublic" && $0.state == .critical })
    #expect(events.contains { $0.component == "disk" && $0.state == .warning })
    #expect(events.contains { $0.component == "listeners" && $0.detail.contains("tcp:8080") })
}

@Test func sqliteMigrationAndMultiNodeIsolation() async throws {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckTests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: folder) }
    let store = try InfrastructureStore(url: folder.appendingPathComponent("test.sqlite3"))
    #expect(try await store.schemaVersion() == InfrastructureStore.currentSchemaVersion)
    let first = InfrastructureNode(id: UUID(), name: "A", role: .gateway, customRole: nil, host: "node-a.invalid", sshPort: 22, createdAt: Date(), updatedAt: Date(), enabled: true)
    let second = InfrastructureNode(id: UUID(), name: "B", role: .dns, customRole: nil, host: "node-b.invalid", sshPort: 22, createdAt: Date(), updatedAt: Date(), enabled: true)
    try await store.upsert(node: first); try await store.upsert(node: second)
    let sample = MonitoringSample(id: UUID(), timestamp: Date(), cpuPercent: 1, memoryPercent: 2, diskPercent: 3, pingMilliseconds: 4, vpsState: .online, wireGuardState: .online, adGuardState: .online, antiZapretState: .online, publicDNSExposed: false, publicListeners: [])
    try await store.insert(sample: sample, nodeID: first.id)
    #expect(try await store.sampleCount(nodeID: first.id) == 1)
    #expect(try await store.sampleCount(nodeID: second.id) == 0)
}

@Test func legacyMonitoringImportIsIdempotent() async throws {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckImport-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: folder) }
    let dbFolder = FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckDB-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: dbFolder, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dbFolder) }
    let node = InfrastructureNode(id: UUID(), name: "Legacy", role: .primary, customRole: nil, host: "legacy.invalid", sshPort: 22, createdAt: Date(), updatedAt: Date(), enabled: true)
    let sample = MonitoringSample(id: UUID(), timestamp: Date(), cpuPercent: 1, memoryPercent: 2, diskPercent: 3, pingMilliseconds: nil, vpsState: .online, wireGuardState: .online, adGuardState: .unknown, antiZapretState: .unknown, publicDNSExposed: false, publicListeners: [])
    var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode([sample])) as! [[String:Any]]; object[0].removeValue(forKey: "nodeID"); try JSONSerialization.data(withJSONObject: object).write(to: folder.appendingPathComponent("samples-legacy.invalid.json"))
    let store = try InfrastructureStore(url: dbFolder.appendingPathComponent("test.sqlite3")); try await store.upsert(node: node); let importer = LegacyMonitoringImporter(folder: folder)
    _ = try await importer.importHistory(for: node, into: store); _ = try await importer.importHistory(for: node, into: store)
    #expect(try await store.sampleCount(nodeID: node.id) == 1)
}

@Test func incidentGroupingSuppressesDependentServices() {
    let node=UUID(), start=Date(); let events=[MonitoringEvent(id:UUID(),timestamp:start,component:"vps",title:"VPS offline",detail:"",state:.offline,recovered:false),MonitoringEvent(id:UUID(),timestamp:start,component:"wg0",title:"wg0 unknown",detail:"",state:.unknown,recovered:false),MonitoringEvent(id:UUID(),timestamp:start.addingTimeInterval(60),component:"vps",title:"VPS recovered",detail:"",state:.online,recovered:true)]
    let incidents=IncidentEngine.incidents(events:events,nodeID:node); #expect(incidents.count == 1); #expect(incidents[0].observableCondition == "VPS connectivity outage"); #expect(incidents[0].recoveryState == .recovered); #expect(incidents[0].duration == 60)
}

@Test func exposureRequiresFirewallEvidenceAndMergesIPFamilies() {
    let listeners=[Listener(protocolName:"tcp",address:"0.0.0.0",port:53,process:"AdGuardHome"),Listener(protocolName:"tcp6",address:"::",port:53,process:"AdGuardHome")]
    let unknown=ExposureAnalyzer.analyze(listeners:listeners,nodeID:UUID(),publicAddresses:[],vpnAddresses:[],firewallEvidence:""); #expect(unknown.count == 1); #expect(unknown[0].classification == .unknown); #expect(unknown[0].addressFamily == .dualStack)
    let blocked=ExposureAnalyzer.analyze(listeners:listeners,nodeID:UUID(),publicAddresses:[],vpnAddresses:[],firewallEvidence:"53/tcp DENY Anywhere"); #expect(blocked[0].classification == .firewallBlocked)
}

@Test func baselineDiffFindsListenersPeersAndPolicy() {
    let node=UUID(); let old=ConfigurationBaseline(id:UUID(),nodeID:node,createdAt:Date(),publicListeners:["tcp:22"],services:["sshd"],ports:[22],wireGuardInterfaces:["wg0"],peerPublicIdentifiers:["peer-a"],dnsBinds:[],sshPolicy:["port":"22"],configurationHashes:["wg0":"a"]); var new=old; new.publicListeners.append("tcp:8080"); new.peerPublicIdentifiers=[]; new.sshPolicy["port"]="2222"; new.configurationHashes["wg0"]="b"; let drift=BaselineEngine.diff(baseline:old,current:new); #expect(drift.contains{$0.category == "public-listener" && $0.kind == .added}); #expect(drift.contains{$0.category == "wireguard-peer" && $0.kind == .removed}); #expect(drift.contains{$0.category == "ssh-policy"}); #expect(drift.contains{$0.category == "config-hash"})
}

@Test func alertsDeduplicateAndEmitRecovery() {
    let rule=AlertRule(id:UUID(),nodeID:UUID(),kind:.nodeOffline,enabled:true,threshold:nil,severity:.critical,cooldown:60,muteUntil:nil,acknowledgedAt:nil); let first=AlertEngine.evaluate(rules:[rule],conditions:[.nodeOffline:true],previous:[:]); #expect(first.events.count == 1); let duplicate=AlertEngine.evaluate(rules:[rule],conditions:[.nodeOffline:true],previous:first.states); #expect(duplicate.events.isEmpty); let recovery=AlertEngine.evaluate(rules:[rule],conditions:[.nodeOffline:false],previous:duplicate.states); #expect(recovery.events.count == 1); #expect(recovery.events[0].isRecovery)
}

@Test func everyAlertKindEmitsOneAlertAndOneRecovery() {
    let node=UUID(),rules=AlertEngine.defaultRules(nodeID:node,peerTimeout:300),active=Dictionary(uniqueKeysWithValues:AlertRuleKind.allCases.map{($0,true)})
    let fired=AlertEngine.evaluate(rules:rules,conditions:active,previous:[:]);#expect(fired.events.count == AlertRuleKind.allCases.count);#expect(Set(fired.events.map{$0.componentID}) == Set(AlertRuleKind.allCases.map{"alert:\($0.rawValue)"}))
    let recovered=AlertEngine.evaluate(rules:rules,conditions:Dictionary(uniqueKeysWithValues:AlertRuleKind.allCases.map{($0,false)}),previous:fired.states);#expect(recovered.events.count == AlertRuleKind.allCases.count);#expect(recovered.events.allSatisfy{$0.isRecovery})
}

@Test func supportBundleRedactsEveryForbiddenSecret() throws {
    let log=LogEntry(timestamp:Date(),subsystem:"test",command:"fixture",stdout:"PrivateKey = supersecret\nPresharedKey = psk\nAuthorization: Bearer abc\nCookie: sid=123\npassword=hunter2\ntoken=xyz",stderr:"",exitCode:0)
    let input=SupportBundleInput(applicationVersion:"test",helperVersion:"1.2.1",node:nil,health:nil,security:SecuritySnapshot(),exposure:[],samples:[],incidents:[],events:[],drift:[],logs:[log]); let files=try SupportBundleService.sanitizedFiles(input); let combined=files.values.joined(separator:"\n"); #expect(!combined.contains("supersecret")); #expect(!combined.contains("hunter2")); #expect(!combined.contains("Bearer abc")); #expect(!SupportBundleService.containsForbiddenSecret(combined))
}

@Test func alertThresholdCooldownAndRecovery() {
    let node=UUID(),now=Date();let rule=AlertRule(id:UUID(),nodeID:node,kind:.disk,enabled:true,threshold:80,severity:.warning,cooldown:300,muteUntil:nil,acknowledgedAt:nil)
    let below=70.0 >= (rule.threshold ?? 80),above=85.0 >= (rule.threshold ?? 80)
    #expect(!below);#expect(above)
    let fired=AlertEngine.evaluate(rules:[rule],conditions:[.disk:above],previous:[:],now:now);#expect(fired.events.count==1)
    let duplicate=AlertEngine.evaluate(rules:[rule],conditions:[.disk:true],previous:fired.states,now:now.addingTimeInterval(60));#expect(duplicate.events.isEmpty)
    let recovery=AlertEngine.evaluate(rules:[rule],conditions:[.disk:false],previous:duplicate.states,now:now.addingTimeInterval(90));#expect(recovery.events.count==1);#expect(recovery.events[0].isRecovery)
    let cooled=AlertEngine.evaluate(rules:[rule],conditions:[.disk:true],previous:recovery.states,now:now.addingTimeInterval(120));#expect(cooled.events.isEmpty)
    let silentRecovery=AlertEngine.evaluate(rules:[rule],conditions:[.disk:false],previous:cooled.states,now:now.addingTimeInterval(150));#expect(silentRecovery.events.isEmpty)
}

@Test func peerAndAdGuardDeltasHandleCounterReset() {
    let node=UUID(),now=Date();let growth=[PeerHistorySample(nodeID:node,id:UUID(),timestamp:now,peerID:"p",name:"P",vpnIP:"10.0.0.2/32",status:.online,receivedBytes:100,sentBytes:200,latestHandshake:now),PeerHistorySample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(30),peerID:"p",name:"P",vpnIP:"10.0.0.2/32",status:.online,receivedBytes:400,sentBytes:800,latestHandshake:now)];#expect(PeerHistoryAnalytics.trafficDelta(points:growth)==900);let peers=[growth[1],PeerHistorySample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(60),peerID:"p",name:"P",vpnIP:"10.0.0.2/32",status:.online,receivedBytes:100,sentBytes:200,latestHandshake:now)];#expect(PeerHistoryAnalytics.trafficDelta(points:peers)==300)
    let normal=[AdGuardHistorySample(nodeID:node,id:UUID(),timestamp:now,totalQueries:1000,blockedQueries:200,blockedPercentage:20,averageProcessingTime:0.001),AdGuardHistorySample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(60),totalQueries:1200,blockedQueries:260,blockedPercentage:21,averageProcessingTime:0.001)];#expect(AdGuardHistoryAnalytics.queryDelta(normal)==200);#expect(AdGuardHistoryAnalytics.blockedDelta(normal)==60);let dns=[normal[1],AdGuardHistorySample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(120),totalQueries:50,blockedQueries:10,blockedPercentage:20,averageProcessingTime:0.001)];#expect(AdGuardHistoryAnalytics.queryDelta(dns)==50);#expect(AdGuardHistoryAnalytics.blockedDelta(dns)==10)
}

@Test func telemetryPersistenceMigrationAndIsolation() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckTelemetry-\(UUID().uuidString)");let legacy=root.appendingPathComponent("legacy");try FileManager.default.createDirectory(at:legacy,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
    let store=try InfrastructureStore(url:root.appendingPathComponent("db.sqlite3"));let a=InfrastructureNode(id:UUID(),name:"A",role:.primary,customRole:nil,host:"a.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true);let b=InfrastructureNode(id:UUID(),name:"B",role:.relay,customRole:nil,host:"b.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true);try await store.upsert(node:a);try await store.upsert(node:b)
    let peer=PeerHistorySample(nodeID:a.id,id:UUID(),timestamp:Date(),peerID:"public-id",name:"PrivateKey = fixture-secret",vpnIP:"10.0.0.2/32",status:.online,receivedBytes:10,sentBytes:20,latestHandshake:Date());try await store.insert(peer:peer);try await store.insert(adGuard:AdGuardHistorySample(nodeID:a.id,id:UUID(),timestamp:Date(),totalQueries:10,blockedQueries:2,blockedPercentage:20,averageProcessingTime:0.001));#expect(try await store.peerHistory(nodeID:a.id).count==1);#expect(try await store.peerHistory(nodeID:b.id).isEmpty);#expect(try await store.adGuardHistory(nodeID:a.id).count==1)
    let bytes=try Data(contentsOf:root.appendingPathComponent("db.sqlite3"));#expect(!String(decoding:bytes,as:UTF8.self).contains("fixture-secret"))
}

@Test func legacyTelemetryAndAlertMigrationIsIdempotent() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckLegacyTelemetry-\(UUID().uuidString)"),telemetry=root.appendingPathComponent("Telemetry"),alerts=root.appendingPathComponent("Alerts");try FileManager.default.createDirectory(at:telemetry,withIntermediateDirectories:true);try FileManager.default.createDirectory(at:alerts,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
    let node=InfrastructureNode(id:UUID(),name:"Legacy",role:.primary,customRole:nil,host:"legacy.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true),now=Date();let peer=PeerHistorySample(nodeID:node.id,id:UUID(),timestamp:now,peerID:"public",name:"Peer",vpnIP:"10.0.0.2/32",status:.online,receivedBytes:1,sentBytes:2,latestHandshake:now),dns=AdGuardHistorySample(nodeID:node.id,id:UUID(),timestamp:now,totalQueries:10,blockedQueries:2,blockedPercentage:20,averageProcessingTime:0.001)
    var peerJSON=try JSONSerialization.jsonObject(with:JSONEncoder().encode([peer])) as! [[String:Any]];peerJSON[0].removeValue(forKey:"nodeID");try JSONSerialization.data(withJSONObject:peerJSON).write(to:telemetry.appendingPathComponent("peers-legacy.invalid.json"));var dnsJSON=try JSONSerialization.jsonObject(with:JSONEncoder().encode([dns])) as! [[String:Any]];dnsJSON[0].removeValue(forKey:"nodeID");try JSONSerialization.data(withJSONObject:dnsJSON).write(to:telemetry.appendingPathComponent("adguard-legacy.invalid.json"));let legacyRule:[[String:Any]]=[["kind":"diskPercent","enabled":true,"threshold":82.0,"cooldownMinutes":15],["kind":"serviceOffline","enabled":false,"threshold":0.0,"cooldownMinutes":22]];try JSONSerialization.data(withJSONObject:legacyRule).write(to:alerts.appendingPathComponent("rules-legacy.invalid.json"))
    let store=try InfrastructureStore(url:root.appendingPathComponent("db.sqlite3"));try await store.upsert(node:node);let importer=LegacyTelemetryImporter(folder:telemetry);try await importer.importHistory(for:node,into:store);try await importer.importHistory(for:node,into:store);#expect(try await store.peerHistory(nodeID:node.id).count==1);#expect(try await store.adGuardHistory(nodeID:node.id).count==1);let rules=try await LegacyAlertImporter(folder:alerts).rules(for:node);let byKind=Dictionary(uniqueKeysWithValues:rules.map{($0.kind,$0)});#expect(byKind[.disk]?.threshold == 82);#expect(byKind[.disk]?.nodeID == node.id);#expect(byKind[.adGuardOffline]?.enabled == false);#expect(byKind[.antiZapretOffline]?.enabled == false);#expect(abs((byKind[.adGuardOffline]?.cooldown ?? 0)-1320)<0.001);#expect(abs((byKind[.antiZapretOffline]?.cooldown ?? 0)-1320)<0.001)
}

@Test func historyWindowsDistinguishFilteredFromMissingAndIncludeSevenDays() {
    let now=Date(),old=MonitoringSample(nodeID:UUID(),id:UUID(),timestamp:now.addingTimeInterval(-7*3600),cpuPercent:1,memoryPercent:2,diskPercent:3,pingMilliseconds:nil,vpsState:.online,wireGuardState:.online,adGuardState:.online,antiZapretState:.online,publicDNSExposed:false,publicListeners:[])
    #expect(MonitoringHistory.filtered([old],hours:6,now:now,timestamp:\.timestamp).isEmpty)
    #expect(![old].isEmpty)
    #expect(MonitoringHistory.filtered([old],hours:168,now:now,timestamp:\.timestamp).count == 1)
}

@Test func observationFreshnessDoesNotConvertStaleToOffline() {
    let now=Date(),fresh=ObservationFreshness(lastObservedAt:now.addingTimeInterval(-30),now:now,staleAfter:120),stale=ObservationFreshness(lastObservedAt:now.addingTimeInterval(-3600),now:now,staleAfter:120),unknown=ObservationFreshness(lastObservedAt:nil,now:now,staleAfter:120)
    #expect(fresh.state == .live);#expect(stale.state == .stale);#expect(unknown.state == .unknown)
}

@Test func monitoringSeriesBreakAcrossSleepGap() {
    let now=Date(),node=UUID();func sample(_ offset:TimeInterval)->MonitoringSample{MonitoringSample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(offset),cpuPercent:1,memoryPercent:2,diskPercent:3,pingMilliseconds:nil,vpsState:.online,wireGuardState:.online,adGuardState:.online,antiZapretState:.online,publicDNSExposed:false,publicListeners:[])}
    #expect(MonitoringHistory.segments([sample(-3600),sample(-3570),sample(0)],expectedInterval:30,timestamp:\.timestamp).count == 2)
}

@MainActor @Test func pollingCoordinatorReplacesExistingLoop() async {
    let coordinator=PollingCoordinator();coordinator.start(interval:{3600},operation:{});let first=coordinator.generation;coordinator.start(interval:{3600},operation:{});#expect(coordinator.generation == first+1);coordinator.stop()
}

@MainActor @Test func nodeOperationGuardRejectsStaleNodeResponses() {
    let guardrail=NodeOperationGuard(),nodeA=UUID(),nodeB=UUID(),capture=guardrail.capture(nodeID:nodeA)
    #expect(guardrail.accepts(nodeID:nodeA,generation:capture.1,activeNodeID:nodeA))
    guardrail.advance()
    #expect(!guardrail.accepts(nodeID:nodeA,generation:capture.1,activeNodeID:nodeB))
}

@MainActor @Test func sleepCancelsSecurityActivityWithoutStuckFlag() {
    let generation=NodeOperationGuard(),activity=InFlightOperationState(),node=UUID(),capture=generation.capture(nodeID:node),token=activity.begin()
    #expect(activity.isActive)
    generation.advance();activity.cancel()
    #expect(!activity.isActive);#expect(!activity.finish(token));#expect(!generation.accepts(nodeID:node,generation:capture.1,activeNodeID:node))
    _=activity.begin();#expect(activity.isActive)
}

@MainActor @Test func doctorResultForPreviousNodeIsRejected() {
    let guardrail=NodeOperationGuard(),nodeA=UUID(),nodeB=UUID(),doctorA=guardrail.capture(nodeID:nodeA)
    guardrail.advance()
    #expect(!guardrail.accepts(nodeID:doctorA.0,generation:doctorA.1,activeNodeID:nodeB))
}

@MainActor @Test func cpuDeltaResetsAtObservationBoundary() {
    let tracker=CPUDeltaTracker()
    #expect(tracker.percentage(idle:80,total:100,fallback:42)==0)
    #expect(tracker.percentage(idle:85,total:120,fallback:42)==75)
    tracker.reset();#expect(tracker.percentage(idle:500,total:1_000,fallback:42)==0)
    #expect(tracker.percentage(idle:510,total:1_100,fallback:42)==90)
}

@Test func monitoringPresentationSegmentsPingAndAdGuardGaps() {
    let now=Date(),node=UUID();func sample(_ seconds:TimeInterval)->MonitoringSample{MonitoringSample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(seconds),cpuPercent:1,memoryPercent:2,diskPercent:3,pingMilliseconds:10,vpsState:.online,wireGuardState:.online,adGuardState:.online,antiZapretState:.online,publicDNSExposed:false,publicListeners:[])};func dns(_ seconds:TimeInterval)->AdGuardHistorySample{AdGuardHistorySample(nodeID:node,id:UUID(),timestamp:now.addingTimeInterval(seconds),totalQueries:1,blockedQueries:0,blockedPercentage:0,averageProcessingTime:0)}
    let presentation=MonitoringPresentation.build(samples:[sample(-3600),sample(-3570),sample(0)],peers:[],adGuard:[dns(-3600),dns(-3540),dns(0)],hours:2,expectedInterval:30,now:now)
    #expect(presentation.sampleSegments.count==2);#expect(presentation.pingSegments.count==2);#expect(presentation.adGuardSegments.count==2)
}

@MainActor @Test func refreshCadencePreventsDuplicateMediumWork() {
    let cadence=RefreshCadenceController(),start=Date()
    #expect(cadence.shouldRun("medium",every:60,now:start))
    #expect(!cadence.shouldRun("medium",every:60,now:start.addingTimeInterval(59)))
    #expect(cadence.shouldRun("medium",every:60,now:start.addingTimeInterval(60)))
    cadence.reset();#expect(cadence.shouldRun("medium",every:60,now:start))
}

@Test func chartDownsamplingPreservesEndpointsSpikesAndGaps() {
    let node=UUID(),start=Date()
    func value(_ index:Int)->MonitoringSample {
        let cpu:Double=index==5_000 ? 100:10,memory:Double=index==7_000 ? 99:20,ping:Double=index==8_000 ? 2_000:20
        return MonitoringSample(nodeID:node,id:UUID(),timestamp:start.addingTimeInterval(Double(index*60)),cpuPercent:cpu,memoryPercent:memory,diskPercent:30,pingMilliseconds:ping,vpsState:.online,wireGuardState:.online,adGuardState:.online,antiZapretState:.online,publicDNSExposed:false,publicListeners:[])
    }
    let values:[MonitoringSample]=(0..<10_080).map(value)
    let rendered=ChartDownsampler.monitoring(values,maxPoints:1_200)
    #expect(rendered.count<=1_200);#expect(rendered.first?.id==values.first?.id);#expect(rendered.last?.id==values.last?.id)
    #expect(rendered.contains{$0.cpuPercent==100});#expect(rendered.contains{$0.memoryPercent==99});#expect(rendered.contains{$0.pingMilliseconds==2_000})
    let gapValues=[values[0],values[1],values[100]]
    #expect(MonitoringHistory.segments(gapValues,expectedInterval:60,timestamp:{(sample:MonitoringSample) in sample.timestamp}).count==2)
}

@Test func sqliteSinceQueriesAndLatestSamplesAvoidFullHistoryLoads() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("SinceQueries-\(UUID())");try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
    let store=try InfrastructureStore(url:root.appendingPathComponent("db.sqlite3")),node=InfrastructureNode(id:UUID(),name:"Fixture",role:.primary,customRole:nil,host:"fixture.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true);try await store.upsert(node:node);let now=Date()
    for offset in [-8_000.0,-100.0]{try await store.insert(sample:MonitoringSample(nodeID:node.id,id:UUID(),timestamp:now.addingTimeInterval(offset),cpuPercent:1,memoryPercent:2,diskPercent:3,pingMilliseconds:nil,vpsState:.online,wireGuardState:.online,adGuardState:.online,antiZapretState:.online,publicDNSExposed:false,publicListeners:[]),nodeID:node.id)}
    #expect(try await store.samples(nodeID:node.id,since:now.addingTimeInterval(-3_600)).count==1)
    let latest=try await store.latestSamples()[node.id]?.timestamp
    #expect(latest.map{abs($0.timeIntervalSince(now.addingTimeInterval(-100)))<0.001} == true)
}

private func sqliteExec(_ path:String,_ sql:String)throws{
    var db:OpaquePointer?;guard sqlite3_open(path,&db)==SQLITE_OK else{throw NSError(domain:"SQLiteFixture",code:1)};defer{sqlite3_close(db)}
    var message:UnsafeMutablePointer<CChar>?;let status=sqlite3_exec(db,sql,nil,nil,&message);if status != SQLITE_OK{let detail=message.map{String(cString:$0)} ?? "SQLite error";sqlite3_free(message);throw NSError(domain:"SQLiteFixture",code:Int(status),userInfo:[NSLocalizedDescriptionKey:detail])}
}

private func makeV4TelemetryFixture(_ url:URL,malformed:Bool=false)throws{
    let sampleTail=malformed ? "" : ",public_listeners TEXT NOT NULL"
    try sqliteExec(url.path,"""
    PRAGMA foreign_keys=ON;
    CREATE TABLE nodes(id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL,custom_role TEXT,host TEXT NOT NULL,ssh_port INTEGER NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,enabled INTEGER NOT NULL);
    INSERT INTO nodes VALUES('00000000-0000-0000-0000-000000000001','A','primary',NULL,'a.invalid',22,0,0,1);
    INSERT INTO nodes VALUES('00000000-0000-0000-0000-000000000002','B','custom',NULL,'b.invalid',22,0,0,1);
    CREATE TABLE monitoring_samples(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),timestamp REAL NOT NULL,cpu REAL NOT NULL,memory REAL NOT NULL,disk REAL NOT NULL,ping REAL,vps_state TEXT NOT NULL,wg_state TEXT NOT NULL,adguard_state TEXT NOT NULL,antizapret_state TEXT NOT NULL,public_dns INTEGER NOT NULL\(sampleTail));
    INSERT INTO monitoring_samples VALUES('10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,1,2,3,NULL,'online','online','unknown','unknown',0\(malformed ? "" : ",'[]'"));
    CREATE TABLE infrastructure_events(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),timestamp REAL NOT NULL,component_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL,state TEXT NOT NULL,is_recovery INTEGER NOT NULL);
    CREATE TABLE peer_history(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),timestamp REAL NOT NULL,peer_id TEXT NOT NULL,name TEXT NOT NULL,vpn_ip TEXT NOT NULL,state TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,latest_handshake REAL);
    CREATE TABLE adguard_history(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),timestamp REAL NOT NULL,total_queries INTEGER NOT NULL,blocked_queries INTEGER NOT NULL,blocked_percentage REAL NOT NULL,average_processing_time REAL NOT NULL);
    PRAGMA user_version=4;
    """)
}

@Test func sqliteV4ToV5PreservesRowsAndScopesTelemetryIdentity() async throws{
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckV5-\(UUID())");try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
    let url=root.appendingPathComponent("db.sqlite3");try makeV4TelemetryFixture(url);let store=try InfrastructureStore(url:url)
    #expect(try await store.schemaVersion()==InfrastructureStore.currentSchemaVersion)
    let a=UUID(uuidString:"00000000-0000-0000-0000-000000000001")!,b=UUID(uuidString:"00000000-0000-0000-0000-000000000002")!,same=UUID(uuidString:"10000000-0000-0000-0000-000000000001")!
    #expect(try await store.sampleCount(nodeID:a)==1)
    let sample=MonitoringSample(nodeID:b,id:same,timestamp:Date(timeIntervalSince1970:2),cpuPercent:4,memoryPercent:5,diskPercent:6,pingMilliseconds:nil,vpsState:.online,wireGuardState:.unknown,adGuardState:.unknown,antiZapretState:.unknown,publicDNSExposed:false,publicListeners:[])
    try await store.insert(sample:sample,nodeID:b);try await store.insert(sample:sample,nodeID:b)
    #expect(try await store.sampleCount(nodeID:a)==1);#expect(try await store.sampleCount(nodeID:b)==1)
}

@Test func sqliteV5MigrationRollsBackOnCopyFailure()throws{
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("TunnelDeckV5Rollback-\(UUID())");try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
    let url=root.appendingPathComponent("db.sqlite3");try makeV4TelemetryFixture(url,malformed:true);#expect(throws:Error.self){_ = try InfrastructureStore(url:url)}
    var db:OpaquePointer?;#expect(sqlite3_open(url.path,&db)==SQLITE_OK);defer{sqlite3_close(db)};var version:Int32=0,rowCount:Int32=0
    var statement:OpaquePointer?;sqlite3_prepare_v2(db,"PRAGMA user_version",-1,&statement,nil);if sqlite3_step(statement)==SQLITE_ROW{version=sqlite3_column_int(statement,0)};sqlite3_finalize(statement)
    sqlite3_prepare_v2(db,"SELECT count(*) FROM monitoring_samples",-1,&statement,nil);if sqlite3_step(statement)==SQLITE_ROW{rowCount=sqlite3_column_int(statement,0)};sqlite3_finalize(statement)
    #expect(version==4);#expect(rowCount==1)
}

@MainActor @Test func rapidNodeSwitchGuardRejectsEveryStaleOperation(){
    let guardrail=NodeOperationGuard(),a=UUID(),b=UUID();var stale:[(UUID?,Int)]=[]
    for index in 0..<100{stale.append(guardrail.capture(nodeID:index.isMultiple(of:2) ? a:b));guardrail.advance()}
    for context in stale{#expect(!guardrail.accepts(nodeID:context.0,generation:context.1,activeNodeID:a));#expect(!guardrail.accepts(nodeID:context.0,generation:context.1,activeNodeID:b))}
}

@Test func malformedLookingProfileMetadataIsDisplayOnly()throws{
    let profile=ServerProfile(name:"22",host:"fixture.invalid",port:22,username:"fixture",keyPath:"",role:"/fake/path/to/key"),data=try JSONEncoder().encode(profile),decoded=try JSONDecoder().decode(ServerProfile.self,from:data)
    #expect(decoded.id==profile.id);#expect(decoded.host=="fixture.invalid");#expect(decoded.port==22);#expect(decoded.role=="/fake/path/to/key")
}

@Test func completedSSHProcessesAreReleased()async throws{
    let service=SSHService(),configuration=SSHConfiguration(host:"127.0.0.1",username:"fixture",keyPath:"",timeout:1,port:1)
    for _ in 0..<20{_ = try? await service.execute(.hostname,configuration:configuration)}
    try await Task.sleep(for:.milliseconds(50))
    #expect(await service.activeProcessCount()==0)
}

@Test func agentPaginationSynchronizesSevenDayBacklogWithoutDuplicates() async throws {
    let total=10_080,pageSize=2_000;var persisted=Set<Int>(),checkpoints:[Int64]=[]
    let result=try await AgentSyncController().paginate(initialCursor:0,safety:AgentPaginationSafety(pageSize:pageSize,maxPages:16,maxRecords:25_000),fetch:{cursor,limit in let start=Int(cursor),end=min(total,start+limit);return AgentPage(items:start<end ? Array((start+1)...end):[],nextCursor:Int64(end))},persist:{items in persisted.formUnion(items)},checkpoint:{checkpoints.append($0)})
    #expect(persisted.count == total);#expect(result.cursor == Int64(total));#expect(result.records == total);#expect(!result.reachedSafetyLimit);#expect(checkpoints.last == Int64(total))
}

@Test func agentPaginationHandlesBoundariesAndEmptyHistory() async throws {
    for total in [0,2_001,4_000] { var persisted:[Int]=[];let result=try await AgentSyncController().paginate(initialCursor:0,safety:AgentPaginationSafety(pageSize:2_000,maxPages:8,maxRecords:10_000),fetch:{cursor,limit in let start=Int(cursor),end=min(total,start+limit);return AgentPage(items:start<end ? Array((start+1)...end):[],nextCursor:Int64(end))},persist:{persisted += $0},checkpoint:{_ in});#expect(persisted.count == total);#expect(result.cursor == Int64(total));#expect(Set(persisted).count == total) }
}

@Test func agentPaginationRejectsStagnantCursor() async {
    await #expect(throws:AgentSyncError.nonAdvancingCursor(current:0,returned:0)){try await AgentSyncController().paginate(initialCursor:0,fetch:{_,_ in AgentPage(items:[1],nextCursor:0)},persist:{_ in},checkpoint:{_ in})}
}

@Test func agentPaginationCheckpointsOnlyCompletePagesAndResumes() async throws {
    var cursor:Int64=0,persisted=Set<Int>(),page=0
    await #expect(throws:PaginationFixtureError.self){try await AgentSyncController().paginate(initialCursor:cursor,safety:AgentPaginationSafety(pageSize:2_000,maxPages:8,maxRecords:10_000),fetch:{current,limit in let start=Int(current),end=min(2_001,start+limit);return AgentPage(items:start<end ? Array((start+1)...end):[],nextCursor:Int64(end))},persist:{items in page += 1;if page==2{throw PaginationFixtureError.failed};persisted.formUnion(items)},checkpoint:{cursor=$0})}
    #expect(cursor == 2_000);#expect(persisted.count == 2_000)
    let resumed=try await AgentSyncController().paginate(initialCursor:cursor,safety:AgentPaginationSafety(pageSize:2_000,maxPages:8,maxRecords:10_000),fetch:{current,limit in let start=Int(current),end=min(2_001,start+limit);return AgentPage(items:start<end ? Array((start+1)...end):[],nextCursor:Int64(end))},persist:{persisted.formUnion($0)},checkpoint:{cursor=$0})
    #expect(resumed.cursor == 2_001);#expect(persisted.count == 2_001)
}

@Test func agentPaginationSupportsCancellationAndSafetyContinuation() async throws {
    let task=Task{try await AgentSyncController().paginate(initialCursor:0,fetch:{cursor,_ in try await Task.sleep(for:.seconds(5));return AgentPage(items:[1],nextCursor:cursor+1)},persist:{_ in},checkpoint:{_ in})};task.cancel();await #expect(throws:CancellationError.self){try await task.value}
    var cursor:Int64=0,count=0
    for _ in 0..<3{let result=try await AgentSyncController().paginate(initialCursor:cursor,safety:AgentPaginationSafety(pageSize:2,maxPages:1,maxRecords:2),fetch:{current,limit in let start=Int(current),end=min(5,start+limit);return AgentPage(items:start<end ? Array((start+1)...end):[],nextCursor:Int64(end))},persist:{count += $0.count},checkpoint:{cursor=$0});if !result.reachedSafetyLimit{break}}
    #expect(cursor == 5);#expect(count == 5)
}

@Test func agentStreamsCheckpointIndependentCursors() async throws {
    let folder=FileManager.default.temporaryDirectory.appendingPathComponent("AgentStreams-\(UUID())");try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:folder)}
    let node=InfrastructureNode(id:UUID(),name:"Fixture",role:.primary,customRole:nil,host:"fixture.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true),store=try InfrastructureStore(url:folder.appendingPathComponent("db.sqlite3"));try await store.upsert(node:node)
    let result=try await AgentSyncController().synchronize(nodeID:node.id,cursors:AgentSyncCursors(),service:AgentFixtureSource(),configuration:SSHConfiguration(host:"fixture.invalid",username:"fixture",keyPath:"",timeout:1),store:store)
    #expect(result.cursors == AgentSyncCursors(samples:1,events:1,peers:1,adGuard:1));#expect(try await store.agentSyncCursors(nodeID:node.id)==result.cursors);#expect(try await store.sampleCount(nodeID:node.id)==1);#expect(try await store.eventCount(nodeID:node.id)==1);#expect(try await store.peerHistory(nodeID:node.id).count==1);#expect(try await store.adGuardHistory(nodeID:node.id).count==1)
}

@Test func sameAgentIdentityPersistsForTwoNodesAndReplayIsIdempotent()async throws{
    let folder=FileManager.default.temporaryDirectory.appendingPathComponent("AgentNodeScope-\(UUID())");try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:folder)}
    let store=try InfrastructureStore(url:folder.appendingPathComponent("db.sqlite3")),a=InfrastructureNode(id:UUID(),name:"A",role:.primary,customRole:nil,host:"a.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true),b=InfrastructureNode(id:UUID(),name:"B",role:.custom,customRole:"Test",host:"b.invalid",sshPort:22,createdAt:Date(),updatedAt:Date(),enabled:true)
    try await store.upsert(node:a);try await store.upsert(node:b);let controller=AgentSyncController(),source=AgentFixtureSource(),configuration=SSHConfiguration(host:"fixture.invalid",username:"fixture",keyPath:"",timeout:1)
    _=try await controller.synchronize(nodeID:a.id,cursors:AgentSyncCursors(),service:source,configuration:configuration,store:store)
    _=try await controller.synchronize(nodeID:b.id,cursors:AgentSyncCursors(),service:source,configuration:configuration,store:store)
    _=try await controller.synchronize(nodeID:a.id,cursors:AgentSyncCursors(),service:source,configuration:configuration,store:store)
    #expect(try await store.sampleCount(nodeID:a.id)==1);#expect(try await store.sampleCount(nodeID:b.id)==1);#expect(try await store.eventCount(nodeID:a.id)==1);#expect(try await store.eventCount(nodeID:b.id)==1)
    #expect(try await store.peerHistory(nodeID:a.id).count==1);#expect(try await store.peerHistory(nodeID:b.id).count==1);#expect(try await store.adGuardHistory(nodeID:a.id).count==1);#expect(try await store.adGuardHistory(nodeID:b.id).count==1)
}

@Test func atomicAgentPageDoesNotAdvanceAfterFailedCommit()async{
    var durableCursor:Int64=0,attempts=0
    await #expect(throws:PaginationFixtureError.self){try await AgentSyncController().paginateAtomic(initialCursor:durableCursor,fetch:{cursor,_ in AgentPage(items:[1,2],nextCursor:cursor+2)},commit:{_,cursor in attempts += 1;if attempts==1{throw PaginationFixtureError.failed};durableCursor=cursor})}
    #expect(durableCursor==0)
}

private enum PaginationFixtureError:Error{case failed}

private actor AgentFixtureSource:AgentHistorySource{
    private let timestamp=ISO8601DateFormatter().string(from:Date())
    private func envelope<T:Decodable & Sendable>(_ cursor:Int64,_ item:T)->AgentEnvelope<AgentTelemetryItem<T>>{cursor==0 ? AgentEnvelope(schemaVersion:1,agentVersion:"2.0.0",items:[AgentTelemetryItem(rowid:1,id:String(repeating:"a",count:64),timestamp:timestamp,payload:item)],nextCursor:1):AgentEnvelope(schemaVersion:1,agentVersion:"2.0.0",items:[],nextCursor:cursor)}
    func samples(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentMonitoringPayload>>{envelope(cursor,AgentMonitoringPayload(cpuPercent:1,memoryPercent:2,diskPercent:3,pingMilliseconds:nil,vpsState:.online,wireGuardState:.online,adGuardState:.online,antiZapretState:.online,publicDNSExposed:false,publicListeners:[]))}
    func events(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentEventPayload>>{envelope(cursor,AgentEventPayload(from:"inactive",to:"active",event:nil))}
    func peers(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentPeerPayload>>{envelope(cursor,AgentPeerPayload(publicIdentifier:"fixture-public",latestHandshake:0,rx:1,tx:2))}
    func adGuard(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentAdGuardPayload>>{envelope(cursor,AgentAdGuardPayload(totalQueries:10,blockedQueries:2,blockedPercentage:20,averageProcessingTime:0.001))}
}

@Test func agentCommandsUseExactUnprivilegedSudoBoundary() {
    #expect(AgentReadCommand.status.arguments == ["/usr/bin/sudo", "-n", "-u", "tunneldeck-agent", "/usr/local/libexec/tunneldeck-agent", "agent-status"])
    #expect(AgentReadCommand.history(kind:.samples,cursor:12,limit:2_000).arguments == ["/usr/bin/sudo", "-n", "-u", "tunneldeck-agent", "/usr/local/libexec/tunneldeck-agent", "telemetry-samples", "--cursor", "12", "--limit", "2000"])
    #expect(!AgentReadCommand.status.arguments.contains("collect"))
    #expect(!AgentReadCommand.status.arguments.contains("/tmp/tunneldeck-agent"))
    #expect(AgentHistoryKind.allCases.map(\.rawValue) == ["samples","events","peers","adguard"])
}

@Test func legacyAndHelper2CapabilitiesRemainSeparate() {
    let legacy=LegacyHelperCapabilities.legacy(version:"1.2.1"),modern=Helper2Capabilities(version:"2.0.0",protocolVersion:2,capabilities:["transaction-v2"])
    #expect(legacy.supports("legacy-safe-writes"));#expect(!modern.supports("legacy-safe-writes"));#expect(Helper2CommandPolicy.arguments(for:.info)==["/usr/local/libexec/tunneldeck-helper2","helper-info"])
    #expect(Helper2Service.decodeCapabilities(CommandResult(stdout:"{\"version\":\"2.0.0\",\"protocolVersion\":2,\"capabilities\":[\"transaction-v2\"]}",stderr:"",exitCode:0,duration:0))?.version=="2.0.0")
    #expect(Helper2Service.decodeCapabilities(CommandResult(stdout:"{\"result\":\"failed\"}",stderr:"failed",exitCode:3,duration:0))==nil)
}

@Test func homeDiscoveryParsesARPAndNDPWithoutMalformedRows(){
    let arp=HomeDiscoveryParser.arp("? (192.168.50.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n? (192.168.50.9) at (incomplete) on en0\nmalformed")
    #expect(arp.count==1);#expect(arp[0].ip=="192.168.50.1");#expect(arp[0].mac=="aa:bb:cc:dd:ee:ff")
    #expect(HomeDeviceIdentity.normalizedMAC("d6:eb:e0:6a:52:b")=="d6:eb:e0:6a:52:0b")
    #expect(HomeDeviceIdentity.normalizedMAC("02:00:00:00:00:00")==nil)
    let ndp=HomeDiscoveryParser.ndp("fe80::1%en0 11:22:33:44:55:66 en0 23h59m59s S R\nNeighbor Linklayer Address Netif Expire S Flags")
    #expect(ndp.count==1);#expect(ndp[0].ip=="fe80::1");#expect(ndp[0].mac=="11:22:33:44:55:66")
    #expect(HomeDiscoveryParser.arp("").isEmpty);#expect(HomeDiscoveryParser.ndp("garbage").isEmpty)
}

@Test func homeDeviceIdentityAndRediscoveryPreserveManualMetadata(){
    let mac="aa:bb:cc:dd:ee:ff",first=HomeDeviceIdentity.stableID(mac:mac,ip:"192.168.1.10",hostname:nil),moved=HomeDeviceIdentity.stableID(mac:mac,ip:"192.168.1.20",hostname:nil)
    #expect(first==moved)
    #expect(HomeDeviceIdentity.stableID(mac:"00:11:22:33:44:55",ip:"192.168.1.10",hostname:nil) != HomeDeviceIdentity.stableID(mac:"00:11:22:33:44:66",ip:"192.168.1.10",hostname:nil))
    let now=Date(),manual=HomeDevice(id:first,displayName:"Kitchen Vacuum",hostname:nil,ipv4:"192.168.1.10",ipv6:nil,macAddress:mac,vendor:nil,type:.vacuum,customType:nil,status:.unknown,lastSeen:nil,firstSeen:now.addingTimeInterval(-300),discoverySources:[.manual],notes:"Upstairs",nameIsManual:true,typeIsManual:true)
    let merged=HomeDeviceReconciler.merge(existing:manual,record:HomeDiscoveryRecord(ip:"192.168.1.20",mac:mac,hostname:"device.local",source:.arp,evidence:"Fresh ARP neighbour"),now:now)
    #expect(merged.id==first);#expect(merged.displayName=="Kitchen Vacuum");#expect(merged.type == .vacuum);#expect(merged.ipv4=="192.168.1.20");#expect(merged.lastSeen==now);#expect(merged.status == .online)
}

@Test func homePresenceUsesConservativeOfflineSemantics(){
    let now=Date();#expect(HomePresence.status(lastSeen:nil,now:now,homeMode:.homeLAN) == .unknown)
    #expect(HomePresence.status(lastSeen:now.addingTimeInterval(-60),now:now,homeMode:.other) == .online)
    #expect(HomePresence.status(lastSeen:now.addingTimeInterval(-3600),now:now,homeMode:.homeLAN) == .unknown)
    #expect(HomePresence.status(lastSeen:now.addingTimeInterval(-90_000),now:now,homeMode:.homeLAN) == .offline)
    #expect(HomePresence.status(lastSeen:now.addingTimeInterval(-90_000),now:now,homeMode:.remote) == .unknown)
}

@Test func homePersistenceMigrationMergeAndPruning()async throws{
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("HomeStore-\(UUID())");try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
    let store=try InfrastructureStore(url:root.appendingPathComponent("db.sqlite3"));#expect(try await store.schemaVersion()==7)
    let now=Date(),a=HomeDevice(displayName:"Manual Name",hostname:nil,ipv4:"192.168.1.10",ipv6:nil,macAddress:"aa:bb:cc:dd:ee:01",vendor:nil,type:.nas,customType:nil,status:.online,lastSeen:now,firstSeen:now,discoverySources:[.manual],nameIsManual:true,typeIsManual:true),b=HomeDevice(displayName:"Duplicate",hostname:nil,ipv4:"192.168.1.11",ipv6:nil,macAddress:"aa:bb:cc:dd:ee:02",vendor:nil,type:.unknown,customType:nil,status:.online,lastSeen:now,firstSeen:now,discoverySources:[.arp])
    try await store.save(homeDevice:a,observation:HomeDeviceObservation(deviceID:a.id,timestamp:now.addingTimeInterval(-2_700_000),status:.online,evidence:"old",ip:a.ipv4,source:.manual));try await store.save(homeDevice:b,observation:HomeDeviceObservation(deviceID:b.id,timestamp:now,status:.online,evidence:"fresh",ip:b.ipv4,source:.arp))
    #expect(try await store.homeObservations(deviceID:a.id,since:.distantPast).isEmpty)
    try await store.mergeHomeDevices(source:b.id,destination:a.id)
    let devices=try await store.homeDevices(),history=try await store.homeObservations(deviceID:a.id,since:.distantPast)
    #expect(devices.count==1);#expect(devices[0].displayName=="Manual Name");#expect(history.count==1);#expect(history[0].deviceID==a.id)
}

@Test func sqliteV5ToV7CreatesHomeInventoryAndSurvivesReopen()async throws{
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("HomeV6-\(UUID())");try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)};let url=root.appendingPathComponent("db.sqlite3")
    var db:OpaquePointer?;#expect(sqlite3_open(url.path,&db)==SQLITE_OK);#expect(sqlite3_exec(db,"PRAGMA user_version=5",nil,nil,nil)==SQLITE_OK);sqlite3_close(db)
    let deviceID:UUID
    do{let store=try InfrastructureStore(url:url),device=HomeDevice(displayName:"Persistent",hostname:nil,ipv4:nil,ipv6:nil,macAddress:nil,vendor:nil,type:.unknown,customType:nil,status:.unknown,lastSeen:nil,firstSeen:Date(),discoverySources:[.manual],routerDisplayName:"Router Name",routerConnectionType:.wifi5,routerLastSeen:Date(),routerOnline:true);deviceID=device.id;#expect(try await store.schemaVersion()==7);try await store.save(homeDevice:device)}
    let reopened=try InfrastructureStore(url:url),devices=try await reopened.homeDevices();#expect(devices.count==1);#expect(devices[0].id==deviceID)
    #expect(devices[0].routerDisplayName=="Router Name");#expect(devices[0].routerConnectionType == .wifi5);#expect(devices[0].routerOnline==true)
}

@Test func homeActiveDiscoveryCandidateBoundaries(){
    let values=HomeDiscoveryService.ipv4Candidates(cidr:"192.168.50.0/24",excluding:"192.168.50.10",maxHosts:512)
    #expect(values.count==253);#expect(!values.contains("192.168.50.0"));#expect(!values.contains("192.168.50.255"));#expect(!values.contains("192.168.50.10"));#expect(values.contains("192.168.50.1"))
    #expect(HomeDiscoveryService.ipv4Candidates(cidr:"10.0.0.0/16",excluding:nil,maxHosts:512).isEmpty)
}

@Test func tpLinkReadAllowlistRejectsWriteActions(){
    #expect(TPLinkArcherAX18Provider.allowed(path:"/admin/smart_network?form=game_accelerator",parameters:["operation":"loadDevice"]))
    #expect(TPLinkArcherAX18Provider.allowed(path:"/admin/dhcps?form=client",parameters:["operation":"load"]))
    #expect(!TPLinkArcherAX18Provider.allowed(path:"/admin/dhcps?form=client",parameters:["operation":"save"]))
    #expect(!TPLinkArcherAX18Provider.allowed(path:"/admin/reboot",parameters:["operation":"load"]))
    #expect(!TPLinkArcherAX18Provider.allowed(path:"/admin/dhcps?form=client",parameters:["operation":"load","extra":"1"]))
}

@Test func tpLinkInventoryNormalizesAndDeduplicatesSanitizedFixtures(){
    let active:[String:Any]=["clients":[
        ["mac":"02:11:22:33:44:55","ip":"192.0.2.10","hostname":"fixture-phone","device_tag":"5g","device_name":"Phone"],
        ["mac":"02:11:22:33:44:66","ip":"192.0.2.20","hostname":"fixture-nas","device_tag":"wired"]
    ]]
    let leases:[String:Any]=["leases":[
        ["macaddr":"02:11:22:33:44:55","ipaddr":"192.0.2.11","name":"dhcp-phone"],
        ["macaddr":"02:11:22:33:44:77","ipaddr":"192.0.2.30","name":"sleeping-device"]
    ]]
    let merged=TPLinkArcherAX18Provider.merge(active:TPLinkArcherAX18Provider.parseActive(active),leases:TPLinkArcherAX18Provider.parseDHCP(leases))
    #expect(merged.count==3);let phone=merged.first{$0.mac=="02:11:22:33:44:55"};#expect(phone?.ipv4=="192.0.2.10");#expect(phone?.online==true);#expect(phone?.connectionType == .wifi5);#expect(phone?.sources.contains(.routerDHCP)==true);#expect(phone?.sources.contains(.routerWireless)==true)
    let sleeping=merged.first{$0.mac=="02:11:22:33:44:77"};#expect(sleeping?.online==nil);#expect(sleeping?.sources==[.routerDHCP])
}

@Test func routerDHCPKnowledgeDoesNotImplyOnline(){
    let now=Date(),record=HomeDiscoveryRecord(ip:"192.0.2.30",mac:"02:11:22:33:44:77",hostname:"fixture",source:.routerDHCP,evidence:"Known lease",routerDisplayName:nil,connectionType:.unknown,online:nil)
    let device=HomeDeviceReconciler.merge(existing:nil,record:record,now:now)
    #expect(device.status == .unknown);#expect(device.lastSeen==nil);#expect(device.routerOnline==nil)
}

@Test func homeAccessProfileImportRenameDeleteAndPathSafety()throws{
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("HomeProfiles-\(UUID())"),source=root.appendingPathComponent("source.conf"),destination=root.appendingPathComponent("profiles");try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)};try Data("[Interface]\nPrivateKey = fixture-only".utf8).write(to:source)
    let imported=try ProfileStore.importHomeAccess(from:source,name:"MacBook",directory:destination);#expect(imported.url.lastPathComponent=="MacBook.conf");#expect((try FileManager.default.attributesOfItem(atPath:imported.url.path)[.posixPermissions] as? NSNumber)?.intValue==0o600)
    let renamed=try ProfileStore.rename(imported,name:"Phone",in:destination);#expect(renamed.url.lastPathComponent=="Phone.conf");#expect(ProfileStore.qrImage(for:"fixture") != nil)
    #expect(throws:ProfileStore.ProfileError.self){try ProfileStore.rename(renamed,name:"../escape",in:destination)}
    try ProfileStore.delete(renamed,within:destination);#expect(!FileManager.default.fileExists(atPath:renamed.url.path))
}

@Test func localDiscoveryProcessLifecycleDoesNotLeak()async throws{
    let runner=LocalCommandRunner()
    for _ in 0..<100{_ = try await runner.run("/usr/bin/true",[])}
    #expect(await runner.activeProcessCount()==0)
    let task=Task{try await runner.run("/bin/sleep",["5"])};try await Task.sleep(for:.milliseconds(30));task.cancel();_ = try? await task.value;try await Task.sleep(for:.milliseconds(30));#expect(await runner.activeProcessCount()==0)
}
