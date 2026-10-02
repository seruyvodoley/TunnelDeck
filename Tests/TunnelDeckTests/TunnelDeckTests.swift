import Testing
@testable import TunnelDeck

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
    #expect(result.public.count == 3)
    #expect(result.public.contains { $0.service == "Clean WireGuard" && $0.addresses.count == 2 })
    #expect(result.public.contains { $0.service == "AntiZapret WireGuard" })
    #expect(result.public.contains { $0.service == "AntiZapret OpenVPN" })
    #expect(result.private.contains { $0.service == "AdGuard Web" && $0.state == .online })
}
