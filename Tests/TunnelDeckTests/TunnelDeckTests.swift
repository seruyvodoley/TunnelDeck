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
    let profiles = ProfileParser.parseListing("/root/wg0.conf|500|2026-01-01T12:00:00\n/root/antizapret/client/a.ovpn|1000|2026-01-02T12:00:00")
    #expect(profiles.count == 2)
    #expect(profiles[0].type == "WireGuard")
    #expect(profiles[1].type == "OpenVPN")
    #expect(profiles[1].category == "AntiZapret")
    #expect(profiles[0].endpoint == "Not downloaded")
}
