import Foundation

enum ReadCommand: String, CaseIterable, Sendable {
    case uname = "uname -a"
    case hostname = "hostname"
    case osRelease = "cat /etc/os-release"
    case uptime = "uptime"
    case cpu = "grep 'cpu ' /proc/stat"
    case memory = "free -b"
    case disk = "df -P -B1 /"
    case addresses = "ip -brief address"
    case routes = "ip route"
    case publicIPv4 = "curl -4 -fsS --max-time 4 https://api.ipify.org"
    case publicIPv6 = "curl -6 -fsS --max-time 4 https://api64.ipify.org"
    case wireGuard = "wg show wg0"
    case wireGuardAll = "wg show all"
    case wireGuardAddress = "ip -brief address show wg0"
    case wireGuardLink = "ip -details link show wg0"
    case units = "systemctl show antizapret.service antizapret-update.service antizapret-update.timer wg-quick@antizapret.service wg-quick@vpn.service openvpn-server@antizapret-udp.service openvpn-server@vpn-udp.service AdGuardHome.service --property=Id,ActiveState,SubState --no-pager"
    case listeners = "ss -H -lntup"
    case antiZapretSettings = "grep -R -h -E '^(ROUTE_ALL|TELEGRAM_INCLUDE|WHATSAPP_INCLUDE|CLOUDFLARE_INCLUDE|WIREGUARD_ENABLE|OPENVPN_UDP_ENABLE|OPENVPN_TCP_ENABLE|OPENVPN_DCO|RESTRICT_FORWARD)=' /root/antizapret/setup"
    case antiZapretFiles = "find /root/antizapret/result -maxdepth 2 -type f -printf '%p|%s|%TY-%Tm-%TdT%TH:%TM:%TS\\n'"
    case profiles = "find /root /root/antizapret/client -type f \\( -name '*.conf' -o -name '*.ovpn' \\) -printf '%p|%s|%TY-%Tm-%TdT%TH:%TM:%TS\\n'"
    case pingInternet = "ping -c 3 -W 2 1.1.1.1"
    case dnsTest = "getent ahostsv4 example.com"
    case iperfDetection = "command -v iperf3"
    case recentAntiZapretLogs = "journalctl -u antizapret.service -n 200 --no-pager -o short-iso"
    case wireGuardService = "systemctl is-active wg-quick@wg0"
    case udpListeners = "ss -H -lunp"
    case ipForward = "sysctl -n net.ipv4.ip_forward"
    case natRules = "iptables-save -t nat"
    case firewallState = "nft list ruleset"
    case adGuardStatus = "systemctl is-active AdGuardHome.service"
    case antiZapretStatus = "systemctl is-active antizapret.service"
    case adGuardBinds = "grep -E '^[[:space:]]*(address|bind_hosts|port):' /opt/AdGuardHome/AdGuardHome.yaml"
    case configurationHashes = "sha256sum /etc/wireguard/wg0.conf /root/tunneldeck/peers.json /root/antizapret/setup /opt/AdGuardHome/AdGuardHome.yaml"
}

enum CommandPolicyError: Error, LocalizedError {
    case invalidHost, invalidUsername, invalidKeyPath, deniedCommand
    var errorDescription: String? {
        switch self {
        case .invalidHost: "Invalid VPS host"
        case .invalidUsername: "Invalid SSH username"
        case .invalidKeyPath: "Invalid SSH key path"
        case .deniedCommand: "Command is not permitted in read-only mode"
        }
    }
}

enum ReadOnlyCommandPolicy {
    static let readOnlyMode = true
    private static let hostPattern = #"^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])$"#
    private static let userPattern = #"^[A-Za-z_][A-Za-z0-9_-]{0,31}$"#

    static func validate(host: String, username: String, keyPath: String) throws {
        guard host.range(of: hostPattern, options: .regularExpression) != nil else { throw CommandPolicyError.invalidHost }
        guard username.range(of: userPattern, options: .regularExpression) != nil else { throw CommandPolicyError.invalidUsername }
        if !keyPath.isEmpty {
            guard keyPath.hasPrefix("/"), !keyPath.contains("\n"), !keyPath.contains("\0") else { throw CommandPolicyError.invalidKeyPath }
        }
    }

    static func authorize(_ command: ReadCommand) -> String { command.rawValue }

    static func authorize(rawCommand: String) throws -> String {
        guard let command = ReadCommand.allCases.first(where: { $0.rawValue == rawCommand }) else {
            throw CommandPolicyError.deniedCommand
        }
        return command.rawValue
    }
}

typealias CommandPolicy = ReadOnlyCommandPolicy

enum WriteHelperCommand: Sendable, Equatable {
    case version, health, listBackups, wireGuardList
    case addPeer(name: String, ip: String, dns: String, mtu: Int, allowedIPs: String, endpoint: String)
    case removePeer(publicKey: String, deleteClient: Bool, allowExisting: Bool)
    case clientConfig(name: String)
    case service(action: String, unit: String)
    case backup(operation: String)
    case backupVerify(identifier: String)
    case restorePreview(identifier: String, type: String)
    case restoreApply(identifier: String, type: String)
}

enum WriteCommandPolicy {
    static let helperPath = "/usr/local/libexec/tunneldeck-helper"
    private static let namePattern = #"^[A-Za-z0-9_-]{1,48}$"#
    private static let keyPattern = #"^[A-Za-z0-9+/]{43}=$"#
    private static let allowedUnits = Set(["wg-quick@wg0", "antizapret", "antizapret-update", "wg-quick@antizapret", "wg-quick@vpn", "openvpn-server@antizapret-udp", "openvpn-server@vpn-udp", "AdGuardHome"])

    static func arguments(for command: WriteHelperCommand) throws -> [String] {
        switch command {
        case .version: return [helperPath, "version"]
        case .health: return [helperPath, "health"]
        case .listBackups: return [helperPath, "list-backups"]
        case .wireGuardList: return [helperPath, "wg-list"]
        case .addPeer(let name, let ip, let dns, let mtu, let allowedIPs, let endpoint):
            guard name.range(of: namePattern, options: .regularExpression) != nil,
                  IPv4Validator.isValid(ip), IPv4Validator.isValid(dns), (1280...1500).contains(mtu),
                  EndpointValidator.isValid(endpoint), AllowedIPsValidator.isValid(allowedIPs) else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "wg-add-peer", "--name", name, "--ip", ip, "--dns", dns, "--mtu", String(mtu), "--allowed-ips", allowedIPs, "--endpoint", endpoint]
        case .removePeer(let publicKey, let deleteClient, let allowExisting):
            guard publicKey.range(of: keyPattern, options: .regularExpression) != nil else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "wg-remove-peer", "--public-key", publicKey] + (deleteClient ? ["--delete-client"] : []) + (allowExisting ? ["--allow-existing"] : [])
        case .clientConfig(let name):
            guard name.range(of: namePattern, options: .regularExpression) != nil else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "wg-client-config", "--name", name]
        case .service(let action, let unit):
            guard ["start", "stop", "restart"].contains(action), allowedUnits.contains(unit) else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "service", action, unit]
        case .backup(let operation):
            guard operation.range(of: namePattern, options: .regularExpression) != nil else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "backup", operation]
        case .backupVerify(let identifier):
            guard identifier.range(of: namePattern, options: .regularExpression) != nil else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "backup-verify", identifier]
        case .restorePreview(let identifier, let type):
            guard identifier.range(of: namePattern, options: .regularExpression) != nil, ["wireguard", "adguard", "antizapret"].contains(type) else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "restore-preview", identifier, "--type", type]
        case .restoreApply(let identifier, let type):
            guard identifier.range(of: namePattern, options: .regularExpression) != nil, ["wireguard", "adguard", "antizapret"].contains(type) else { throw CommandPolicyError.deniedCommand }
            return [helperPath, "restore-apply", identifier, "--type", type, "--confirm", "RESTORE"]
        }
    }
}

enum IPv4Validator {
    static func isValid(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
    }
}

enum EndpointValidator {
    static func isValid(_ value: String) -> Bool {
        guard let separator = value.lastIndex(of: ":"), let port = Int(value[value.index(after: separator)...]) else { return false }
        let host = value[..<separator]
        return !host.isEmpty && host.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" } && (1...65535).contains(port)
    }
}

enum AllowedIPsValidator {
    static func isValid(_ value: String) -> Bool {
        let values = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        return !values.isEmpty && values.count <= 8 && values.allSatisfy { item in
            let pair = item.split(separator: "/"); return pair.count == 2 && IPv4Validator.isValid(String(pair[0])) && (Int(pair[1]).map { (0...32).contains($0) } ?? false)
        }
    }
}