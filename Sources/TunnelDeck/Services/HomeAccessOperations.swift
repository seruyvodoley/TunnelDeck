import Foundation

enum HomeInternetPolicy: String, CaseIterable, Identifiable, Sendable {
  case unknown = "Unknown"
  case vpn = "VPN"
  case direct = "Direct"

  var id: String { rawValue }
}

enum HomeGatewayStatus: String, Sendable {
  case unknown = "Unknown"
  case online = "Online"
  case offline = "Offline"
}

struct HomeDeviceProbeSnapshot: Sendable, Equatable {
  let checkedAt: Date
  let reachable: Bool
  let latencyMilliseconds: Double?
  let openPorts: Set<Int>
  let error: String?

  var serviceSummary: String {
    let labels = HomeServiceCatalog.labels(for: openPorts)
    return labels.isEmpty ? "No known services" : labels.joined(separator: " · ")
  }
}

enum HomeServiceCatalog {
  static let knownPorts: [Int] = [
    22,  // SSH
    80,  // HTTP
    443,  // HTTPS
    445,  // SMB
    631,  // IPP
    3389,  // RDP
    5900,  // VNC / Screen Sharing
    8123,  // Home Assistant
  ]

  static func name(for port: Int) -> String {
    switch port {
    case 22: "SSH"
    case 80: "HTTP"
    case 443: "HTTPS"
    case 445: "SMB"
    case 631: "IPP"
    case 3389: "RDP"
    case 5900: "Screen"
    case 8123: "Home Assistant"
    default: "TCP \(port)"
    }
  }

  static func labels(for ports: Set<Int>) -> [String] {
    ports.sorted().map(name(for:))
  }
}

private struct HomeLocalCommandOutput: Sendable {
  let status: Int32
  let stdout: String
  let stderr: String
}

enum HomeDeviceProbeService {
  static func probe(ip: String) async -> HomeDeviceProbeSnapshot {
    async let latencyTask = pingLatency(ip)

    let openPorts = await withTaskGroup(
      of: (Int, Bool).self,
      returning: Set<Int>.self
    ) { group in
      for port in HomeServiceCatalog.knownPorts {
        group.addTask {
          (port, await portOpen(ip: ip, port: port))
        }
      }

      var result = Set<Int>()
      for await (port, open) in group {
        if open { result.insert(port) }
      }
      return result
    }

    let latency = await latencyTask
    let reachable = latency != nil || !openPorts.isEmpty

    return HomeDeviceProbeSnapshot(
      checkedAt: Date(),
      reachable: reachable,
      latencyMilliseconds: latency,
      openPorts: openPorts,
      error: reachable
        ? nil
        : "No ICMP response and no known TCP service answered."
    )
  }

  private static func pingLatency(_ ip: String) async -> Double? {
    let result = await run(
      "/sbin/ping",
      ["-c", "1", "-W", "1000", ip]
    )

    guard result.status == 0 else { return nil }

    let pattern = #"time[=<]([0-9.]+)\s*ms"#
    guard
      let regex = try? NSRegularExpression(pattern: pattern),
      let match = regex.firstMatch(
        in: result.stdout,
        range: NSRange(result.stdout.startIndex..., in: result.stdout)
      ),
      let range = Range(match.range(at: 1), in: result.stdout)
    else {
      return nil
    }

    return Double(result.stdout[range])
  }

  private static func portOpen(ip: String, port: Int) async -> Bool {
    let result = await run(
      "/usr/bin/nc",
      ["-z", "-G", "1", ip, String(port)]
    )
    return result.status == 0
  }

  private static func run(
    _ executable: String,
    _ arguments: [String]
  ) async -> HomeLocalCommandOutput {
    await Task.detached(priority: .utility) {
      let process = Process()
      let output = Pipe()
      let error = Pipe()

      process.executableURL = URL(fileURLWithPath: executable)
      process.arguments = arguments
      process.standardOutput = output
      process.standardError = error

      do {
        try process.run()
        process.waitUntilExit()

        return HomeLocalCommandOutput(
          status: process.terminationStatus,
          stdout: String(
            decoding: output.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
          ),
          stderr: String(
            decoding: error.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
          )
        )
      } catch {
        return HomeLocalCommandOutput(
          status: 127,
          stdout: "",
          stderr: error.localizedDescription
        )
      }
    }.value
  }
}

struct HomeGatewayTestResult: Sendable {
  let status: HomeGatewayStatus
  let message: String
}

enum HomeGatewayService {
  static func test(
    host: String,
    username: String,
    keyPath: String
  ) async -> HomeGatewayTestResult {
    let command = """
      printf 'hostname='
      hostname
      printf 'tdhome='
      if wg show tdhome >/dev/null 2>&1; then
        echo up
        wg show tdhome latest-handshakes 2>/dev/null | tail -n 1
      else
        echo down
      fi
      """

    let result = await ssh(
      host: host,
      username: username,
      keyPath: keyPath,
      command: command
    )

    if result.exitCode == 0 {
      let value = result.stdout
        .trimmingCharacters(in: .whitespacesAndNewlines)
      return HomeGatewayTestResult(
        status: .online,
        message: value.isEmpty ? "Gateway SSH is available." : value
      )
    }

    return HomeGatewayTestResult(
      status: .offline,
      message: result.stderr.isEmpty
        ? "Gateway SSH test failed."
        : result.stderr
    )
  }

  static func wakeCommand(mac: String) -> String? {
    guard let mac = HomeDeviceIdentity.normalizedMAC(mac) else {
      return nil
    }

    return """
      MAC='\(mac)'
      if command -v etherwake >/dev/null 2>&1; then
        etherwake -i br-lan "$MAC"
      elif command -v ether-wake >/dev/null 2>&1; then
        ether-wake -i br-lan "$MAC"
      else
        echo 'etherwake is not installed on Home Gateway' >&2
        exit 127
      fi
      """
  }

  static func wake(
    host: String,
    username: String,
    keyPath: String,
    mac: String
  ) async -> CommandResult {
    guard let command = wakeCommand(mac: mac) else {
      return CommandResult(
        stdout: "",
        stderr: "A valid device MAC address is required for Wake-on-LAN.",
        exitCode: 2,
        duration: 0
      )
    }

    return await ssh(
      host: host,
      username: username,
      keyPath: keyPath,
      command: command
    )
  }

  private static func ssh(
    host: String,
    username: String,
    keyPath: String,
    command: String
  ) async -> CommandResult {
    let cleanHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
    let cleanUser = username.trimmingCharacters(in: .whitespacesAndNewlines)

    guard
      cleanHost.range(
        of: #"^[A-Za-z0-9._:-]+$"#,
        options: .regularExpression
      ) != nil,
      cleanUser.range(
        of: #"^[A-Za-z0-9._-]+$"#,
        options: .regularExpression
      ) != nil
    else {
      return CommandResult(
        stdout: "",
        stderr: "Invalid Home Gateway SSH target.",
        exitCode: 2,
        duration: 0
      )
    }

    let started = Date()

    return await Task.detached(priority: .utility) {
      let process = Process()
      let output = Pipe()
      let error = Pipe()

      process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")

      var arguments = [
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=4",
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=yes",
      ]

      let expandedKey = (keyPath as NSString).expandingTildeInPath
      if !expandedKey.isEmpty {
        arguments += [
          "-i", expandedKey,
          "-o", "IdentitiesOnly=yes",
        ]
      }

      arguments += [
        "\(cleanUser)@\(cleanHost)",
        command,
      ]

      process.arguments = arguments
      process.standardOutput = output
      process.standardError = error

      do {
        try process.run()
        process.waitUntilExit()

        return CommandResult(
          stdout: SecretRedactor.redact(
            String(
              decoding: output.fileHandleForReading.readDataToEndOfFile(),
              as: UTF8.self
            )
          ),
          stderr: SecretRedactor.redact(
            String(
              decoding: error.fileHandleForReading.readDataToEndOfFile(),
              as: UTF8.self
            )
          ),
          exitCode: process.terminationStatus,
          duration: Date().timeIntervalSince(started)
        )
      } catch {
        return CommandResult(
          stdout: "",
          stderr: SecretRedactor.redact(error.localizedDescription),
          exitCode: 127,
          duration: Date().timeIntervalSince(started)
        )
      }
    }.value
  }
}
