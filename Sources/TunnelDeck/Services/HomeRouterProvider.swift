import CCommonCrypto
import CryptoKit
import Foundation
import Security

struct RouterClientRecord: Sendable, Equatable {
    let mac: String
    var ipv4: String?
    var ipv6: String?
    var hostname: String?
    var displayName: String?
    var connectionType: HomeConnectionType
    var online: Bool?
    var leaseExpires: Date?
    var sources: Set<HomeDiscoverySource>
}

struct HomeRouterInfo: Sendable, Equatable {
    let provider: String
    let hardwareVersion: String?
    let firmwareVersion: String?
}

protocol RouterClientInventoryProvider: Sendable {
    func connect(address: String, username: String?, password: String) async throws -> HomeRouterInfo
    func clients() async throws -> [RouterClientRecord]
    func disconnect() async
}

enum HomeRouterProviderError: LocalizedError, Equatable {
    case invalidAddress
    case authenticationRequired
    case authenticationFailed
    case unsupportedFirmware
    case malformedResponse
    case writeOperationRejected
    case unavailable

    var errorDescription: String? {
        switch self {
        case .invalidAddress: "Invalid router address."
        case .authenticationRequired: "Router authentication is required."
        case .authenticationFailed: "Router authentication failed."
        case .unsupportedFirmware: "This router firmware protocol is not supported safely."
        case .malformedResponse: "The router returned a malformed response."
        case .writeOperationRejected: "A non-read router operation was rejected before transmission."
        case .unavailable: "The router is unavailable."
        }
    }
}

struct RouterHTTPResponse: Sendable {
    let data: Data
    let headers: [String: String]

    func header(_ name: String) -> String? {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

protocol RouterHTTPTransport: Sendable {
    func post(url: URL, body: Data, headers: [String: String]) async throws -> RouterHTTPResponse
}

final class URLSessionRouterTransport: RouterHTTPTransport, @unchecked Sendable {
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: configuration)
    }

    func post(url: URL, body: Data, headers: [String: String] = [:]) async throws -> RouterHTTPResponse {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.timeoutInterval = 12
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw HomeRouterProviderError.unavailable
        }

        var responseHeaders: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            responseHeaders[String(describing: key)] = String(describing: value)
        }
        return RouterHTTPResponse(data: data, headers: responseHeaders)
    }
}

actor TPLinkArcherAX18Provider: RouterClientInventoryProvider {
    private enum ReadAction: String {
        case activeClients = "loadDevice"
        case dhcpLeases = "load"
    }

    private let transport: any RouterHTTPTransport
    private var baseURL: URL?
    private var token: String?
    private var sysauth: String?
    private var crypto: TPLinkCryptoSession?
    private var info = HomeRouterInfo(provider: "TP-Link Archer AX18", hardwareVersion: nil, firmwareVersion: nil)

    init(transport: any RouterHTTPTransport = URLSessionRouterTransport()) {
        self.transport = transport
    }

    func connect(address: String, username: String?, password: String) async throws -> HomeRouterInfo {
        guard let base = Self.validBaseURL(address) else {
            throw HomeRouterProviderError.invalidAddress
        }

        baseURL = base
        token = nil
        sysauth = nil
        crypto = nil

        let config = try await plain(
            path: "/device_config?form=config",
            body: "operation=read"
        )
        let certifications = Self.strings(config["certification"])
        guard certifications.contains("SG CLS L1 STAGE2") || certifications.contains("EU CE RED") else {
            throw HomeRouterProviderError.unsupportedFirmware
        }

        // SG L1 S2 requests these with operation=read in the URL query.
        let keys = try await plain(path: "/login?form=keys&operation=read", body: "")
        let auth = try await plain(path: "/login?form=auth&operation=read", body: "")

        guard
            let sequence = Self.int(auth["seq"]),
            let authKey = Self.stringArray(auth["key"]), authKey.count == 2,
            let passwordKey = Self.stringArray(keys["password"]), passwordKey.count == 2
        else {
            throw HomeRouterProviderError.malformedResponse
        }

        let effectiveUsername = Self.effectiveUsername(username)
        let session = try TPLinkCryptoSession(
            username: effectiveUsername,
            password: password,
            sequence: sequence,
            authModulus: authKey[0],
            authExponent: authKey[1]
        )

        // Password encryption is RSA PKCS#1 v1.5 for SG L1 S2.
        let encryptedPassword = try TPLinkRSA.encryptPKCS1v15Hex(
            Data(password.utf8),
            modulus: passwordKey[0],
            exponent: passwordKey[1]
        )

        // Keep this exact ordering to mirror the router's own JavaScript/client.
        let loginPayload = Self.loginPayload(encryptedPassword: encryptedPassword)
        let sealed = try session.sealLogin(loginPayload)
        let loginURL = try endpoint(baseURL: base, token: "", path: "/login?form=login")
        let loginResponse = try await transport.post(
            url: loginURL,
            body: Self.encryptedBody(sign: sealed.sign, data: sealed.data),
            headers: [:]
        )

        let login = try Self.unwrapEncrypted(loginResponse.data, session: session, login: true)
        guard let stok = Self.string(login["stok"]), !stok.isEmpty else {
            throw HomeRouterProviderError.authenticationFailed
        }
        guard let cookie = Self.sysauthCookie(from: loginResponse.headers), !cookie.isEmpty else {
            throw HomeRouterProviderError.malformedResponse
        }

        token = stok
        sysauth = cookie
        crypto = session

        if let firmware = Self.dictionary(config["firmware"]) {
            info = HomeRouterInfo(
                provider: "TP-Link Archer AX18",
                hardwareVersion: Self.string(firmware["hardwareVersion"]),
                firmwareVersion: Self.string(firmware["firmwareVersion"])
            )
        }
        return info
    }

    func clients() async throws -> [RouterClientRecord] {
        guard let token, let sysauth, let session = crypto else {
            throw HomeRouterProviderError.authenticationRequired
        }

        do {
            let active = try await read(
                .activeClients,
                path: "/admin/smart_network?form=game_accelerator",
                session: session,
                token: token,
                sysauth: sysauth
            )
            let leases = try await read(
                .dhcpLeases,
                path: "/admin/dhcps?form=client",
                session: session,
                token: token,
                sysauth: sysauth
            )
            return Self.merge(active: Self.parseActive(active), leases: Self.parseDHCP(leases))
        } catch HomeRouterProviderError.authenticationRequired {
            self.token = nil
            self.sysauth = nil
            crypto = nil
            throw HomeRouterProviderError.authenticationRequired
        }
    }

    func disconnect() {
        token = nil
        sysauth = nil
        crypto = nil
    }

    private func read(
        _ action: ReadAction,
        path: String,
        session: TPLinkCryptoSession,
        token: String,
        sysauth: String
    ) async throws -> [String: Any] {
        let parameters: [String: String] = ["operation": action.rawValue]
        guard Self.allowed(path: path, parameters: parameters) else {
            throw HomeRouterProviderError.writeOperationRejected
        }

        guard let baseURL else {
            throw HomeRouterProviderError.invalidAddress
        }

        let clear = Self.formString(parameters)
        let sealed = try session.sealRequest(clear)
        let url = try endpoint(baseURL: baseURL, token: token, path: path)
        let response = try await transport.post(
            url: url,
            body: Self.encryptedBody(sign: sealed.sign, data: sealed.data),
            headers: ["Cookie": "sysauth=\(sysauth)"]
        )
        return try Self.unwrapEncrypted(response.data, session: session, login: false)
    }

    static func allowed(path: String, parameters: [String: String]) -> Bool {
        let exact: [String: Set<String>] = [
            "/admin/smart_network?form=game_accelerator": ["loadDevice"],
            "/admin/dhcps?form=client": ["load"]
        ]
        guard
            let operations = exact[path],
            let operation = parameters["operation"],
            operations.contains(operation),
            parameters.count == 1
        else {
            return false
        }
        return true
    }

    static func effectiveUsername(_ username: String?) -> String {
        let value = username?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return value.isEmpty ? "admin" : value
    }

    static func loginPayload(encryptedPassword: String) -> String {
        "operation=login&password=\(encryptedPassword)&confirm=true"
    }

    static func sysauthCookie(from headers: [String: String]) -> String? {
        guard let value = headers.first(where: { $0.key.caseInsensitiveCompare("Set-Cookie") == .orderedSame })?.value,
              let range = value.range(of: "sysauth=", options: .caseInsensitive)
        else {
            return nil
        }

        let tail = value[range.upperBound...]
        let cookie = String(tail.prefix { $0 != ";" && $0 != "," }).trimmingCharacters(in: .whitespacesAndNewlines)
        return cookie.isEmpty ? nil : cookie
    }

    private func plain(path: String, body: String) async throws -> [String: Any] {
        guard let baseURL else {
            throw HomeRouterProviderError.invalidAddress
        }
        let url = try endpoint(baseURL: baseURL, token: "", path: path)
        let response = try await transport.post(url: url, body: Data(body.utf8), headers: [:])
        return try Self.unwrapPlain(response.data)
    }

    private func endpoint(baseURL: URL, token: String, path: String) throws -> URL {
        guard let value = URL(string: "/cgi-bin/luci/;stok=\(token)\(path)", relativeTo: baseURL)?.absoluteURL else {
            throw HomeRouterProviderError.invalidAddress
        }
        return value
    }

    private static func validBaseURL(_ value: String) -> URL? {
        let raw = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidate = raw.contains("://") ? raw : "http://\(raw)"
        guard
            let url = URL(string: candidate),
            ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
            url.user == nil,
            url.password == nil,
            url.query == nil,
            url.fragment == nil,
            url.host != nil
        else {
            return nil
        }
        return URL(string: "\(url.scheme!)://\(url.host!)\(url.port.map { ":\($0)" } ?? "")/")
    }

    private static func unwrapPlain(_ data: Data) throws -> [String: Any] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw HomeRouterProviderError.malformedResponse
        }

        if let success = bool(root["success"]), !success {
            throw errorForFailure(root, login: false)
        }

        let payload: Any = root["data"] ?? root
        return payload as? [String: Any] ?? ["items": payload]
    }

    private static func unwrapEncrypted(
        _ data: Data,
        session: TPLinkCryptoSession,
        login: Bool
    ) throws -> [String: Any] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw HomeRouterProviderError.malformedResponse
        }

        if let success = bool(root["success"]), !success, root["data"] as? String == nil {
            throw errorForFailure(root, login: login)
        }

        guard let encrypted = root["data"] as? String else {
            throw HomeRouterProviderError.malformedResponse
        }

        let clear = try session.open(encrypted)
        guard
            let decodedData = clear.data(using: .utf8),
            let decoded = try JSONSerialization.jsonObject(with: decodedData) as? [String: Any]
        else {
            throw HomeRouterProviderError.malformedResponse
        }

        guard bool(decoded["success"]) == true else {
            throw errorForFailure(decoded, login: login)
        }

        let payload: Any = decoded["data"] ?? decoded
        return payload as? [String: Any] ?? ["items": payload]
    }

    private static func errorForFailure(_ object: [String: Any], login: Bool) -> HomeRouterProviderError {
        let nested = dictionary(object["data"])
        let rawCode =
            string(nested?["errorcode"]) ??
            string(nested?["errorCode"]) ??
            string(object["errorcode"]) ??
            string(object["errorCode"]) ??
            string(object["error"]) ??
            ""
        let code = rawCode.lowercased()
        if !login && (code.contains("timeout") || code.contains("permission")) {
            return .authenticationRequired
        }
        return .authenticationFailed
    }

    private static func encryptedBody(sign: String, data: String) -> Data {
        Data("sign=\(sign.urlFormEncoded)&data=\(data.urlFormEncoded)".utf8)
    }

    private static func formString(_ values: [String: String]) -> String {
        values.keys.sorted().map {
            "\($0.urlFormEncoded)=\((values[$0] ?? "").urlFormEncoded)"
        }.joined(separator: "&")
    }

    private static func dictionary(_ value: Any?) -> [String: Any]? { value as? [String: Any] }
    private static func string(_ value: Any?) -> String? {
        if let value = value as? String { return value }
        if let value = value as? NSNumber { return value.stringValue }
        return nil
    }
    private static func bool(_ value: Any?) -> Bool? {
        if let value = value as? Bool { return value }
        if let value = value as? NSNumber { return value.boolValue }
        return nil
    }
    private static func int(_ value: Any?) -> Int? { value as? Int ?? (value as? NSNumber)?.intValue }
    private static func stringArray(_ value: Any?) -> [String]? { value as? [String] }
    private static func strings(_ value: Any?) -> [String] { value as? [String] ?? [] }

    private static func arrays(in value: Any) -> [[[String: Any]]] {
        if let rows = value as? [[String: Any]] { return [rows] }
        if let object = value as? [String: Any] { return object.values.flatMap { arrays(in: $0) } }
        if let list = value as? [Any] { return list.flatMap { arrays(in: $0) } }
        return []
    }

    static func parseActive(_ object: [String: Any]) -> [RouterClientRecord] {
        arrays(in: object).flatMap { $0 }.compactMap { row in
            guard let mac = HomeDeviceIdentity.normalizedMAC(string(row["mac"]) ?? string(row["macaddr"])) else {
                return nil
            }
            let tag = (string(row["device_tag"]) ?? string(row["deviceTag"]) ?? string(row["conn_type"]) ?? "").lowercased()
            let connection: HomeConnectionType =
                tag.contains("wired") ? .ethernet :
                tag.contains("2g") ? .wifi24 :
                tag.contains("5g") ? .wifi5 :
                tag.contains("6g") ? .wifi6 : .wifi
            return RouterClientRecord(
                mac: mac,
                ipv4: string(row["ip"]) ?? string(row["ipaddr"]),
                hostname: string(row["hostname"]),
                displayName: string(row["device_name"]) ?? string(row["deviceName"]) ?? string(row["name"]),
                connectionType: connection,
                online: true,
                sources: [.routerClient, connection == .ethernet ? .routerWired : .routerWireless]
            )
        }
    }

    static func parseDHCP(_ object: [String: Any]) -> [RouterClientRecord] {
        arrays(in: object).flatMap { $0 }.compactMap { row in
            guard let mac = HomeDeviceIdentity.normalizedMAC(
                string(row["mac"]) ?? string(row["macaddr"]) ?? string(row["mac_address"])
            ) else {
                return nil
            }
            return RouterClientRecord(
                mac: mac,
                ipv4: string(row["ip"]) ?? string(row["ipaddr"]) ?? string(row["assigned_ip"]),
                hostname: string(row["name"]) ?? string(row["hostname"]),
                displayName: nil,
                connectionType: .unknown,
                online: nil,
                leaseExpires: nil,
                sources: [.routerDHCP]
            )
        }
    }

    static func merge(active: [RouterClientRecord], leases: [RouterClientRecord]) -> [RouterClientRecord] {
        var values = [String: RouterClientRecord]()
        for value in leases + active {
            if var old = values[value.mac] {
                old.ipv4 = value.ipv4 ?? old.ipv4
                old.ipv6 = value.ipv6 ?? old.ipv6
                old.hostname = value.hostname ?? old.hostname
                old.displayName = value.displayName ?? old.displayName
                if value.connectionType != .unknown {
                    old.connectionType = value.connectionType
                }
                old.online = value.online ?? old.online
                old.sources.formUnion(value.sources)
                values[value.mac] = old
            } else {
                values[value.mac] = value
            }
        }
        return values.values.sorted { $0.mac < $1.mac }
    }
}

struct TPLinkCryptoSession: Sendable {
    private static let signatureChunk = 53

    let key: String
    let iv: String
    let sequence: Int
    let loginHash: String
    let authModulus: String
    let authExponent: String

    init(
        username: String,
        password: String,
        sequence: Int,
        authModulus: String,
        authExponent: String
    ) throws {
        key = Self.digits(16)
        iv = Self.digits(16)
        self.sequence = sequence
        loginHash = Self.sha256Hex("\(username)\(password)")
        self.authModulus = authModulus
        self.authExponent = authExponent
    }

    func sealLogin(_ clear: String) throws -> (sign: String, data: String) {
        let encrypted = try encrypt(clear)
        let signature = "\(formattedAESKey)&h=\(loginHash)&s=\(sequence + encrypted.utf8.count)"
        return (
            try TPLinkRSA.encryptOAEPHexChunked(
                Data(signature.utf8),
                modulus: authModulus,
                exponent: authExponent,
                preferredChunkSize: Self.signatureChunk
            ),
            encrypted
        )
    }

    func sealRequest(_ clear: String) throws -> (sign: String, data: String) {
        let encrypted = try encrypt(clear)
        let requestHash = Self.sha256Hex(encrypted)
        let signature = "h=\(requestHash)&s=\(sequence + encrypted.utf8.count)"
        return (Self.hmacSHA256Chunks(signature, key: formattedAESKey), encrypted)
    }

    func open(_ encrypted: String) throws -> String {
        guard let data = Data(base64Encoded: encrypted) else {
            throw HomeRouterProviderError.malformedResponse
        }
        let clear = try Self.aes(
            data,
            key: key,
            iv: iv,
            operation: CCOperation(kCCDecrypt)
        )
        guard let string = String(data: clear, encoding: .utf8) else {
            throw HomeRouterProviderError.malformedResponse
        }
        return string
    }

    private var formattedAESKey: String { "k=\(key)&i=\(iv)" }

    private func encrypt(_ clear: String) throws -> String {
        try Self.aes(
            Data(clear.utf8),
            key: key,
            iv: iv,
            operation: CCOperation(kCCEncrypt)
        ).base64EncodedString()
    }

    private static func digits(_ count: Int) -> String {
        String((0..<count).map { _ in Character(String(Int.random(in: 0...9))) })
    }

    private static func sha256Hex(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func hmacSHA256Chunks(_ value: String, key: String) -> String {
        let bytes = Array(value.utf8)
        let hmacKey = SymmetricKey(data: Data(key.utf8))
        var result = ""

        for start in stride(from: 0, to: bytes.count, by: signatureChunk) {
            let end = min(start + signatureChunk, bytes.count)
            let code = HMAC<SHA256>.authenticationCode(
                for: Data(bytes[start..<end]),
                using: hmacKey
            )
            result += code.map { String(format: "%02x", $0) }.joined()
        }
        return result
    }

    private static func aes(
        _ input: Data,
        key: String,
        iv: String,
        operation: CCOperation
    ) throws -> Data {
        let outputCapacity = input.count + kCCBlockSizeAES128
        var output = Data(count: outputCapacity)
        var moved = 0
        let status = output.withUnsafeMutableBytes { out in
            input.withUnsafeBytes { src in
                key.withCString { keyPtr in
                    iv.withCString { ivPtr in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr,
                            kCCKeySizeAES128,
                            ivPtr,
                            src.baseAddress,
                            input.count,
                            out.baseAddress,
                            outputCapacity,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw HomeRouterProviderError.unsupportedFirmware
        }
        output.count = moved
        return output
    }
}

enum TPLinkRSA {
    static func encryptPKCS1v15Hex(_ data: Data, modulus: String, exponent: String) throws -> String {
        let key = try publicKey(modulus: modulus, exponent: exponent)
        let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
        guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
            throw HomeRouterProviderError.unsupportedFirmware
        }
        guard data.count <= SecKeyGetBlockSize(key) - 11 else {
            throw HomeRouterProviderError.unsupportedFirmware
        }

        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(key, algorithm, data as CFData, &error) as Data? else {
            if let error { throw error.takeRetainedValue() }
            throw HomeRouterProviderError.unsupportedFirmware
        }
        return hexString(encrypted)
    }

    static func encryptOAEPHexChunked(
        _ data: Data,
        modulus: String,
        exponent: String,
        preferredChunkSize: Int = 53
    ) throws -> String {
        let key = try publicKey(modulus: modulus, exponent: exponent)
        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA1
        guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
            throw HomeRouterProviderError.unsupportedFirmware
        }

        let maxOAEPChunk = SecKeyGetBlockSize(key) - 42
        let chunkSize = min(preferredChunkSize, maxOAEPChunk)
        guard chunkSize > 0 else {
            throw HomeRouterProviderError.unsupportedFirmware
        }

        var result = ""
        for start in stride(from: 0, to: data.count, by: chunkSize) {
            let end = min(start + chunkSize, data.count)
            let part = data.subdata(in: start..<end)
            var error: Unmanaged<CFError>?
            guard let encrypted = SecKeyCreateEncryptedData(key, algorithm, part as CFData, &error) as Data? else {
                if let error { throw error.takeRetainedValue() }
                throw HomeRouterProviderError.unsupportedFirmware
            }
            result += hexString(encrypted)
        }
        return result
    }

    private static func publicKey(modulus: String, exponent: String) throws -> SecKey {
        let modulusData = try hex(modulus)
        let exponentData = try hex(exponent)
        let keyData = derSequence(derInteger(modulusData) + derInteger(exponentData))
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: modulusData.count * 8
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            if let error { throw error.takeRetainedValue() }
            throw HomeRouterProviderError.unsupportedFirmware
        }
        return key
    }

    private static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func hex(_ value: String) throws -> Data {
        guard value.count.isMultiple(of: 2) else {
            throw HomeRouterProviderError.malformedResponse
        }
        var data = Data()
        var index = value.startIndex
        while index < value.endIndex {
            let end = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<end], radix: 16) else {
                throw HomeRouterProviderError.malformedResponse
            }
            data.append(byte)
            index = end
        }
        return data
    }

    private static func derInteger(_ value: Data) -> Data {
        let body = (value.first ?? 0) & 0x80 != 0 ? Data([0]) + value : value
        return Data([0x02]) + derLength(body.count) + body
    }

    private static func derSequence(_ value: Data) -> Data {
        Data([0x30]) + derLength(value.count) + value
    }

    private static func derLength(_ count: Int) -> Data {
        if count < 128 {
            return Data([UInt8(count)])
        }
        let bytes = withUnsafeBytes(of: UInt32(count).bigEndian) { Array($0).drop { $0 == 0 } }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

private extension String {
    var urlFormEncoded: String {
        addingPercentEncoding(withAllowedCharacters: CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? ""
    }
}
