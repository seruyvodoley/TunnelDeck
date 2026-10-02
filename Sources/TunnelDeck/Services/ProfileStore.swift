import AppKit
import CoreImage.CIFilterBuiltins
import Foundation
import SwiftUI

struct LocalProfile: Identifiable, Hashable, Sendable {
    var id: String { url.path }
    let url: URL
    let modified: Date
    var name: String { url.lastPathComponent }
    var type: String { url.pathExtension.lowercased() == "ovpn" ? "OpenVPN" : "WireGuard" }
}

enum ProfileStore {
    static let profilesURL: URL = {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("TunnelDeck/Profiles", isDirectory: true)
    }()
    static let homeAccessURL: URL = {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("TunnelDeck/HomeAccess", isDirectory: true)
    }()

    static func prepare() throws {
        for url in [profilesURL, homeAccessURL] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        }
    }

    static func saveConfiguration(_ content: String, name: String) throws -> LocalProfile {
        guard name.range(of: #"^[A-Za-z0-9_-]{1,48}$"#, options: .regularExpression) != nil else { throw CommandPolicyError.deniedCommand }
        try prepare()
        let url = profilesURL.appendingPathComponent(name).appendingPathExtension("conf")
        try Data(content.utf8).write(to: url, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return LocalProfile(url: url, modified: Date())
    }

    static func list(in directory: URL = profilesURL) -> [LocalProfile] {
        (try? prepare())
        let keys: Set<URLResourceKey> = [.contentModificationDateKey, .isRegularFileKey]
        return ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: Array(keys))) ?? []).compactMap { url in
            guard ["conf", "ovpn"].contains(url.pathExtension.lowercased()), let values = try? url.resourceValues(forKeys: keys), values.isRegularFile == true else { return nil }
            return LocalProfile(url: url, modified: values.contentModificationDate ?? .distantPast)
        }.sorted { $0.modified > $1.modified }
    }

    static func delete(_ profile: LocalProfile) throws { try FileManager.default.removeItem(at: profile.url) }
    static func reveal(_ profile: LocalProfile) { NSWorkspace.shared.activateFileViewerSelecting([profile.url]) }
    static func revealURL(_ url: URL) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    static func open(_ profile: LocalProfile) { NSWorkspace.shared.open(profile.url) }
    static func content(_ profile: LocalProfile) throws -> String { try String(contentsOf: profile.url, encoding: .utf8) }

    static func qrImage(for value: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        let context = CIContext()
        guard let cgImage = context.createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: cgImage.width, height: cgImage.height))
    }
}
