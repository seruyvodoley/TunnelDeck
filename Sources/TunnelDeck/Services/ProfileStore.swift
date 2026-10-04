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
    enum ProfileError:Error{case invalidName,invalidType,outsideDirectory}
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

    static func importHomeAccess(from source:URL,name:String?=nil,directory:URL=homeAccessURL)throws->LocalProfile{
        let ext=source.pathExtension.lowercased();guard ext=="conf" else{throw ProfileError.invalidType};let stem=name ?? source.deletingPathExtension().lastPathComponent;guard validName(stem)else{throw ProfileError.invalidName};try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]);let destination=directory.appendingPathComponent(stem).appendingPathExtension("conf");guard contained(destination,in:directory)else{throw ProfileError.outsideDirectory};let access=source.startAccessingSecurityScopedResource();defer{if access{source.stopAccessingSecurityScopedResource()}};try Data(contentsOf:source).write(to:destination,options:[.atomic,.completeFileProtection]);try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:destination.path);return LocalProfile(url:destination,modified:Date())
    }
    static func rename(_ profile:LocalProfile,name:String,in directory:URL=homeAccessURL)throws->LocalProfile{guard validName(name),contained(profile.url,in:directory)else{throw ProfileError.invalidName};let destination=directory.appendingPathComponent(name).appendingPathExtension(profile.url.pathExtension);guard contained(destination,in:directory)else{throw ProfileError.outsideDirectory};try FileManager.default.moveItem(at:profile.url,to:destination);try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:destination.path);return LocalProfile(url:destination,modified:Date())}
    static func delete(_ profile: LocalProfile) throws { try FileManager.default.removeItem(at: profile.url) }
    static func delete(_ profile:LocalProfile,within directory:URL)throws{guard contained(profile.url,in:directory)else{throw ProfileError.outsideDirectory};try FileManager.default.removeItem(at:profile.url)}
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
    static func validName(_ value:String)->Bool{value.range(of:#"^[A-Za-z0-9][A-Za-z0-9 _-]{0,47}$"#,options:.regularExpression) != nil}
    static func contained(_ url:URL,in directory:URL)->Bool{let root=directory.standardizedFileURL.resolvingSymlinksInPath().path+"/",candidate=url.standardizedFileURL.resolvingSymlinksInPath().path;return candidate.hasPrefix(root)}
}
