import Foundation

enum HomeDeviceType:String,Codable,Sendable,CaseIterable,Identifiable{
    case mac="Mac",computer="PC / Laptop",phone="Phone",tablet="Tablet",router="Router",printer="Printer",nas="NAS",smartTV="Smart TV",iot="IoT",vacuum="Vacuum",server="Server",unknown="Unknown",custom="Custom"
    var id:String{rawValue}
}

enum HomeDeviceReachability:String,Codable,Sendable{case online,offline,unknown}
enum HomeDiscoverySource:String,Codable,Sendable,CaseIterable{case arp,ndp,bonjour,manual}
enum HomeNetworkMode:String,Codable,Sendable{case homeLAN="HOME LAN",remote="REMOTE HOME ACCESS",other="OTHER NETWORK",unknown="UNKNOWN"}

struct HomeNetwork:Identifiable,Codable,Sendable,Equatable{
    var id=UUID();var name="Home";var cidr="";var routerIP="";var notes="";var createdAt=Date();var updatedAt=Date()
}

struct HomeDevice:Identifiable,Codable,Sendable,Hashable{
    var id=UUID();var displayName:String;var hostname:String?;var ipv4:String?;var ipv6:String?;var macAddress:String?;var vendor:String?;var type:HomeDeviceType;var customType:String?;var status:HomeDeviceReachability;var lastSeen:Date?;var firstSeen:Date;var discoverySources:Set<HomeDiscoverySource>;var isPinned=false;var notes:String?;var preferredAccessURL:String?;var preferredSSHHost:String?;var nameIsManual=false;var typeIsManual=false;var reachabilityEvidence:String?;var lastSuccessfulObservation:Date?
}

struct HomeDeviceObservation:Identifiable,Codable,Sendable{
    var id=UUID();let deviceID:UUID;let timestamp:Date;let status:HomeDeviceReachability;let evidence:String;let ip:String?;let source:HomeDiscoverySource
}

struct HomeDiscoveryRecord:Sendable,Equatable{
    let ip:String;let mac:String?;let hostname:String?;let source:HomeDiscoverySource;let evidence:String
}

struct HomeNetworkSnapshot:Sendable,Equatable{
    var macLANIP:String?;var probableSubnet:String?;var defaultGateway:String?;var interface:String?;var mode:HomeNetworkMode = .unknown;var routeEvidence:String="No verified route"
}

enum HomeDeviceIdentity{
    static func normalizedMAC(_ value:String?)->String?{guard let value else{return nil};let cleaned=value.lowercased().replacingOccurrences(of:"-",with:":");let parts=cleaned.split(separator:":");guard parts.count==6,parts.allSatisfy({(1...2).contains($0.count) && $0.allSatisfy(\.isHexDigit)})else{return nil};return parts.map{$0.count==1 ? "0\($0)":String($0)}.joined(separator:":")}
    static func stableID(mac:String?,manualID:UUID?=nil,ip:String?,hostname:String?)->UUID{
        if let manualID{return manualID};let key=normalizedMAC(mac).map{"mac|\($0)"} ?? "fallback|\(hostname?.lowercased() ?? "")|\(ip ?? "")";var bytes=[UInt8](repeating:0,count:16);for(index,byte)in key.utf8.enumerated(){bytes[index%16]=bytes[index%16]&*31&+byte};return UUID(uuid:(bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
    }
}

enum HomeDeviceReconciler{
    static func merge(existing:HomeDevice?,record:HomeDiscoveryRecord,now:Date=Date())->HomeDevice{
        let mac=HomeDeviceIdentity.normalizedMAC(record.mac)
        var device=existing ?? HomeDevice(id:HomeDeviceIdentity.stableID(mac:mac,ip:record.ip,hostname:record.hostname),displayName:record.hostname ?? record.ip,hostname:record.hostname,ipv4:nil,ipv6:nil,macAddress:mac,vendor:nil,type:.unknown,customType:nil,status:.online,lastSeen:now,firstSeen:now,discoverySources:[],reachabilityEvidence:record.evidence,lastSuccessfulObservation:now)
        if !device.nameIsManual,let hostname=record.hostname{device.displayName=hostname}
        device.hostname=device.hostname ?? record.hostname;device.macAddress=mac ?? device.macAddress
        if record.ip.contains(":"){device.ipv6=record.ip}else{device.ipv4=record.ip}
        device.status = .online;device.lastSeen=now;device.lastSuccessfulObservation=now;device.reachabilityEvidence=record.evidence;device.discoverySources.insert(record.source)
        return device
    }
}

enum HomePresence{
    static func status(lastSeen:Date?,now:Date=Date(),homeMode:HomeNetworkMode)->HomeDeviceReachability{guard let lastSeen else{return .unknown};let age=now.timeIntervalSince(lastSeen);if age<=120{return .online};if homeMode == .homeLAN && age>=86_400{return .offline};return .unknown}
    static func label(_ date:Date?,now:Date=Date())->String{guard let date else{return "Never confirmed"};let age=now.timeIntervalSince(date);if age<90{return "Seen now"};return "Seen \(date.formatted(.relative(presentation:.numeric)))"}
}
