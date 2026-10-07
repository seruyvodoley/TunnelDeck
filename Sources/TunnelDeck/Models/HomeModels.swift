import Foundation

enum HomeDeviceType:String,Codable,Sendable,CaseIterable,Identifiable{
    case mac="Mac",computer="PC / Laptop",phone="Phone",tablet="Tablet",router="Router",printer="Printer",nas="NAS",smartTV="Smart TV",iot="IoT",vacuum="Vacuum",server="Server",unknown="Unknown",custom="Custom"
    var id:String{rawValue}
}

enum HomeDeviceReachability:String,Codable,Sendable{case online,offline,unknown}
enum HomeDiscoverySource:String,Codable,Sendable,CaseIterable{case routerClient="router-client",routerDHCP="router-dhcp",routerWireless="router-wireless",routerWired="router-wired",arp,ndp,bonjour,manual}
enum HomeNetworkMode:String,Codable,Sendable{case homeLAN="HOME LAN",remote="REMOTE HOME ACCESS",other="OTHER NETWORK",unknown="UNKNOWN"}
enum HomeRouterState:String,Codable,Sendable{case connected="Connected",authenticationRequired="Authentication Required",unavailable="Unavailable",notConfigured="Not Configured"}
enum HomeConnectionType:String,Codable,Sendable{case ethernet="Ethernet",wifi24="Wi-Fi 2.4 GHz",wifi5="Wi-Fi 5 GHz",wifi6="Wi-Fi 6",wifi="Wi-Fi",unknown="Unknown"}

struct HomeNetwork:Identifiable,Codable,Sendable,Equatable{
    var id=UUID();var name="Home";var cidr="";var routerIP="";var notes="";var createdAt=Date();var updatedAt=Date()
}

struct HomeDevice:Identifiable,Codable,Sendable,Hashable{
    var id=UUID();var displayName:String;var hostname:String?;var ipv4:String?;var ipv6:String?;var macAddress:String?;var vendor:String?;var type:HomeDeviceType;var customType:String?;var status:HomeDeviceReachability;var lastSeen:Date?;var firstSeen:Date;var discoverySources:Set<HomeDiscoverySource>;var isPinned=false;var notes:String?;var preferredAccessURL:String?;var preferredSSHHost:String?;var nameIsManual=false;var typeIsManual=false;var reachabilityEvidence:String?;var lastSuccessfulObservation:Date?;var routerDisplayName:String?;var routerConnectionType:HomeConnectionType?;var routerLastSeen:Date?;var routerOnline:Bool?
}

struct HomeDeviceObservation:Identifiable,Codable,Sendable{
    var id=UUID();let deviceID:UUID;let timestamp:Date;let status:HomeDeviceReachability;let evidence:String;let ip:String?;let source:HomeDiscoverySource
}

struct HomeDiscoveryRecord:Sendable,Equatable{
    let ip:String;let mac:String?;let hostname:String?;let source:HomeDiscoverySource;let evidence:String;var routerDisplayName:String?=nil;var connectionType:HomeConnectionType?=nil;var online:Bool?=nil
}

struct HomeDiscoveryDiagnostics:Sendable,Equatable{
    var mode="Passive";var candidates=0;var initialARP=0;var finalARP=0;var ndp=0;var routerRecords=0;var reconciled=0;var duration:TimeInterval=0;var message:String?
}

struct HomeNetworkSnapshot:Sendable,Equatable{
    var macLANIP:String?;var probableSubnet:String?;var defaultGateway:String?;var interface:String?;var mode:HomeNetworkMode = .unknown;var routeEvidence:String="No verified route";var routerConfigurationWarning:String?
}

enum HomeDeviceIdentity{
    static func normalizedMAC(_ value:String?)->String?{guard let value else{return nil};let cleaned=value.lowercased().replacingOccurrences(of:"-",with:":");let parts=cleaned.split(separator:":");guard parts.count==6,parts.allSatisfy({(1...2).contains($0.count) && $0.allSatisfy(\.isHexDigit)})else{return nil};let normalized=parts.map{$0.count==1 ? "0\($0)":String($0)}.joined(separator:":");guard normalized != "02:00:00:00:00:00",normalized != "00:00:00:00:00:00" else{return nil};return normalized}
    static func stableID(mac:String?,manualID:UUID?=nil,ip:String?,hostname:String?)->UUID{
        if let manualID{return manualID};let key=normalizedMAC(mac).map{"mac|\($0)"} ?? "fallback|\(hostname?.lowercased() ?? "")|\(ip ?? "")";var bytes=[UInt8](repeating:0,count:16);for(index,byte)in key.utf8.enumerated(){bytes[index%16]=bytes[index%16]&*31&+byte};return UUID(uuid:(bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
    }
}

enum HomeDeviceReconciler{
    static func merge(existing:HomeDevice?,record:HomeDiscoveryRecord,now:Date=Date())->HomeDevice{
        let mac=HomeDeviceIdentity.normalizedMAC(record.mac)
        var device=existing ?? HomeDevice(id:HomeDeviceIdentity.stableID(mac:mac,ip:record.ip,hostname:record.hostname),displayName:record.hostname ?? record.ip,hostname:record.hostname,ipv4:nil,ipv6:nil,macAddress:mac,vendor:nil,type:.unknown,customType:nil,status:.online,lastSeen:now,firstSeen:now,discoverySources:[],reachabilityEvidence:record.evidence,lastSuccessfulObservation:now)
        if !device.nameIsManual{if let routerName=record.routerDisplayName,!routerName.isEmpty{device.displayName=routerName}else if let hostname=record.hostname{device.displayName=hostname}}
        device.hostname=device.hostname ?? record.hostname;device.macAddress=mac ?? device.macAddress
        if record.ip.contains(":"){device.ipv6=record.ip}else{device.ipv4=record.ip}
        let isOnline=record.online == true || record.source == .arp || record.source == .ndp
        if isOnline{device.status = .online;device.lastSeen=now;device.lastSuccessfulObservation=now}
        else if existing == nil{device.status = .unknown;device.lastSeen=nil;device.lastSuccessfulObservation=nil}
        device.reachabilityEvidence=record.evidence;device.discoverySources.insert(record.source)
        if record.source == .routerClient || record.source == .routerWireless || record.source == .routerWired || record.source == .routerDHCP{device.routerDisplayName=record.routerDisplayName;device.routerConnectionType=record.connectionType;device.routerLastSeen=now;device.routerOnline=record.online}
        return device
    }
}

enum HomePresence{
    static func status(lastSeen:Date?,now:Date=Date(),homeMode:HomeNetworkMode)->HomeDeviceReachability{guard let lastSeen else{return .unknown};let age=now.timeIntervalSince(lastSeen);if age<=120{return .online};if homeMode == .homeLAN && age>=86_400{return .offline};return .unknown}
    static func retainedStatus(current:HomeDeviceReachability,lastSeen:Date?,now:Date=Date(),homeMode:HomeNetworkMode)->HomeDeviceReachability{
        let inferred=status(lastSeen:lastSeen,now:now,homeMode:homeMode)
        return inferred == .unknown ? current:inferred
    }
    static func label(_ date:Date?,now:Date=Date())->String{guard let date else{return "Never confirmed"};let age=now.timeIntervalSince(date);if age<90{return "Seen now"};return "Seen \(date.formatted(.relative(presentation:.numeric)))"}
}
