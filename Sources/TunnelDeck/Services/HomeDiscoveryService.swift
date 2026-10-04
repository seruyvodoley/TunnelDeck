import Foundation

enum HomeDiscoveryParser{
    static func arp(_ text:String)->[HomeDiscoveryRecord]{text.split(separator:"\n").compactMap{line in
        let value=String(line);guard let ip=value.firstMatch(of:/\(([0-9.]+)\)/)?.1 else{return nil};let fields=value.split(whereSeparator:\.isWhitespace);guard let at=fields.firstIndex(of:"at"),fields.indices.contains(at+1)else{return nil};let raw=String(fields[at+1]);guard raw != "(incomplete)",let mac=HomeDeviceIdentity.normalizedMAC(raw)else{return nil};let host=fields.first.map(String.init).flatMap{$0=="?" ? nil:$0};return HomeDiscoveryRecord(ip:String(ip),mac:mac,hostname:host,source:.arp,evidence:"Fresh ARP neighbour")}}
    static func ndp(_ text:String)->[HomeDiscoveryRecord]{text.split(separator:"\n").compactMap{line in
        let fields=line.split(whereSeparator:\.isWhitespace);guard fields.count>=3 else{return nil};let ip=String(fields[0]).split(separator:"%").first.map(String.init) ?? "";guard ip.contains(":"),!ip.lowercased().contains("neighbor") else{return nil};let mac=HomeDeviceIdentity.normalizedMAC(String(fields[1]));guard mac != nil else{return nil};return HomeDiscoveryRecord(ip:ip,mac:mac,hostname:nil,source:.ndp,evidence:"Fresh IPv6 neighbour")}}
    static func route(_ text:String)->(gateway:String?,interface:String?){var gateway:String?,interface:String?;for line in text.split(separator:"\n"){let pair=line.split(separator:":",maxSplits:1).map{String($0).trimmingCharacters(in:.whitespaces)};guard pair.count==2 else{continue};if pair[0]=="gateway"{gateway=pair[1]};if pair[0]=="interface"{interface=pair[1]}};return(gateway,interface)}
}

actor LocalCommandRunner{
    private var process:Process?
    func run(_ executable:String,_ arguments:[String])async throws->String{
        guard process==nil else{throw CancellationError()};let task=Process(),pipe=Pipe();task.executableURL=URL(fileURLWithPath:executable);task.arguments=arguments;task.standardOutput=pipe;task.standardError=Pipe();process=task
        defer{if process === task{process=nil};try? pipe.fileHandleForReading.close()}
        return try await withTaskCancellationHandler{try await withCheckedThrowingContinuation{continuation in task.terminationHandler={finished in let data=pipe.fileHandleForReading.readDataToEndOfFile();finished.terminationHandler=nil;continuation.resume(returning:finished.terminationStatus==0 ? String(decoding:data,as:UTF8.self):"")};do{try task.run()}catch{task.terminationHandler=nil;continuation.resume(throwing:error)}}}onCancel:{Task{await self.cancel()}}
    }
    func cancel(){if let process,process.isRunning{process.terminate()}}
    func activeProcessCount()->Int{process == nil ? 0:1}
}

actor HomeDiscoveryService{
    private let runner:LocalCommandRunner
    init(runner:LocalCommandRunner=LocalCommandRunner()){self.runner=runner}
    func discover(configuration:HomeNetwork?)async throws->(HomeNetworkSnapshot,[HomeDiscoveryRecord]){
        async let arp=runner.run("/usr/sbin/arp",["-an"])
        let arpText=(try? await arp) ?? ""
        try Task.checkCancellation()
        let ndpText=(try? await runner.run("/usr/sbin/ndp",["-an"])) ?? ""
        let defaultRoute=(try? await runner.run("/sbin/route",["-n","get","default"])) ?? "",route=HomeDiscoveryParser.route(defaultRoute)
        let localValue=LocalNetworkService.lanIPv4(),lanIP=(localValue.isEmpty || localValue=="—") ? nil:localValue
        var snapshot=HomeNetworkSnapshot(macLANIP:lanIP,probableSubnet:lanIP.flatMap(Self.suggestedCIDR),defaultGateway:route.gateway,interface:route.interface)
        if let configuration,!configuration.cidr.isEmpty{
            if let lanIP,Self.contains(configuration.cidr,ip:lanIP){snapshot.mode = .homeLAN;snapshot.routeEvidence="Local address belongs to configured Home LAN"}
            else if !configuration.routerIP.isEmpty{let target=(try? await runner.run("/sbin/route",["-n","get",configuration.routerIP])) ?? "",path=HomeDiscoveryParser.route(target);if let interface=path.interface,interface.hasPrefix("utun"){snapshot.mode = .remote;snapshot.routeEvidence="Verified route through \(interface)"}else if lanIP != nil{snapshot.mode = .other;snapshot.routeEvidence="No verified route to configured Home LAN"}}
        }else if lanIP != nil{snapshot.mode = .other;snapshot.routeEvidence="Configure and confirm the Home LAN CIDR"}
        let records=(HomeDiscoveryParser.arp(arpText)+HomeDiscoveryParser.ndp(ndpText)).filter{record in
            guard record.ip != lanIP,record.mac != "ff:ff:ff:ff:ff:ff" else{return false}
            if let first=Int(record.ip.split(separator:".").first ?? ""),(224...239).contains(first){return false}
            return true
        }
        return(snapshot,records)
    }
    func cancel()async{await runner.cancel()}
    func activeProcessCount()async->Int{await runner.activeProcessCount()}
    static func suggestedCIDR(_ ip:String)->String?{let parts=ip.split(separator:".");guard parts.count==4,parts.allSatisfy({UInt8($0) != nil})else{return nil};return parts.prefix(3).joined(separator:".")+".0/24"}
    static func contains(_ cidr:String,ip:String)->Bool{let parts=cidr.split(separator:"/"),address=ip.split(separator:".").compactMap{UInt32($0)};guard parts.count==2,let bits=Int(parts[1]),bits>=0,bits<=32,address.count==4 else{return false};let network=parts[0].split(separator:".").compactMap{UInt32($0)};guard network.count==4 else{return false};func value(_ p:[UInt32])->UInt32{p.reduce(0){($0<<8)|$1}};let mask:UInt32=bits==0 ? 0:UInt32.max << UInt32(32-bits);return value(address)&mask == value(network)&mask}
}
