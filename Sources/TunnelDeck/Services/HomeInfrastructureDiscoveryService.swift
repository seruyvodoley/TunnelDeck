import Foundation

actor HomeInfrastructureDiscoveryService{
    private let ssh:SSHService
    init(ssh:SSHService){self.ssh=ssh}

    func discover(vpsConfiguration:SSHConfiguration,gatewayConfigurations:[SSHConfiguration],homeNetwork:HomeNetwork?,homeDeviceCount:Int,handshakeTimeout:TimeInterval)async->HomeInfrastructureSnapshot{
        let attempted=Date()
        async let vpsResult:CommandResult? = safeExecute(.topologyVPS,configuration:vpsConfiguration)
        let gatewayResult=await firstOpenWrt(in:gatewayConfigurations)
        let vps=await vpsResult

        var snapshot=HomeInfrastructureSnapshot(homeCIDR:homeNetwork?.cidr.nonEmptyValue,homeDeviceCount:homeDeviceCount,lastAttemptAt:attempted)
        if let vps{
            let parsed=HomeInfrastructureParser.vps(vps.stdout,commandSucceeded:vps.succeeded,now:attempted,handshakeTimeout:handshakeTimeout)
            snapshot.vpsPolicy=parsed.policy
            snapshot.vpsTunnels=parsed.tunnels
        }
        if let gatewayResult{
            let parsed=HomeInfrastructureParser.openWrt(gatewayResult.result.stdout,host:gatewayResult.configuration.host,commandSucceeded:gatewayResult.result.succeeded,now:attempted,handshakeTimeout:handshakeTimeout,vpsTunnels:snapshot.vpsTunnels)
            snapshot.gateway=parsed.gateway
            snapshot.gatewayTunnels=parsed.tunnels
        }

        if snapshot.gateway.state == .online || snapshot.vpsPolicy.state == .online{
            snapshot.observedAt=attempted
        }
        let gatewayLabel=snapshot.gateway.host.map{"OpenWrt \($0)"} ?? "OpenWrt unavailable"
        let vpsLabel=snapshot.vpsPolicy.state == .online ? "VPS policy observed":"VPS policy unavailable"
        snapshot.sourceSummary="\(gatewayLabel) · \(vpsLabel)"
        return snapshot
    }

    private func safeExecute(_ command:ReadCommand,configuration:SSHConfiguration)async->CommandResult?{
        guard !configuration.host.isEmpty else{return nil}
        return try? await ssh.execute(command,configuration:configuration)
    }

    private func firstOpenWrt(in configurations:[SSHConfiguration])async->(configuration:SSHConfiguration,result:CommandResult)?{
        for configuration in configurations{
            guard let result=await safeExecute(.topologyOpenWrt,configuration:configuration),result.succeeded else{continue}
            let sections=TaggedDiscoveryOutput.sections(result.stdout)
            guard let board=sections["BOARD"],board.localizedCaseInsensitiveContains("OpenWrt") else{continue}
            return(configuration,result)
        }
        return nil
    }
}

enum TaggedDiscoveryOutput{
    static func sections(_ text:String)->[String:String]{
        var result:[String:[String]]=[:],current:String?
        for raw in text.components(separatedBy:.newlines){
            let line=raw.trimmingCharacters(in:.whitespacesAndNewlines)
            if line.hasPrefix("__TD_"),line.hasSuffix("__"){
                current=String(line.dropFirst(5).dropLast(2))
                if let current,result[current]==nil{result[current]=[]}
            }else if let current{result[current,default:[]].append(raw)}
        }
        return result.mapValues{$0.joined(separator:"\n").trimmingCharacters(in:.whitespacesAndNewlines)}
    }
}

enum HomeInfrastructureParser{
    struct OpenWrtResult:Sendable{var gateway:OpenWrtGatewaySnapshot;var tunnels:[InfrastructureTunnelSnapshot]}
    struct VPSResult:Sendable{var policy:VPSPolicySnapshot;var tunnels:[InfrastructureTunnelSnapshot]}

    static func openWrt(_ text:String,host:String,commandSucceeded:Bool,now:Date,handshakeTimeout:TimeInterval,vpsTunnels:[InfrastructureTunnelSnapshot])->OpenWrtResult{
        let sections=TaggedDiscoveryOutput.sections(text)
        var gateway=OpenWrtGatewaySnapshot(host:host,observedAt:commandSucceeded ? now:nil,evidence:commandSucceeded ? "Read-only SSH discovery from \(host)":nil)
        if commandSucceeded,let board=sections["BOARD"],board.localizedCaseInsensitiveContains("OpenWrt"){
            gateway.state = .online
            if let data=board.data(using:.utf8),let root=try? JSONSerialization.jsonObject(with:data)as? [String:Any]{
                gateway.hostname=root["hostname"] as? String
                gateway.model=root["model"] as? String
                if let release=root["release"] as? [String:Any]{
                    gateway.version=(release["description"] as? String) ?? (release["version"] as? String)
                }
            }
        }
        gateway.uptime=sections["UPTIME"]?.nonEmptyValue
        gateway.lanIPv4=interfaceAddress("br-lan",in:sections["INTERFACES"] ?? "")
        let mainDefault=parseDefaultRoute(sections["ROUTES"] ?? "",preferredTable:nil)
        gateway.defaultGateway=mainDefault.gateway
        gateway.defaultInterface=mainDefault.interface
        gateway.ipv4Forwarding=parseBool(sections["FORWARD"])
        parseDHCP(sections["DHCP"] ?? "",into:&gateway)

        let routes=sections["ROUTES"] ?? "",rules=sections["RULES"] ?? ""
        let markedPolicies=parseMarkedPolicies(rules:rules,routes:routes)
        if let foreign=markedPolicies.first(where:{$0.interface != nil && $0.interface != gateway.defaultInterface}){
            gateway.foreignMark=foreign.mark;gateway.foreignPriority=foreign.priority;gateway.foreignTable=foreign.table;gateway.foreignInterface=foreign.interface
        }
        gateway.ruPrefixCount=countNFTElements(sections["RU4"] ?? "")
        gateway.nftEvidence=(sections["NFT_HINTS"] ?? "").split(separator:"\n").map(String.init)
        gateway.directExceptions=parseDirectExceptions(sections["DIRECT"] ?? "")
        gateway.scripts=(sections["SCRIPTS"] ?? "").split(separator:"\n").map(String.init).filter{!$0.isEmpty}

        let allTunnelText=[sections["WG"] ?? "",sections["AWG"] ?? ""].joined(separator:"\n")
        var tunnels=parseTunnels(allTunnelText,interfaces:sections["INTERFACES"] ?? "",links:sections["LINKS"] ?? "",commandSucceeded:commandSucceeded,observedOn:"OpenWrt",now:now,handshakeTimeout:handshakeTimeout)
        if let foreign=gateway.foreignInterface{assignRole("Foreign Exit",to:foreign,in:&tunnels)}
        if let homeExit=vpsTunnels.first(where:{$0.role=="Remote RU Home Exit"})?.name{assignRole("Remote RU Home Exit",to:homeExit,in:&tunnels)}

        if let wg0=vpsTunnels.first(where:{$0.name=="wg0"})?.localAddress{
            gateway.managementInterface=findRouteInterface(to:wg0,in:routes,excluding:Set([gateway.defaultInterface,gateway.foreignInterface].compactMap{$0}))
            if let management=gateway.managementInterface{assignRole("Remote Home LAN Management",to:management,in:&tunnels)}
        }
        return OpenWrtResult(gateway:gateway,tunnels:tunnels)
    }

    static func vps(_ text:String,commandSucceeded:Bool,now:Date,handshakeTimeout:TimeInterval)->VPSResult{
        let sections=TaggedDiscoveryOutput.sections(text)
        var policy=VPSPolicySnapshot(state:commandSucceeded ? .online:.unknown,observedAt:commandSucceeded ? now:nil,evidence:commandSucceeded ? "Read-only VPS SSH policy discovery":nil)
        let routes=sections["ROUTES"] ?? "",rules=sections["RULES"] ?? ""
        policy.publicInterface=parseDefaultRoute(routes,preferredTable:"main").interface ?? parseDefaultRoute(routes,preferredTable:nil).interface
        policy.ruPrefixCount=Int((sections["RU_COUNT"] ?? "").trimmingCharacters(in:.whitespacesAndNewlines))
        let policies=parseMarkedPolicies(rules:rules,routes:routes)
        if let ru=policies.first(where:{$0.interface != nil && $0.interface != policy.publicInterface}){
            policy.ruMark=ru.mark;policy.ruPriority=ru.priority;policy.ruTable=ru.table;policy.homeExitInterface=ru.interface
        }
        let allTunnelText=[sections["WG"] ?? "",sections["AWG"] ?? ""].joined(separator:"\n")
        var tunnels=parseTunnels(allTunnelText,interfaces:sections["INTERFACES"] ?? "",links:sections["LINKS"] ?? "",commandSucceeded:commandSucceeded,observedOn:"VPS",now:now,handshakeTimeout:handshakeTimeout)
        if let homeExit=policy.homeExitInterface{assignRole("Remote RU Home Exit",to:homeExit,in:&tunnels)}
        if tunnels.contains(where:{$0.name=="wg0"}){assignRole("Remote Access VPN",to:"wg0",in:&tunnels)}
        return VPSResult(policy:policy,tunnels:tunnels)
    }

    private struct MarkedPolicy{var priority:Int?;var mark:String?;var table:String?;var interface:String?}

    private static func parseMarkedPolicies(rules:String,routes:String)->[MarkedPolicy]{
        var result:[MarkedPolicy]=[]
        for raw in rules.split(separator:"\n"){
            let line=String(raw),lower=line.lowercased()
            guard lower.contains("fwmark"),lower.contains("lookup") else{continue}
            let tokens=line.replacingOccurrences(of:":",with:" : ").split(whereSeparator:\.isWhitespace).map(String.init)
            let priority=Int(tokens.first?.trimmingCharacters(in:CharacterSet(charactersIn:":")) ?? "")
            let mark=value(after:"fwmark",tokens:tokens)
            guard let table=value(after:"lookup",tokens:tokens) ?? value(after:"table",tokens:tokens) else{continue}
            let route=parseDefaultRoute(routes,preferredTable:table)
            result.append(MarkedPolicy(priority:priority,mark:mark,table:table,interface:route.interface))
        }
        return result
    }

    private static func parseDefaultRoute(_ text:String,preferredTable:String?)->(gateway:String?,interface:String?){
        for raw in text.split(separator:"\n"){
            let line=String(raw),tokens=line.split(whereSeparator:\.isWhitespace).map(String.init)
            guard tokens.first=="default" else{continue}
            if let preferredTable{
                if preferredTable=="main"{
                    if line.contains(" table ") {continue}
                }else if !line.contains("table \(preferredTable)") && !line.contains("lookup \(preferredTable)") {continue}
            }else if line.contains(" table ") {continue}
            return(value(after:"via",tokens:tokens),value(after:"dev",tokens:tokens))
        }
        if let preferredTable{
            for raw in text.split(separator:"\n"){
                let line=String(raw),tokens=line.split(whereSeparator:\.isWhitespace).map(String.init)
                guard tokens.first=="default",line.contains("table \(preferredTable)") else{continue}
                return(value(after:"via",tokens:tokens),value(after:"dev",tokens:tokens))
            }
        }
        return(nil,nil)
    }

    private static func parseDHCP(_ text:String,into gateway:inout OpenWrtGatewaySnapshot){
        let values=Dictionary(uniqueKeysWithValues:text.split(separator:"\n").compactMap{raw->(String,String)? in
            let pair=raw.split(separator:"=",maxSplits:1,omittingEmptySubsequences:false)
            guard pair.count==2 else{return nil};return(String(pair[0]),String(pair[1]))
        })
        let dnsmasq=values["dnsmasq"]=="active"
        gateway.dhcpServer=dnsmasq && values["ignore"] != "1"
        gateway.dnsServer=dnsmasq
        gateway.filterAAAA=parseBool(values["filter_aaaa"])
        gateway.upstreamDNS=(values["servers"] ?? "").split(whereSeparator:{ $0==" " || $0=="," }).map(String.init).filter{IPv4Validator.isValid($0)}
    }

    private static func parseTunnels(_ text:String,interfaces:String,links:String,commandSucceeded:Bool,observedOn:String,now:Date,handshakeTimeout:TimeInterval)->[InfrastructureTunnelSnapshot]{
        let blocks=interfaceBlocks(text)
        var result:[InfrastructureTunnelSnapshot]=[]
        for(name,block)in blocks{
            var parsed=WireGuardParser.parse(block,now:now,timeout:handshakeTimeout)
            parsed.interface=name
            let peer=parsed.peers.first
            let local=interfaceAddress(name,in:interfaces)
            let state:HealthState
            if let peer{state=peer.latestHandshake == nil ? .warning:peer.status}else{state=.online}
            result.append(InfrastructureTunnelSnapshot(name:name,role:"Discovered Tunnel",transport:name.lowercased().contains("awg") ? "AmneziaWG":"WireGuard",localAddress:local,peerAddress:peerAddress(from:local,allowed:peer?.vpnIP),endpoint:peer?.endpoint=="—" ? nil:peer?.endpoint,listenPort:Int(parsed.listenPort),mtu:linkMTU(name,in:links),latestHandshake:peer?.latestHandshake,receivedBytes:parsed.receivedBytes,sentBytes:parsed.sentBytes,state:state,observedOn:[observedOn],evidence:"Interface observed by \(observedOn) SSH"))
        }
        if commandSucceeded{
            for expected in ["awgtd0","homeexit","tdhome"] where !result.contains(where:{$0.name==expected}){
                // A successful discovery explicitly proves these legacy names are absent, but dynamic policy names are handled separately.
            }
        }
        return result.sorted{$0.name<$1.name}
    }

    private static func interfaceBlocks(_ text:String)->[String:String]{
        var result:[String:[String]]=[:],current:String?
        for raw in text.components(separatedBy:.newlines){
            let line=raw.trimmingCharacters(in:.whitespaces)
            if line.hasPrefix("interface:"){
                current=line.split(separator:":",maxSplits:1).last.map{$0.trimmingCharacters(in:.whitespaces)}
            }
            if let current{result[current,default:[]].append(raw)}
        }
        return result.mapValues{$0.joined(separator:"\n")}
    }

    private static func interfaceAddress(_ name:String,in text:String)->String?{
        for raw in text.split(separator:"\n"){
            let tokens=raw.split(whereSeparator:\.isWhitespace).map(String.init)
            guard tokens.first==name else{continue}
            return tokens.first(where:{$0.contains(".") && $0.contains("/")})
        }
        return nil
    }

    private static func linkMTU(_ name:String,in text:String)->Int?{
        let lines=text.components(separatedBy:.newlines)
        for(index,line)in lines.enumerated() where line.contains("\(name):") || line.contains(" \(name):"){
            let sample=([line]+lines.dropFirst(index+1).prefix(1)).joined(separator:" ")
            let tokens=sample.split(whereSeparator:\.isWhitespace).map(String.init)
            if let value=value(after:"mtu",tokens:tokens),let mtu=Int(value){return mtu}
        }
        return nil
    }

    private static func peerAddress(from local:String?,allowed:String?)->String?{
        if let allowed,allowed != "—",allowed != "0.0.0.0/0",let first=allowed.split(separator:",").first{return String(first)}
        guard let local else{return nil}
        let parts=local.split(separator:"/"),octets=parts[0].split(separator:".").compactMap{Int($0)}
        guard parts.count==2,parts[1]=="30",octets.count==4 else{return nil}
        let last=octets[3],peer=last%4==1 ? last+1:last%4==2 ? last-1:-1
        guard peer>=0 else{return nil}
        return "\(octets[0]).\(octets[1]).\(octets[2]).\(peer)/30"
    }

    private static func findRouteInterface(to ipWithCIDR:String,in routes:String,excluding:Set<String>)->String?{
        let ip=ipWithCIDR.split(separator:"/").first.map(String.init) ?? ipWithCIDR
        for raw in routes.split(separator:"\n"){
            let line=String(raw),tokens=line.split(whereSeparator:\.isWhitespace).map(String.init)
            guard let destination=tokens.first,destination.contains("/"),HomeDiscoveryService.contains(destination,ip:ip),let dev=value(after:"dev",tokens:tokens),!excluding.contains(dev) else{continue}
            return dev
        }
        return nil
    }

    private static func countNFTElements(_ text:String)->Int?{
        guard text.contains("set ") else{return nil}
        guard let start=text.range(of:"elements = {") else{return 0}
        let tail=text[start.upperBound...]
        guard let end=tail.firstIndex(of:"}") else{return nil}
        let body=tail[..<end].trimmingCharacters(in:.whitespacesAndNewlines)
        if body.isEmpty{return 0}
        return body.split(separator:",").count
    }

    private static func parseDirectExceptions(_ text:String)->[String]{
        let regex=try? NSRegularExpression(pattern:#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#)
        let ns=text as NSString
        let matches=regex?.matches(in:text,range:NSRange(location:0,length:ns.length)) ?? []
        var seen=Set<String>(),result:[String]=[]
        for match in matches{
            let ip=ns.substring(with:match.range)
            guard IPv4Validator.isValid(ip),seen.insert(ip).inserted else{continue}
            result.append(ip)
        }
        return result
    }

    private static func parseBool(_ value:String?)->Bool?{
        guard let value=value?.trimmingCharacters(in:.whitespacesAndNewlines).lowercased(),!value.isEmpty else{return nil}
        if ["1","true","yes","active","on"].contains(value){return true}
        if ["0","false","no","inactive","off"].contains(value){return false}
        return nil
    }

    private static func value(after key:String,tokens:[String])->String?{
        guard let index=tokens.firstIndex(of:key),tokens.indices.contains(index+1) else{return nil}
        return tokens[index+1]
    }

    private static func assignRole(_ role:String,to name:String,in tunnels:inout [InfrastructureTunnelSnapshot]){
        guard let index=tunnels.firstIndex(where:{$0.name==name}) else{return}
        tunnels[index].role=role
    }
}

private extension String{
    var nonEmptyValue:String?{let value=trimmingCharacters(in:.whitespacesAndNewlines);return value.isEmpty ? nil:value}
}
