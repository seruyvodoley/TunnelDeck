import Foundation

struct AgentSyncCursors:Codable,Sendable{var samples:Int64=0;var events:Int64=0;var peers:Int64=0;var adGuard:Int64=0}
struct AgentSyncResult: Sendable { let imported: Int; let cursors:AgentSyncCursors; let newestTimestamp: Date? }

actor AgentSyncController {
    func synchronize(nodeID: UUID, cursors:AgentSyncCursors, service: AgentService, configuration: SSHConfiguration, store: InfrastructureStore) async throws -> AgentSyncResult {
        let response = try await service.samples(cursor: cursors.samples, configuration: configuration)
        let eventResponse=try await service.events(cursor:cursors.events,configuration:configuration),peerResponse=try await service.peers(cursor:cursors.peers,configuration:configuration),adGuardResponse=try await service.adGuard(cursor:cursors.adGuard,configuration:configuration)
        var imported = 0
        var newest: Date?
        for item in response.items ?? [] {
            guard let timestamp=ISO8601DateFormatter().date(from:item.timestamp) else{continue}
            let payload=item.payload
            let sample=MonitoringSample(nodeID:nodeID,id:stableUUID(item.id),timestamp:timestamp,cpuPercent:payload.cpuPercent,memoryPercent:payload.memoryPercent,diskPercent:payload.diskPercent,pingMilliseconds:payload.pingMilliseconds,vpsState:payload.vpsState,wireGuardState:payload.wireGuardState,adGuardState:payload.adGuardState,antiZapretState:payload.antiZapretState,publicDNSExposed:payload.publicDNSExposed,publicListeners:payload.publicListeners)
            try await store.insert(sample: sample, nodeID: nodeID)
            imported += 1
            newest = max(newest ?? sample.timestamp, sample.timestamp)
        }
        for item in eventResponse.items ?? []{guard let timestamp=date(item.timestamp)else{continue};let payload=item.payload;try await store.insert(event:InfrastructureEvent(id:stableUUID(item.id),nodeID:nodeID,timestamp:timestamp,componentID:"agent",kind:"agent",title:payload.event ?? "Agent observation",detail:[payload.from,payload.to].compactMap{$0}.joined(separator:" → "),state:payload.to=="active" ? .online:.unknown,isRecovery:false));imported += 1}
        for item in peerResponse.items ?? []{guard let timestamp=date(item.timestamp)else{continue};let value=item.payload,handshake=value.latestHandshake>0 ? Date(timeIntervalSince1970:TimeInterval(value.latestHandshake)):nil;try await store.insert(peer:PeerHistorySample(nodeID:nodeID,id:stableUUID(item.id),timestamp:timestamp,peerID:value.publicIdentifier,name:value.publicIdentifier,vpnIP:"—",status:handshake.map{timestamp.timeIntervalSince($0)<300 ? .online:.offline} ?? .unknown,receivedBytes:value.rx,sentBytes:value.tx,latestHandshake:handshake));imported += 1}
        for item in adGuardResponse.items ?? []{guard let timestamp=date(item.timestamp)else{continue};let value=item.payload;try await store.insert(adGuard:AdGuardHistorySample(nodeID:nodeID,id:stableUUID(item.id),timestamp:timestamp,totalQueries:value.totalQueries,blockedQueries:value.blockedQueries,blockedPercentage:value.blockedPercentage,averageProcessingTime:value.averageProcessingTime));imported += 1}
        let next=AgentSyncCursors(samples:response.nextCursor ?? cursors.samples,events:eventResponse.nextCursor ?? cursors.events,peers:peerResponse.nextCursor ?? cursors.peers,adGuard:adGuardResponse.nextCursor ?? cursors.adGuard)
        return AgentSyncResult(imported: imported, cursors:next, newestTimestamp: newest)
    }
    private func date(_ value:String)->Date?{ISO8601DateFormatter().date(from:value)}
    private func stableUUID(_ hex:String)->UUID{let value=String(hex.prefix(32));let formatted="\(value.prefix(8))-\(value.dropFirst(8).prefix(4))-\(value.dropFirst(12).prefix(4))-\(value.dropFirst(16).prefix(4))-\(value.dropFirst(20).prefix(12))";return UUID(uuidString:formatted) ?? UUID()}
}
