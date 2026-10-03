import Foundation

struct AgentSyncCursors: Codable, Sendable, Equatable { var samples:Int64=0;var events:Int64=0;var peers:Int64=0;var adGuard:Int64=0 }
struct AgentSyncResult: Sendable { let imported:Int;let cursors:AgentSyncCursors;let newestTimestamp:Date?;let reachedSafetyLimit:Bool }
struct AgentPaginationSafety: Sendable { let pageSize:Int;let maxPages:Int;let maxRecords:Int;static let standard=AgentPaginationSafety(pageSize:2_000,maxPages:16,maxRecords:25_000) }
struct AgentPage<Item:Sendable>:Sendable{let items:[Item];let nextCursor:Int64}
struct AgentPaginationResult:Sendable,Equatable{let cursor:Int64;let records:Int;let pages:Int;let reachedSafetyLimit:Bool}
enum AgentSyncError:Error,Equatable{case nonAdvancingCursor(current:Int64,returned:Int64);case cursorMovedBackwards(current:Int64,returned:Int64);case malformedTimestamp(String);case malformedIdentifier(String)}

protocol AgentHistorySource:Sendable{
    func samples(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentMonitoringPayload>>
    func events(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentEventPayload>>
    func peers(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentPeerPayload>>
    func adGuard(cursor:Int64,limit:Int,configuration:SSHConfiguration)async throws->AgentEnvelope<AgentTelemetryItem<AgentAdGuardPayload>>
}

actor AgentSyncController {
    func synchronize(nodeID:UUID,cursors initial:AgentSyncCursors,service:any AgentHistorySource,configuration:SSHConfiguration,store:InfrastructureStore,safety:AgentPaginationSafety = .standard)async throws->AgentSyncResult{
        var cursors=initial,imported=0,newest:Date?,limited=false
        let samples=try await paginate(initialCursor:cursors.samples,safety:safety,fetch:{cursor,limit in let response=try await service.samples(cursor:cursor,limit:limit,configuration:configuration);return AgentPage(items:response.items ?? [],nextCursor:response.nextCursor ?? cursor)},persist:{items in for item in items{try Task.checkCancellation();let timestamp=try self.date(item.timestamp),value=item.payload;try await store.insert(sample:MonitoringSample(nodeID:nodeID,id:try self.stableUUID(item.id),timestamp:timestamp,cpuPercent:value.cpuPercent,memoryPercent:value.memoryPercent,diskPercent:value.diskPercent,pingMilliseconds:value.pingMilliseconds,vpsState:value.vpsState,wireGuardState:value.wireGuardState,adGuardState:value.adGuardState,antiZapretState:value.antiZapretState,publicDNSExposed:value.publicDNSExposed,publicListeners:value.publicListeners),nodeID:nodeID);newest=max(newest ?? timestamp,timestamp)}},checkpoint:{cursor in cursors.samples=cursor;try await store.saveAgentSyncCursors(cursors,nodeID:nodeID)})
        imported += samples.records;limited = limited || samples.reachedSafetyLimit
        let events=try await paginate(initialCursor:cursors.events,safety:safety,fetch:{cursor,limit in let response=try await service.events(cursor:cursor,limit:limit,configuration:configuration);return AgentPage(items:response.items ?? [],nextCursor:response.nextCursor ?? cursor)},persist:{items in for item in items{try Task.checkCancellation();let timestamp=try self.date(item.timestamp),value=item.payload;try await store.insert(event:InfrastructureEvent(id:try self.stableUUID(item.id),nodeID:nodeID,timestamp:timestamp,componentID:"agent",kind:"agent",title:value.event ?? "Agent observation",detail:[value.from,value.to].compactMap{$0}.joined(separator:" → "),state:value.to=="active" ? .online:.unknown,isRecovery:false))}},checkpoint:{cursor in cursors.events=cursor;try await store.saveAgentSyncCursors(cursors,nodeID:nodeID)})
        imported += events.records;limited = limited || events.reachedSafetyLimit
        let peers=try await paginate(initialCursor:cursors.peers,safety:safety,fetch:{cursor,limit in let response=try await service.peers(cursor:cursor,limit:limit,configuration:configuration);return AgentPage(items:response.items ?? [],nextCursor:response.nextCursor ?? cursor)},persist:{items in for item in items{try Task.checkCancellation();let timestamp=try self.date(item.timestamp),value=item.payload,handshake=value.latestHandshake>0 ? Date(timeIntervalSince1970:TimeInterval(value.latestHandshake)):nil;try await store.insert(peer:PeerHistorySample(nodeID:nodeID,id:try self.stableUUID(item.id),timestamp:timestamp,peerID:value.publicIdentifier,name:value.publicIdentifier,vpnIP:"—",status:handshake.map{timestamp.timeIntervalSince($0)<300 ? .online:.offline} ?? .unknown,receivedBytes:value.rx,sentBytes:value.tx,latestHandshake:handshake))}},checkpoint:{cursor in cursors.peers=cursor;try await store.saveAgentSyncCursors(cursors,nodeID:nodeID)})
        imported += peers.records;limited = limited || peers.reachedSafetyLimit
        let adGuard=try await paginate(initialCursor:cursors.adGuard,safety:safety,fetch:{cursor,limit in let response=try await service.adGuard(cursor:cursor,limit:limit,configuration:configuration);return AgentPage(items:response.items ?? [],nextCursor:response.nextCursor ?? cursor)},persist:{items in for item in items{try Task.checkCancellation();let timestamp=try self.date(item.timestamp),value=item.payload;try await store.insert(adGuard:AdGuardHistorySample(nodeID:nodeID,id:try self.stableUUID(item.id),timestamp:timestamp,totalQueries:value.totalQueries,blockedQueries:value.blockedQueries,blockedPercentage:value.blockedPercentage,averageProcessingTime:value.averageProcessingTime))}},checkpoint:{cursor in cursors.adGuard=cursor;try await store.saveAgentSyncCursors(cursors,nodeID:nodeID)})
        imported += adGuard.records;limited = limited || adGuard.reachedSafetyLimit
        return AgentSyncResult(imported:imported,cursors:cursors,newestTimestamp:newest,reachedSafetyLimit:limited)
    }

    func paginate<Item:Sendable>(initialCursor:Int64,safety:AgentPaginationSafety = .standard,fetch:(Int64,Int)async throws->AgentPage<Item>,persist:([Item])async throws->Void,checkpoint:(Int64)async throws->Void)async throws->AgentPaginationResult{
        var cursor=initialCursor,pages=0,records=0
        while pages<safety.maxPages && records<safety.maxRecords{
            try Task.checkCancellation();let page=try await fetch(cursor,safety.pageSize);pages += 1
            guard !page.items.isEmpty else{return AgentPaginationResult(cursor:cursor,records:records,pages:pages,reachedSafetyLimit:false)}
            guard page.nextCursor>=cursor else{throw AgentSyncError.cursorMovedBackwards(current:cursor,returned:page.nextCursor)}
            guard page.nextCursor>cursor else{throw AgentSyncError.nonAdvancingCursor(current:cursor,returned:page.nextCursor)}
            guard records+page.items.count<=safety.maxRecords else{return AgentPaginationResult(cursor:cursor,records:records,pages:pages-1,reachedSafetyLimit:true)}
            try await persist(page.items);cursor=page.nextCursor;records += page.items.count;try await checkpoint(cursor)
        }
        return AgentPaginationResult(cursor:cursor,records:records,pages:pages,reachedSafetyLimit:true)
    }
    private func date(_ value:String)throws->Date{guard let date=ISO8601DateFormatter().date(from:value)else{throw AgentSyncError.malformedTimestamp(value)};return date}
    private func stableUUID(_ hex:String)throws->UUID{let value=String(hex.prefix(32)),formatted="\(value.prefix(8))-\(value.dropFirst(8).prefix(4))-\(value.dropFirst(12).prefix(4))-\(value.dropFirst(16).prefix(4))-\(value.dropFirst(20).prefix(12))";guard hex.count>=32,let id=UUID(uuidString:formatted)else{throw AgentSyncError.malformedIdentifier(hex)};return id}
}
