import CSQLite
import Foundation

enum PersistenceError: Error, LocalizedError {
    case open(String), execute(String), prepare(String), bind(String)
    var errorDescription: String? {
        switch self { case .open(let value), .execute(let value), .prepare(let value), .bind(let value): value }
    }
}

actor InfrastructureStore {
    static let currentSchemaVersion = 7
    private nonisolated(unsafe) var database: OpaquePointer?
    let url: URL

    init(url: URL? = nil) throws {
        if let url { self.url = url } else {
            let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TunnelDeck", isDirectory: true)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            self.url = folder.appendingPathComponent("infrastructure.sqlite3")
        }
        var handle: OpaquePointer?
        guard sqlite3_open_v2(self.url.path, &handle, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "Unable to open SQLite database"
            sqlite3_close(handle); throw PersistenceError.open(message)
        }
        database = handle
        try Self.configure(handle)
        try Self.migrate(handle)
    }

    deinit { sqlite3_close(database) }

    func schemaVersion() throws -> Int { Int(try scalar("PRAGMA user_version")) }

    func upsert(node: InfrastructureNode) throws {
        try run("""
            INSERT INTO nodes(id,name,role,custom_role,host,ssh_port,created_at,updated_at,enabled)
            VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,role=excluded.role,custom_role=excluded.custom_role,host=excluded.host,
            ssh_port=excluded.ssh_port,updated_at=excluded.updated_at,enabled=excluded.enabled
            """, [.text(node.id.uuidString), .text(node.name), .text(node.role.rawValue), .optional(node.customRole), .text(node.host), .integer(node.sshPort), .date(node.createdAt), .date(node.updatedAt), .integer(node.enabled ? 1 : 0)])
    }

    func nodes() throws -> [InfrastructureNode] {
        try query("SELECT id,name,role,custom_role,host,ssh_port,created_at,updated_at,enabled FROM nodes ORDER BY name") { statement in
            InfrastructureNode(id: UUID(uuidString: Self.text(statement, 0))!, name: Self.text(statement, 1), role: NodeRole(rawValue: Self.text(statement, 2)) ?? .custom, customRole: Self.optionalText(statement, 3), host: Self.text(statement, 4), sshPort: Int(sqlite3_column_int(statement, 5)), createdAt: Self.date(statement, 6), updatedAt: Self.date(statement, 7), enabled: sqlite3_column_int(statement, 8) != 0)
        }
    }

    func insert(sample: MonitoringSample, nodeID: UUID) throws {
        let listeners = String(data: try JSONEncoder().encode(sample.publicListeners), encoding: .utf8) ?? "[]"
        try run("""
            INSERT OR IGNORE INTO monitoring_samples(id,node_id,timestamp,cpu,memory,disk,ping,vps_state,wg_state,adguard_state,antizapret_state,public_dns,public_listeners)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [.text(sample.id.uuidString), .text(nodeID.uuidString), .date(sample.timestamp), .real(sample.cpuPercent), .real(sample.memoryPercent), .real(sample.diskPercent), sample.pingMilliseconds.map(Binding.real) ?? .null, .text(sample.vpsState.rawValue), .text(sample.wireGuardState.rawValue), .text(sample.adGuardState.rawValue), .text(sample.antiZapretState.rawValue), .integer(sample.publicDNSExposed ? 1 : 0), .text(listeners)])
        try prune("monitoring_samples", nodeID, sample.timestamp)
    }

    func insert(event: InfrastructureEvent) throws {
        try run("INSERT OR IGNORE INTO infrastructure_events(id,node_id,timestamp,component_id,kind,title,detail,state,is_recovery) VALUES(?,?,?,?,?,?,?,?,?)", [.text(event.id.uuidString), .text(event.nodeID.uuidString), .date(event.timestamp), .text(event.componentID), .text(event.kind), .text(event.title), .text(event.detail), .text(event.state.rawValue), .integer(event.isRecovery ? 1 : 0)])
        try prune("infrastructure_events", event.nodeID, event.timestamp)
    }

    func sampleCount(nodeID: UUID) throws -> Int { Int(try scalar("SELECT count(*) FROM monitoring_samples WHERE node_id=?", [.text(nodeID.uuidString)])) }
    func eventCount(nodeID: UUID) throws -> Int { Int(try scalar("SELECT count(*) FROM infrastructure_events WHERE node_id=?", [.text(nodeID.uuidString)])) }
    func samples(nodeID: UUID, since: Date? = nil) throws -> [MonitoringSample] { let clause=since == nil ? "" : " AND timestamp>=?";let bindings:[Binding]=[.text(nodeID.uuidString)]+(since.map{[.date($0)]} ?? []);return try query("SELECT id,timestamp,cpu,memory,disk,ping,vps_state,wg_state,adguard_state,antizapret_state,public_dns,public_listeners FROM monitoring_samples WHERE node_id=?\(clause) ORDER BY timestamp",bindings) { s in let ping=sqlite3_column_type(s,5)==SQLITE_NULL ? nil : sqlite3_column_double(s,5); let listeners=(try? JSONDecoder().decode([String].self,from:Data(Self.text(s,11).utf8))) ?? []; return MonitoringSample(nodeID:nodeID,id:UUID(uuidString:Self.text(s,0))!,timestamp:Self.date(s,1),cpuPercent:sqlite3_column_double(s,2),memoryPercent:sqlite3_column_double(s,3),diskPercent:sqlite3_column_double(s,4),pingMilliseconds:ping,vpsState:HealthState(rawValue:Self.text(s,6)) ?? .unknown,wireGuardState:HealthState(rawValue:Self.text(s,7)) ?? .unknown,adGuardState:HealthState(rawValue:Self.text(s,8)) ?? .unknown,antiZapretState:HealthState(rawValue:Self.text(s,9)) ?? .unknown,publicDNSExposed:sqlite3_column_int(s,10) != 0,publicListeners:listeners) } }
    func latestSamples() throws -> [UUID:MonitoringSample] { let rows:[MonitoringSample]=try query("SELECT m.node_id,m.id,m.timestamp,m.cpu,m.memory,m.disk,m.ping,m.vps_state,m.wg_state,m.adguard_state,m.antizapret_state,m.public_dns,m.public_listeners FROM monitoring_samples m JOIN (SELECT node_id,MAX(timestamp) timestamp FROM monitoring_samples GROUP BY node_id) latest ON latest.node_id=m.node_id AND latest.timestamp=m.timestamp"){s in let nodeID=UUID(uuidString:Self.text(s,0))!,ping=sqlite3_column_type(s,6)==SQLITE_NULL ? nil:sqlite3_column_double(s,6),listeners=(try? JSONDecoder().decode([String].self,from:Data(Self.text(s,12).utf8))) ?? [];return MonitoringSample(nodeID:nodeID,id:UUID(uuidString:Self.text(s,1))!,timestamp:Self.date(s,2),cpuPercent:sqlite3_column_double(s,3),memoryPercent:sqlite3_column_double(s,4),diskPercent:sqlite3_column_double(s,5),pingMilliseconds:ping,vpsState:HealthState(rawValue:Self.text(s,7)) ?? .unknown,wireGuardState:HealthState(rawValue:Self.text(s,8)) ?? .unknown,adGuardState:HealthState(rawValue:Self.text(s,9)) ?? .unknown,antiZapretState:HealthState(rawValue:Self.text(s,10)) ?? .unknown,publicDNSExposed:sqlite3_column_int(s,11) != 0,publicListeners:listeners)};return Dictionary(rows.map{($0.nodeID,$0)},uniquingKeysWith:{first,_ in first}) }
    func events(nodeID: UUID, since: Date? = nil) throws -> [InfrastructureEvent] { let clause=since == nil ? "" : " AND timestamp>=?";let bindings:[Binding]=[.text(nodeID.uuidString)]+(since.map{[.date($0)]} ?? []);return try query("SELECT id,timestamp,component_id,kind,title,detail,state,is_recovery FROM infrastructure_events WHERE node_id=?\(clause) ORDER BY timestamp",bindings) { s in InfrastructureEvent(id:UUID(uuidString:Self.text(s,0))!,nodeID:nodeID,timestamp:Self.date(s,1),componentID:Self.text(s,2),kind:Self.text(s,3),title:Self.text(s,4),detail:Self.text(s,5),state:HealthState(rawValue:Self.text(s,6)) ?? .unknown,isRecovery:sqlite3_column_int(s,7) != 0) } }
    func save(baseline: ConfigurationBaseline) throws { let payload = String(data: try JSONEncoder().encode(baseline), encoding: .utf8)!; try run("INSERT INTO configuration_baselines(id,node_id,created_at,payload) VALUES(?,?,?,?)", [.text(baseline.id.uuidString),.text(baseline.nodeID.uuidString),.date(baseline.createdAt),.text(payload)]) }
    func latestBaseline(nodeID: UUID) throws -> ConfigurationBaseline? { let rows: [String] = try query("SELECT payload FROM configuration_baselines WHERE node_id=? ORDER BY created_at DESC LIMIT 1",[.text(nodeID.uuidString)]) { Self.text($0,0) }; return try rows.first.map { try JSONDecoder().decode(ConfigurationBaseline.self, from: Data($0.utf8)) } }
    func insert(peer:PeerHistorySample)throws{try run("INSERT OR IGNORE INTO peer_history(id,node_id,timestamp,peer_id,name,vpn_ip,state,rx,tx,latest_handshake) VALUES(?,?,?,?,?,?,?,?,?,?)",[.text(peer.id.uuidString),.text(peer.nodeID.uuidString),.date(peer.timestamp),.text(SecretRedactor.redact(peer.peerID)),.text(SecretRedactor.redact(peer.name)),.text(SecretRedactor.redact(peer.vpnIP)),.text(peer.status.rawValue),.integer64(peer.receivedBytes),.integer64(peer.sentBytes),peer.latestHandshake.map(Binding.date) ?? .null]);try prune("peer_history",peer.nodeID,peer.timestamp)}
    func insert(adGuard:AdGuardHistorySample)throws{try run("INSERT OR IGNORE INTO adguard_history(id,node_id,timestamp,total_queries,blocked_queries,blocked_percentage,average_processing_time) VALUES(?,?,?,?,?,?,?)",[.text(adGuard.id.uuidString),.text(adGuard.nodeID.uuidString),.date(adGuard.timestamp),.integer(adGuard.totalQueries),.integer(adGuard.blockedQueries),.real(adGuard.blockedPercentage),.real(adGuard.averageProcessingTime)]);try prune("adguard_history",adGuard.nodeID,adGuard.timestamp)}
    func peerHistory(nodeID:UUID,since:Date?=nil)throws->[PeerHistorySample]{let clause=since == nil ? "":" AND timestamp>=?",bindings:[Binding]=[.text(nodeID.uuidString)]+(since.map{[.date($0)]} ?? []);return try query("SELECT id,timestamp,peer_id,name,vpn_ip,state,rx,tx,latest_handshake FROM peer_history WHERE node_id=?\(clause) ORDER BY timestamp",bindings){s in PeerHistorySample(nodeID:nodeID,id:UUID(uuidString:Self.text(s,0))!,timestamp:Self.date(s,1),peerID:Self.text(s,2),name:Self.text(s,3),vpnIP:Self.text(s,4),status:HealthState(rawValue:Self.text(s,5)) ?? .unknown,receivedBytes:UInt64(sqlite3_column_int64(s,6)),sentBytes:UInt64(sqlite3_column_int64(s,7)),latestHandshake:sqlite3_column_type(s,8)==SQLITE_NULL ? nil:Self.date(s,8))}}
    func adGuardHistory(nodeID:UUID,since:Date?=nil)throws->[AdGuardHistorySample]{let clause=since == nil ? "":" AND timestamp>=?",bindings:[Binding]=[.text(nodeID.uuidString)]+(since.map{[.date($0)]} ?? []);return try query("SELECT id,timestamp,total_queries,blocked_queries,blocked_percentage,average_processing_time FROM adguard_history WHERE node_id=?\(clause) ORDER BY timestamp",bindings){s in AdGuardHistorySample(nodeID:nodeID,id:UUID(uuidString:Self.text(s,0))!,timestamp:Self.date(s,1),totalQueries:Int(sqlite3_column_int64(s,2)),blockedQueries:Int(sqlite3_column_int64(s,3)),blockedPercentage:sqlite3_column_double(s,4),averageProcessingTime:sqlite3_column_double(s,5))}}
    func save(alertRules:[AlertRule],nodeID:UUID)throws{try transaction{try run("DELETE FROM alert_rules WHERE node_id=?",[.text(nodeID.uuidString)]);for rule in alertRules{let payload=String(data:try JSONEncoder().encode(rule),encoding:.utf8)!;try run("INSERT INTO alert_rules(id,node_id,payload) VALUES(?,?,?)",[.text(rule.id.uuidString),.text(nodeID.uuidString),.text(payload)])}}}
    func alertRules(nodeID:UUID)throws->[AlertRule]{try query("SELECT payload FROM alert_rules WHERE node_id=?",[.text(nodeID.uuidString)]){s in try JSONDecoder().decode(AlertRule.self,from:Data(Self.text(s,0).utf8))}}
    func save(alertStates:[UUID:AlertRuntimeState],nodeID:UUID)throws{for(id,state)in alertStates{let payload=String(data:try JSONEncoder().encode(state),encoding:.utf8)!;try run("INSERT INTO alert_state(rule_id,node_id,active,last_fired,acknowledged_at,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET active=excluded.active,last_fired=excluded.last_fired,acknowledged_at=excluded.acknowledged_at,payload=excluded.payload",[.text(id.uuidString),.text(nodeID.uuidString),.integer(state.active ? 1:0),state.lastFiredAt.map(Binding.date) ?? .null,state.acknowledgedAt.map(Binding.date) ?? .null,.text(payload)])}}
    func alertStates(nodeID:UUID)throws->[UUID:AlertRuntimeState]{Dictionary(uniqueKeysWithValues:try query("SELECT rule_id,payload FROM alert_state WHERE node_id=?",[.text(nodeID.uuidString)]){s in (UUID(uuidString:Self.text(s,0))!,try JSONDecoder().decode(AlertRuntimeState.self,from:Data(Self.text(s,1).utf8)))})}
    func saveAgentSyncCursors(_ cursors:AgentSyncCursors,nodeID:UUID)throws{for(stream,cursor)in[("samples",cursors.samples),("events",cursors.events),("peers",cursors.peers),("adguard",cursors.adGuard)]{try run("INSERT INTO agent_sync_state(node_id,stream,cursor) VALUES(?,?,?) ON CONFLICT(node_id,stream) DO UPDATE SET cursor=excluded.cursor",[.text(nodeID.uuidString),.text(stream),.integer64(UInt64(max(0,cursor)))])}}
    func agentSyncCursors(nodeID:UUID)throws->AgentSyncCursors{let values=Dictionary(uniqueKeysWithValues:try query("SELECT stream,cursor FROM agent_sync_state WHERE node_id=?",[.text(nodeID.uuidString)]){s in(Self.text(s,0),sqlite3_column_int64(s,1))});return AgentSyncCursors(samples:values["samples"] ?? 0,events:values["events"] ?? 0,peers:values["peers"] ?? 0,adGuard:values["adguard"] ?? 0)}
    func resetAgentSyncCursors(nodeID:UUID)throws{try run("DELETE FROM agent_sync_state WHERE node_id=?",[.text(nodeID.uuidString)])}
    func deleteNode(_ nodeID:UUID)throws{try run("DELETE FROM nodes WHERE id=?",[.text(nodeID.uuidString)])}
    func mergeNodeData(from source:UUID,into destination:UUID)throws{
        guard source != destination else{return}
        try transaction {
            for table in ["monitoring_samples","infrastructure_events","peer_history","adguard_history"] {
                try run("INSERT OR IGNORE INTO \(table) SELECT ? AS node_id,id,timestamp" + Self.mergeTail(table) + " FROM \(table) WHERE node_id=?",[.text(destination.uuidString),.text(source.uuidString)])
            }
            try run("DELETE FROM nodes WHERE id=?",[.text(source.uuidString)])
        }
    }

    func persistAgentSamples(_ samples:[MonitoringSample],nodeID:UUID,cursors:AgentSyncCursors)throws{try transaction{for sample in samples{try insert(sample:sample,nodeID:nodeID)};try saveAgentSyncCursors(cursors,nodeID:nodeID)}}
    func persistAgentEvents(_ events:[InfrastructureEvent],nodeID:UUID,cursors:AgentSyncCursors)throws{try transaction{for event in events{try insert(event:event)};try saveAgentSyncCursors(cursors,nodeID:nodeID)}}
    func persistAgentPeers(_ peers:[PeerHistorySample],nodeID:UUID,cursors:AgentSyncCursors)throws{try transaction{for peer in peers{try insert(peer:peer)};try saveAgentSyncCursors(cursors,nodeID:nodeID)}}
    func persistAgentAdGuard(_ values:[AdGuardHistorySample],nodeID:UUID,cursors:AgentSyncCursors)throws{try transaction{for value in values{try insert(adGuard:value)};try saveAgentSyncCursors(cursors,nodeID:nodeID)}}
    func save(homeNetwork value:HomeNetwork)throws{try run("INSERT INTO home_networks(id,name,cidr,router_ip,notes,created_at,updated_at,is_active) VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name,cidr=excluded.cidr,router_ip=excluded.router_ip,notes=excluded.notes,updated_at=excluded.updated_at,is_active=1",[.text(value.id.uuidString),.text(value.name),.text(value.cidr),.text(value.routerIP),.text(value.notes),.date(value.createdAt),.date(value.updatedAt)])}
    func activeHomeNetwork()throws->HomeNetwork?{try query("SELECT id,name,cidr,router_ip,notes,created_at,updated_at FROM home_networks WHERE is_active=1 ORDER BY updated_at DESC LIMIT 1"){s in HomeNetwork(id:UUID(uuidString:Self.text(s,0))!,name:Self.text(s,1),cidr:Self.text(s,2),routerIP:Self.text(s,3),notes:Self.text(s,4),createdAt:Self.date(s,5),updatedAt:Self.date(s,6))}.first}
    func save(homeDevice value:HomeDevice,observation:HomeDeviceObservation?=nil)throws{let sources=String(data:try JSONEncoder().encode(value.discoverySources),encoding:.utf8) ?? "[]";try transaction{try run("""
        INSERT INTO home_devices(id,display_name,hostname,ipv4,ipv6,mac_address,vendor,type,custom_type,status,last_seen,first_seen,sources,is_pinned,notes,preferred_url,preferred_ssh,name_manual,type_manual,evidence,last_success,router_display_name,router_connection_type,router_last_seen,router_online)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,hostname=excluded.hostname,ipv4=excluded.ipv4,ipv6=excluded.ipv6,mac_address=excluded.mac_address,vendor=excluded.vendor,type=excluded.type,custom_type=excluded.custom_type,status=excluded.status,last_seen=excluded.last_seen,sources=excluded.sources,is_pinned=excluded.is_pinned,notes=excluded.notes,preferred_url=excluded.preferred_url,preferred_ssh=excluded.preferred_ssh,name_manual=excluded.name_manual,type_manual=excluded.type_manual,evidence=excluded.evidence,last_success=excluded.last_success,router_display_name=excluded.router_display_name,router_connection_type=excluded.router_connection_type,router_last_seen=excluded.router_last_seen,router_online=excluded.router_online
        """,[.text(value.id.uuidString),.text(value.displayName),.optional(value.hostname),.optional(value.ipv4),.optional(value.ipv6),.optional(value.macAddress),.optional(value.vendor),.text(value.type.rawValue),.optional(value.customType),.text(value.status.rawValue),value.lastSeen.map(Binding.date) ?? .null,.date(value.firstSeen),.text(sources),.integer(value.isPinned ? 1:0),.optional(value.notes),.optional(value.preferredAccessURL),.optional(value.preferredSSHHost),.integer(value.nameIsManual ? 1:0),.integer(value.typeIsManual ? 1:0),.optional(value.reachabilityEvidence),value.lastSuccessfulObservation.map(Binding.date) ?? .null,.optional(value.routerDisplayName),.optional(value.routerConnectionType?.rawValue),value.routerLastSeen.map(Binding.date) ?? .null,value.routerOnline.map{.integer($0 ? 1:0)} ?? .null]);for(address,family)in[(value.ipv4,"ipv4"),(value.ipv6,"ipv6")]{if let address{try run("INSERT INTO home_device_addresses(device_id,address,family,last_seen) VALUES(?,?,?,?) ON CONFLICT(device_id,address) DO UPDATE SET last_seen=excluded.last_seen",[.text(value.id.uuidString),.text(address),.text(family),.date(value.lastSeen ?? Date())])}};if let observation{try insertHomeObservation(observation)};try run("DELETE FROM home_device_observations WHERE timestamp<?",[.date(Date().addingTimeInterval(-2_592_000))])}}
    func homeDevices()throws->[HomeDevice]{try query("SELECT id,display_name,hostname,ipv4,ipv6,mac_address,vendor,type,custom_type,status,last_seen,first_seen,sources,is_pinned,notes,preferred_url,preferred_ssh,name_manual,type_manual,evidence,last_success,router_display_name,router_connection_type,router_last_seen,router_online FROM home_devices ORDER BY is_pinned DESC,display_name COLLATE NOCASE"){s in let sources=(try? JSONDecoder().decode(Set<HomeDiscoverySource>.self,from:Data(Self.text(s,12).utf8))) ?? [];return HomeDevice(id:UUID(uuidString:Self.text(s,0))!,displayName:Self.text(s,1),hostname:Self.optionalText(s,2),ipv4:Self.optionalText(s,3),ipv6:Self.optionalText(s,4),macAddress:Self.optionalText(s,5),vendor:Self.optionalText(s,6),type:HomeDeviceType(rawValue:Self.text(s,7)) ?? .unknown,customType:Self.optionalText(s,8),status:HomeDeviceReachability(rawValue:Self.text(s,9)) ?? .unknown,lastSeen:Self.optionalDate(s,10),firstSeen:Self.date(s,11),discoverySources:sources,isPinned:sqlite3_column_int(s,13) != 0,notes:Self.optionalText(s,14),preferredAccessURL:Self.optionalText(s,15),preferredSSHHost:Self.optionalText(s,16),nameIsManual:sqlite3_column_int(s,17) != 0,typeIsManual:sqlite3_column_int(s,18) != 0,reachabilityEvidence:Self.optionalText(s,19),lastSuccessfulObservation:Self.optionalDate(s,20),routerDisplayName:Self.optionalText(s,21),routerConnectionType:Self.optionalText(s,22).flatMap(HomeConnectionType.init(rawValue:)),routerLastSeen:Self.optionalDate(s,23),routerOnline:sqlite3_column_type(s,24)==SQLITE_NULL ? nil:sqlite3_column_int(s,24) != 0)}}
    func deleteHomeDevice(_ id:UUID)throws{try run("DELETE FROM home_devices WHERE id=?",[.text(id.uuidString)])}
    func mergeHomeDevices(source:UUID,destination:UUID)throws{guard source != destination else{return};try transaction{try run("INSERT OR IGNORE INTO home_device_addresses(device_id,address,family,last_seen) SELECT ?,address,family,last_seen FROM home_device_addresses WHERE device_id=?",[.text(destination.uuidString),.text(source.uuidString)]);try run("UPDATE home_device_observations SET device_id=? WHERE device_id=?",[.text(destination.uuidString),.text(source.uuidString)]);try run("DELETE FROM home_devices WHERE id=?",[.text(source.uuidString)])}}
    func homeObservations(deviceID:UUID,since:Date)throws->[HomeDeviceObservation]{try query("SELECT id,timestamp,status,evidence,ip,source FROM home_device_observations WHERE device_id=? AND timestamp>=? ORDER BY timestamp",[.text(deviceID.uuidString),.date(since)]){s in HomeDeviceObservation(id:UUID(uuidString:Self.text(s,0))!,deviceID:deviceID,timestamp:Self.date(s,1),status:HomeDeviceReachability(rawValue:Self.text(s,2)) ?? .unknown,evidence:Self.text(s,3),ip:Self.optionalText(s,4),source:HomeDiscoverySource(rawValue:Self.text(s,5)) ?? .manual)}}
    private func insertHomeObservation(_ value:HomeDeviceObservation)throws{try run("INSERT OR IGNORE INTO home_device_observations(id,device_id,timestamp,status,evidence,ip,source) VALUES(?,?,?,?,?,?,?)",[.text(value.id.uuidString),.text(value.deviceID.uuidString),.date(value.timestamp),.text(value.status.rawValue),.text(value.evidence),.optional(value.ip),.text(value.source.rawValue)])}
    private func prune(_ table:String,_ nodeID:UUID,_ now:Date)throws{try run("DELETE FROM \(table) WHERE node_id=? AND timestamp<?",[.text(nodeID.uuidString),.real(now.addingTimeInterval(-604_800).timeIntervalSince1970)])}

    private static func configure(_ db: OpaquePointer?) throws {
        try exec(db, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
    }

    private static func migrate(_ db: OpaquePointer?) throws {
        let current = try scalar(db, "PRAGMA user_version")
        guard current <= currentSchemaVersion else { throw PersistenceError.execute("Database schema is newer than this app") }
        if current < 1 {
            try exec(db, "BEGIN IMMEDIATE")
            do {
                try exec(db, """
                CREATE TABLE nodes(id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL,custom_role TEXT,host TEXT NOT NULL,ssh_port INTEGER NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,enabled INTEGER NOT NULL);
                CREATE TABLE monitoring_samples(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,timestamp REAL NOT NULL,cpu REAL NOT NULL,memory REAL NOT NULL,disk REAL NOT NULL,ping REAL,vps_state TEXT NOT NULL,wg_state TEXT NOT NULL,adguard_state TEXT NOT NULL,antizapret_state TEXT NOT NULL,public_dns INTEGER NOT NULL,public_listeners TEXT NOT NULL);
                CREATE INDEX monitoring_node_time ON monitoring_samples(node_id,timestamp);
                CREATE TABLE service_state_history(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,service_id TEXT NOT NULL,timestamp REAL NOT NULL,state TEXT NOT NULL);
                CREATE TABLE infrastructure_events(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,timestamp REAL NOT NULL,component_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL,state TEXT NOT NULL,is_recovery INTEGER NOT NULL);
                CREATE INDEX events_node_time ON infrastructure_events(node_id,timestamp);
                CREATE TABLE incidents(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,started_at REAL NOT NULL,ended_at REAL,severity TEXT NOT NULL,observable_condition TEXT NOT NULL,affected_components TEXT NOT NULL,timeline TEXT NOT NULL,recovery_state TEXT NOT NULL);
                CREATE TABLE configuration_baselines(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,created_at REAL NOT NULL,payload TEXT NOT NULL);
                CREATE TABLE configuration_drift(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,baseline_id TEXT NOT NULL,detected_at REAL NOT NULL,payload TEXT NOT NULL);
                CREATE TABLE alert_rules(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,payload TEXT NOT NULL);
                CREATE TABLE alert_state(rule_id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,active INTEGER NOT NULL,last_fired REAL,acknowledged_at REAL,payload TEXT NOT NULL);
                PRAGMA user_version=1;
                """)
                try exec(db, "COMMIT")
            } catch { try? exec(db, "ROLLBACK"); throw error }
        }
        if current < 2 {
            try exec(db, "BEGIN IMMEDIATE")
            do {
                try exec(db, "CREATE TABLE import_log(source_key TEXT PRIMARY KEY,node_id TEXT NOT NULL,imported_at REAL NOT NULL,row_count INTEGER NOT NULL); PRAGMA user_version=2;")
                try exec(db, "COMMIT")
            } catch { try? exec(db, "ROLLBACK"); throw error }
        }
        if current < 3 {
            try exec(db, "BEGIN IMMEDIATE")
            do {
                try exec(db, "CREATE TABLE peer_history(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,timestamp REAL NOT NULL,peer_id TEXT NOT NULL,name TEXT NOT NULL,vpn_ip TEXT NOT NULL,state TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,latest_handshake REAL); CREATE INDEX peer_history_node_time ON peer_history(node_id,timestamp); CREATE TABLE adguard_history(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,timestamp REAL NOT NULL,total_queries INTEGER NOT NULL,blocked_queries INTEGER NOT NULL,blocked_percentage REAL NOT NULL,average_processing_time REAL NOT NULL); CREATE INDEX adguard_history_node_time ON adguard_history(node_id,timestamp); PRAGMA user_version=3;")
                try exec(db, "COMMIT")
            } catch { try? exec(db, "ROLLBACK"); throw error }
        }
        if current < 4 {
            try exec(db,"BEGIN IMMEDIATE")
            do { try exec(db,"CREATE TABLE agent_sync_state(node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,stream TEXT NOT NULL,cursor INTEGER NOT NULL,PRIMARY KEY(node_id,stream)); PRAGMA user_version=4;");try exec(db,"COMMIT") } catch { try? exec(db,"ROLLBACK");throw error }
        }
        if current < 5 { try migrateTelemetryIdentityToV5(db) }
        if current < 6 {
            try exec(db,"BEGIN IMMEDIATE")
            do{try exec(db,"""
                CREATE TABLE home_networks(id TEXT PRIMARY KEY,name TEXT NOT NULL,cidr TEXT NOT NULL,router_ip TEXT NOT NULL,notes TEXT NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,is_active INTEGER NOT NULL);
                CREATE TABLE home_devices(id TEXT PRIMARY KEY,display_name TEXT NOT NULL,hostname TEXT,ipv4 TEXT,ipv6 TEXT,mac_address TEXT,vendor TEXT,type TEXT NOT NULL,custom_type TEXT,status TEXT NOT NULL,last_seen REAL,first_seen REAL NOT NULL,sources TEXT NOT NULL,is_pinned INTEGER NOT NULL,notes TEXT,preferred_url TEXT,preferred_ssh TEXT,name_manual INTEGER NOT NULL,type_manual INTEGER NOT NULL,evidence TEXT,last_success REAL);
                CREATE UNIQUE INDEX home_device_mac ON home_devices(mac_address) WHERE mac_address IS NOT NULL;
                CREATE TABLE home_device_addresses(device_id TEXT NOT NULL REFERENCES home_devices(id) ON DELETE CASCADE,address TEXT NOT NULL,family TEXT NOT NULL,last_seen REAL NOT NULL,PRIMARY KEY(device_id,address));
                CREATE INDEX home_addresses_value ON home_device_addresses(address);
                CREATE TABLE home_device_observations(id TEXT PRIMARY KEY,device_id TEXT NOT NULL REFERENCES home_devices(id) ON DELETE CASCADE,timestamp REAL NOT NULL,status TEXT NOT NULL,evidence TEXT NOT NULL,ip TEXT,source TEXT NOT NULL);
                CREATE INDEX home_observation_device_time ON home_device_observations(device_id,timestamp);
                PRAGMA user_version=6;
                COMMIT;
                """) }catch{try? exec(db,"ROLLBACK");throw error}
        }
        if current < 7 {
            try exec(db,"BEGIN IMMEDIATE")
            do {
                try exec(db,"ALTER TABLE home_devices ADD COLUMN router_display_name TEXT; ALTER TABLE home_devices ADD COLUMN router_connection_type TEXT; ALTER TABLE home_devices ADD COLUMN router_last_seen REAL; ALTER TABLE home_devices ADD COLUMN router_online INTEGER; PRAGMA user_version=7; COMMIT")
            } catch { try? exec(db,"ROLLBACK");throw error }
        }
    }

    private static func migrateTelemetryIdentityToV5(_ db:OpaquePointer?)throws{
        let tables=["monitoring_samples","infrastructure_events","peer_history","adguard_history"]
        let definitions:[String:String]=[
            "monitoring_samples":"node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,id TEXT NOT NULL,timestamp REAL NOT NULL,cpu REAL NOT NULL,memory REAL NOT NULL,disk REAL NOT NULL,ping REAL,vps_state TEXT NOT NULL,wg_state TEXT NOT NULL,adguard_state TEXT NOT NULL,antizapret_state TEXT NOT NULL,public_dns INTEGER NOT NULL,public_listeners TEXT NOT NULL,PRIMARY KEY(node_id,id)",
            "infrastructure_events":"node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,id TEXT NOT NULL,timestamp REAL NOT NULL,component_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL,state TEXT NOT NULL,is_recovery INTEGER NOT NULL,PRIMARY KEY(node_id,id)",
            "peer_history":"node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,id TEXT NOT NULL,timestamp REAL NOT NULL,peer_id TEXT NOT NULL,name TEXT NOT NULL,vpn_ip TEXT NOT NULL,state TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,latest_handshake REAL,PRIMARY KEY(node_id,id)",
            "adguard_history":"node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,id TEXT NOT NULL,timestamp REAL NOT NULL,total_queries INTEGER NOT NULL,blocked_queries INTEGER NOT NULL,blocked_percentage REAL NOT NULL,average_processing_time REAL NOT NULL,PRIMARY KEY(node_id,id)"
        ]
        let columns:[String:String]=[
            "monitoring_samples":"node_id,id,timestamp,cpu,memory,disk,ping,vps_state,wg_state,adguard_state,antizapret_state,public_dns,public_listeners",
            "infrastructure_events":"node_id,id,timestamp,component_id,kind,title,detail,state,is_recovery",
            "peer_history":"node_id,id,timestamp,peer_id,name,vpn_ip,state,rx,tx,latest_handshake",
            "adguard_history":"node_id,id,timestamp,total_queries,blocked_queries,blocked_percentage,average_processing_time"
        ]
        try exec(db,"BEGIN IMMEDIATE")
        do{
            for table in tables {
                let before=try scalar(db,"SELECT count(*) FROM \(table)")
                try exec(db,"CREATE TABLE \(table)_v5(\(definitions[table]!)); INSERT INTO \(table)_v5(\(columns[table]!)) SELECT \(columns[table]!) FROM \(table);")
                guard try scalar(db,"SELECT count(*) FROM \(table)_v5")==before else{throw PersistenceError.execute("v5 copy validation failed for \(table)")}
            }
            for table in tables { try exec(db,"DROP TABLE \(table); ALTER TABLE \(table)_v5 RENAME TO \(table);") }
            try exec(db,"CREATE INDEX monitoring_node_time ON monitoring_samples(node_id,timestamp); CREATE INDEX events_node_time ON infrastructure_events(node_id,timestamp); CREATE INDEX peer_history_node_time ON peer_history(node_id,timestamp); CREATE INDEX adguard_history_node_time ON adguard_history(node_id,timestamp); PRAGMA user_version=5; COMMIT")
        }catch{try? exec(db,"ROLLBACK");throw error}
    }

    private static func mergeTail(_ table:String)->String{
        switch table {
        case "monitoring_samples":return ",cpu,memory,disk,ping,vps_state,wg_state,adguard_state,antizapret_state,public_dns,public_listeners"
        case "infrastructure_events":return ",component_id,kind,title,detail,state,is_recovery"
        case "peer_history":return ",peer_id,name,vpn_ip,state,rx,tx,latest_handshake"
        case "adguard_history":return ",total_queries,blocked_queries,blocked_percentage,average_processing_time"
        default:return ""
        }
    }

    private enum Binding { case text(String), integer(Int), integer64(UInt64), real(Double), null; static func optional(_ value: String?) -> Binding { value.map(Binding.text) ?? .null }; static func date(_ value: Date) -> Binding { .real(value.timeIntervalSince1970) } }
    private func run(_ sql: String, _ bindings: [Binding] = []) throws { try Self.withStatement(database, sql, bindings) { statement in guard sqlite3_step(statement) == SQLITE_DONE else { throw PersistenceError.execute(String(cString: sqlite3_errmsg(database))) } } }
    private func transaction(_ body:()throws->Void)throws{try Self.exec(database,"BEGIN IMMEDIATE");do{try body();try Self.exec(database,"COMMIT")}catch{try? Self.exec(database,"ROLLBACK");throw error}}
    private func scalar(_ sql: String, _ bindings: [Binding] = []) throws -> Int64 { try Self.scalar(database, sql, bindings) }
    private static func scalar(_ db: OpaquePointer?, _ sql: String, _ bindings: [Binding] = []) throws -> Int64 { try withStatement(db, sql, bindings) { statement in guard sqlite3_step(statement) == SQLITE_ROW else { throw PersistenceError.execute("Expected SQLite row") }; return sqlite3_column_int64(statement, 0) } }
    private func query<T>(_ sql: String, _ bindings: [Binding] = [], map: (OpaquePointer) throws -> T) throws -> [T] { try Self.withStatement(database, sql, bindings) { statement in var values: [T] = []; while sqlite3_step(statement) == SQLITE_ROW { values.append(try map(statement)) }; return values } }
    private static func withStatement<T>(_ db: OpaquePointer?, _ sql: String, _ bindings: [Binding], body: (OpaquePointer) throws -> T) throws -> T {
        var statement: OpaquePointer?; guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw PersistenceError.prepare(String(cString: sqlite3_errmsg(db))) }; defer { sqlite3_finalize(statement) }
        for (offset, binding) in bindings.enumerated() { let index = Int32(offset + 1); let result: Int32; switch binding { case .text(let value): result = sqlite3_bind_text(statement, index, value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)); case .integer(let value): result = sqlite3_bind_int64(statement, index, Int64(value)); case .integer64(let value): result = sqlite3_bind_int64(statement,index,Int64(clamping:value)); case .real(let value): result = sqlite3_bind_double(statement, index, value); case .null: result = sqlite3_bind_null(statement, index) }; guard result == SQLITE_OK else { throw PersistenceError.bind(String(cString: sqlite3_errmsg(db))) } }
        return try body(statement)
    }
    private static func exec(_ db: OpaquePointer?, _ sql: String) throws { var error: UnsafeMutablePointer<CChar>?; guard sqlite3_exec(db, sql, nil, nil, &error) == SQLITE_OK else { let message = error.map { String(cString: $0) } ?? "SQLite error"; sqlite3_free(error); throw PersistenceError.execute(message) } }
    private static func text(_ statement: OpaquePointer, _ column: Int32) -> String { sqlite3_column_text(statement, column).map { String(cString: $0) } ?? "" }
    private static func optionalText(_ statement: OpaquePointer, _ column: Int32) -> String? { sqlite3_column_type(statement, column) == SQLITE_NULL ? nil : text(statement, column) }
    private static func optionalDate(_ statement:OpaquePointer,_ column:Int32)->Date?{sqlite3_column_type(statement,column)==SQLITE_NULL ? nil:date(statement,column)}
    private static func date(_ statement: OpaquePointer, _ column: Int32) -> Date { Date(timeIntervalSince1970: sqlite3_column_double(statement, column)) }
}

actor LegacyMonitoringImporter {
    private let folder: URL
    init(folder: URL? = nil) { self.folder = folder ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TunnelDeck/Monitoring", isDirectory: true) }

    func importHistory(for node: InfrastructureNode, into store: InfrastructureStore) async throws -> (samples: Int, events: Int) {
        let key = Self.hostKey(node.host)
        let decoder = JSONDecoder()
        let samplesURL = folder.appendingPathComponent("samples-\(key).json")
        let eventsURL = folder.appendingPathComponent("events-\(key).json")
        let samples = (try? decoder.decode([MonitoringSample].self, from: Data(contentsOf: samplesURL))) ?? []
        let events = (try? decoder.decode([MonitoringEvent].self, from: Data(contentsOf: eventsURL))) ?? []
        for sample in samples { try await store.insert(sample: sample, nodeID: node.id) }
        for event in events { try await store.insert(event: LegacyModelAdapter.event(from: event, nodeID: node.id)) }
        return (samples.count, events.count)
    }

    static func hostKey(_ host: String) -> String { String((host.isEmpty ? "unconfigured" : host).map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." ? $0 : "_" }.prefix(120)) }
}
