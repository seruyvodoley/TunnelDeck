import CSQLite
import Foundation

enum PersistenceError: Error, LocalizedError {
    case open(String), execute(String), prepare(String), bind(String)
    var errorDescription: String? {
        switch self { case .open(let value), .execute(let value), .prepare(let value), .bind(let value): value }
    }
}

actor InfrastructureStore {
    static let currentSchemaVersion = 2
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
    }

    func insert(event: InfrastructureEvent) throws {
        try run("INSERT OR IGNORE INTO infrastructure_events(id,node_id,timestamp,component_id,kind,title,detail,state,is_recovery) VALUES(?,?,?,?,?,?,?,?,?)", [.text(event.id.uuidString), .text(event.nodeID.uuidString), .date(event.timestamp), .text(event.componentID), .text(event.kind), .text(event.title), .text(event.detail), .text(event.state.rawValue), .integer(event.isRecovery ? 1 : 0)])
    }

    func sampleCount(nodeID: UUID) throws -> Int { Int(try scalar("SELECT count(*) FROM monitoring_samples WHERE node_id=?", [.text(nodeID.uuidString)])) }
    func eventCount(nodeID: UUID) throws -> Int { Int(try scalar("SELECT count(*) FROM infrastructure_events WHERE node_id=?", [.text(nodeID.uuidString)])) }
    func save(baseline: ConfigurationBaseline) throws { let payload = String(data: try JSONEncoder().encode(baseline), encoding: .utf8)!; try run("INSERT INTO configuration_baselines(id,node_id,created_at,payload) VALUES(?,?,?,?)", [.text(baseline.id.uuidString),.text(baseline.nodeID.uuidString),.date(baseline.createdAt),.text(payload)]) }
    func latestBaseline(nodeID: UUID) throws -> ConfigurationBaseline? { let rows: [String] = try query("SELECT payload FROM configuration_baselines WHERE node_id='\(nodeID.uuidString)' ORDER BY created_at DESC LIMIT 1") { Self.text($0,0) }; return rows.first.flatMap { try? JSONDecoder().decode(ConfigurationBaseline.self, from: Data($0.utf8)) } }

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
    }

    private enum Binding { case text(String), integer(Int), real(Double), null; static func optional(_ value: String?) -> Binding { value.map(Binding.text) ?? .null }; static func date(_ value: Date) -> Binding { .real(value.timeIntervalSince1970) } }
    private func run(_ sql: String, _ bindings: [Binding] = []) throws { try Self.withStatement(database, sql, bindings) { statement in guard sqlite3_step(statement) == SQLITE_DONE else { throw PersistenceError.execute(String(cString: sqlite3_errmsg(database))) } } }
    private func scalar(_ sql: String, _ bindings: [Binding] = []) throws -> Int64 { try Self.scalar(database, sql, bindings) }
    private static func scalar(_ db: OpaquePointer?, _ sql: String, _ bindings: [Binding] = []) throws -> Int64 { try withStatement(db, sql, bindings) { statement in guard sqlite3_step(statement) == SQLITE_ROW else { throw PersistenceError.execute("Expected SQLite row") }; return sqlite3_column_int64(statement, 0) } }
    private func query<T>(_ sql: String, map: (OpaquePointer) throws -> T) throws -> [T] { try Self.withStatement(database, sql, []) { statement in var values: [T] = []; while sqlite3_step(statement) == SQLITE_ROW { values.append(try map(statement)) }; return values } }
    private static func withStatement<T>(_ db: OpaquePointer?, _ sql: String, _ bindings: [Binding], body: (OpaquePointer) throws -> T) throws -> T {
        var statement: OpaquePointer?; guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw PersistenceError.prepare(String(cString: sqlite3_errmsg(db))) }; defer { sqlite3_finalize(statement) }
        for (offset, binding) in bindings.enumerated() { let index = Int32(offset + 1); let result: Int32; switch binding { case .text(let value): result = sqlite3_bind_text(statement, index, value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)); case .integer(let value): result = sqlite3_bind_int64(statement, index, Int64(value)); case .real(let value): result = sqlite3_bind_double(statement, index, value); case .null: result = sqlite3_bind_null(statement, index) }; guard result == SQLITE_OK else { throw PersistenceError.bind(String(cString: sqlite3_errmsg(db))) } }
        return try body(statement)
    }
    private static func exec(_ db: OpaquePointer?, _ sql: String) throws { var error: UnsafeMutablePointer<CChar>?; guard sqlite3_exec(db, sql, nil, nil, &error) == SQLITE_OK else { let message = error.map { String(cString: $0) } ?? "SQLite error"; sqlite3_free(error); throw PersistenceError.execute(message) } }
    private static func text(_ statement: OpaquePointer, _ column: Int32) -> String { sqlite3_column_text(statement, column).map { String(cString: $0) } ?? "" }
    private static func optionalText(_ statement: OpaquePointer, _ column: Int32) -> String? { sqlite3_column_type(statement, column) == SQLITE_NULL ? nil : text(statement, column) }
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
