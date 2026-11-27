//
//  FlowProcessRecord.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A flow's process
/// The process a network flow's record names, as `flow_process`: some of an Endpoint Security process's keys, under
/// the same names, so a rule on `process.executable.path` or `process.audit_token.pid` reads flows too.
///
/// Nothing is made up. A key the socket and the lineage table didn't give is left out: the token when no live read
/// and no lineage record gave it, the parent and group when the process was reaped before its socket's first update,
/// and the session when it wasn't running then.
public struct FlowProcessRecord: Codable, Equatable, Sendable {
    /// An executable's path and name.
    public struct Executable: Codable, Equatable, Sendable {
        public var path: String
        public var name: String
    }

    /// The socket's last user.
    public var pid: Int32
    var audit_token: ESLoggerAuditToken?
    public var audit_token_string: String?
    public var euid: Int?
    public var euid_human: String?
    public var ppid, group_id, session_id: Int32?
    public var executable: Executable?
    public var signing_id, team_id: String?
    /// A ``CodeSigningType``'s raw value, absent when it's unknown.
    public var codesigning_type: String?

    /// Its audit token, when it has one.
    public var auditToken: AuditToken? { audit_token?.token }

    /// - Parameters:
    ///   - pid: The process's pid.
    ///   - token: Its audit token, if it's known.
    ///   - euidHuman: Its effective user's name, kept only with the token.
    ///   - ppid: Its parent's pid, if it was read.
    ///   - groupID: Its process group, if it was read.
    ///   - sessionID: Its session, if it was read.
    ///   - path: Its executable's path, if it's known.
    ///   - signingID: Its signing ID.
    ///   - teamID: Its team ID.
    ///   - codesigningType: How it's signed, kept only with a path and when it's known.
    init(pid: Int32, token: AuditToken?, euidHuman: String?, ppid: Int32?, groupID: Int32?, sessionID: Int32?,
         path: String?, signingID: String?, teamID: String?, codesigningType: String?) {
        self.pid = pid
        audit_token = token.map(ESLoggerAuditToken.init)
        audit_token_string = token?.toString()
        euid = token.map { Int($0.euid) }
        euid_human = token == nil ? nil : euidHuman
        (self.ppid, group_id, session_id) = (ppid, groupID, sessionID)
        executable = path.map { Executable(path: $0, name: $0.lastPathComponent) }
        (signing_id, team_id) = (signingID, teamID)
        let known = path != nil && codesigningType != CodeSigningType.unknown.rawValue
        codesigning_type = known ? codesigningType : nil
    }

    /// A flow's process, as the client read it and the lineage table completed it. The effective user is named
    /// from this Mac's user database.
    ///
    /// - Parameter flow: The process.
    init(_ flow: FlowProcess) {
        let token = flow.token.map(AuditToken.init(from:))
        let program = flow.program
        self.init(pid: flow.pid, token: token,
                  euidHuman: token.flatMap { Process.userName(Int($0.euid), systemAccountsOnly: false) },
                  ppid: flow.ppid, groupID: flow.groupID, sessionID: flow.sessionID, path: program?.path,
                  signingID: program?.signingID, teamID: program?.teamID, codesigningType: program?.codesigningType)
    }

    /// The process a flow's `Message` carries (``Process/init(_:)``), as its record writes it.
    ///
    /// - Parameter process: The process.
    public init(_ process: Process) {
        self.init(pid: process.pid, token: process.audit_token, euidHuman: process.euid_human,
                  ppid: Self.read(process.ppid), groupID: Self.read(process.group_id),
                  sessionID: Self.read(process.session_id), path: process.executable?.path,
                  signingID: process.signing_id, teamID: process.team_id,
                  codesigningType: process.codesigning_type.rawValue)
    }

    /// The process a stored flow's row keeps, as its record writes it. The same as from the `Process` it was stored
    /// from (`NetworkFlowEventTests`).
    ///
    /// - Parameter row: The row.
    init(_ row: ESProcess) {
        let token = row.audit_token.map {
            AuditToken(pid: $0.pid, pidversion: $0.pidversion, asid: $0.asid, auid: $0.auid, euid: $0.euid,
                       ruid: $0.ruid, rgid: $0.rgid, egid: $0.egid)
        }
        let executable = row.executable
        self.init(pid: row.pid, token: token, euidHuman: row.euid_human, ppid: Self.read(row.ppid),
                  groupID: Self.read(row.group_id), sessionID: Self.read(row.session_id),
                  path: executable.map { $0.path ?? "" }, signingID: row.signing_id, teamID: row.team_id,
                  codesigningType: executable == nil ? nil : row.codesigning_type)
    }

    /// - Parameter id: A pid, process group or session, or ``Process/unread``.
    /// - Returns: It, or `nil` when it wasn't read.
    private static func read(_ id: Int32) -> Int32? {
        id == Process.unread ? nil : id
    }
}


// MARK: - The Process a flow's Message carries
extension Process {
    /// A pid, process group or session a flow's process didn't have read. No process has a negative one.
    static let unread: Int32 = -1

    /// The process a network flow's `Message` carries, from its record's values: what the capture lanes, the event
    /// store and the relations read. Everything the record doesn't have is zero, `nil` or `false`, and a pid, group
    /// or session that wasn't read is ``unread``, so the pipeline's own flows are told by their group
    /// (`PipelineScope`) and an unread one never matches.
    ///
    /// - Parameter record: The record's process.
    init(_ record: FlowProcessRecord) {
        start_time = TimeVal(from: timeval())
        pid = record.pid
        ppid = record.ppid ?? Self.unread
        original_ppid = ppid
        group_id = record.group_id ?? Self.unread
        session_id = record.session_id ?? Self.unread
        codesigning_flags = 0
        (signing_id, team_id) = (record.signing_id, record.team_id)
        audit_token = record.auditToken
        audit_token_string = record.audit_token_string ?? ""
        executable = record.executable.map { File(path: $0.path) }
        is_platform_binary = false
        is_es_client = false
        euid = record.euid
        ruid = audit_token.map { Int($0.ruid) }
        euid_human = record.euid_human
        ruid_human = euid == ruid ? euid_human : nil
        codesigning_type = record.codesigning_type.flatMap(CodeSigningType.init(rawValue:)) ?? .unknown
    }

    /// The process a network flow's `Message` carries, from the client's. Its real user is named from this Mac's user
    /// database too, as an Endpoint Security process's is.
    ///
    /// - Parameter flow: The process, as the client read it and the lineage table completed it.
    init(flow: FlowProcess) {
        self.init(FlowProcessRecord(flow))
        if ruid != euid { ruid_human = Self.userName(ruid, systemAccountsOnly: false) }
    }
}
