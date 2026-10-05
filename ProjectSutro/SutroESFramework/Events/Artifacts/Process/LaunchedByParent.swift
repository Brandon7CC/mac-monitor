//
//  LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Launched by parent
/// The process that really caused another one to run: a Mac Monitor addition beside eslogger's fields.
///
/// On macOS launchd (pid 1) starts most processes, whoever asked for them, so the Unix parent often hides the cause.
/// Mac Monitor names the launched-by parent from the strongest signal it has (``Source``), only on the two events that
/// create a process: `event.exec.launched_by_parent` (for the exec's target) and `event.fork.launched_by_parent` (for
/// the fork's child). eslogger's own fields keep their key paths and values.
///
/// It isn't ``ESEnrichable``: the Security Extension stamps it when it serializes an event (``MessageSerializer``),
/// from the message's own fields, and an event or trace that doesn't carry one gets one resolved the same way
/// (``Message/resolveLaunchedByParent(by:path:)``), with ``resolved_by`` saying who did it.
///
/// Every key is always written, `null` when unknown, so the object has one shape. To find the launched-by parent of any
/// other event's process, find the exec or fork whose created process (its target or child) has that event's
/// `process.audit_token`, and read that event's `launched_by_parent`.
public struct LaunchedByParent: Codable, Hashable {
    /// The signal that named the launched-by parent. The raw values are the JSON values.
    public enum Source: String, Codable, CaseIterable {
        /// The Unix parent: `parent_audit_token` (or `ppid`) when it isn't launchd, or `original_ppid` when launchd
        /// adopted the process before its exec (that parent had exited, so only its pid is known). Otherwise launchd
        /// itself, when nothing better is known (a launchd fork, `xpcproxy`).
        case unixParent = "unix_parent"
        /// The process the kernel holds responsible (`responsible_audit_token`) when it isn't the process itself or
        /// launchd: an XPC service's host app, for example.
        case responsibleProcess = "responsible_process"
        /// launchd, starting the job named in ``LaunchedByParent/launchd_job``.
        case launchdJob = "launchd_job"
        /// The process that asked LaunchServices to launch an app (Finder, the Dock, an app opening a document). No
        /// process is named when LaunchServices recorded none (`open` from a shell).
        case launchServices = "launch_services"
    }
    
    /// Who resolved the answer, which also says when.
    public enum ResolvedBy: String, Codable, CaseIterable {
        /// The Security Extension, as it serialized the event, from the message alone.
        case securityExtension = "security_extension"
        /// Mac Monitor, after receiving the event: from a LaunchServices record, or for an event from a Security
        /// Extension that didn't resolve one.
        case app
        /// Mac Monitor, opening a trace that didn't carry one (eslogger's, Mac Monitor 2.1's), from the trace alone.
        case `import`
    }
    
    /// The launchd job that started the process, named by `XPC_SERVICE_NAME` in its exec environment. Only set for a
    /// direct launchd child that launchd's `xpcproxy` exec'd: any other process inherited the variable, or chose it.
    public struct LaunchdJob: Codable, Hashable {
        /// The job's label: `com.example.agent`, or `application.<bundle ID>.…` for an app LaunchServices launched.
        public var label: String
        
        /// - Parameter label: The job's label.
        public init(label: String) {
            self.label = label
        }
    }
    
    /// The signal that named the launched-by parent.
    public var source: Source
    /// The launched-by parent, exactly, with a zeroed `id` so equal answers compare equal. `nil` when only its pid is
    /// known (``Source/unixParent`` after a reparent) or no process is named (``Source/launchServices`` without one).
    public var audit_token: AuditToken?
    /// The launched-by parent's pid: its token's, or the only thing known about it.
    public var pid: Int32?
    /// The launched-by parent's executable, when known: named by an earlier event of the same process image (its pid
    /// and pid version), or else read by pid when the event was handled. ``audit_token`` is the identity.
    public var path: String?
    /// The launchd job that started the process, when it's a direct launchd child with a label.
    public var launchd_job: LaunchdJob?
    /// Who resolved the answer.
    public var resolved_by: ResolvedBy
    
    /// - Parameters:
    ///   - source: The signal that named the launched-by parent.
    ///   - audit_token: Its audit token, stored with a zeroed `id`.
    ///   - pid: Its pid, when there's no token (the token's pid otherwise).
    ///   - path: Its executable, when known.
    ///   - launchd_job: The job that started the process, when it's a direct launchd child with a label.
    ///   - resolved_by: Who resolved it.
    public init(source: Source, audit_token: AuditToken?, pid: Int32? = nil, path: String?,
                launchd_job: LaunchdJob? = nil, resolved_by: ResolvedBy) {
        self.source = source
        self.audit_token = audit_token?.rowKey
        self.pid = audit_token?.pid ?? pid
        self.path = path
        self.launchd_job = launchd_job
        self.resolved_by = resolved_by
    }
    
    
    // MARK: Coding
    /// The JSON keys, which are the property names.
    enum CodingKeys: String, CodingKey {
        case source, audit_token, pid, path, launchd_job, resolved_by
    }
    
    /// Write every key, `null` when unknown, and the token the way eslogger writes one (without an `id`).
    ///
    /// Each value goes through the container's own call for its type rather than as an optional, which saves the
    /// Security Extension about a sixth of the launched-by parent's encoding on every exec and fork.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The encoder's error.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(source.rawValue, forKey: .source)
        if let audit_token {
            try container.encode(ESLoggerAuditToken(audit_token), forKey: .audit_token)
        } else {
            try container.encodeNil(forKey: .audit_token)
        }
        if let pid { try container.encode(pid, forKey: .pid) } else { try container.encodeNil(forKey: .pid) }
        if let path { try container.encode(path, forKey: .path) } else { try container.encodeNil(forKey: .path) }
        if let launchd_job {
            try container.encode(launchd_job, forKey: .launchd_job)
        } else {
            try container.encodeNil(forKey: .launchd_job)
        }
        try container.encode(resolved_by.rawValue, forKey: .resolved_by)
    }
    
    /// Read what ``encode(to:)`` writes. A token with an `id` (Mac Monitor's own shape) reads the same.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: `DecodingError` for a missing or unknown ``source`` or ``resolved_by``, or a value of the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(source: try container.decode(Source.self, forKey: .source),
                  audit_token: try container.decodeIfPresent(ESLoggerAuditToken.self, forKey: .audit_token)?.token,
                  pid: try container.decodeIfPresent(Int32.self, forKey: .pid),
                  path: try container.decodeIfPresent(String.self, forKey: .path),
                  launchd_job: try container.decodeIfPresent(LaunchdJob.self, forKey: .launchd_job),
                  resolved_by: try container.decode(ResolvedBy.self, forKey: .resolved_by))
    }
}


// MARK: - Reading it leniently
extension KeyedDecodingContainer {
    /// A launched-by parent, or `nil` when it's missing, `null`, or can't be read (an unknown
    /// ``LaunchedByParent/Source`` or ``LaunchedByParent/ResolvedBy`` from a newer writer, or a value of the wrong
    /// type).
    ///
    /// The synthesized decoders of ``ProcessExecEvent`` and ``ProcessForkEvent`` call this rather than the generic
    /// `decodeIfPresent(_:forKey:)`, for `JSONDecoder` (the Security Extension's events) and ``TraceDecoder`` (traces)
    /// alike. Mac Monitor drops (or skips) an event it can't decode, and a launched-by parent must never cost one:
    /// without it, Mac Monitor resolves its own.
    ///
    /// - Parameters:
    ///   - type: ``LaunchedByParent``.
    ///   - key: The key.
    /// - Returns: The launched-by parent, or `nil`.
    /// - Throws: Never.
    func decodeIfPresent(_ type: LaunchedByParent.Type, forKey key: Key) throws -> LaunchedByParent? {
        guard contains(key), !((try? decodeNil(forKey: key)) ?? true) else { return nil }
        return try? decode(LaunchedByParent.self, forKey: key)
    }
}
