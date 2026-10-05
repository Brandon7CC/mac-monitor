//
//  RawMessageFixture+Lineage.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Lineage labels
extension XCTestCase {
    /// The label launchd gives the fixture app's instance, as LaunchServices launches an app.
    static let lineageAppLabel = "application.com.example.App.1.2.00000000-0000-0000-0000-000000000000"
}


// MARK: - Lineage tokens
extension AuditToken {
    /// A token for the launched-by parent tests, with the zeroed `id` a ``LaunchedByParent`` stores its token with.
    ///
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - pidversion: The pid version.
    /// - Returns: The token of a root process in audit session 100000
    ///   (``RawMessageFixture/auditToken(pid:euid:pidversion:asid:)``).
    static func fixture(pid: Int32, pidversion: UInt32) -> AuditToken {
        AuditToken(from: RawMessageFixture.auditToken(pid: pid, pidversion: pidversion)).rowKey
    }
}


// MARK: - Forks
extension RawMessageFixture {
    /// Make the message's event a fork by its initiating process, whose child has these parents. The forking process
    /// takes the parent's token, and the child the forking process's executable.
    ///
    /// Only for a message made as a fork (`type: ES_EVENT_TYPE_NOTIFY_FORK`).
    ///
    /// - Parameters:
    ///   - childPID: The child's pid.
    ///   - parent: The child's parent: the forking process.
    ///   - responsible: The child's responsible process.
    ///   - ppid: The child's `ppid`, or `nil` for the parent's pid.
    ///   - originalPPID: The child's `original_ppid`, or `nil` for its `ppid`.
    /// - Returns: The child.
    @discardableResult
    func fork(childPID: Int32, parent: audit_token_t, responsible: audit_token_t, ppid: Int32? = nil,
              originalPPID: Int32? = nil) -> UnsafeMutablePointer<es_process_t> {
        message.pointee.process.pointee.audit_token = parent
        let path = String(cString: message.pointee.process.pointee.executable.pointee.path.data)
        let child = process(path: path, signingID: "com.apple.true", pid: childPID)
        /// The token's sixth value is its pid (the test target doesn't link libbsm's `audit_token_to_pid`).
        child.pointee.ppid = ppid ?? Int32(bitPattern: parent.val.5)
        child.pointee.original_ppid = originalPPID ?? child.pointee.ppid
        child.pointee.parent_audit_token = parent
        child.pointee.responsible_audit_token = responsible
        message.pointee.event.fork.child = child
        return child
    }
}


// MARK: - Execs
extension XCTestCase {
    /// An audit token as eslogger writes one, of a root process in audit session 100001.
    ///
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - pidversion: The pid version.
    /// - Returns: The token's object.
    func esloggerToken(pid: Int, pidversion: Int) -> [String: Any] {
        ["asid": 100_001, "auid": 4_294_967_295, "egid": 0, "euid": 0, "pid": pid, "pidversion": pidversion, "rgid": 0,
         "ruid": 0]
    }
    
    /// An eslogger exec record: the eslogger exit fixture's process (`/usr/libexec/exampled`, pid 4242, its own
    /// responsible process) execs itself again, under another parent and environment.
    ///
    /// Exec events are never built from raw messages (see ``RawMessageFixture``): they're read from eslogger's JSON.
    ///
    /// - Parameters:
    ///   - parent: The parent's pid and pid version: the target's `parent_audit_token`, `ppid` and `original_ppid`.
    ///   - originalPPID: The target's `original_ppid`, if not the parent's pid.
    ///   - env: The target's environment.
    /// - Returns: The record.
    /// - Throws: The error reading the exit fixture, or an `XCTest` failure if it has no process.
    func esloggerExec(parent: (pid: Int, pidversion: Int), originalPPID: Int? = nil,
                      env: [String] = []) throws -> [String: Any] {
        var target = try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any])
        target["ppid"] = parent.pid
        target["original_ppid"] = originalPPID ?? parent.pid
        target["parent_audit_token"] = esloggerToken(pid: parent.pid, pidversion: parent.pidversion)
        return try esloggerRecord("exec", type: Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue), [
            "target": target, "script": NSNull(), "dyld_exec_path": "/usr/libexec/exampled",
            "cwd": ["path": "/", "path_truncated": false, "stat": [:]], "last_fd": 2, "image_cputype": 16_777_228,
            "image_cpusubtype": 2, "args": ["/usr/libexec/exampled"], "fds": [], "env": env,
        ])
    }
    
    /// An exec record as launchd starts a job's program: exec'd by `xpcproxy` (the platform binary at
    /// `/usr/libexec/xpcproxy`), which sets the job's `XPC_SERVICE_NAME`.
    ///
    /// - Parameters:
    ///   - record: An exec record (``esloggerExec(parent:originalPPID:env:)``).
    ///   - platform: Is the exec'ing `xpcproxy` a platform binary? Only a copy of it isn't.
    /// - Returns: The record, exec'd by `xpcproxy`.
    /// - Throws: An `XCTest` failure if the record has no process or executable.
    func execedByXPCProxy(_ record: [String: Any], platform: Bool = true) throws -> [String: Any] {
        var record = record
        var process = try XCTUnwrap(record["process"] as? [String: Any])
        var executable = try XCTUnwrap(process["executable"] as? [String: Any])
        executable["path"] = "/usr/libexec/xpcproxy"
        process["executable"] = executable
        process["is_platform_binary"] = platform
        record["process"] = process
        return record
    }
}


// MARK: - Processes and their events
extension XCTestCase {
    /// A process as eslogger writes one: the eslogger exit fixture's, as another process with its own parents.
    ///
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - pidversion: The pid version.
    ///   - path: The executable.
    ///   - parent: The parent's pid and pid version: `parent_audit_token`, and `ppid`.
    ///   - originalPPID: `original_ppid`, if not the parent's pid.
    ///   - responsible: The responsible process's pid and pid version, if not the process itself.
    /// - Returns: The process's object.
    /// - Throws: The error reading the exit fixture, or an `XCTest` failure if it has no process.
    func esloggerProcess(pid: Int, pidversion: Int, path: String, parent: (pid: Int, pidversion: Int),
                         originalPPID: Int? = nil,
                         responsible: (pid: Int, pidversion: Int)? = nil) throws -> [String: Any] {
        var process = try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any])
        var executable = try XCTUnwrap(process["executable"] as? [String: Any])
        executable["path"] = path
        let responsible = responsible ?? (pid, pidversion)
        process["executable"] = executable
        process["audit_token"] = esloggerToken(pid: pid, pidversion: pidversion)
        process["ppid"] = parent.pid
        process["original_ppid"] = originalPPID ?? parent.pid
        process["parent_audit_token"] = esloggerToken(pid: parent.pid, pidversion: parent.pidversion)
        process["responsible_audit_token"] = esloggerToken(pid: responsible.pid, pidversion: responsible.pidversion)
        return process
    }
    
    /// An exec read as File > Open Trace… reads it: one process image execs the next.
    ///
    /// - Parameters:
    ///   - process: The exec'ing image (``esloggerProcess(pid:pidversion:path:parent:originalPPID:responsible:)``).
    ///   - target: The new image.
    ///   - env: The new image's environment.
    /// - Returns: The event.
    /// - Throws: The error reading the record.
    func execMessage(by process: [String: Any], of target: [String: Any], env: [String] = []) throws -> Message {
        let path = (target["executable"] as? [String: Any])?["path"] as? String ?? ""
        var record = try esloggerRecord("exec", type: Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue), [
            "target": target, "script": NSNull(), "dyld_exec_path": path,
            "cwd": ["path": "/", "path_truncated": false, "stat": [:]], "last_fd": 2, "image_cputype": 16_777_228,
            "image_cpusubtype": 2, "args": [path], "fds": [], "env": env,
        ])
        record["process"] = process
        return try importRecord(record)
    }
    
    /// A fork read as File > Open Trace… reads it.
    ///
    /// - Parameters:
    ///   - process: The forking process.
    ///   - child: The child.
    /// - Returns: The event.
    /// - Throws: The error reading the record.
    func forkMessage(by process: [String: Any], of child: [String: Any]) throws -> Message {
        var record = try esloggerRecord("fork", type: Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue), ["child": child])
        record["process"] = process
        return try importRecord(record)
    }
    
    /// An exit read as File > Open Trace… reads it: an event that creates no process.
    ///
    /// - Parameter process: The exiting process.
    /// - Returns: The event.
    /// - Throws: The error reading the record.
    func exitMessage(of process: [String: Any]) throws -> Message {
        var record = try fixtureObject("eslogger-exit.jsonl")
        record["process"] = process
        return try importRecord(record)
    }
}


// MARK: - The lineage trace
extension XCTestCase {
    /// The shell (pid 401) of the lineage fixture's shell children.
    ///
    /// - Returns: Its process.
    /// - Throws: The error reading the exit fixture.
    func shell() throws -> [String: Any] {
        try esloggerProcess(pid: 401, pidversion: 4010, path: "/bin/zsh", parent: (300, 3000))
    }
    
    /// The exec that made pid 401 the shell, under a parent the trace doesn't have.
    ///
    /// - Returns: The exec.
    /// - Throws: The error reading the record.
    func shellExec() throws -> Message {
        let login = try esloggerProcess(pid: 401, pidversion: 4009, path: "/usr/bin/login", parent: (300, 3000))
        return try execMessage(by: login, of: try shell())
    }
    
    /// The lineage fixture's events with others before them, with launched-by parents named as opening the trace names
    /// them.
    ///
    /// - Parameter earlier: Events before the fixture's.
    /// - Returns: `earlier`, then the fixture's 10 events (a shell's fork and exec, a launchd job's three, an app, its
    ///   XPC service, a reparented exec, an exec with `XPC_SERVICE_NAME=0`, and the job's child), in order.
    /// - Throws: The error reading the fixture.
    func lineageTrace(after earlier: [Message] = []) throws -> [Message] {
        var messages = earlier + (try fixtureRecords("eslogger-lineage.jsonl").map { try importRecord($0) })
        TraceLaunchedByParents().fill(&messages)
        return messages
    }
}
