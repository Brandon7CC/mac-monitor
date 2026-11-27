//
//  ProcessExecEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation
import OSLog

// MARK: - Process Execution event https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t
public struct ProcessExecEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    /// Base properties `es_event_exec_t`
    public var argc: Int
    public var env, args: [String]
    public var fds: [FileDescriptor]
    
    public var script, cwd: File?                               // message >= 2, message >= 3
    public var last_fd, image_cputype, image_cpusubtype: Int?   // message >= 4, message >= 6
    public var dyld_exec_path: String?                          // message >=7   (macOS 13.3+)
    
    public var target: Process
    
    /// Mac Monitor enrichment
    public var certificate_chain: [X509Cert] = []
    public var command_line: String?
    public var script_content: String?
    public var resolved_script_path: String?
    /// Milliseconds from the target executable's birth (its `stat`'s `st_birthtimespec`) to the exec: a binary that
    /// runs seconds after it was written is new, as a dropper's payload is. `nil` when the birth time is unknown. Set
    /// with the message's time (``Message/deriveExecutableAge()``).
    public var executable_age_ms: Int?
    /// Mac Monitor's launched-by parent of ``target`` (``LaunchedByParent``): stamped by the Security Extension's
    /// serializer from the message's own fields, not by ``enrich()``, which also runs on traces recorded on other Macs,
    /// where no process's path may be read. `nil` until it's resolved.
    public var launched_by_parent: LaunchedByParent?
    /// The keys of ``target``'s ancestors, nearest first (``ProcessKey``, ``ProcessLineage``): stamped by the
    /// Security Extension's serializer. Empty for a child of launchd, and `nil` when its lineage isn't tracked.
    public var ancestor_keys: [String]?
    /// What scanning the script the exec runs with Apple's XProtect rules found, while scanning is on: Endpoint
    /// Security's `script`, the script an interpreter's arguments name, or an AppleScript applet's `main.scpt`. `nil`
    /// for an exec that runs no script Mac Monitor found, while scanning is off, or in a record from Mac Monitor
    /// before 3.3.0 or eslogger.
    public var yara_scan: YaraScan?
    /// The script as the capture lane read it, for its scan: never encoded, and taken off the event before it's sent
    /// (``Message/requestYaraScan(of:from:volumes:)``).
    var scriptRead: ScriptRead?

    /// Every key but ``scriptRead``.
    enum CodingKeys: String, CodingKey {
        case id, argc, env, args, fds, script, cwd, last_fd, image_cputype, image_cpusubtype, dyld_exec_path, target
        case certificate_chain, command_line, script_content, resolved_script_path, executable_age_ms
        case launched_by_parent, ancestor_keys, yara_scan
    }

    // @note construct a new process_exec
    init(from rawMessage: UnsafePointer<es_message_t>) {
        es_retain_message(rawMessage)
        var execEvent: es_event_exec_t = rawMessage.pointee.event.exec
        
        // MARK: - Conform to ESLogger
        // version Indicates the message version
        let version = rawMessage.pointee.version
        
        // The new process that is being executed
        self.target = Process(from: execEvent.target.pointee, version: Int(version))
        
        // Arguments (the command line is joined from them by `enrich()`)
        self.argc = Int(es_exec_arg_count(&execEvent))
        self.args = ProcessHelpers.parseExecArgs(execEvent: &execEvent)
        
        // Environment variables
        self.env = ProcessHelpers.parseExecEnv(event: &execEvent)
        
        // Open file descriptors
        self.fds = ProcessHelpers.getFds(event: &execEvent)
        
        /// Script being executed by interpreter (e.g. `./foo.sh` not `/bin/sh ./foo.sh`) (2), and the current working
        /// directory at exec time (3).
        if version >= 2 { script = execEvent.script.map { File(from: $0.pointee) } }
        if version >= 3 { cwd = File(from: execEvent.cwd.pointee) }
        
        /// @note Mac Monitor enrichment -- script content
        readScript()

        // Highest open file descriptor after the exec completed (4), the CPU type and subtype of the executable image
        // (6), and the exec path passed up to dyld, before symlink resolution (7, macOS 13.3+).
        last_fd = version >= 4 ? Int(execEvent.last_fd) : nil
        image_cputype = version >= 6 ? Int(execEvent.image_cputype) : nil
        image_cpusubtype = version >= 6 ? Int(execEvent.image_cpusubtype) : nil
        dyld_exec_path = version >= 7 ? execEvent.dyld_exec_path.string : nil
        
        // MARK: - Code Signing certificate chain
        if target.codesigning_flags & Int64(CS_VALID) != 0, let executable = target.executable {
            certificate_chain = ProcessHelpers.getCodeSigningCerts(forBinaryAt: executable.path,
                                                                    stat: executable.stat)
        }
        
        enrich()
        es_release_message(rawMessage)
    }
}


// MARK: - Mac Monitor enrichment
extension ProcessExecEvent: ESEnrichable {
    /// Derive `argc`, the command line (the arguments joined by spaces), and `resolved_script_path` when ES recognizes
    /// the scripting interpreter (`script`).
    ///
    /// Not derived: the certificate chain and the script's content, which are read from the executable and the script.
    public mutating func enrich() {
        argc = args.count
        command_line = command_line ?? args.joined(separator: " ").trimmingCharacters(in: .whitespaces)
        /// Populate `resolved_script_path` if ES recognizes the scripting interpreter
        resolved_script_path = resolved_script_path ?? script?.path
    }
}


// MARK: - Script content
extension ProcessExecEvent {
    /// Read the script this exec runs, as the capture lane does as it builds the event: the script found among the
    /// arguments, its text, and what was read of it for its scan (``scriptRead``).
    mutating func readScript() {
        let read = Self.readScript(reported: script, args: args, workingDirectory: cwd?.path,
                                   interpreterName: target.executable?.name,
                                   reader: target.audit_token.map(FileReader.init(token:)))
        resolved_script_path = read.path ?? resolved_script_path
        (script_content, scriptRead) = (read.content, read.read)
    }

    /// The script an exec runs, and its text, read for the user the exec's target runs as: the Security Extension, as
    /// root, never reads them a file they couldn't read themselves.
    ///
    /// The script ES reports is the script, even when it can't be read: Mac Monitor doesn't look among the arguments
    /// then, or `./evil.sh decoy.txt`, with `evil.sh` unreadable, would show `decoy.txt`. It's read only while its path
    /// still names the file ES saw. Without one, the script of a supported interpreter is the argument its options
    /// leave (``ScriptInterpreter/scriptArgument(in:)``), opened once to check it and read its text. Either is read
    /// without updating its access time or downloading it when it's dataless (``ReadingThreadPolicy``).
    ///
    /// - Parameters:
    ///   - script: The script ES reported (message version 2), or `nil`.
    ///   - args: The exec's arguments.
    ///   - workingDirectory: The exec's working directory (message version 3), or `nil` to not look among the
    ///     arguments.
    ///   - interpreterName: The name of the target's executable.
    ///   - reader: Who the script is read for, from the target's audit token, or `nil` to read nothing.
    /// - Returns: The script Mac Monitor found among the arguments (`nil` for ES's, which ``enrich()`` names), the
    ///   script's text, `nil` when it wasn't read, and what was read of it.
    static func readScript(reported script: File?, args: [String], workingDirectory: String?,
                           interpreterName: String?,
                           reader: FileReader?) -> (path: String?, content: String?, read: ScriptRead?) {
        guard let reader else { return (nil, nil, nil) }
        if let script {
            let read = ReadingThreadPolicy.whileReading {
                ProcessHelpers.readScript(at: script.path, for: reader, expecting: FileIdentity(script.stat))
            }
            return (nil, read.map { ProcessHelpers.scriptText(of: $0.bytes) }, read)
        }
        guard let workingDirectory, let interpreter = interpreterName.flatMap(ScriptInterpreter.named),
              let found = ReadingThreadPolicy.whileReading({
                  ProcessHelpers.scriptFromArgs(args: args, interpreter: interpreter,
                                                workingDirectory: workingDirectory, reader: reader)
              }) else {
            return (nil, nil, nil)
        }
        return (found.path, found.content, found.read)
    }
}


// MARK: - XPC service name
extension ProcessExecEvent {
    /// The XPC service name in a process's environment.
    ///
    /// Only an entry named exactly `XPC_SERVICE_NAME` counts. launchd sets it to `0` for a process that isn't an XPC
    /// service, which counts as none.
    ///
    /// - Parameter env: The environment's `KEY=value` entries, in order.
    /// - Returns: The first `XPC_SERVICE_NAME`'s value, or `nil` without one or when it's empty or `0`.
    static func xpcServiceName(in env: [String]) -> String? {
        let prefix = "XPC_SERVICE_NAME="
        guard let entry = env.first(where: { $0.hasPrefix(prefix) }) else { return nil }
        let name = String(entry.dropFirst(prefix.count))
        return name.isEmpty || name == "0" ? nil : name
    }
}
