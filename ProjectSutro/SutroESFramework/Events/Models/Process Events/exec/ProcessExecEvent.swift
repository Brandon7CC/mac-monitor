//
//  ProcessExecEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation
import OSLog

// MARK: - Process Execution event https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t
public struct ProcessExecEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
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
    
    // MARK: - Protocol conformance
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: ProcessExecEvent, rhs: ProcessExecEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    // @note construct a new process_exec
    init(from rawMessage: UnsafePointer<es_message_t>, forcedQuarantineSigningIDs: [String] = []) {
        es_retain_message(rawMessage)
        var execEvent: es_event_exec_t = rawMessage.pointee.event.exec
        
        // MARK: - Conform to ESLogger
        // version Indicates the message version
        let version = rawMessage.pointee.version
        
        // The new process that is being executed
        self.target = Process(
            from: execEvent.target.pointee,
            version: Int(version),
            isExecMessage: true
        )
        
        // Arguments and command line
        self.argc = Int(es_exec_arg_count(&execEvent))
        self.args = ProcessHelpers.parseExecArgs(execEvent: &execEvent)
        
        /// @note Mac Monitor enrichment
        self.command_line = ProcessHelpers.parseCommandLine(execEvent: &execEvent)
        
        // Environment variables
        self.env = ProcessHelpers.parseExecEnv(event: &execEvent)
        
        // Open file descriptors
        self.fds = ProcessHelpers.getFds(event: &execEvent)
        
        /// Script being executed by interpreter (e.g. `./foo.sh` not `/bin/sh ./foo.sh`).
        if version >= 2, let script = execEvent.script {
            self.script = File(from: script.pointee)
            /// Pull the script content from the file path
            if let path = self.script?.path {
                self.script_content = ProcessHelpers
                    .getFileContents(at: path)
            }
        }
        
        // Current working directory at exec time.
        if version >= 3 {
            self.cwd = File(from: execEvent.cwd.pointee)
            
            /// @note Mac Monitor enrichment -- script content
            /// If the process executed is a supported interpreter -- attempt to pull the script
            if let exeName: String = self.target.executable?.name {
                let isScripting: Bool = ProcessHelpers.supportedInterpreters.contains { exeName.hasPrefix($0) }
                if isScripting {
                    if self.script_content == nil {
                        if let cwd = self.cwd,
                           let resolved_script_path = ProcessHelpers
                            .parseScriptFromArgs(
                                args: self.args,
                                workingDirectory: cwd.path
                            ){
                            self.resolved_script_path = resolved_script_path
                            self.script_content = ProcessHelpers
                                .getFileContents(at: resolved_script_path)
                        }
                    }
                }
            }
        }
        
        /// Populate `resolved_script_path` if ES recognizes the scripting interpreter
        if self.resolved_script_path == nil,
           let script = self.script {
            self.resolved_script_path = script.path
        }
        
        // Highest open file descriptor after the exec completed
        if version >= 4 {
            self.last_fd = Int(execEvent.last_fd)
        }
        
        if version >= 6 {
            // The CPU type of the executable image which is being executed.
            self.image_cputype = Int(execEvent.image_cputype)
            // The CPU subtype of the executable image.
            self.image_cpusubtype = Int(execEvent.image_cpusubtype)
        }
        
        // Version 7 - macOS 13.3+
        // The exec path passed up to dyld, before symlink resolution.
        if version >= 7, execEvent.dyld_exec_path.length > 0 {
            self.dyld_exec_path = String(cString: execEvent.dyld_exec_path.data)
        }
        
        // MARK: - Code Signing certificate chain
        if (UInt32(target.codesigning_flags) & UInt32(CS_VALID)) == UInt32(
            CS_VALID
        ) {
            if let executable = self.target.executable {
                self.certificate_chain = ProcessHelpers
                    .getCodeSigningCerts(forBinaryAt: executable.path)
            }
        }
        
        es_release_message(rawMessage)
    }
}
