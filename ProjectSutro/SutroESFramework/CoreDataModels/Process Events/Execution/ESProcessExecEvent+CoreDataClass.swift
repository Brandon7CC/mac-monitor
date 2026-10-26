//
//  RCESProcessExecEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData
import OSLog

@objc(ESProcessExecEvent)
public class ESProcessExecEvent: NSManagedObject, Identifiable, LaunchedByParentColumns {
    @NSManaged public var argsData: Data?
    @NSManaged public var envData: Data?
    @NSManaged public var command_line: String?
    @NSManaged public var certificateChainData: Data?
    /// The new process image. The row may be shared with the events that process goes on to cause.
    @NSManaged public var target: ESProcess
    /// The `id` ``target`` had in this event (and exports). A shared row keeps the `id` of the first event that
    /// stored it.
    @NSManaged public var target_id: UUID?
    @NSManaged public var dyld_exec_path: String?
    /// Milliseconds from the executable's birth to the exec (``ProcessExecEvent/executable_age_ms``), or `nil`.
    @NSManaged public var executable_age_ms: NSNumber?
    @NSManaged public var script: ESFile?
    @NSManaged public var cwd: ESFile?
    @NSManaged public var last_fd: Int64
    @NSManaged public var fdsData: Data?
    @NSManaged public var image_cputype: Int64
    @NSManaged public var image_cpusubtype: Int64
    @NSManaged public var script_content: String?
    @NSManaged public var resolved_script_path: String?
    /// ``launched_by_parent``, in plain columns (``LaunchedByParentColumns``).
    @NSManaged public var launched_by_parent_source, launched_by_parent_resolved_by: String?
    @NSManaged public var launched_by_parent_path, launched_by_parent_job: String?
    @NSManaged public var launched_by_parent_pid: NSNumber?
    @NSManaged public var launched_by_parent_token: Data?

    enum CodingKeys: String, CodingKey {
        case command_line
        case certificate_chain
        case target
        case dyld_exec_path
        case script
        case resolved_script_path
        case cwd
        case last_fd
        case image_cputype
        case image_cpusubtype
        case fds
        case args
        case env
        case script_content
        case launched_by_parent
        case executable_age_ms
    }
    
    public var args: [String] {
        get {
            guard let data = argsData else { return [] }
            return (try? JSONDecoder().decode([String].self, from: data)) ?? []
        }
        set {
            argsData = try? JSONEncoder().encode(newValue)
        }
    }
    
    public var env: [String] {
        get {
            guard let data = envData else { return [] }
            return (try? JSONDecoder().decode([String].self, from: data)) ?? []
        }
        set {
            envData = try? JSONEncoder().encode(newValue)
        }
    }
    
    /// Mac Monitor's launched-by parent of ``target`` (``LaunchedByParent``), kept in plain columns
    /// (``LaunchedByParentColumns``). `nil` until it's resolved.
    public var launched_by_parent: LaunchedByParent? {
        get { storedLaunchedByParent }
        set { storedLaunchedByParent = newValue }
    }
    
    /// The XPC service launchd started the process as: `XPC_SERVICE_NAME`'s value in ``env``, or `nil` without one.
    public var xpcServiceName: String? {
        Self.xpcServiceName(in: env)
    }
    
    /// The XPC service name in a process's environment (``ProcessExecEvent/xpcServiceName(in:)``).
    ///
    /// - Parameter env: The environment's `KEY=value` entries, in order.
    /// - Returns: The first `XPC_SERVICE_NAME`'s value, or `nil` without one or when it's empty or `0`.
    static func xpcServiceName(in env: [String]) -> String? { ProcessExecEvent.xpcServiceName(in: env) }
    
    
    public var fds: [FileDescriptor] {
        get {
            guard let data = fdsData else { return [] }
            return (try? JSONDecoder().decode([FileDescriptor].self, from: data)) ?? []
        }
        set {
            fdsData = try? JSONEncoder().encode(newValue)
        }
    }
    
    public var certificate_chain: [X509Cert] {
        get {
            guard let data = certificateChainData else { return [] }
            return (try? JSONDecoder().decode([X509Cert].self, from: data)) ?? []
        }
        set {
            certificateChainData = try? JSONEncoder().encode(newValue)
        }
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessExecEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let execEvent: ProcessExecEvent = message.event.exec!
        let description = NSEntityDescription.entity(forEntityName: "ESProcessExecEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        // MARK: - Conform to ESLogger
        self.dyld_exec_path = execEvent.dyld_exec_path // macOS 13.3+
        /// The new process image: shared with the events it goes on to cause (see ``ESProcess/row(for:version:in:)``).
        attach(ESProcess.row(for: execEvent.target, version: message.version, in: context), to: #keyPath(ESProcessExecEvent.target))
        self.target_id = execEvent.target.id
        
        self.fds = execEvent.fds
        self.args = execEvent.args
        self.env = execEvent.env
        
        if let script = execEvent.script {
            attach(ESFile.row(for: script, in: context), to: #keyPath(ESProcessExecEvent.script))
        }
        if let resolved_script_path = execEvent.resolved_script_path {
            self.resolved_script_path = resolved_script_path
        }
        self.script_content = execEvent.script_content
        
        if let cwd = execEvent.cwd {
            attach(ESFile.row(for: cwd, in: context), to: #keyPath(ESProcessExecEvent.cwd))
        }
        
        if let last_fd = execEvent.last_fd {
            self.last_fd = Int64(last_fd)
        }
        
        if let image_cputype = execEvent.image_cputype {
            self.image_cputype = Int64(image_cputype)
        }
        if let image_cpusubtype = execEvent.image_cpusubtype {
            self.image_cpusubtype = Int64(image_cpusubtype)
        }
        
        self.command_line = execEvent.command_line ?? ""
        self.certificate_chain = execEvent.certificate_chain
        self.launched_by_parent = execEvent.launched_by_parent
        self.executable_age_ms = execEvent.executable_age_ms.map { NSNumber(value: $0) }
    }
}

// MARK: - Encodable conformance
extension ESProcessExecEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        // MARK: - Conform to ESLogger
        try container.encode(ESProcessRecord(process: target, id: target_id ?? target.id), forKey: .target)
        try container.encode(fds, forKey: .fds)
        try container.encode(script, forKey: .script)
        try container
            .encode(resolved_script_path, forKey: .resolved_script_path)
        try container.encode(script_content, forKey: .script_content)
        try container.encode(cwd, forKey: .cwd)
        try container.encode(last_fd, forKey: .last_fd)
        try container.encode(args, forKey: .args)
        try container.encode(env, forKey: .env)
        
        try container.encode(image_cputype, forKey: .image_cputype)
        try container.encode(image_cpusubtype, forKey: .image_cpusubtype)
        // @note don't include dyld_exec_path if we're not on macOS 13.3+
        if #available(macOS 13.3, *) {
            try container.encode(dyld_exec_path, forKey: .dyld_exec_path)
        }
        
        try container.encode(command_line, forKey: .command_line)
        /// `null` when the executable's birth time is unknown, so the key is always there.
        try container.encode(executable_age_ms?.intValue, forKey: .executable_age_ms)
        
        // @note don't include the cert chain in json if there is none
        if !self.certificate_chain.isEmpty && self.certificate_chain.count != 0 {
            try container.encode(certificate_chain, forKey: .certificate_chain)
        }
        
        /// Mac Monitor's enrichment beside eslogger's fields: `null` when there's none, so the key is always there.
        try container.encode(launched_by_parent, forKey: .launched_by_parent)
    }
}


// MARK: - Executable age
extension ESProcessExecEvent {
    /// An executable created less than this many seconds before it ran is new, as a dropper's payload is.
    public static let newExecutableAge: TimeInterval = 300

    /// Seconds from the executable's birth to the exec (``executable_age_ms``), or `nil` when it's unknown or the
    /// birth time is after the exec.
    public var executableAge: TimeInterval? {
        executable_age_ms.map { $0.doubleValue / 1000 }.flatMap { $0 >= 0 ? $0 : nil }
    }

    /// Was the executable created just before it ran (``newExecutableAge``)?
    public var isNewExecutable: Bool {
        executableAge.map { $0 < Self.newExecutableAge } ?? false
    }
}
