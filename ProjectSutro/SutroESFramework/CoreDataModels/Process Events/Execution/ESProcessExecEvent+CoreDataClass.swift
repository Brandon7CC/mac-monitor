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
public class ESProcessExecEvent: NSManagedObject {
    enum CodingKeys: String, CodingKey {
        case id
        case pid
        case target_proc_audit_token_string
        case target_proc_parent_audit_token_string
        case target_proc_responsible_audit_token_string
        case allow_jit, command_line, get_task_allow
        case is_adhoc_signed
        case is_es_client
        case is_platform_binary
        case process_name
        case process_path
        case rootless
        case signing_id
        case skip_lv
        case team_id
        case start_time
        case cdhash
        case certificate_chain
        case ruid
        case euid
        case ruid_human
        case euid_human
        case file_quarantine_type
        case cs_type
        case group_id
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
        self.id = execEvent.id
        
        // MARK: - Conform to ESLogger
        self.dyld_exec_path = execEvent.dyld_exec_path // macOS 13.3+
        self.target = ESProcess(
            from: execEvent.target,
            version: message.version,
            insertIntoManagedObjectContext: context
        )
        
        self.fds = execEvent.fds
        self.args = execEvent.args
        self.env = execEvent.env
        
        if let script = execEvent.script {
            self.script = ESFile(from: script, insertIntoManagedObjectContext: context)
            
        }
        if let resolved_script_path = execEvent.resolved_script_path {
            self.resolved_script_path = resolved_script_path
        }
        self.script_content = execEvent.script_content
        
        if let cwd = execEvent.cwd {
            self.cwd = ESFile(from: cwd, insertIntoManagedObjectContext: context)
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
    }
}

// MARK: - Encodable conformance
extension ESProcessExecEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        // MARK: - Conform to ESLogger
        try container.encode(target, forKey: .target)
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
        
        // @note don't include the cert chain in json if there is none
        if !self.certificate_chain.isEmpty && self.certificate_chain.count != 0 {
            try container.encode(certificate_chain, forKey: .certificate_chain)
        }
    }
}
