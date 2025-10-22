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
        case id, pid, target_proc_audit_token_string, target_proc_parent_audit_token_string, target_proc_responsible_audit_token_string, allow_jit, command_line, get_task_allow, is_adhoc_signed, is_es_client, is_platform_binary, process_name, process_path, rootless, signing_id, skip_lv, team_id, start_time, cdhash, certificate_chain, ruid, euid, ruid_human, euid_human, file_quarantine_type, cs_type, group_id, target, dyld_exec_path, script, cwd, last_fd, image_cputype, image_cpusubtype, fds, args, env, script_content
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
            self.script_content = execEvent.script_content
        }
        
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
