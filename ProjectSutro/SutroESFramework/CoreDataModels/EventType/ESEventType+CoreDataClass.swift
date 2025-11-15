//
//  ESEventType+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//
//

import Foundation
import CoreData

@objc(ESEventType)
public class ESEventType: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        
        /// Process events
        case exec
        case fork
        case exit
        case signal
        case proc_suspend_resume
        
        /// Interporcess events
        case remote_thread_create
        case trace
        
        /// Code signing events
        case cs_invalidated
        
        /// Memory mapping events
        case mmap
        case mprotect
        
        /// File system events
        case create
        case unlink
        case rename
        case open
        case write
        case close
        case dup
        
        /// Symbolic link events
        case link
        
        /// File metadata events
        case setextattr
        case deleteextattr
        case setmode
        
        /// Pseudoterminal events
        case pty_grant
        
        /// File system mounting events
        case mount
        
        /// Login events
        case login_login
        case lw_session_login
        case lw_session_unlock
        
        /// OpenSSH events
        case openssh_login
        case openssh_logout
        
        /// Kernel events
        case iokit_open
        
        /// Security Authorization events
        case authorization_petition
        case authorization_judgement
        
        /// Task port events
        case get_task
        case proc_check
        
        /// MDM events
        case profile_add
        
        /// Service management events
        case btm_launch_item_add
        case btm_launch_item_remove
        
        /// XProtect events
        case xp_malware_detected
        case xp_malware_remediated
        
        /// Directory events
        case od_create_user
        case od_modify_password
        case od_group_add
        case od_group_remove
        case od_create_group
        case od_attribute_value_add
        
        /// XPC events
        case xpc_connect
        
        /// Socket events
        case uipc_connect
        case uipc_bind
        
        /// TCC events
        case tcc_modify
        
        /// Gatekeeper events
        case gatekeeper_user_override
    }
    
    
    // MARK: - Custom Core Data initilizer for ESEventType
    convenience init(
        from message: Message,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESEventType", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = UUID()
        
        switch message.event {
            // MARK: Process events
        case .exec(_):
            self.exec = ESProcessExecEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .fork(_):
            self.fork = ESProcessForkEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .exit(_):
            self.exit = ESProcessExitEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .signal(_):
            self.signal = ESProcessSignalEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .proc_suspend_resume(_):
            self.proc_suspend_resume = ESProcessSocketEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .proc_check(_):
            self.proc_check = ESProcessCheckEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Interprocess events
        case .remote_thread_create(_):
            self.remote_thread_create = ESRemoteThreadCreateEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .trace(_):
            self.trace = ESProcessTraceEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Code Signing events
        case .cs_invalidated(_):
            self.cs_invalidated = ESCodeSignatureInvalidatedEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            
            // MARK: Memory mapping events
        case .mmap(_):
            self.mmap = ESMMapEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .mprotect(_):
            self.mprotect = ESMProtectEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: File System events
        case .create(_):
            self.create = ESFileCreateEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .rename(_):
            self.rename = ESFileRenameEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .open(_):
            self.open = ESFileOpenEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .write(_):
            self.write = ESFileWriteEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .close(_):
            self.close = ESFileCloseEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .unlink(_):
            self.unlink = ESFileDeleteEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .dup(_):
            self.dup = ESFDDuplicateEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Symbolic Link events
        case .link(_):
            self.link = ESLinkEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: File Metadata events
        case .setextattr(_):
            self.setextattr = ESXattrSetEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .deleteextattr(_):
            self.deleteextattr = ESXattrDeleteEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .setmode(_):
            self.setmode = ESSetModeEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Pseudoterminal Event
        case .pty_grant(_):
            self.pty_grant = ESPTYGrantEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: File System Mounting events
        case .mount(_):
            self.mount = ESMountEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Login events
        case .login_login(_):
            self.login_login = ESLoginLoginEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .lw_session_login(_):
            self.lw_session_login = ESLWLoginEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .lw_session_unlock(_):
            self.lw_session_unlock = ESLWUnlockEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: OpenSSH events
        case .openssh_login(_):
            self.openssh_login = ESOpenSSHLoginEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .openssh_logout(_):
            self.openssh_logout = ESOpenSSHLogoutEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Kernel events
        case .iokit_open(_):
            self.iokit_open = ESIOKitOpenEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Security Authorization events
        case .authorization_petition(_):
            self.authorization_petition = ESAuthorizationPetitionEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .authorization_judgement(_):
            self.authorization_judgement = ESAuthorizationJudgementEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Task Port events
        case .get_task(_):
            self.get_task = ESGetTaskEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: MDM events
        case .profile_add(_):
            self.profile_add = ESProfileAddEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Service Management events
        case .btm_launch_item_add(_):
            self.btm_launch_item_add = ESLaunchItemAddEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .btm_launch_item_remove(_):
            self.btm_launch_item_remove = ESLaunchItemRemoveEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: XProtect events
        case .xp_malware_detected(_):
            self.xp_malware_detected = ESXProtectDetect(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .xp_malware_remediated(_):
            self.xp_malware_remediated = ESXProtectRemediate(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: Directory events
        case .od_create_user(_):
            self.od_create_user = ESODCreateUserEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .od_modify_password(_):
            self.od_modify_password = ESODModifyPasswordEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .od_group_add(_):
            self.od_group_add = ESODGroupAddEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .od_group_remove(_):
            self.od_group_remove = ESODGroupRemoveEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .od_create_group(_):
            self.od_create_group = ESODCreateGroupEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .od_attribute_value_add(_):
            self.od_attribute_value_add = ESODAttributeValueAddEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            
            // MARK: XPC events
        case .xpc_connect(_):
            self.xpc_connect = ESXPCConnectEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            // MARK: Socket events
        case .uipc_connect(_):
            self.uipc_connect = ESUIPCConnectEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
        case .uipc_bind(_):
            self.uipc_bind = ESUIPCBindEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            // MARK: TCC events
        case .tcc_modify(_):
            self.tcc_modify = ESTCCModifyEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
            // MARK: Gatekeeper events
        case .gatekeeper_user_override(_):
            self.gatekeeper_user_override = ESGatekeeperUserOverrideEvent(
                from: message,
                insertIntoManagedObjectContext: context
            )
            
        default:
            break
        }
        
        
    }
    
}

// MARK: - Encodable conformance
extension ESEventType: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        // MARK: Process events
        try container.encodeIfPresent(exec, forKey: .exec)
        try container.encodeIfPresent(fork, forKey: .fork)
        try container.encodeIfPresent(exit, forKey: .exit)
        try container.encodeIfPresent(signal, forKey: .signal)
        try container.encodeIfPresent(proc_suspend_resume, forKey: .proc_suspend_resume)
        try container.encodeIfPresent(proc_check, forKey: .proc_check)
        
        // MARK: Interprocess events
        try container.encodeIfPresent(trace, forKey: .trace)
        try container.encodeIfPresent(remote_thread_create, forKey: .remote_thread_create)
        
        // MARK: Code Signing events
        try container.encodeIfPresent(cs_invalidated, forKey: .cs_invalidated)
        
        // MARK: Memory mapping events
        try container.encodeIfPresent(mmap, forKey: .mmap)
        try container.encodeIfPresent(mprotect, forKey: .mprotect)
        
        // MARK: File System events
        try container.encodeIfPresent(create, forKey: .create)
        try container.encodeIfPresent(unlink, forKey: .unlink)
        try container.encodeIfPresent(rename, forKey: .rename)
        try container.encodeIfPresent(`open`, forKey: .open)
        try container.encodeIfPresent(write, forKey: .write)
        try container.encodeIfPresent(close, forKey: .close)
        try container.encodeIfPresent(dup, forKey: .dup)
        
        // MARK: Symbolic Link events
        try container.encodeIfPresent(link, forKey: .link)
        
        // MARK: File Metadata events
        try container.encodeIfPresent(setextattr, forKey: .setextattr)
        try container.encodeIfPresent(deleteextattr, forKey: .deleteextattr)
        try container.encodeIfPresent(setmode, forKey: .setmode)
        
        // MARK: Pseudoterminal events
        try container.encodeIfPresent(pty_grant, forKey: .pty_grant)
        
        // MARK: File System Mounting events
        try container.encodeIfPresent(mount, forKey: .mount)
        
        // MARK: Login events
        try container.encodeIfPresent(login_login, forKey: .login_login)
        try container.encodeIfPresent(lw_session_login, forKey: .lw_session_login)
        try container.encodeIfPresent(lw_session_unlock, forKey: .lw_session_unlock)
        
        // MARK: OpenSSH events
        try container.encodeIfPresent(openssh_login, forKey: .openssh_login)
        try container.encodeIfPresent(openssh_logout, forKey: .openssh_logout)
        
        // MARK: Kernel events
        try container.encodeIfPresent(iokit_open, forKey: .iokit_open)
        
        // MARK: Security Authorization events
        try container.encodeIfPresent(authorization_petition, forKey: .authorization_petition)
        try container.encodeIfPresent(authorization_judgement, forKey: .authorization_judgement)
        
        // MARK: Task Port events
        try container.encodeIfPresent(get_task, forKey: .get_task)
        
        // MARK: MDM events
        try container.encodeIfPresent(profile_add, forKey: .profile_add)
        
        // MARK: Service Management events
        try container.encodeIfPresent(btm_launch_item_add, forKey: .btm_launch_item_add)
        try container.encodeIfPresent(btm_launch_item_remove, forKey: .btm_launch_item_remove)
        
        // MARK: XProtect events
        try container.encodeIfPresent(xp_malware_detected, forKey: .xp_malware_detected)
        try container.encodeIfPresent(xp_malware_remediated, forKey: .xp_malware_remediated)
        
        // MARK: Directory events
        try container.encodeIfPresent(od_create_user, forKey: .od_create_user)
        try container.encodeIfPresent(od_modify_password, forKey: .od_modify_password)
        try container.encodeIfPresent(od_group_add, forKey: .od_group_add)
        try container.encodeIfPresent(od_group_remove, forKey: .od_group_remove)
        try container.encodeIfPresent(od_create_group, forKey: .od_create_group)
        try container.encodeIfPresent(od_attribute_value_add, forKey: .od_attribute_value_add)
        
        // MARK: XPC events
        try container.encodeIfPresent(xpc_connect, forKey: .xpc_connect)
        
        // MARK: Socket events
        try container.encodeIfPresent(uipc_connect, forKey: .uipc_connect)
        try container.encodeIfPresent(uipc_bind, forKey: .uipc_bind)
        
        // MARK: TCC events
        try container.encodeIfPresent(tcc_modify, forKey: .tcc_modify)
        
        // MARK: Gatekeeper events
        try container.encodeIfPresent(gatekeeper_user_override, forKey: .gatekeeper_user_override)
    }
}
