//
//  ESEventType+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//
//

import Foundation
import CoreData


extension ESEventType {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESEventType> {
        return NSFetchRequest<ESEventType>(entityName: "ESEventType")
    }

    @NSManaged public var id: UUID?
    
    @NSManaged public var exec: ESProcessExecEvent?
    @NSManaged public var fork: ESProcessForkEvent?
    @NSManaged public var exit: ESProcessExitEvent?
    @NSManaged public var proc_check: ESProcessCheckEvent?
    
    @NSManaged public var mmap: ESMMapEvent?
    @NSManaged public var mprotect: ESMProtectEvent?
    
    @NSManaged public var create: ESFileCreateEvent?
    @NSManaged public var unlink: ESFileDeleteEvent?
    @NSManaged public var rename: ESFileRenameEvent?
    @NSManaged public var open: ESFileOpenEvent?
    @NSManaged public var write: ESFileWriteEvent?
    @NSManaged public var close: ESFileCloseEvent?
    @NSManaged public var dup: ESFDDuplicateEvent?
    
    @NSManaged public var setextattr: ESXattrSetEvent?
    @NSManaged public var deleteextattr: ESXattrDeleteEvent?
    @NSManaged public var setmode: ESSetModeEvent?
    
    @NSManaged public var pty_grant: ESPTYGrantEvent?
    
    @NSManaged public var btm_launch_item_add: ESLaunchItemAddEvent?
    @NSManaged public var btm_launch_item_remove: ESLaunchItemRemoveEvent?
    
    @NSManaged public var openssh_login: ESOpenSSHLoginEvent?
    @NSManaged public var openssh_logout: ESOpenSSHLogoutEvent?
    
    @NSManaged public var mount: ESMountEvent?
    
    @NSManaged public var login_login: ESLoginLoginEvent?
    @NSManaged public var lw_session_login: ESLWLoginEvent?
    @NSManaged public var lw_session_unlock: ESLWUnlockEvent?
    
    @NSManaged public var link: ESLinkEvent?
    
    @NSManaged public var signal: ESProcessSignalEvent?
    @NSManaged public var remote_thread_create: ESRemoteThreadCreateEvent?
    @NSManaged public var proc_suspend_resume: ESProcessSocketEvent?
    @NSManaged public var trace: ESProcessTraceEvent?
    @NSManaged public var get_task: ESGetTaskEvent?
    
    @NSManaged public var iokit_open: ESIOKitOpenEvent?
    
    @NSManaged public var cs_invalidated: ESCodeSignatureInvalidatedEvent?
    
    @NSManaged public var authorization_petition: ESAuthorizationPetitionEvent?
    @NSManaged public var authorization_judgement: ESAuthorizationJudgementEvent?
    
    @NSManaged public var profile_add: ESProfileAddEvent?
    
    @NSManaged public var od_create_user: ESODCreateUserEvent?
    @NSManaged public var od_modify_password: ESODModifyPasswordEvent?
    @NSManaged public var od_group_add: ESODGroupAddEvent?
    @NSManaged public var od_group_remove: ESODGroupRemoveEvent?
    @NSManaged public var od_create_group: ESODCreateGroupEvent?
    @NSManaged public var od_attribute_value_add: ESODAttributeValueAddEvent?
    
    @NSManaged public var xpc_connect: ESXPCConnectEvent?
    
    @NSManaged public var xp_malware_detected: ESXProtectDetect?
    @NSManaged public var xp_malware_remediated: ESXProtectRemediate?
    
    @NSManaged public var uipc_connect: ESUIPCConnectEvent?
    @NSManaged public var uipc_bind: ESUIPCBindEvent?
    
    @NSManaged public var tcc_modify: ESTCCModifyEvent?
    
    @NSManaged public var gatekeeper_user_override: ESGatekeeperUserOverrideEvent?

}

extension ESEventType : Identifiable {

}
