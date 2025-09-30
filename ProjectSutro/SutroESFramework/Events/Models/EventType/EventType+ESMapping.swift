//
//  EventType+ESMapping.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//

import Foundation


extension EventType {
    static func from(rawMessage: UnsafePointer<es_message_t>,
                     forcedQuarantineSigningIDs: [String]) -> (event: EventType, eventType: String, context: String?, targetPath: String?) {
        switch rawMessage.pointee.event_type {
        // MARK: - Process events
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let event = ProcessExecEvent(from: rawMessage, forcedQuarantineSigningIDs: forcedQuarantineSigningIDs)
            return (
                .exec(event),
                "ES_EVENT_TYPE_NOTIFY_EXEC",
                String(event.command_line?.prefix(200) ?? ""),
                event.target.executable?.path
            )
        case ES_EVENT_TYPE_NOTIFY_FORK:
            let event = ProcessForkEvent(from: rawMessage)
            return (
                .fork(event),
                "ES_EVENT_TYPE_NOTIFY_FORK",
                event.child.executable?.name,
                event.child.executable?.path
            )
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            let event = ProcessExitEvent(from: rawMessage)
            let pathPointer = rawMessage.pointee.process.pointee.executable.pointee.path
            let initiatingProcPath: String = pathPointer.length > 0 ? String(
                cString: pathPointer.data
            ) : ""
            let initiatingProcName: String = URL(
                string: initiatingProcPath
            )?.lastPathComponent ?? ""
            
            return (
                .exit(event),
                "ES_EVENT_TYPE_NOTIFY_EXIT",
                initiatingProcName,
                initiatingProcPath
            )
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let event = ProcessSignalEvent(from: rawMessage)
            let targetPath = event.target.executable?.path
            let context = "[\(event.signal_name)] \(targetPath ?? "")"
            return (
                .signal(event),
                "ES_EVENT_TYPE_NOTIFY_SIGNAL",
                context,
                targetPath
            )
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            let event = ProcessSocketEvent(from: rawMessage)
            let type: String = event.type_string.replacing("ES_PROC_SUSPEND_RESUME_TYPE_", with: "")
            let procName: String = event.target?.executable?.name ?? ""
            let context = "[\(type)] \(procName)"
            let target_path = event.target?.executable?.path ?? ""
            return (
                .proc_suspend_resume(event),
                "ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME",
                context,
                target_path
            )
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            let event = ProcessCheckEvent(from: rawMessage)
            let targetProcPath: String = event.target?.executable?.path ?? ""
            _ = event.type_string.replacing("ES_PROC_CHECK_TYPE_", with: "")
            let context = "[\(event.type_string)] \(targetProcPath)"
            return (
                .proc_check(event),
                "ES_EVENT_TYPE_NOTIFY_PROC_CHECK",
                context,
                targetProcPath
            )
            

        // MARK: - Interprocess events
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            let event = RemoteThreadCreateEvent(from: rawMessage)
            let targetPath = event.target.executable?.path ?? "Unknown"
            let context = "[\(event.thread_state)] \(targetPath)"
            return (
                .remote_thread_create(event),
                "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE",
                context,
                targetPath
            )
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            let event = ProcessTraceEvent(from: rawMessage)
            let context: String = event.target.executable?.name ?? "Unknown"
            let targetPath: String = event.target.executable?.path ?? "Unknown"
            return (
                .trace(event),
                "ES_EVENT_TYPE_NOTIFY_TRACE",
                context,
                targetPath
            )
        
        
        // MARK: - Code Signing events
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            let event = CodeSignatureInvalidatedEvent(from: rawMessage)
            let pathPointer = rawMessage.pointee.process.pointee.executable.pointee.path
            let initiatingProcPath: String = pathPointer.length > 0 ? String(
                cString: pathPointer.data
            ) : ""
            return (
                .cs_invalidated(event),
                "ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED",
                initiatingProcPath,
                nil // @note: `target_path` does not make sense in this context.
            )
        
        
        // MARK: - Memory mapping events
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let event = MMapEvent(from: rawMessage)
            let context = event.source.path
            return (
                .mmap(event),
                "ES_EVENT_TYPE_NOTIFY_MMAP",
                context,
                context // Target path
            )
            
            
        // MARK: - File System events
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            let event = FileCreateEvent(from: rawMessage, shouldCheckQuarantine: true)
            var targetPath: String = ""
            switch(event.destination_type) {
            case Int(ES_DESTINATION_TYPE_EXISTING_FILE.rawValue):
                targetPath = event.destination.existing_file!.path
            case Int(ES_DESTINATION_TYPE_NEW_PATH.rawValue):
                let dir: String = event.destination.new_path!.dir.path
                let fileName: String = event.destination.new_path!.filename
                targetPath = "\(dir)\\/\(fileName)"
            default:
                break
            }
            
            return (
                .create(event),
                "ES_EVENT_TYPE_NOTIFY_CREATE",
                targetPath, // Context
                targetPath  // Target path
            )
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let event = FileRenameEvent(from: rawMessage)
            
            var targetPath: String = ""
            var targetFileName: String = ""
            var context: String = ""
            
            switch(event.destination_type) {
            case Int(ES_DESTINATION_TYPE_EXISTING_FILE.rawValue):
                targetPath = event.destination.existing_file!.path
                targetFileName = URL(string: targetPath)?.lastPathComponent ?? ""
            case Int(ES_DESTINATION_TYPE_NEW_PATH.rawValue):
                let dir: String = event.destination.new_path!.dir.path
                targetFileName = event.destination.new_path!.filename
                targetPath = "\(dir)\\/\(targetFileName)"
            default:
                break
            }
            
            context = "\(URL(fileURLWithPath: event.source.path).lastPathComponent) → \(targetFileName)"
            
            return (
                .rename(event),
                "ES_EVENT_TYPE_NOTIFY_RENAME",
                context,        // Context
                targetPath      // Target path
            )
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            let event = FileOpenEvent(from: rawMessage)
            return (
                .open(event),
                "ES_EVENT_TYPE_NOTIFY_OPEN",
                event.file.path,
                event.file.path
            )

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let event = FileWriteEvent(from: rawMessage)
            let tgtPath: String = event.target.path
            return (
                .write(event),
                "ES_EVENT_TYPE_NOTIFY_WRITE",
                tgtPath,       // Context
                tgtPath        // Target path
            )
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let event = FileCloseEvent(from: rawMessage)
            return (
                .close(event),
                "ES_EVENT_TYPE_NOTIFY_CLOSE",
                event.file_path,
                event.file_path
            )
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let event = FileDeleteEvent(from: rawMessage)
            return (
                .unlink(event),
                "ES_EVENT_TYPE_NOTIFY_UNLINK",
                event.file_path,
                event.file_path
            )
        case ES_EVENT_TYPE_NOTIFY_DUP:
            let event = FDDuplicateEvent(from: rawMessage)
            let tgtPath: String = event.target.path
            return (
                .dup(event),
                "ES_EVENT_TYPE_NOTIFY_DUP",
                tgtPath,       // Context
                tgtPath        // Target path
            )
        
            
        // MARK: - Symbolic Link events
        case ES_EVENT_TYPE_NOTIFY_LINK:
            let event = LinkEvent(from: rawMessage)
            return (
                .link(event),
                "ES_EVENT_TYPE_NOTIFY_LINK",
                event.target_file_path,
                event.target_file_path
            )

        
        // MARK: - File Metadata events
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            let event = XattrSetEvent(from: rawMessage)
            let context = "[\(event.xattr ?? "")] \(event.file_path ?? "")"
            return (
                .setextattr(event),
                "ES_EVENT_TYPE_NOTIFY_SETEXTATTR",
                context,
                event.file_path
            )
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            let event = XattrDeleteEvent(from: rawMessage)
            let context = "[\(event.xattr ?? "")] \(event.file_path ?? "")"
            return (
                .deleteextattr(event),
                "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR",
                context,
                event.file_path
            )
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            let event = SetModeEvent(from: rawMessage)
            let tgtPath: String = event.target.path
            let mode: Int32 = event.mode
            let context = "(\(mode)) → \(tgtPath)"
            
            return (
                .setmode(event),
                "ES_EVENT_TYPE_NOTIFY_SETMODE",
                context, // Context
                tgtPath  // Target path
            )
        
            
        // MARK: - Pseudoterminal events
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            let event = PTYGrantEvent(from: rawMessage)
            let tgtPath: String = rawMessage.pointee.process.pointee.executable.pointee.path.toString() ?? ""
            
            let context = "(\(String(event.dev))) → \(tgtPath)"
            return (
                .pty_grant(event),
                "ES_EVENT_TYPE_NOTIFY_PTY_GRANT",
                context,    // Context
                tgtPath     // Target path
            )

        
        // MARK: - Service Management events
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            let event = LaunchItemAddEvent(from: rawMessage)
            return (
                .btm_launch_item_add(event),
                "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD",
                event.item.item_path, // Context
                nil // @note: `target_path` does not make sense in this context.
            )
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            let event = LaunchItemRemoveEvent(from: rawMessage)
            return (
                .btm_launch_item_remove(event),
                "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE",
                event.item.item_path, // Context
                nil // @note: `target_path` does not make sense in this context.
            )
        
            
        // MARK: OpenSSH events
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
            let event = SSHLoginEvent(from: rawMessage)
            return (
                .openssh_login(event),
                "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN",
                event.source_address,
                nil // @note: `target_path` does not make sense in this context.
            )
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
            let event = SSHLogoutEvent(from: rawMessage)
            return (
                .openssh_logout(event),
                "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT",
                event.source_address,
                nil // @note: `target_path` does not make sense in this context.
            )
        
            
        // MARK: - XProtect events
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
            let event = XProtectDetectEvent(from: rawMessage)
            return (
                .xp_malware_detected(event),
                "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED",
                event.detected_path,
                event.detected_path
            )
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
            let event = XProtecRemediateEvent(from: rawMessage)
            return (
                .xp_malware_remediated(event),
                "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED",
                event.remediated_path,
                event.remediated_path
            )
        
            
        // MARK: - File System Mounting events
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            let event = MountEvent(from: rawMessage)
            return (
                .mount(event),
                "ES_EVENT_TYPE_NOTIFY_MOUNT",
                event.mount_directory,
                event.mount_directory
            )

            
        // MARK: Login events
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
            let event = LoginLoginEvent(from: rawMessage)
            return (
                .login_login(event),
                "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN",
                event.username,
                nil // @note: `target_path` does not make sense in this context.
            )
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
            let event = LWLoginEvent(from: rawMessage)
            return (
                .lw_session_login(event),
                "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN",
                event.username,
                nil // @note: `target_path` does not make sense in this context.
            )
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
            let event = LWUnlockEvent(from: rawMessage)
            return (
                .lw_session_unlock(event),
                "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK",
                event.username,
                nil // @note: `target_path` does not make sense in this context.
            )

        
        // MARK: Kernel events
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            let event = IOKitOpenEvent(from: rawMessage)
            return (
                .iokit_open(event),
                "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN",
                event.user_client_class,
                nil // @note: `target_path` does not make sense in this context.
            )

        
        // MARK: - Task Port events
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            let event = GetTaskEvent(from: rawMessage)
            let context = "[\(event.type ?? "")] \(event.process_path ?? "")"
            return (
                .get_task(event),
                "ES_EVENT_TYPE_NOTIFY_GET_TASK",
                context,
                event.process_path
            )
            
            
        // MARK: MDM events
        case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
            let event = ProfileAddEvent(from: rawMessage)
            let scope: String = event.profile_scope ?? ""
            let displayName: String = event.profile_display_name ?? ""
            let profId: String = event.profile_identifier ?? ""
            let context: String = "[Scope: \(scope)]  Name: \(displayName), ID: \(profId)"
            return (
                .profile_add(event),
                "ES_EVENT_TYPE_NOTIFY_PROFILE_ADD",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
            
            
        // MARK: - Security Authorization events
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
            let event = AuthorizationJudgementEvent(from: rawMessage)
            let petitionerName: String = event.petitioner_process_name ?? ""
            let instigatorName: String = event.instigator_process_name ?? ""
            let result = event.results ?? ""
            let context = "\(result): \(petitionerName) → \(instigatorName)"
            return (
                .authorization_judgement(event),
                "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT",
                context,
                event.instigator_process_path
            )
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            let event = AuthorizationPetitionEvent(from: rawMessage)
            let petitionerName: String = event.petitioner_process_name ?? ""
            let instigatorName: String = event.instigator_process_name ?? ""
            let rights: String = event.rights
            let context = "\(rights): \(petitionerName) → \(instigatorName)"
            return (
                .authorization_petition(event),
                "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION",
                context,
                event.petitioner_process_path
            )
        
            
        // MARK: - XPC events
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            let event = XPCConnectEvent(from: rawMessage)
            let requestorPath: String = String(
                cString: rawMessage.pointee.process.pointee.executable.pointee.path.data
            )
            let requestorName = URL(fileURLWithPath: requestorPath).lastPathComponent
            let serviceLabel: String = event.service_name ?? ""
            let serviceDomain: String = event.service_domain_type ?? ""
            
            let context = "\(requestorName) → \(serviceLabel) in \(serviceDomain)"
            return (
                .xpc_connect(event),
                "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
            
            
        // MARK: - Open Directory events
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
            let event = OpenDirectoryCreateUserEvent(from: rawMessage)
            let node: String = event.node_name ?? ""
            let username: String = event.user_name ?? ""
            let errorCode: String = event.error_code_human ?? ""
            
            let context = "[\(errorCode)] \(username) in \(node)"
            return (
                .od_create_user(event),
                "ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
            
        case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
            let event = OpenDirectoryModifyPasswordEvent(from: rawMessage)
            let node: String = event.node_name ?? ""
            let accountName: String = event.account_name ?? ""
            let errorCode: String = event.error_code_human ?? ""
            
            let context = "[\(errorCode)] \(accountName) in \(node)"
            return (
                .od_modify_password(event),
                "ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
        
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
            let event = OpenDirectoryGroupAddEvent(from: rawMessage)
            let node: String = event.node_name ?? ""
            let member: String = event.member ?? ""
            let groupName: String = event.group_name ?? ""
            let errorCode: String = event.error_code_human ?? ""
            
            let context = "[\(errorCode)] Added \(member) to \(groupName) in \(node)"
            return (
                .od_group_add(event),
                "ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
            
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
            let event = OpenDirectoryGroupRemoveEvent(from: rawMessage)
            let node: String = event.node_name ?? ""
            let member: String = event.member ?? ""
            let groupName: String = event.group_name ?? ""
            let errorCode: String = event.error_code_human ?? ""
            
            let context = "[\(errorCode)] Removed \(member) from \(groupName) in \(node)"
            return (
                .od_group_remove(event),
                "ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
        
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
            let event = OpenDirectoryCreateGroupEvent(from: rawMessage)
            let node: String = event.node_name ?? ""
            let groupName: String = event.group_name ?? ""
            let errorCode: String = event.error_code_human ?? ""
            
            let context = "[\(errorCode)] \(groupName) in \(node)"
            return (
                .od_create_group(event),
                "ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
            
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
            let event = OpenDirectoryAttributeValueAddEvent(from: rawMessage)
            let errorCode: String = event.error_code_human ?? ""
            let node: String = event.node_name ?? ""
            let attributeName: String = event.attribute_name ?? ""
            let attributeValue: String = event.attribute_value ?? ""
            
            let context = "[\(errorCode)] \(attributeName) → \(attributeValue) in \(node)"
            return (
                .od_attribute_value_add(event),
                "ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
        
        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
            let event = TCCModifyEvent(from: rawMessage)
            
            // Identity is the type of the action (bundle Id, policy Id, exe path, domain Id)
            let identity = event.identity
            // Service is the TCC right
            let service = event.service
            // Reason is "why" the TCC right was modified
            let reasonString = event.reason_string.replacingOccurrences(of: "ES_TCC_AUTHORIZATION_REASON_", with: "")
            let context = "[\(reasonString)] \(service) → \(identity)"
            return (
                .tcc_modify(event),
                "ES_EVENT_TYPE_NOTIFY_TCC_MODIFY",
                context,
                nil // @note: `target_path` does not make sense in this context.
            )
        
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
            let event = GatekeeperUserOverrideEvent(from: rawMessage)
            var context = ""
            if let overridePath = event.file.file_path {
                context = overridePath
            } else if let file = event.file.file {
                context = file.path
            }
            
            
            return (
                .gatekeeper_user_override(event),
                "ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE",
                context,
                context // Override path is the target path
            )
            

        default:
            return (.unknown, "NOT MAPPED", nil, nil)
        }
    }
}
