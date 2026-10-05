//
//  EventType+ESMapping.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//

import Foundation


extension EventType {
    /// Model a raw Endpoint Security message's event.
    ///
    /// - Parameters:
    ///   - rawMessage: The message.
    ///   - forcedQuarantineSigningIDs: Signing IDs Apple forces into File Quarantine, for `EXEC` events.
    /// - Returns: The event, or ``unknown`` for a type Mac Monitor doesn't model.
    static func from(rawMessage: UnsafePointer<es_message_t>, forcedQuarantineSigningIDs: [String]) -> EventType {
        switch rawMessage.pointee.event_type {
        // MARK: Process events
        case ES_EVENT_TYPE_NOTIFY_EXEC: .exec(ProcessExecEvent(from: rawMessage, forcedQuarantineSigningIDs: forcedQuarantineSigningIDs))
        case ES_EVENT_TYPE_NOTIFY_FORK: .fork(ProcessForkEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_EXIT: .exit(ProcessExitEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_SIGNAL: .signal(ProcessSignalEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: .proc_suspend_resume(ProcessSocketEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK: .proc_check(ProcessCheckEvent(from: rawMessage))
        // MARK: Interprocess events
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: .remote_thread_create(RemoteThreadCreateEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_TRACE: .trace(ProcessTraceEvent(from: rawMessage))
        // MARK: Code Signing events
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: .cs_invalidated(CodeSignatureInvalidatedEvent(from: rawMessage))
        // MARK: Memory mapping events
        case ES_EVENT_TYPE_NOTIFY_MMAP: .mmap(MMapEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_MPROTECT: .mprotect(MProtectEvent(from: rawMessage))
        // MARK: File System events
        case ES_EVENT_TYPE_NOTIFY_CREATE: .create(FileCreateEvent(from: rawMessage, shouldCheckQuarantine: true))
        case ES_EVENT_TYPE_NOTIFY_RENAME: .rename(FileRenameEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OPEN: .open(FileOpenEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_WRITE: .write(FileWriteEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_CLOSE: .close(FileCloseEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_UNLINK: .unlink(FileDeleteEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_DUP: .dup(FDDuplicateEvent(from: rawMessage))
        // MARK: Symbolic Link events
        case ES_EVENT_TYPE_NOTIFY_LINK: .link(LinkEvent(from: rawMessage))
        // MARK: File Metadata events
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: .setextattr(XattrSetEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR: .getextattr(XattrGetEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR: .listextattr(XattrListEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR: .deleteextattr(XattrDeleteEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_SETMODE: .setmode(SetModeEvent(from: rawMessage))
        // MARK: Pseudoterminal events
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT: .pty_grant(PTYGrantEvent(from: rawMessage))
        // MARK: Service Management events
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: .btm_launch_item_add(LaunchItemAddEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE: .btm_launch_item_remove(LaunchItemRemoveEvent(from: rawMessage))
        // MARK: OpenSSH events
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: .openssh_login(SSHLoginEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: .openssh_logout(SSHLogoutEvent(from: rawMessage))
        // MARK: XProtect events
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: .xp_malware_detected(XProtectDetectEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED: .xp_malware_remediated(XProtecRemediateEvent(from: rawMessage))
        // MARK: File System Mounting events
        case ES_EVENT_TYPE_NOTIFY_MOUNT: .mount(MountEvent(from: rawMessage))
        // MARK: Login events
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN: .login_login(LoginLoginEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: .lw_session_login(LWLoginEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK: .lw_session_unlock(LWUnlockEvent(from: rawMessage))
        // MARK: Kernel events
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: .iokit_open(IOKitOpenEvent(from: rawMessage))
        // MARK: Task Port events
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: .get_task(GetTaskEvent(from: rawMessage))
        // MARK: MDM events
        case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD: .profile_add(ProfileAddEvent(from: rawMessage))
        // MARK: Security Authorization events
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT: .authorization_judgement(AuthorizationJudgementEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION: .authorization_petition(AuthorizationPetitionEvent(from: rawMessage))
        // MARK: XPC events
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: .xpc_connect(XPCConnectEvent(from: rawMessage))
        // MARK: Open Directory events
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER: .od_create_user(OpenDirectoryCreateUserEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD: .od_modify_password(OpenDirectoryModifyPasswordEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD: .od_group_add(OpenDirectoryGroupAddEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE: .od_group_remove(OpenDirectoryGroupRemoveEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP: .od_create_group(OpenDirectoryCreateGroupEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD: .od_attribute_value_add(OpenDirectoryAttributeValueAddEvent(from: rawMessage))
        // MARK: Socket events
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: .uipc_connect(UIPCConnectEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: .uipc_bind(UIPCBindEvent(from: rawMessage))
        // MARK: TCC events
        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY: .tcc_modify(TCCModifyEvent(from: rawMessage))
        // MARK: Gatekeeper events
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: .gatekeeper_user_override(GatekeeperUserOverrideEvent(from: rawMessage))
        default: .unknown
        }
    }
    
    /// What the event tables show of the event besides its type: its context, and the path it targets.
    ///
    /// A function of the event and the process that caused it, so an event read back from a trace (``TraceImporter``)
    /// gets the same as one recorded live.
    ///
    /// - Parameter initiatingPath: The path of the process that caused the event (`es_message_t.process`).
    /// - Returns: The event's context and target path; `nil` where they don't make sense for the event type.
    func summary(initiatingPath: String) -> (context: String?, targetPath: String?) {
        switch self {
        // MARK: Process events
        case .exec(let event):
            return (String(event.command_line?.prefix(200) ?? ""), event.target.executable?.path)
        case .fork(let event):
            return (event.child.executable?.name, event.child.executable?.path)
        case .exit:
            return (URL(string: initiatingPath)?.lastPathComponent ?? "", initiatingPath)
        case .signal(let event):
            let targetPath = event.target.executable?.path
            return ("[\(event.signal_name)] \(targetPath ?? "")", targetPath)
        case .proc_suspend_resume(let event):
            let type = event.type_string.replacing("ES_PROC_SUSPEND_RESUME_TYPE_", with: "")
            return ("[\(type)] \(event.target?.executable?.name ?? "")", event.target?.executable?.path ?? "")
        case .proc_check(let event):
            let targetPath = event.target?.executable?.path ?? ""
            return ("[\(event.type_string)] \(targetPath)", targetPath)
        // MARK: Interprocess events
        case .remote_thread_create(let event):
            let targetPath = event.target.executable?.path ?? "Unknown"
            /// The flavor's name, or its number when this Mac's architecture doesn't name it.
            let flavor = event.thread_state_string ?? event.thread_state.map { "flavor \($0.flavor)" }
            return (flavor.map { "[\($0)] \(targetPath)" } ?? targetPath, targetPath)
        case .trace(let event):
            return (event.target.executable?.name ?? "Unknown", event.target.executable?.path ?? "Unknown")
        // MARK: Code Signing events
        case .cs_invalidated:
            return (initiatingPath, nil)
        // MARK: Memory mapping events
        case .mmap(let event):
            return (event.source.path, event.source.path)
        case .mprotect(let event):
            let flags = event.flags.joined(separator: "|").replacingOccurrences(of: "VM_PROT_", with: "")
            return ("(\(flags))(\(event.kb_size) kb) → \(initiatingPath)", nil)
        // MARK: File System events
        case .create(let event):
            let targetPath = Self.destinationPath(event.destination)
            return (targetPath, targetPath)
        case .rename(let event):
            let targetPath = Self.destinationPath(event.destination)
            let targetFileName = switch event.destination {
            case .existing_file: URL(string: targetPath)?.lastPathComponent ?? ""
            case .new_path(let path): path.filename
            case .unknown: ""
            }
            return ("\(URL(fileURLWithPath: event.source.path).lastPathComponent) → \(targetFileName)", targetPath)
        case .open(let event):
            return (event.file.path, event.file.path)
        case .write(let event):
            return (event.target.path, event.target.path)
        case .close(let event):
            return (event.target.path, event.target.path)
        case .unlink(let event):
            return (event.target.path, event.target.path)
        case .dup(let event):
            return (event.target.path, event.target.path)
        // MARK: Symbolic Link events
        case .link(let event):
            let targetPath = URL(fileURLWithPath: event.target_dir.path).appendingPathComponent(event.target_filename).path()
            return (targetPath, targetPath)
        // MARK: File Metadata events
        case .setextattr(let event):
            return ("[\(event.extattr)] \(event.target.path)", event.target.path)
        case .getextattr(let event):
            return ("[\(event.extattr)] \(event.target.path)", event.target.path)
        case .listextattr(let event):
            return (event.target.path, event.target.path)
        case .deleteextattr(let event):
            return ("[\(event.extattr)] \(event.target.path)", event.target.path)
        case .setmode(let event):
            return ("(\(event.mode)) → \(event.target.path)", event.target.path)
        // MARK: Pseudoterminal events
        case .pty_grant(let event):
            return ("(\(String(event.dev))) → \(initiatingPath)", initiatingPath)
        // MARK: Service Management events
        case .btm_launch_item_add(let event):
            return (event.item.item_path, nil)
        case .btm_launch_item_remove(let event):
            return (event.item.item_path, nil)
        // MARK: OpenSSH events
        case .openssh_login(let event):
            return ("[\(event.success ? "Success" : "Fail")] \(event.source_address) → \(event.username)", nil)
        case .openssh_logout(let event):
            return (event.source_address, nil)
        // MARK: XProtect events
        case .xp_malware_detected(let event):
            return (event.detected_path, event.detected_path)
        case .xp_malware_remediated(let event):
            return (event.remediated_path, event.remediated_path)
        // MARK: File System Mounting events
        case .mount(let event):
            let targetPath = event.statfs.f_mntonname
            return ("[\(event.disposition_string.replacingOccurrences(of: "ES_MOUNT_DISPOSITION_", with: ""))] \(targetPath)", targetPath)
        // MARK: Login events
        case .login_login(let event):
            return (event.username, nil)
        case .lw_session_login(let event):
            return (event.username, nil)
        case .lw_session_unlock(let event):
            return (event.username, nil)
        // MARK: Kernel events
        case .iokit_open(let event):
            return (event.user_client_class, nil)
        // MARK: Task Port events
        case .get_task(let event):
            guard let exe = event.target.executable else { return ("", "") }
            return ("[\(event.type_string.replacingOccurrences(of: "ES_GET_TASK_TYPE_", with: ""))] \(exe.path)", exe.path)
        // MARK: MDM events
        case .profile_add(let event):
            return (event.profile.toString(), nil)
        // MARK: Security Authorization events
        case .authorization_judgement(let event):
            let result = event.results.map({ $0.description }).joined(separator: "|")
            let names = "\(event.petitioner?.executable?.name ?? "") → \(event.instigator?.executable?.name ?? "")"
            return ("\(result): \(names)", event.instigator?.executable?.path ?? "")
        case .authorization_petition(let event):
            let names = "\(event.petitioner?.executable?.name ?? "") → \(event.instigator?.executable?.name ?? "")"
            return ("[\(event.rights.joined(separator: ","))] \(names)", event.petitioner?.executable?.path ?? "")
        // MARK: XPC events
        case .xpc_connect(let event):
            let requestorName = URL(fileURLWithPath: initiatingPath).lastPathComponent
            return ("\(requestorName) → \(event.service_name) in \(event.service_domain_type_string)", nil)
        // MARK: Open Directory events
        case .od_create_user(let event):
            return ("[\(event.error_code_human ?? "")] \(event.user_name ?? "") in \(event.node_name ?? "")", nil)
        case .od_modify_password(let event):
            return ("[\(event.error_code_human ?? "")] \(event.account_name ?? "") in \(event.node_name ?? "")", nil)
        case .od_group_add(let event):
            let change = "Added \(event.memberSummary) to \(event.group_name ?? "")"
            return ("[\(event.error_code_human ?? "")] \(change) in \(event.node_name ?? "")", nil)
        case .od_group_remove(let event):
            let change = "Removed \(event.memberSummary) from \(event.group_name ?? "")"
            return ("[\(event.error_code_human ?? "")] \(change) in \(event.node_name ?? "")", nil)
        case .od_create_group(let event):
            return ("[\(event.error_code_human ?? "")] \(event.group_name ?? "") in \(event.node_name ?? "")", nil)
        case .od_attribute_value_add(let event):
            let attribute = "\(event.attribute_name ?? "") → \(event.attribute_value ?? "")"
            return ("[\(event.error_code_human ?? "")] \(attribute) in \(event.node_name ?? "")", nil)
        // MARK: Socket events
        case .uipc_connect(let event):
            let metadata = event.protocol != 0
                ? "\(event.protocol_string), \(event.type_string), \(event.domain_string)"
                : "[\(event.type_string)]"
            return ("\(metadata) → \(event.file.path)", event.file.path)
        case .uipc_bind(let event):
            let targetPath = URL(fileURLWithPath: event.dir.path).appendingPathComponent(event.filename).path()
            return (targetPath, targetPath)
        // MARK: TCC events
        case .tcc_modify(let event):
            let reason = event.reason_string.replacingOccurrences(of: "ES_TCC_AUTHORIZATION_REASON_", with: "")
            return ("[\(reason)] \(event.service) → \(event.identity)", nil)
        // MARK: Gatekeeper events
        case .gatekeeper_user_override(let event):
            let path = event.file.file_path ?? event.file.file?.path ?? ""
            return (path, path)
        case .unknown:
            return (nil, nil)
        }
    }
    
    /// The full path of a create or rename event's destination, as the event's target path.
    ///
    /// Read from the destination itself rather than its `destination_type`, which a trace file may contradict.
    ///
    /// - Parameter destination: The event's destination.
    /// - Returns: The existing file's path, the new path's directory and file name joined by "\/", or "" for a
    ///   destination that can't be read.
    private static func destinationPath(_ destination: FileDestination) -> String {
        switch destination {
        case .existing_file(let file): file.path
        case .new_path(let path): "\(path.dir.path)\\/\(path.filename)"
        case .unknown: ""
        }
    }
}
