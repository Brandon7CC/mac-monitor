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
    /// - Parameter rawMessage: The message.
    /// - Returns: The event, or ``unknown`` for a type Mac Monitor doesn't model.
    static func from(rawMessage: UnsafePointer<es_message_t>) -> EventType {
        switch rawMessage.pointee.event_type {
        // MARK: Process events
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            .exec(ProcessExecEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_FORK:
            .fork(ProcessForkEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            .exit(ProcessExitEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            .signal(ProcessSignalEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            .proc_suspend_resume(ProcessSocketEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            .proc_check(ProcessCheckEvent(from: rawMessage))
        // MARK: Interprocess events
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            .remote_thread_create(RemoteThreadCreateEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            .trace(ProcessTraceEvent(from: rawMessage))
        // MARK: Code Signing events
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            .cs_invalidated(CodeSignatureInvalidatedEvent(from: rawMessage))
        // MARK: Memory mapping events
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            .mmap(MMapEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            .mprotect(MProtectEvent(from: rawMessage))
        // MARK: File System events
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            .create(FileCreateEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            .rename(FileRenameEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            .open(FileOpenEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            .write(TargetFileEvent(from: rawMessage.pointee.event.write))
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            .close(FileCloseEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            .unlink(FileDeleteEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_DUP:
            .dup(TargetFileEvent(from: rawMessage.pointee.event.dup))
        // MARK: Symbolic Link events
        case ES_EVENT_TYPE_NOTIFY_LINK:
            .link(LinkEvent(from: rawMessage))
        // MARK: File Metadata events
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            .setextattr(XattrEvent(from: rawMessage.pointee.event.setextattr))
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            .getextattr(XattrEvent(from: rawMessage.pointee.event.getextattr))
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            .listextattr(TargetFileEvent(from: rawMessage.pointee.event.listextattr))
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            .deleteextattr(XattrEvent(from: rawMessage.pointee.event.deleteextattr))
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            .setmode(SetModeEvent(from: rawMessage))
        // MARK: Pseudoterminal events
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            .pty_grant(PTYGrantEvent(from: rawMessage))
        // MARK: Service Management events
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            .btm_launch_item_add(LaunchItemAddEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            .btm_launch_item_remove(LaunchItemRemoveEvent(from: rawMessage))
        // MARK: OpenSSH events
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
            .openssh_login(SSHLoginEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
            .openssh_logout(SSHLogoutEvent(from: rawMessage))
        // MARK: XProtect events
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
            .xp_malware_detected(XProtectDetectEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
            .xp_malware_remediated(XProtecRemediateEvent(from: rawMessage))
        // MARK: File System Mounting events
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            .mount(MountEvent(from: rawMessage))
        // MARK: Login events
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
            .login_login(LoginLoginEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
            .lw_session_login(LWSessionEvent(from: rawMessage.pointee.event.lw_session_login.pointee))
        case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
            .lw_session_unlock(LWSessionEvent(from: rawMessage.pointee.event.lw_session_unlock.pointee))
        // MARK: Kernel events
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            .iokit_open(IOKitOpenEvent(from: rawMessage))
        // MARK: Task Port events
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            .get_task(GetTaskEvent(from: rawMessage))
        // MARK: MDM events
        case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
            .profile_add(ProfileAddEvent(from: rawMessage))
        // MARK: Security Authorization events
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
            .authorization_judgement(AuthorizationJudgementEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            .authorization_petition(AuthorizationPetitionEvent(from: rawMessage))
        // MARK: XPC events
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            .xpc_connect(XPCConnectEvent(from: rawMessage))
        // MARK: Open Directory events
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
            .od_create_user(OpenDirectoryCreateUserEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
            .od_modify_password(OpenDirectoryModifyPasswordEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
            .od_group_add(OpenDirectoryGroupAddEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
            .od_group_remove(OpenDirectoryGroupRemoveEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
            .od_create_group(OpenDirectoryCreateGroupEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
            .od_attribute_value_add(OpenDirectoryAttributeValueAddEvent(from: rawMessage))
        // MARK: Socket events
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            .uipc_connect(UIPCConnectEvent(from: rawMessage))
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            .uipc_bind(UIPCBindEvent(from: rawMessage))
        // MARK: TCC events
        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
            .tcc_modify(TCCModifyEvent(from: rawMessage))
        // MARK: Gatekeeper events
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
            .gatekeeper_user_override(GatekeeperUserOverrideEvent(from: rawMessage))
        default:
            .unknown
        }
    }
    
    /// What the event tables show of the event besides its type: its context, and the path it targets.
    ///
    /// A function of the event and the process that caused it, so an event read back from a trace (``TraceImporter``)
    /// gets the same as one recorded live. `nil` means the event type has no such thing. `""` means it does, but this
    /// event doesn't say.
    ///
    /// - Parameter initiatingPath: The path of the process that caused the event (`es_message_t.process`).
    /// - Returns: The event's context and target path.
    func summary(initiatingPath: String) -> (context: String?, targetPath: String?) {
        switch self {
        // MARK: Process events
        case .exec(let event):
            return (String(event.command_line?.prefix(200) ?? ""), event.target.executable?.path)
        case .fork(let event):
            return (event.child.executable?.name, event.child.executable?.path)
        case .exit:
            return (initiatingPath.lastPathComponent, initiatingPath)
        case .signal(let event):
            let targetPath = event.target.executable?.path ?? ""
            return (Self.tagged(event.signal_name, targetPath), targetPath)
        case .proc_suspend_resume(let event):
            let type = event.type_string.droppingPrefix("ES_PROC_SUSPEND_RESUME_TYPE_")
            return (Self.tagged(type, event.target?.executable?.name ?? ""), event.target?.executable?.path ?? "")
        case .proc_check(let event):
            let targetPath = event.target?.executable?.path ?? ""
            return (Self.tagged(event.type_string, targetPath), targetPath)
        // MARK: Interprocess events
        case .remote_thread_create(let event):
            let targetPath = event.target.executable?.path ?? ""
            /// The flavor's name, or its number when this Mac's architecture doesn't name it.
            let flavor = event.thread_state_string ?? event.thread_state.map { "flavor \($0.flavor)" }
            return (flavor.map { Self.tagged($0, targetPath) } ?? targetPath, targetPath)
        case .trace(let event):
            return (event.target.executable?.name ?? "", event.target.executable?.path ?? "")
        // MARK: Code Signing events
        case .cs_invalidated:
            return (initiatingPath, nil)
        // MARK: Memory mapping events
        case .mmap(let event):
            return Self.about(event.source.path)
        case .mprotect(let event):
            let flags = event.flags.map { $0.droppingPrefix("VM_PROT_") }.joined(separator: "|")
            return ("(\(flags))(\(event.kb_size) kb) → \(initiatingPath)", nil)
        // MARK: File System events
        case .create(let event):
            return Self.about(Self.destinationPath(event.destination))
        case .rename(let event):
            let targetPath = Self.destinationPath(event.destination)
            let targetFileName = switch event.destination {
            case .existing_file: targetPath.lastPathComponent
            case .new_path(let path): path.filename
            case .unknown: ""
            }
            return ("\(event.source.path.lastPathComponent) → \(targetFileName)", targetPath)
        case .open(let event):
            return Self.about(event.file.path)
        case .write(let event), .dup(let event):
            return Self.about(event.target.path)
        case .close(let event):
            return Self.about(event.target.path)
        case .unlink(let event):
            return Self.about(event.target.path)
        // MARK: Symbolic Link events
        case .link(let event):
            return Self.about(Self.join(event.target_dir.path, event.target_filename))
        // MARK: File Metadata events
        case .setextattr(let event), .getextattr(let event), .deleteextattr(let event):
            return (Self.tagged(event.extattr, event.target.path), event.target.path)
        case .listextattr(let event):
            return Self.about(event.target.path)
        case .setmode(let event):
            return ("(\(event.mode)) → \(event.target.path)", event.target.path)
        // MARK: Pseudoterminal events
        case .pty_grant(let event):
            return ("(\(event.dev)) → \(initiatingPath)", initiatingPath)
        // MARK: Service Management events
        case .btm_launch_item_add(let event):
            return (event.item.item_path, nil)
        case .btm_launch_item_remove(let event):
            return (event.item.item_path, nil)
        // MARK: OpenSSH events
        case .openssh_login(let event):
            let login = "\(event.source_address) → \(event.username)"
            return (Self.tagged(event.success ? "Success" : "Fail", login), nil)
        case .openssh_logout(let event):
            return (event.source_address, nil)
        // MARK: XProtect events
        case .xp_malware_detected(let event):
            return Self.about(event.detected_path)
        case .xp_malware_remediated(let event):
            return (event.remediated_path, event.remediated_path)
        // MARK: File System Mounting events
        case .mount(let event):
            let targetPath = event.statfs.f_mntonname
            let disposition = event.disposition_string.droppingPrefix("ES_MOUNT_DISPOSITION_")
            return (Self.tagged(disposition, targetPath), targetPath)
        // MARK: Login events
        case .login_login(let event):
            return (event.username, nil)
        case .lw_session_login(let event), .lw_session_unlock(let event):
            return (event.username, nil)
        // MARK: Kernel events
        case .iokit_open(let event):
            return (event.user_client_class, nil)
        // MARK: Task Port events
        case .get_task(let event):
            guard let path = event.target.executable?.path else { return ("", "") }
            return (Self.tagged(event.type_string.droppingPrefix("ES_GET_TASK_TYPE_"), path), path)
        // MARK: MDM events
        case .profile_add(let event):
            return (event.profile.toString(), nil)
        // MARK: Security Authorization events
        case .authorization_judgement(let event):
            let result = event.results.map(\.description).joined(separator: "|")
            let names = "\(event.petitioner?.executable?.name ?? "") → \(event.instigator?.executable?.name ?? "")"
            return ("\(result): \(names)", event.instigator?.executable?.path ?? "")
        case .authorization_petition(let event):
            let names = "\(event.petitioner?.executable?.name ?? "") → \(event.instigator?.executable?.name ?? "")"
            return (Self.tagged(event.rights.joined(separator: ","), names), event.petitioner?.executable?.path ?? "")
        // MARK: XPC events
        case .xpc_connect(let event):
            let requestor = initiatingPath.lastPathComponent
            return ("\(requestor) → \(event.service_name) in \(event.service_domain_type_string)", nil)
        // MARK: Open Directory events
        case .od_create_user(let event):
            let user = "\(event.user_name ?? "") in \(event.node_name ?? "")"
            return (Self.tagged(event.error_code_human ?? "", user), nil)
        case .od_modify_password(let event):
            let account = "\(event.account_name ?? "") in \(event.node_name ?? "")"
            return (Self.tagged(event.error_code_human ?? "", account), nil)
        case .od_group_add(let event):
            let change = "Added \(event.memberSummary) to \(event.group_name ?? "") in \(event.node_name ?? "")"
            return (Self.tagged(event.error_code_human ?? "", change), nil)
        case .od_group_remove(let event):
            let change = "Removed \(event.memberSummary) from \(event.group_name ?? "") in \(event.node_name ?? "")"
            return (Self.tagged(event.error_code_human ?? "", change), nil)
        case .od_create_group(let event):
            let group = "\(event.group_name ?? "") in \(event.node_name ?? "")"
            return (Self.tagged(event.error_code_human ?? "", group), nil)
        case .od_attribute_value_add(let event):
            let attribute = "\(event.attribute_name ?? "") → \(event.attribute_value ?? "")"
                + " in \(event.node_name ?? "")"
            return (Self.tagged(event.error_code_human ?? "", attribute), nil)
        // MARK: Socket events
        case .uipc_connect(let event):
            let metadata = event.protocol != 0
                ? "\(event.protocol_string), \(event.type_string), \(event.domain_string)"
                : "[\(event.type_string)]"
            return ("\(metadata) → \(event.file.path)", event.file.path)
        case .uipc_bind(let event):
            return Self.about(Self.join(event.dir.path, event.filename))
        // MARK: TCC events
        case .tcc_modify(let event):
            let reason = event.reason_string.droppingPrefix("ES_TCC_AUTHORIZATION_REASON_")
            return (Self.tagged(reason, "\(event.service) → \(event.identity)"), nil)
        // MARK: Gatekeeper events
        case .gatekeeper_user_override(let event):
            return Self.about(event.file.file_path ?? event.file.file?.path ?? "")
        case .unknown:
            return (nil, nil)
        }
    }
    
    /// A summary whose context is the path it targets.
    ///
    /// - Parameter path: The path.
    /// - Returns: The path as both.
    private static func about(_ path: String) -> (context: String?, targetPath: String?) {
        (path, path)
    }
    
    /// A context that starts with a detail in brackets, such as `[SIGKILL] /usr/bin/true`.
    ///
    /// - Parameters:
    ///   - tag: The detail.
    ///   - text: The rest.
    /// - Returns: The context.
    private static func tagged(_ tag: String, _ text: String) -> String {
        "[\(tag)] \(text)"
    }
    
    /// A directory and a file name joined into a path, as written, without percent escapes.
    ///
    /// Joined natively for a summary built as the event arrives: `URL` asks the file system whether the path is a
    /// folder, and `NSString` hands back a string that isn't contiguous UTF-8.
    ///
    /// - Parameters:
    ///   - directory: The directory.
    ///   - name: The file name.
    /// - Returns: The path.
    private static func join(_ directory: String, _ name: String) -> String {
        directory.hasSuffix("/") ? directory + name : directory + "/" + name
    }
    
    /// The full path of a create or rename event's destination, as the event's target path.
    ///
    /// Read from the destination itself rather than its `destination_type`, which a trace file may contradict. A new
    /// path is joined with "\/", as `target_path` has been written since 1.9. The trace import and the quarantine
    /// check read that form.
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
