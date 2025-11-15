//
//  EventType+Accessors.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/25.
//

import Foundation

extension EventType {
    // MARK: Process events
    var exec: ProcessExecEvent? {
        if case .exec(let e) = self { return e }
        return nil
    }

    var fork: ProcessForkEvent? {
        if case .fork(let e) = self { return e }
        return nil
    }

    var exit: ProcessExitEvent? {
        if case .exit(let e) = self { return e }
        return nil
    }
    
    var signal: ProcessSignalEvent? {
        if case .signal(let e) = self { return e }
        return nil
    }
    
    var proc_suspend_resume: ProcessSocketEvent? {
        if case .proc_suspend_resume(let e) = self { return e }
        return nil
    }
    
    var proc_check: ProcessCheckEvent? {
        if case .proc_check(let e) = self { return e }
        return nil
    }

    
    // MARK: Interprocess events
    var remote_thread_create: RemoteThreadCreateEvent? {
        if case .remote_thread_create(let e) = self { return e }
        return nil
    }
    
    var trace: ProcessTraceEvent? {
        if case .trace(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Code Signing events
    var cs_invalidated: CodeSignatureInvalidatedEvent? {
        if case .cs_invalidated(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Memory mapping events
    var mmap: MMapEvent? {
        if case .mmap(let e) = self { return e }
        return nil
    }
    
    var mprotect: MProtectEvent? {
        if case .mprotect(let e) = self { return e }
        return nil
    }
    
    
    // MARK: File System events
    var create: FileCreateEvent? {
        if case .create(let e) = self { return e }
        return nil
    }
    
    var rename: FileRenameEvent? {
        if case .rename(let e) = self { return e }
        return nil
    }

    var open: FileOpenEvent? {
        if case .open(let e) = self { return e }
        return nil
    }

    var write: FileWriteEvent? {
        if case .write(let e) = self { return e }
        return nil
    }

    var close: FileCloseEvent? {
        if case .close(let e) = self { return e }
        return nil
    }

    var unlink: FileDeleteEvent? {
        if case .unlink(let e) = self { return e }
        return nil
    }
    
    
    var dup: FDDuplicateEvent? {
        if case .dup(let e) = self { return e }
        return nil
    }
    
    // MARK: Symbolic Link events
    var link: LinkEvent? {
        if case .link(let e) = self { return e }
        return nil
    }
    
    
    // MARK: File Metadata events
    var setextattr: XattrSetEvent? {
        if case .setextattr(let e) = self { return e }
        return nil
    }

    var deleteextattr: XattrDeleteEvent? {
        if case .deleteextattr(let e) = self { return e }
        return nil
    }
    
    var setmode: SetModeEvent? {
        if case .setmode(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Pseudoterminal events
    var pty_grant: PTYGrantEvent? {
        if case .pty_grant(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Service Management events
    var btm_launch_item_add: LaunchItemAddEvent? {
        if case .btm_launch_item_add(let e) = self { return e }
        return nil
    }

    var btm_launch_item_remove: LaunchItemRemoveEvent? {
        if case .btm_launch_item_remove(let e) = self { return e }
        return nil
    }
    
    
    // MARK: OpenSSH events
    var openssh_login: SSHLoginEvent? {
        if case .openssh_login(let e) = self { return e }
        return nil
    }

    var openssh_logout: SSHLogoutEvent? {
        if case .openssh_logout(let e) = self { return e }
        return nil
    }
    
    
    // MARK: XProtect events
    var xp_malware_detected: XProtectDetectEvent? {
        if case .xp_malware_detected(let e) = self { return e }
        return nil
    }

    var xp_malware_remediated: XProtecRemediateEvent? {
        if case .xp_malware_remediated(let e) = self { return e }
        return nil
    }
    
    
    // MARK: File System Mounting events
    var mount: MountEvent? {
        if case .mount(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Login events
    var login_login: LoginLoginEvent? {
        if case .login_login(let e) = self { return e }
        return nil
    }

    var lw_session_login: LWLoginEvent? {
        if case .lw_session_login(let e) = self { return e }
        return nil
    }

    var lw_session_unlock: LWUnlockEvent? {
        if case .lw_session_unlock(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Kernel events
    var iokit_open: IOKitOpenEvent? {
        if case .iokit_open(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Task Port events
    var get_task: GetTaskEvent? {
        if case .get_task(let e) = self { return e }
        return nil
    }

    
    // MARK: MDM events
    var profile_add: ProfileAddEvent? {
        if case .profile_add(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Security Authorization events
    var authorization_petition: AuthorizationPetitionEvent? {
        if case .authorization_petition(let e) = self { return e }
        return nil
    }

    var authorization_judgement: AuthorizationJudgementEvent? {
        if case .authorization_judgement(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Directory events
    var od_create_user: OpenDirectoryCreateUserEvent? {
        if case .od_create_user(let e) = self { return e }
        return nil
    }

    var od_modify_password: OpenDirectoryModifyPasswordEvent? {
        if case .od_modify_password(let e) = self { return e }
        return nil
    }

    var od_group_add: OpenDirectoryGroupAddEvent? {
        if case .od_group_add(let e) = self { return e }
        return nil
    }

    var od_group_remove: OpenDirectoryGroupRemoveEvent? {
        if case .od_group_remove(let e) = self { return e }
        return nil
    }

    var od_create_group: OpenDirectoryCreateGroupEvent? {
        if case .od_create_group(let e) = self { return e }
        return nil
    }

    var od_attribute_value_add: OpenDirectoryAttributeValueAddEvent? {
        if case .od_attribute_value_add(let e) = self { return e }
        return nil
    }
    
    
    // MARK: XPC events
    var xpc_connect: XPCConnectEvent? {
        if case .xpc_connect(let e) = self { return e }
        return nil
    }
    
    
    // MARK: Socket events
    var uipc_connect: UIPCConnectEvent? {
        if case .uipc_connect(let e) = self { return e }
        return nil
    }
    
    var uipc_bind: UIPCBindEvent? {
        if case .uipc_bind(let e) = self { return e }
        return nil
    }
    
    
    // MARK: TCC events
    var tcc_modify: TCCModifyEvent? {
        if case .tcc_modify(let e) = self { return e }
        return nil
    }
    
    // MARK: Gatekeeper events
    var gatekeeper_user_override: GatekeeperUserOverrideEvent? {
        if case .gatekeeper_user_override(let e) = self { return e }
        return nil
    }
}
