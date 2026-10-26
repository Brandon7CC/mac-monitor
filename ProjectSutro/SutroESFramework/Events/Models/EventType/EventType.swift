//
//  EventType.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/31/25.
//

import Foundation

// MARK: - EventType enum
public enum EventType: Hashable, Codable {
    // MARK: Process events
    case exec(ProcessExecEvent)
    case fork(ProcessForkEvent)
    case exit(ProcessExitEvent)
    case signal(ProcessSignalEvent)
    case proc_suspend_resume(ProcessSocketEvent)
    case proc_check(ProcessCheckEvent)
    
    // MARK: Interprocess events
    case remote_thread_create(RemoteThreadCreateEvent)
    case trace(ProcessTraceEvent)
    
    // MARK: Code Signing events
    case cs_invalidated(CodeSignatureInvalidatedEvent)
    
    // MARK: Memory mapping events
    case mmap(MMapEvent)
    case mprotect(MProtectEvent)
    
    // MARK: File System events
    case create(FileCreateEvent)
    case rename(FileRenameEvent)
    case open(FileOpenEvent)
    case write(TargetFileEvent)
    case close(FileCloseEvent)
    case unlink(FileDeleteEvent)
    case dup(TargetFileEvent)
    
    // MARK: Symbolic Link events
    case link(LinkEvent)
    
    // MARK: File Metadata events
    case setextattr(XattrEvent)
    case deleteextattr(XattrEvent)
    case listextattr(TargetFileEvent)
    case getextattr(XattrEvent)
    case setmode(SetModeEvent)
    
    // MARK: Pseudoterminal events
    case pty_grant(PTYGrantEvent)
    
    // MARK: Service Management events
    case btm_launch_item_add(LaunchItemAddEvent)
    case btm_launch_item_remove(LaunchItemRemoveEvent)
    
    // MARK: OpenSSH events
    case openssh_login(SSHLoginEvent)
    case openssh_logout(SSHLogoutEvent)
    
    // MARK: XProtect events
    case xp_malware_detected(XProtectDetectEvent)
    case xp_malware_remediated(XProtecRemediateEvent)
    
    // MARK: File System Mounting events
    case mount(MountEvent)
    
    // MARK: Login events
    case login_login(LoginLoginEvent)
    case lw_session_login(LWSessionEvent)
    case lw_session_unlock(LWSessionEvent)
    
    // MARK: Kernel events
    case iokit_open(IOKitOpenEvent)
    
    // MARK: Task Port events
    case get_task(GetTaskEvent)
    
    // MARK: MDM events
    case profile_add(ProfileAddEvent)

    // MARK: Security Authorization events
    case authorization_petition(AuthorizationPetitionEvent)
    case authorization_judgement(AuthorizationJudgementEvent)
    
    // MARK: Directory events
    case od_create_user(OpenDirectoryCreateUserEvent)
    case od_modify_password(OpenDirectoryModifyPasswordEvent)
    case od_group_add(OpenDirectoryGroupAddEvent)
    case od_group_remove(OpenDirectoryGroupRemoveEvent)
    case od_create_group(OpenDirectoryCreateGroupEvent)
    case od_attribute_value_add(OpenDirectoryAttributeValueAddEvent)
    
    // MARK: XPC events
    case xpc_connect(XPCConnectEvent)
    
    // MARK: Socket events
    case uipc_connect(UIPCConnectEvent)
    case uipc_bind(UIPCBindEvent)
    
    // MARK: TCC events
    case tcc_modify(TCCModifyEvent)
    
    // MARK: Gatekeeper events
    case gatekeeper_user_override(GatekeeperUserOverrideEvent)
    
    case unknown
}


// MARK: - Payload identity
/// A payload compared and hashed by its ``id`` alone: two values are one Endpoint Security event when their ids match.
public protocol IdentityHashable: Identifiable, Hashable {}

extension IdentityHashable {
    /// Compare two payloads by ``id``.
    ///
    /// - Parameters:
    ///   - lhs: A payload.
    ///   - rhs: Another payload.
    /// - Returns: Whether their ids match.
    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id }
    
    /// Hash the payload's ``id``.
    ///
    /// - Parameter hasher: The hasher to feed.
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
