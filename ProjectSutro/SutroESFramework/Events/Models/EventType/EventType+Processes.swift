//
//  EventType+Processes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation

// MARK: - Every process a payload carries
extension EventType {
    /// Visit every process the payload carries: an exec's target, a fork's child, a signal's instigator and target,
    /// and so on. The message's initiating process (``Message/process``) isn't the payload's, so it isn't visited.
    ///
    /// The switch names every case, so a new event type has to say which processes it carries. A process Endpoint
    /// Security left out (`nil`) isn't visited.
    ///
    /// - Parameter body: Called once with each process, in the order the payload declares them. It may change it.
    mutating func forEachProcess(_ body: (inout Process) -> Void) {
        switch self {
        // MARK: Process and interprocess events
        case .exec(var e): body(&e.target); self = .exec(e)
        case .fork(var e): body(&e.child); self = .fork(e)
        case .signal(var e): Self.visit(&e.instigator, body); body(&e.target); self = .signal(e)
        case .proc_suspend_resume(var e): Self.visit(&e.target, body); self = .proc_suspend_resume(e)
        case .proc_check(var e): Self.visit(&e.target, body); self = .proc_check(e)
        case .remote_thread_create(var e): body(&e.target); self = .remote_thread_create(e)
        case .trace(var e): body(&e.target); self = .trace(e)
        case .get_task(var e): body(&e.target); self = .get_task(e)

        // MARK: Service Management and MDM events
        case .btm_launch_item_add(var e):
            Self.visit(&e.instigator, body); Self.visit(&e.app, body); self = .btm_launch_item_add(e)
        case .btm_launch_item_remove(var e):
            Self.visit(&e.instigator, body); Self.visit(&e.app, body); self = .btm_launch_item_remove(e)
        case .profile_add(var e): Self.visit(&e.instigator, body); self = .profile_add(e)

        // MARK: Security Authorization and TCC events
        case .authorization_petition(var e):
            Self.visit(&e.instigator, body); Self.visit(&e.petitioner, body); self = .authorization_petition(e)
        case .authorization_judgement(var e):
            Self.visit(&e.instigator, body); Self.visit(&e.petitioner, body); self = .authorization_judgement(e)
        case .tcc_modify(var e):
            Self.visit(&e.instigator, body); Self.visit(&e.responsible, body); self = .tcc_modify(e)

        // MARK: Directory events
        case .od_create_user(var e): Self.visit(&e.instigator, body); self = .od_create_user(e)
        case .od_modify_password(var e): Self.visit(&e.instigator, body); self = .od_modify_password(e)
        case .od_group_add(var e): Self.visit(&e.instigator, body); self = .od_group_add(e)
        case .od_group_remove(var e): Self.visit(&e.instigator, body); self = .od_group_remove(e)
        case .od_create_group(var e): Self.visit(&e.instigator, body); self = .od_create_group(e)
        case .od_attribute_value_add(var e): Self.visit(&e.instigator, body); self = .od_attribute_value_add(e)

        // MARK: Events that carry no process
        case .exit, .cs_invalidated, .mmap, .mprotect, .create, .rename, .open, .write, .close, .unlink, .dup, .link,
             .setextattr, .deleteextattr, .listextattr, .getextattr, .setmode, .pty_grant, .openssh_login,
             .openssh_logout, .xp_malware_detected, .xp_malware_remediated, .mount, .login_login, .lw_session_login,
             .lw_session_unlock, .iokit_open, .xpc_connect, .uipc_connect, .uipc_bind, .gatekeeper_user_override,
             .unknown:
            break
        }
    }

    /// Visit a process Endpoint Security may leave out.
    ///
    /// - Parameters:
    ///   - process: The process, or `nil`, which isn't visited.
    ///   - body: Called with the process, which it may change.
    private static func visit(_ process: inout Process?, _ body: (inout Process) -> Void) {
        if process != nil { body(&process!) }
    }
}
