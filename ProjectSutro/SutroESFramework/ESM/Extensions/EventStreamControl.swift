//
//  EventStreamControl.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import EndpointSecurity


// @discussion notes are from Endpoint Security documentation
@objc public enum NewClientResult: Int {
    // @note The caller has reached the maximum number of allowed simultaneously connected clients.
    case tooManyClients
    // @note The caller is not properly entitled to connect.
    case notEntitled
    // @note The caller lacks Transparency, Consent, and Control (TCC) approval from the user.
    case notPermitted
    // @note The caller is not running as root.
    case notPrivileged
    // @note Communication with the ES subsystem failed, or other error condition.
    case internalSubsystem
    // @note One or more invalid arguments were provided.
    case invalidArgument
    case waiting
    case success
    /// Mac Monitor's own refusal, not Endpoint Security's: another Mac Monitor owns the event stream. Last, so the
    /// cases above keep their raw values over XPC.
    case streamOwned
}


extension NewClientResult {
    /// Mac Monitor's name for what `es_new_client` returned.
    ///
    /// - Parameter result: The result of `es_new_client`.
    public init(_ result: es_new_client_result_t) {
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            self = .success
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            self = .tooManyClients
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            self = .notEntitled
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            self = .notPermitted
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            self = .notPrivileged
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            self = .invalidArgument
        default:
            self = .internalSubsystem
        }
    }
}


extension EndpointSecurityManager {
    // @discussion this function is used when "dropping" platform binaries.
    public func isEventCritical(message: Message) -> Bool {
        switch message.event {
        case .exec,
             .fork,
             .exit,
             .mmap,
             .create,
             .open,
             .close,
             .write,
             .unlink,
             .rename,
             .proc_suspend_resume,
             .get_task,
             .iokit_open,
             .dup,
             .deleteextattr,
             .setextattr,
             .signal,
             .xpc_connect:
            return false
        default:
            return true
        }
    }
}
