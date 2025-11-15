//
//  EventSubscriptions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/12/23.
//

import Foundation

/// macOS 14.0 Sonoma version
///
/// Used to determine event availability
let sonoma = OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)
/// macOS 15.0 Sequoia version
let sequoia = OperatingSystemVersion(majorVersion: 15, minorVersion: 0, patchVersion: 0)

/// Sonoma events (macOS 14.x)
var sonomaEvents: [es_event_type_t] {
    return [
        ES_EVENT_TYPE_NOTIFY_PROFILE_ADD,
        ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER,
        ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD,
        ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD,
        ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD,
        ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT,
        ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP
    ]
}

/// Sequoia events (macOS 15.x)
///
/// Always includes 15.0 events, with 15.4+ additions gated by availability checks.
var sequoiaEvents: [es_event_type_t] {
    var list: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
    ]
    if #available(macOS 15.4, *) {
        list.append(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY)
    }
    return list
}

/// All the Endpoint Security events supported by Mac Monitor
public var supportedEvents: [es_event_type_t] {
    let coreEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
        ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
        ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
        ES_EVENT_TYPE_NOTIFY_MOUNT,
        ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
        ES_EVENT_TYPE_NOTIFY_DUP,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_LINK,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
        ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
        ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
        ES_EVENT_TYPE_NOTIFY_TRACE,
        ES_EVENT_TYPE_NOTIFY_GET_TASK,
        ES_EVENT_TYPE_NOTIFY_PROC_CHECK,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_PTY_GRANT,
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_UIPC_BIND
    ]
    
    var list = coreEvents
    
    // If we're on Sonoma then we have more events to play with
    if ProcessInfo().isOperatingSystemAtLeast(sonoma) {
        list += sonomaEvents
    }
    
    // If we're on Sequoia then we add additional events
    if ProcessInfo().isOperatingSystemAtLeast(sequoia) {
        list += sequoiaEvents
    }
    
    return list
}

/// The default event subscriptions for Mac Monitor
///
/// The above ``supportedEvents`` array describes the events we've modeled and this array
/// specifies which events should be subscribed to on first launch.
public var defaultEventSubscriptions: [es_event_type_t] {
    let defaultEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
        ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
        ES_EVENT_TYPE_NOTIFY_MOUNT,
        ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ES_EVENT_TYPE_NOTIFY_TRACE,
        ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_PTY_GRANT,
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
        ES_EVENT_TYPE_NOTIFY_LINK
    ]
    
    var list = defaultEvents
    
    // If we're on Sonoma and we have an additional event we'd like to subscribe to
    if ProcessInfo().isOperatingSystemAtLeast(sonoma) {
        list += sonomaEvents
    }
    
    // If we're on Sequoia then we add additional defaults
    if ProcessInfo().isOperatingSystemAtLeast(sequoia) {
        list += sequoiaEvents
    }
    
    return list
}
