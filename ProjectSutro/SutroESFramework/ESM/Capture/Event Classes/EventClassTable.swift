//
//  EventClassTable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Event class table
/// Apple's classification of every NOTIFY event Mac Monitor names, and the client each event goes to: the only place
/// the capture layer decides which client serves which event.
///
/// ``categories`` copies the categories Apple's documentation files the events under, so it can be checked against
/// the documentation. An event's category decides its client (``AppleEventCategory/eventClass``): the process client
/// takes the process and interprocess syscalls plus every userspace security event, which Apple leaves uncategorized,
/// while the file and memory clients take the kernel's high-volume file and memory syscalls.
///
/// An event the table doesn't list (one a newer SDK adds, such as macOS 27's `bootstrap_check_in`) is
/// ``AppleEventCategory/uncategorized``, so it goes to the process client, as Apple's newer security events do.
public enum EventClassTable {
    /// Apple's documentation categories, in Apple's order. Each NOTIFY event in `allESEvents` is listed once.
    static let categories: [(category: AppleEventCategory, events: [es_event_type_t])] = [
        (.fileSystem, [
            ES_EVENT_TYPE_NOTIFY_ACCESS, ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_NOTIFY_COPYFILE,
            ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_DUP,
            ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_FCNTL, ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_TRUNCATE,
            ES_EVENT_TYPE_NOTIFY_LOOKUP, ES_EVENT_TYPE_NOTIFY_SEARCHFS
        ]),
        (.fileMetadata, [
            ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_NOTIFY_FSGETPATH, ES_EVENT_TYPE_NOTIFY_GETATTRLIST,
            ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, ES_EVENT_TYPE_NOTIFY_READDIR,
            ES_EVENT_TYPE_NOTIFY_SETACL, ES_EVENT_TYPE_NOTIFY_SETATTRLIST, ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
            ES_EVENT_TYPE_NOTIFY_SETFLAGS, ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_NOTIFY_SETOWNER,
            ES_EVENT_TYPE_NOTIFY_STAT, ES_EVENT_TYPE_NOTIFY_UTIMES
        ]),
        (.fileProvider, [ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE]),
        (.link, [ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_READLINK, ES_EVENT_TYPE_NOTIFY_UNLINK]),
        (.fileSystemMounting, [ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_NOTIFY_UNMOUNT, ES_EVENT_TYPE_NOTIFY_REMOUNT]),
        (.memoryMapping, [ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_MPROTECT]),
        (.process, [
            ES_EVENT_TYPE_NOTIFY_CHDIR, ES_EVENT_TYPE_NOTIFY_CHROOT, ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_PROC_CHECK, ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_EXIT
        ]),
        (.interprocess, [
            ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
        ]),
        (.taskPort, [
            ES_EVENT_TYPE_NOTIFY_GET_TASK, ES_EVENT_TYPE_NOTIFY_GET_TASK_READ, ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME
        ]),
        (.userAndGroupID, [
            ES_EVENT_TYPE_NOTIFY_SETUID, ES_EVENT_TYPE_NOTIFY_SETGID, ES_EVENT_TYPE_NOTIFY_SETEUID,
            ES_EVENT_TYPE_NOTIFY_SETEGID, ES_EVENT_TYPE_NOTIFY_SETREUID, ES_EVENT_TYPE_NOTIFY_SETREGID
        ]),
        (.codeSigning, [ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED]),
        (.socket, [ES_EVENT_TYPE_NOTIFY_UIPC_BIND, ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT]),
        (.clock, [ES_EVENT_TYPE_NOTIFY_SETTIME]),
        (.kernel, [ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_NOTIFY_KEXTLOAD, ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD]),
        (.pseudoterminal, [ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, ES_EVENT_TYPE_NOTIFY_PTY_GRANT]),
        (.uncategorized, [
            ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
            ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT, ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE,
            ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
            ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
            ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD,
            ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET,
            ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD, ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER,
            ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER, ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD,
            ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE, ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET,
            ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP,
            ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER, ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP,
            ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, ES_EVENT_TYPE_NOTIFY_PROFILE_ADD,
            ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE, ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
            ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, ES_EVENT_TYPE_NOTIFY_SU, ES_EVENT_TYPE_NOTIFY_SUDO,
            ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
            ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
        ])
    ]
    
    /// Each listed event's category, by `es_event_type_t` raw value. An event listed twice keeps its first category
    /// (`EventClassTableTests` fails on a duplicate rather than this trapping at launch).
    private static let categoryByEvent: [UInt32: AppleEventCategory] = Dictionary(
        categories.flatMap { entry in entry.events.map { ($0.rawValue, entry.category) } },
        uniquingKeysWith: { first, _ in first })
    
    /// The category Apple files an event under.
    ///
    /// - Parameter event: An event type.
    /// - Returns: Its category, or ``AppleEventCategory/uncategorized`` for an event the table doesn't list.
    public static func category(of event: es_event_type_t) -> AppleEventCategory {
        categoryByEvent[event.rawValue] ?? .uncategorized
    }
    
    /// The client that serves an event.
    ///
    /// - Parameter event: An event type.
    /// - Returns: The class of the event's category.
    public static func eventClass(of event: es_event_type_t) -> EventClass {
        category(of: event).eventClass
    }
    
    /// Each class's share of a subscription list.
    ///
    /// - Parameter events: Event types, such as a session's subscriptions.
    /// - Returns: The events by class, each class's in the order they appear in `events`. A class with no events is
    ///   left out.
    public static func split(_ events: [es_event_type_t]) -> [EventClass: [es_event_type_t]] {
        Dictionary(grouping: events, by: eventClass(of:))
    }
}
