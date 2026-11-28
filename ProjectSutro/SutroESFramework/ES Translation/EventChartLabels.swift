//
//  EventChartLabels.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Chart labels
/// The mini-chart's bars beside the System Security Unified table: each event's label, and the bars' order.
public enum EventChartLabels {
    /// The bars' order, top to bottom. A label missing here gets no bar. Mac Monitor's network events come last.
    public static let order: [String] = [
        "EXEC", "FORK", "EXIT", "MMAP", "MPROTECT", "CREATE", "DELETEEXTATTR", "SETEXTATTR", "GETEXTATTR",
        "LISTEXTATTR", "SETMODE", "LAUNCH_ITEM_ADD", "LAUNCH_ITEM_REMOVE", "OPENSSH_LOGIN", "OPENSSH_LOGOUT", "MOUNT",
        "LOGIN_LOGIN", "DUP", "RENAME", "LW_UNLOCK", "LW_LOGIN", "AUTHENTICATION", "XP_MALWARE_DETECTED",
        "XP_MALWARE_REMEDIATED", "UNLINK", "OPEN", "WRITE", "LINK", "CLOSE", "SIGNAL", "REMOTE_THREAD", "IOKIT_OPEN",
        "CS_INVALIDATED", "PROC_SUSPEND_RESUME", "TRACE", "GET_TASK", "PROC_CHECK", "PROFILE_ADD", "OD_CREATE_USER",
        "OD_MODIFY_PASSWORD", "OD_GROUP_ADD", "OD_GROUP_CREATE", "OD_GROUP_REMOVE", "OD_ATTR_ADD", "XPC_CONNECT",
        "AUTH_PETITION", "AUTH_JUDGEMENT", "TCC_MODIFY", "GATEKEEPER_USER_OVERRIDE", "PTY_GRANT", "UIPC_CONNECT",
        "UIPC_BIND", "NEW_FLOW", "FLOW_CLOSED"
    ]

    /// The labels shorter than the event's chart label (``EventNames/chartLabel(_:)``).
    private static let renamed: [String: String] = [
        "BTM_LAUNCH_ITEM_ADD": "LAUNCH_ITEM_ADD",
        "BTM_LAUNCH_ITEM_REMOVE": "LAUNCH_ITEM_REMOVE",
        "LW_SESSION_UNLOCK": "LW_UNLOCK",
        "LW_SESSION_LOGIN": "LW_LOGIN",
        "REMOTE_THREAD_CREATE": "REMOTE_THREAD",
        "AUTHORIZATION_PETITION": "AUTH_PETITION",
        "AUTHORIZATION_JUDGEMENT": "AUTH_JUDGEMENT",
        "OD_CREATE_GROUP": "OD_GROUP_CREATE",
        "OD_ATTRIBUTE_VALUE_ADD": "OD_ATTR_ADD",
    ]

    /// An event's bar label.
    ///
    /// - Parameter eventType: An `ES_EVENT_TYPE_NOTIFY_*` name, or a Mac Monitor event's.
    /// - Returns: The chart label (e.g. `EXEC`, `LW_UNLOCK`, `NEW_FLOW`).
    public static func label(for eventType: String) -> String {
        let name = EventNames.chartLabel(eventType)
        return renamed[name] ?? name
    }
}
