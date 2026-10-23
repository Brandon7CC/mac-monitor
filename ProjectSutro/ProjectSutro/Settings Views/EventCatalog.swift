//
//  EventCatalog.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import Foundation
import SutroESFramework


// MARK: - Event catalog
/// The events Mac Monitor supports on this Mac (``supportedEvents``), grouped and named for people, as Settings
/// lists them in Subscriptions and in Path Muting's Add sheet.
enum EventCatalog {
    /// One event.
    struct Event: Identifiable, Hashable {
        /// Its `ES_EVENT_TYPE_NOTIFY_` name.
        let name: String
        /// Its name for people, such as "Execution".
        let title: String

        var id: String { name }
        /// Its short name, as macmonitor knows it: `exec`.
        var shortName: String { String(name.dropFirst(Self.prefix.count)).lowercased() }
        /// Its SF Symbol (``eventStringToImage(from:)``).
        var symbol: String { eventStringToImage(from: name) }
        /// Apple's documentation for it: a page per event, named in lowercase, such as
        /// `endpointsecurity/es_event_type_notify_exec`.
        var documentation: URL {
            URL(string: "https://developer.apple.com/documentation/endpointsecurity/\(name.lowercased())")!
        }

        /// What every name starts with.
        static let prefix = "ES_EVENT_TYPE_NOTIFY_"
    }

    /// A titled group of events.
    struct Group: Identifiable {
        let title: String
        let events: [Event]
        var id: String { title }
    }

    /// Each group's title and its events' short names and titles, in order.
    private static let layout: [(String, [(String, String)])] = [
        ("Process", [("exec", "Execution"), ("fork", "Fork"), ("exit", "Exit"), ("signal", "Signal"),
                     ("proc_check", "Process check"), ("proc_suspend_resume", "Suspend or resume"),
                     ("get_task", "Get task port"), ("remote_thread_create", "Remote thread"), ("trace", "Trace"),
                     ("cs_invalidated", "Code signature invalidated"), ("pty_grant", "Pseudoterminal granted")]),
        ("File system", [("open", "Open"), ("close", "Close"), ("create", "Create"), ("write", "Write"),
                         ("rename", "Rename"), ("link", "Hard link"), ("unlink", "Delete"),
                         ("dup", "Duplicate descriptor"), ("mount", "Mount")]),
        ("File metadata", [("setmode", "Change mode"), ("getextattr", "Read extended attribute"),
                           ("setextattr", "Set extended attribute"), ("listextattr", "List extended attributes"),
                           ("deleteextattr", "Delete extended attribute")]),
        ("Memory", [("mmap", "Map memory"), ("mprotect", "Change memory protection")]),
        ("Login and sessions", [("login_login", "Login"), ("lw_session_login", "Login window login"),
                                ("lw_session_unlock", "Screen unlock"), ("openssh_login", "SSH login"),
                                ("openssh_logout", "SSH logout")]),
        ("Authorization and privacy", [("authorization_petition", "Authorization request"),
                                       ("authorization_judgement", "Authorization decision"),
                                       ("tcc_modify", "Privacy permission changed"),
                                       ("gatekeeper_user_override", "Gatekeeper override")]),
        ("Background items and profiles", [("btm_launch_item_add", "Background item added"),
                                           ("btm_launch_item_remove", "Background item removed"),
                                           ("profile_add", "Configuration profile added")]),
        ("Directory services", [("od_create_user", "User created"), ("od_create_group", "Group created"),
                                ("od_group_add", "Added to group"), ("od_group_remove", "Removed from group"),
                                ("od_modify_password", "Password changed"),
                                ("od_attribute_value_add", "Directory attribute added")]),
        ("IPC and kernel", [("xpc_connect", "XPC connection"), ("uipc_bind", "Unix socket bound"),
                            ("uipc_connect", "Unix socket connected"), ("iokit_open", "IOKit open")]),
        ("XProtect", [("xp_malware_detected", "Malware detected"), ("xp_malware_remediated", "Malware remediated")])
    ]

    /// The groups, with only the events this Mac supports, and any supported event the layout doesn't name under
    /// Other, so a new event always shows up.
    static let groups: [Group] = {
        let supported = supportedEvents.map { eventTypeToString(from: $0) }
        var named = Set<String>()
        var groups = layout.map { title, events in
            Group(title: title, events: events.compactMap { short, title in
                let name = Event.prefix + short.uppercased()
                named.insert(name)
                return supported.contains(name) ? Event(name: name, title: title) : nil
            })
        }
        let others = supported.filter { !named.contains($0) }.sorted()
            .map { Event(name: $0, title: String($0.dropFirst(Event.prefix.count)).lowercased()) }
        groups.append(Group(title: "Other", events: others))
        return groups.filter { !$0.events.isEmpty }
    }()

    /// Every event, in the groups' order.
    static var events: [Event] { groups.flatMap(\.events) }

    /// An event by its `ES_EVENT_TYPE_NOTIFY_` name.
    ///
    /// - Parameter name: The name.
    /// - Returns: The event, named for people when the catalog knows it.
    static func event(named name: String) -> Event {
        events.first { $0.name == name }
            ?? Event(name: name, title: String(name.dropFirst(Event.prefix.count)).lowercased())
    }
}
