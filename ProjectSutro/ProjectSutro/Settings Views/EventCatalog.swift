//
//  EventCatalog.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
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
        var shortName: String { CommandLineEvents.shortName(name) }
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

    /// A titled group of events: a class of telemetry.
    struct Group: Identifiable {
        let title: String
        /// Its SF Symbol, on its tile.
        let symbol: String
        /// Its color, set here and nowhere else: its tile's, and its events' wherever they're shown by class
        /// (Settings ▸ Subscriptions, Event Facts' correlation).
        let tint: Color
        let events: [Event]
        var id: String { title }
        
        /// The same group with other events, such as a search's matches.
        ///
        /// - Parameter events: The events.
        /// - Returns: The group.
        func with(_ events: [Event]) -> Group { Group(title: title, symbol: symbol, tint: tint, events: events) }
    }

    /// Each group's title, symbol and color, and its events' short names and titles, in order.
    private static let layout: [(String, String, Color, [(String, String)])] = [
        ("Process", "cpu", .blue, [
            ("exec", "Execution"), ("fork", "Fork"), ("exit", "Exit"), ("signal", "Signal"),
            ("proc_check", "Process check"), ("proc_suspend_resume", "Suspend or resume"),
            ("get_task", "Get task port"), ("remote_thread_create", "Remote thread"), ("trace", "Trace"),
            ("cs_invalidated", "Code signature invalidated"), ("pty_grant", "Pseudoterminal granted")
        ]),
        ("File system", "doc", .teal, [
            ("open", "Open"), ("close", "Close"), ("create", "Create"), ("write", "Write"), ("rename", "Rename"),
            ("link", "Hard link"), ("unlink", "Delete"), ("dup", "Duplicate descriptor"), ("mount", "Mount")
        ]),
        ("File metadata", "tag", .indigo, [
            ("setmode", "Change mode"), ("getextattr", "Read extended attribute"),
            ("setextattr", "Set extended attribute"), ("listextattr", "List extended attributes"),
            ("deleteextattr", "Delete extended attribute")
        ]),
        ("Memory", "memorychip", .purple, [
            ("mmap", "Map memory"), ("mprotect", "Change memory protection")
        ]),
        ("Login and sessions", "person.crop.circle", .green, [
            ("login_login", "Login"), ("lw_session_login", "Login window login"),
            ("lw_session_unlock", "Screen unlock"), ("openssh_login", "SSH login"), ("openssh_logout", "SSH logout")
        ]),
        ("Authorization and privacy", "hand.raised", .orange, [
            ("authorization_petition", "Authorization request"), ("authorization_judgement", "Authorization decision"),
            ("tcc_modify", "Privacy permission changed"), ("gatekeeper_user_override", "Gatekeeper override")
        ]),
        ("Background items and profiles", "gearshape.2", .pink, [
            ("btm_launch_item_add", "Background item added"), ("btm_launch_item_remove", "Background item removed"),
            ("profile_add", "Configuration profile added")
        ]),
        ("Directory services", "person.2", .brown, [
            ("od_create_user", "User created"), ("od_create_group", "Group created"),
            ("od_group_add", "Added to group"), ("od_group_remove", "Removed from group"),
            ("od_modify_password", "Password changed"), ("od_attribute_value_add", "Directory attribute added")
        ]),
        ("IPC and kernel", "arrow.left.arrow.right", .cyan, [
            ("xpc_connect", "XPC connection"), ("uipc_bind", "Unix socket bound"),
            ("uipc_connect", "Unix socket connected"), ("iokit_open", "IOKit open")
        ]),
        ("XProtect", "xmark.shield", .red, [
            ("xp_malware_detected", "Malware detected"), ("xp_malware_remediated", "Malware remediated")
        ]),
    ]

    /// The groups, with only the events this Mac supports, and any supported event the layout doesn't name under
    /// Other, so a new event always shows up.
    static let groups: [Group] = {
        let supported = supportedEvents.map { eventTypeToString(from: $0) }
        var named = Set<String>()
        var groups = layout.map { title, symbol, tint, events in
            Group(title: title, symbol: symbol, tint: tint, events: events.compactMap { short, title in
                let name = Event.prefix + short.uppercased()
                named.insert(name)
                return supported.contains(name) ? Event(name: name, title: title) : nil
            })
        }
        let others = supported.filter { !named.contains($0) }.sorted()
            .map { Event(name: $0, title: CommandLineEvents.shortName($0)) }
        groups.append(Group(title: "Other", symbol: "ellipsis.circle", tint: .gray, events: others))
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
            ?? Event(name: name, title: CommandLineEvents.shortName(name))
    }
}
