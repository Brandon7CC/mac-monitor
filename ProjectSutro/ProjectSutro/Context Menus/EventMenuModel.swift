//
//  EventMenuModel.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/10/26.
//

import SwiftUI
import SutroESFramework
import EndpointSecurity
import OSLog


// MARK: - The event
/// What an event's context menu needs from the event, read once when the menu is built. An item never touches the
/// event again, which may have been cleared by the time the item is chosen.
struct EventMenuFacts {
    /// The event, for "Event metadata".
    let eventID: UUID
    /// The event's `ES_EVENT_TYPE_*` name.
    let eventType: String
    /// The initiating process's executable path and name.
    let processPath: String?
    let processName: String?
    /// The initiating process's effective user, by name.
    let euid: String?
    /// The event's target path, "" if it has none.
    let targetPath: String
    /// Is it a process execution, which has its own menu?
    let isExec: Bool
    /// A process execution's new executable path and name.
    let execTargetPath: String?
    let execTargetName: String?
    /// Was the event recorded on this Mac (rather than read from a trace)? Only then can a path be muted, or the event
    /// type unsubscribed from.
    let isRecorded: Bool

    /// Which menu the event gets, and so which Settings switches decide its items.
    var kind: ContextMenuKind { isExec ? .exec : .other }

    /// Read an event's facts.
    ///
    /// - Parameters:
    ///   - message: The right-clicked event.
    ///   - isRecorded: Was it recorded on this Mac, rather than read from a trace?
    /// - Returns: The facts, or `nil` for an event without a type, which gets no menu.
    init?(message: ESMessage, isRecorded: Bool) {
        guard let eventType = message.es_event_type else { return nil }
        let exec = message.event.exec
        self.init(eventID: message.id, eventType: eventType, processPath: message.process.executable?.path,
                  processName: message.process.executable?.name, euid: message.process.euid_human,
                  targetPath: message.target_path ?? "", isExec: exec != nil,
                  execTargetPath: exec?.target.executable?.path, execTargetName: exec?.target.executable?.name,
                  isRecorded: isRecorded)
    }

    /// The facts as given, for an event that isn't in the store.
    init(eventID: UUID, eventType: String, processPath: String?, processName: String?, euid: String?,
         targetPath: String, isExec: Bool, execTargetPath: String?, execTargetName: String?, isRecorded: Bool) {
        self.eventID = eventID
        self.eventType = eventType
        self.processPath = processPath
        self.processName = processName
        self.euid = euid
        self.targetPath = targetPath
        self.isExec = isExec
        self.execTargetPath = execTargetPath
        self.execTargetName = execTargetName
        self.isRecorded = isRecorded
    }

    /// A recorded sample event for Settings > Context Menus' preview: `zsh` running `curl`, or `curl` opening a file.
    ///
    /// - Parameter kind: Which menu.
    /// - Returns: The sample's facts.
    static func sample(_ kind: ContextMenuKind) -> EventMenuFacts {
        let exec = kind == .exec
        return EventMenuFacts(eventID: UUID(),
                              eventType: exec ? "ES_EVENT_TYPE_NOTIFY_EXEC" : "ES_EVENT_TYPE_NOTIFY_OPEN",
                              processPath: exec ? "/bin/zsh" : "/usr/bin/curl", processName: exec ? "zsh" : "curl",
                              euid: "root", targetPath: exec ? "" : "/private/tmp/report.txt", isExec: exec,
                              execTargetPath: exec ? "/usr/bin/curl" : nil, execTargetName: exec ? "curl" : nil,
                              isRecorded: true)
    }
}


// MARK: - What an item does
/// What choosing an event menu item does.
enum EventMenuAction {
    /// Open the event in an "Event Facts" window.
    case openFacts(UUID)
    /// Hide every event of this `ES_EVENT_TYPE_*` name.
    case filterEvent(String)
    /// Hide the events whose target path contains this path.
    case filterTarget(String)
    /// Hide the events this executable path initiated.
    case filterInitiating(String)
    /// Hide the events of this effective user.
    case filterUser(String)
    /// Show only this process's events, by its initiating path or, for an exec, its new executable's path, alone or
    /// with its whole process tree.
    case select(path: String, asTarget: Bool, fullTree: Bool)
    /// Add a mute to the saved set: a path, how it's matched, and the event types (none is every event).
    case mute(String, es_mute_path_type_t, events: [String])
    /// Stop Endpoint Security delivering this event type.
    case unsubscribe(String)

    /// Do it.
    ///
    /// - Parameters:
    ///   - filters: The event tables' filters.
    ///   - manager: The Security Extension's manager, for mutes and subscriptions.
    ///   - openWindow: Opens the "Event Facts" window for an event.
    @MainActor
    func perform(filters: Binding<Filters>, manager: EndpointSecurityManager, openWindow: OpenWindowAction) {
        switch self {
        case .openFacts(let id):
            openWindow(value: id)
        case .filterEvent(let eventType):
            filters.wrappedValue.events.append(eventType)
        case .filterTarget(let path):
            filters.wrappedValue.targetPaths.append(path)
        case .filterInitiating(let path):
            filters.wrappedValue.initiatingPaths.append(path)
        case .filterUser(let euid):
            filters.wrappedValue.userIDs.append(euid)
        case .select(let path, let asTarget, let fullTree):
            if asTarget {
                filters.wrappedValue.rootIncludedTargetProcessPath = path
            } else {
                filters.wrappedValue.rootIncludedInitiatingProcessPath = path
            }
            filters.wrappedValue.shouldIncludeProcessSubTrees = fullTree
        case .mute(let path, let type, let events):
            os_log("Requesting ES mute: \(path)")
            manager.puntPathToMute(pathToMute: path, muteCase: type, pathEvents: events, from: .eventMenu)
        case .unsubscribe(let eventType):
            os_log("Requesting ES unsubscribe from: \(eventType)")
            manager.setSubscription(eventType, enabled: false)
        }
    }
}


// MARK: - The menu
/// One line of an event's context menu: an item, a section's header, or a separator.
///
/// ``entries(_:isOn:)`` is the only description of the menu: the AppKit tables (``EventRowMenu``), the SwiftUI menus
/// (``EventMenuView``) and Settings > Context Menus' preview all draw what it returns.
enum EventMenuEntry {
    case item(String, EventMenuAction)
    case header(String)
    case separator

    /// An event's menu, as the user's Settings switches leave it.
    ///
    /// - Parameters:
    ///   - facts: The event.
    ///   - prefs: The user's preferences.
    /// - Returns: The menu's lines, in order.
    static func entries(_ facts: EventMenuFacts, prefs: UserPrefs) -> [EventMenuEntry] {
        entries(facts) { $0.binding(prefs, for: facts.kind).wrappedValue }
    }

    /// An event's menu: "Event metadata", the filters, "Select", and "Advanced".
    ///
    /// While a trace is open the items that change what the Security Extension records (mute and unsubscribe) are left
    /// out, and so is "Advanced" if that leaves it empty.
    ///
    /// - Parameters:
    ///   - facts: The event.
    ///   - isOn: Is a Settings switch on, for the event's menu?
    /// - Returns: The menu's lines, in order.
    static func entries(_ facts: EventMenuFacts, isOn: (ContextMenuOption) -> Bool) -> [EventMenuEntry] {
        let sections = facts.isExec ? execSections(facts, isOn: isOn) : otherSections(facts, isOn: isOn)
        var entries: [EventMenuEntry] = [.item("Event metadata", .openFacts(facts.eventID)), .separator]
        entries += sections.filters
        entries += [.separator, .header("Select")]
        entries += sections.select
        if facts.isRecorded || !sections.advanced.isEmpty {
            entries += [.separator, .header("Advanced")]
            entries += sections.advanced
        }
        return entries
    }

    /// The items of every event but a process execution.
    ///
    /// - Parameters:
    ///   - facts: The event.
    ///   - isOn: Is a Settings switch on, for this menu?
    /// - Returns: The filter, "Select" and "Advanced" items.
    private static func otherSections(_ facts: EventMenuFacts, isOn: (ContextMenuOption) -> Bool)
        -> (filters: [EventMenuEntry], select: [EventMenuEntry], advanced: [EventMenuEntry]) {
        let type = facts.eventType, euid = facts.euid ?? ""
        var filters: [EventMenuEntry] = [], select: [EventMenuEntry] = [], advanced: [EventMenuEntry] = []
        if isOn(.filterProcessPath) {
            filters.append(.item("Filter initiating path: \"\(facts.processName ?? "")\"",
                                 .filterInitiating(facts.processPath ?? "")))
        }
        filters.append(.item("Filter event: \"\(type)\"", .filterEvent(type)))
        if isOn(.filterUser) { filters.append(.item("Filter euid: \"\(euid)\"", .filterUser(euid))) }

        if let name = facts.processName, let path = facts.processPath {
            select = selectItems(name: name, path: path, asTarget: false)
        }

        /// File and `MMAP` events filter and mute the folder they target rather than the file.
        let target = IntelligentEventTargeting.menuTarget(of: facts.targetPath, esEventType: type)
        let hasTarget = !facts.targetPath.isEmpty
        if isOn(.filterTargetPath) && hasTarget {
            advanced.append(.item("Filter target path: \"\(target.path)\"", .filterTarget(target.path)))
        }
        if facts.isRecorded && isOn(.muteProcessPath) {
            advanced.append(.item("Mute initiating path: \"\(facts.processPath ?? "")\"",
                                  .mute(facts.processPath ?? "", ES_MUTE_PATH_TYPE_LITERAL, events: [])))
        }
        if facts.isRecorded && isOn(.muteTargetPath) && hasTarget {
            let muteType = target.isFolder ? ES_MUTE_PATH_TYPE_TARGET_PREFIX : ES_MUTE_PATH_TYPE_TARGET_LITERAL
            advanced.append(.item("Mute target path event: \"\(target.path)\"",
                                  .mute(target.path, muteType, events: [type])))
        }
        if facts.isRecorded && isOn(.unsubscribe) {
            advanced.append(.item("Unsubscribe: \"\(type)\"", .unsubscribe(type)))
        }
        return (filters, select, advanced)
    }

    /// The items of a process execution.
    ///
    /// - Parameters:
    ///   - facts: The event.
    ///   - isOn: Is a Settings switch on, for this menu?
    /// - Returns: The filter, "Select" and "Advanced" items.
    private static func execSections(_ facts: EventMenuFacts, isOn: (ContextMenuOption) -> Bool)
        -> (filters: [EventMenuEntry], select: [EventMenuEntry], advanced: [EventMenuEntry]) {
        let type = facts.eventType, euid = facts.euid ?? ""
        var filters: [EventMenuEntry] = [], select: [EventMenuEntry] = [], advanced: [EventMenuEntry] = []
        if isOn(.filterTargetPath), let targetPath = facts.execTargetPath {
            filters.append(.item("Filter target path: \"\(targetPath)\"", .filterTarget(targetPath)))
        }
        filters.append(.item("Filter event: \"\(type)\"", .filterEvent(type)))
        if isOn(.filterUser) { filters.append(.item("Filter euid: \"\(euid)\"", .filterUser(euid))) }
        if isOn(.filterProcessPath), let path = facts.processPath {
            filters.append(.item("Filter initiating path: \"\(path)\"", .filterInitiating(path)))
        }

        if let name = facts.execTargetName, let path = facts.execTargetPath {
            select = selectItems(name: name, path: path, asTarget: true)
        }

        if facts.isRecorded && isOn(.muteTargetPath) {
            /// The muted executable by its path's last component, not the executable's name.
            let targetPath = facts.execTargetPath ?? ""
            advanced.append(.item("Mute target path: \"\(targetPath.lastPathComponent)\"",
                                  .mute(targetPath, ES_MUTE_PATH_TYPE_TARGET_LITERAL, events: [])))
        }
        if facts.isRecorded && isOn(.muteProcessPath) {
            advanced.append(.item("Mute initiating path: \"\(facts.processName ?? "")\"",
                                  .mute(facts.processPath ?? "", ES_MUTE_PATH_TYPE_LITERAL, events: [])))
        }
        if facts.isRecorded && isOn(.unsubscribe) {
            advanced.append(.item("Unsubscribe: \"\(type)\"", .unsubscribe(type)))
        }
        return (filters, select, advanced)
    }

    /// "Select": show only one process's events, or its whole process tree.
    ///
    /// - Parameters:
    ///   - name: The process's name, for the titles.
    ///   - path: Its executable path.
    ///   - asTarget: Is it an exec's new executable, rather than the initiating process?
    /// - Returns: The "Only" and "Full tree" items.
    private static func selectItems(name: String, path: String, asTarget: Bool) -> [EventMenuEntry] {
        [.item("→ Only: \"\(name)\" events", .select(path: path, asTarget: asTarget, fullTree: false)),
         .item("↕ Full tree: \"\(name)\" events", .select(path: path, asTarget: asTarget, fullTree: true))]
    }
}


// MARK: - SwiftUI menu
/// An event's context menu as SwiftUI menu items, for the Event Facts window's tables and inspector.
struct EventMenuView: View {
    @Environment(\.openWindow) private var openWindow

    /// The right-clicked event.
    let message: ESMessage
    let filters: Binding<Filters>
    let manager: EndpointSecurityManager
    let prefs: UserPrefs

    /// The menu's lines: nothing for an event without a type.
    private var entries: [EventMenuEntry] {
        guard let facts = EventMenuFacts(message: message, isRecorded: !manager.coreDataContainer.isShowingTrace)
        else { return [] }
        return EventMenuEntry.entries(facts, prefs: prefs)
    }

    var body: some View {
        ForEach(Array(entries.enumerated()), id: \.offset) { _, entry in
            switch entry {
            case .item(let title, let action):
                Button(title) { action.perform(filters: filters, manager: manager, openWindow: openWindow) }
            case .header(let title):
                Text(title).bold()
            case .separator:
                Divider()
            }
        }
    }
}
