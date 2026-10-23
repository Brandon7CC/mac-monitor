//
//  CorrelationSummary.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import CoreData
import SutroESFramework


// MARK: - Summary
/// The events a process instigated, as the Correlation tab shows them: a row each, how many of each kind, and the
/// findings worth a look. Made once from ``ESMessage/correlated_array`` on the main thread, the view context's queue.
struct CorrelationSummary {
    /// One correlated event.
    struct Row: Identifiable {
        let message: ESMessage
        /// Seconds from the exec to this event.
        let seconds: Double
        /// Its short name, such as `create`.
        let type: String
        /// Its SF Symbol.
        let symbol: String
        let kind: Kind
        /// Its context, as the event tables show it.
        let context: String
        let target: String
        /// A few words on what it did, such as "Not quarantined" or "Mode 0755", for the inspector.
        let detail: String
        /// The first finding it's part of.
        let finding: Finding?

        var id: NSManagedObjectID { message.objectID }

        /// Does the row mention some text, case-insensitively?
        ///
        /// - Parameter query: The text, lowercased.
        /// - Returns: `true` if its type, context, target, detail, or initiating signing ID contains it.
        func mentions(_ query: String) -> Bool {
            [type, context, target, detail, message.process.signing_id ?? ""]
                .contains { $0.lowercased().contains(query) }
        }
    }

    /// A kind of event: its group in Settings ▸ Subscriptions (``EventCatalog``).
    struct Kind: Identifiable, Hashable {
        let title: String
        let color: Color
        var id: String { title }
    }

    /// The process that ran: the exec's target.
    let processName: String
    /// Newest last.
    let rows: [Row]
    /// Each kind with its number of events, most first.
    let kinds: [(kind: Kind, count: Int)]
    /// Each finding with its events, in ``Finding`` order.
    let findings: [(finding: Finding, rows: [Row])]
    /// Seconds from the exec to the last event.
    let duration: Double

    /// - Parameter exec: An exec event, whose target's events are summarized.
    init(exec: ESMessage) {
        processName = exec.event.exec?.target.executable?.name ?? exec.process.executable?.name ?? "Process"
        let start = exec.message_darwin_time
        rows = exec.correlated_array.reversed().map { message in
            let seconds = start.flatMap { start in message.message_darwin_time?.timeIntervalSince(start) } ?? 0
            let name = message.es_event_type ?? ""
            return Row(message: message, seconds: max(seconds, 0),
                       type: name.replacingOccurrences(of: EventCatalog.Event.prefix, with: "").lowercased(),
                       symbol: eventStringToImage(from: name), kind: Self.kind(of: name),
                       context: Self.stored(message.context), target: Self.stored(message.target_path),
                       detail: Self.detail(of: message), finding: Finding.allCases.first { $0.matches(message) })
        }
        var counts: [Kind: Int] = [:]
        rows.forEach { counts[$0.kind, default: 0] += 1 }
        kinds = counts.map { ($0.key, $0.value) }
            .sorted { $0.count > $1.count || ($0.count == $1.count && $0.kind.title < $1.kind.title) }
        let rows = rows
        findings = Finding.allCases.compactMap { finding in
            let matching = rows.filter { finding.matches($0.message) }
            return matching.isEmpty ? nil : (finding, matching)
        }
        duration = rows.last?.seconds ?? 0
    }

    // MARK: Kinds
    /// The kind each event is, by its `ES_EVENT_TYPE_NOTIFY_` name.
    private static let groups: [String: String] = Dictionary(
        EventCatalog.groups.flatMap { group in group.events.map { ($0.name, group.title) } },
        uniquingKeysWith: { first, _ in first })
    /// Each kind's color.
    private static let colors: [String: Color] = [
        "Process": .blue, "File system": .orange, "File metadata": .purple, "Memory": .teal,
        "Login and sessions": .indigo, "Authorization and privacy": .yellow, "Background items and profiles": .green,
        "Directory services": .brown, "IPC and kernel": .pink, "XProtect": .red,
    ]

    /// - Parameter name: An `ES_EVENT_TYPE_NOTIFY_` name.
    /// - Returns: Its kind, or Other for one the catalog doesn't group.
    private static func kind(of name: String) -> Kind {
        let title = groups[name] ?? "Other"
        return Kind(title: title, color: colors[title] ?? .gray)
    }

    // MARK: Details
    /// A stored string, without the placeholder an event without one is stored with.
    ///
    /// - Parameter value: The stored value.
    /// - Returns: The value, or "" for none.
    private static func stored(_ value: String?) -> String {
        value == "Not supported" ? "" : value ?? ""
    }

    /// A few words on what an event did, from its own fields, unless its context already says them: an extended
    /// attribute's name, a signal's, and an XPC service's domain are in the context.
    ///
    /// - Parameter message: The event.
    /// - Returns: The words, or "" for an event whose context says it all.
    private static func detail(of message: ESMessage) -> String {
        let event = message.event
        if let create = event.create { return create.is_quarantined == 0 ? "Not quarantined" : "Quarantined" }
        if let rename = event.rename {
            let from = "From \(rename.source.path ?? rename.source.name)"
            return rename.is_quarantined == 0 ? from + " · not quarantined" : from
        }
        if let setmode = event.setmode { return "Mode 0" + String(setmode.mode, radix: 8) }
        if let mmap = event.mmap {
            return access(mmap.protection, [(PROT_READ, "read"), (PROT_WRITE, "write"), (PROT_EXEC, "execute")])
        }
        /// `fflag`'s FREAD and FWRITE: opened to read, write, or both.
        if let open = event.open { return access(open.fflag, [(FREAD, "read"), (FWRITE, "write")]) }
        if let close = event.close { return close.modified ? "Modified" : "Not modified" }
        if let fork = event.fork { return "Child pid \(fork.child.pid)" }
        if let exit = event.exit { return "Status \(exit.stat)" }
        if let item = event.btm_launch_item_add?.item {
            return short(item.item_type_string, dropping: "ES_BTM_ITEM_TYPE_")
        }
        return ""
    }

    /// - Parameters:
    ///   - value: Access bit flags, such as an open's `fflag`.
    ///   - names: What each flag allows.
    /// - Returns: What the flags set allow, such as "Read and write".
    private static func access(_ value: some BinaryInteger, _ names: [(Int32, String)]) -> String {
        let allowed = names.filter { Int(value) & Int($0.0) != 0 }.map(\.1)
        return ListFormatter.localizedString(byJoining: allowed).capitalizedFirst
    }

    /// - Parameters:
    ///   - name: An Endpoint Security constant's name, such as `ES_BTM_ITEM_TYPE_AGENT`.
    ///   - prefix: Its prefix.
    /// - Returns: The rest, capitalized: `Agent`.
    private static func short(_ name: String, dropping prefix: String) -> String {
        name.replacingOccurrences(of: prefix, with: "").replacingOccurrences(of: "_", with: " ").capitalized
    }
}


// MARK: - Findings
/// What's worth a look among a process's events, each a card above its correlated events.
enum Finding: String, CaseIterable, Identifiable {
    case reflectiveLoading, notQuarantined, quarantineRemoved, backgroundItem, xprotect, appleScript, keychain, login

    var id: Self { self }

    /// Is an event part of this finding?
    ///
    /// - Parameter message: The event.
    /// - Returns: `true` if it is.
    func matches(_ message: ESMessage) -> Bool {
        let event = message.event
        switch self {
        case .reflectiveLoading:
            guard event.create != nil || event.write != nil || event.mmap != nil else { return false }
            return pathIsReflectiveLoadingImage(message.target_path ?? "")
        case .notQuarantined:
            /// Only from a process whose files macOS quarantines: every file a shell writes is unquarantined.
            guard message.process.file_quarantine_type != FileQuarantineType.disabled.rawValue else { return false }
            return event.create?.is_quarantined == 0 || event.rename?.is_quarantined == 0
        case .quarantineRemoved:
            return event.deleteextattr?.extattr == "com.apple.quarantine"
        case .backgroundItem:
            return event.btm_launch_item_add != nil
        case .xprotect:
            return event.xp_malware_detected != nil || event.xp_malware_remediated != nil
        case .appleScript:
            return event.mmap.map { pathIsOSAComponent(filePath: $0.source.path ?? "") } ?? false
        case .keychain:
            return event.open.map { ($0.file.path ?? "").contains("/Keychains/") } ?? false
        case .login:
            return event.login_login != nil || event.lw_session_login != nil || event.openssh_login != nil
        }
    }

    /// The card's title.
    ///
    /// - Parameter count: How many events are part of it.
    /// - Returns: The title, such as "3 files not quarantined".
    func title(_ count: Int) -> String {
        switch self {
        case .reflectiveLoading: return "Reflective loading"
        case .notQuarantined: return count == 1 ? "1 file not quarantined" : "\(count) files not quarantined"
        case .quarantineRemoved: return count == 1 ? "Quarantine removed" : "Quarantine removed ×\(count)"
        case .backgroundItem: return count == 1 ? "Background item added" : "\(count) background items added"
        case .xprotect: return "XProtect detection"
        case .appleScript: return "AppleScript loaded"
        case .keychain: return "Keychain opened"
        case .login: return count == 1 ? "Login" : "\(count) logins"
        }
    }

    /// Why it's worth a look, for the inspector.
    var explanation: String {
        switch self {
        case .reflectiveLoading:
            return "Wrote or mapped the image NSCreateObjectFileImageFromMemory makes of a Mach-O it loads from "
                + "memory: reflective code loading (T1620)."
        case .notQuarantined:
            return "Written without the quarantine attribute by a process whose files macOS quarantines, so "
                + "Gatekeeper won't check it when it's opened."
        case .quarantineRemoved:
            return "Deleted com.apple.quarantine, so Gatekeeper won't check the file when it's opened."
        case .backgroundItem:
            return "Added a background item, which runs again at login."
        case .xprotect:
            return "XProtect detected or remediated malware."
        case .appleScript:
            return "Mapped an Open Scripting Architecture component, as a process running AppleScript does."
        case .keychain:
            return "Opened a keychain, which holds passwords and keys."
        case .login:
            return "A login, by the login window, login(1), or SSH."
        }
    }

    var symbol: String {
        switch self {
        case .reflectiveLoading: return "memorychip"
        case .notQuarantined: return "exclamationmark.shield"
        case .quarantineRemoved: return "xmark.shield"
        case .backgroundItem: return "gearshape.2"
        case .xprotect: return "xmark.octagon"
        case .appleScript: return "applescript"
        case .keychain: return "key"
        case .login: return "person.badge.key"
        }
    }

    var tint: Color {
        switch self {
        case .notQuarantined: return .orange
        case .reflectiveLoading, .quarantineRemoved, .xprotect: return .red
        case .backgroundItem: return .green
        case .appleScript: return .purple
        case .keychain, .login: return .blue
        }
    }
}


private extension String {
    /// The string with its first letter capitalized: "read and write" reads "Read and write".
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
