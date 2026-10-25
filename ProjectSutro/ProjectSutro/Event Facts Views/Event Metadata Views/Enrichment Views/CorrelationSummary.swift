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
        /// Every finding it's part of, by identity.
        let findings: Set<UUID>

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
    /// Each finding with its events, in Settings ▸ Findings' order.
    let findings: [(finding: Finding, rows: [Row])]
    /// Seconds from the exec to the last event.
    let duration: Double

    /// - Parameters:
    ///   - exec: An exec event, whose target's events are summarized.
    ///   - matcher: The findings to look for (``FindingStore``).
    init(exec: ESMessage, matcher: FindingMatcher) {
        processName = exec.event.exec?.target.executable?.name ?? exec.process.executable?.name ?? "Process"
        let start = exec.message_darwin_time
        rows = exec.correlated_array.reversed().map { message in
            let seconds = start.flatMap { start in message.message_darwin_time?.timeIntervalSince(start) } ?? 0
            let name = message.es_event_type ?? ""
            let matched = matcher.matches(message)
            return Row(message: message, seconds: max(seconds, 0),
                       type: name.replacingOccurrences(of: EventCatalog.Event.prefix, with: "").lowercased(),
                       symbol: eventStringToImage(from: name), kind: Self.kind(of: name),
                       context: Self.stored(message.context), target: Self.stored(message.target_path),
                       detail: Self.detail(of: message), finding: matched.first,
                       findings: Set(matched.map(\.id)))
        }
        var counts: [Kind: Int] = [:]
        rows.forEach { counts[$0.kind, default: 0] += 1 }
        kinds = counts.map { ($0.key, $0.value) }
            .sorted { $0.count > $1.count || ($0.count == $1.count && $0.kind.title < $1.kind.title) }
        let rows = rows
        findings = matcher.order.compactMap { finding in
            let matching = rows.filter { $0.findings.contains(finding.id) }
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


private extension String {
    /// The string with its first letter capitalized: "read and write" reads "Read and write".
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
