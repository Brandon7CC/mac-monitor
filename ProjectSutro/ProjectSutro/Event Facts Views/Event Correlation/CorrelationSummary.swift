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
        /// The first finding it's part of.
        let finding: Finding?
        /// Every finding it's part of, by identity.
        let findings: Set<UUID>

        var id: NSManagedObjectID { message.objectID }

        /// Does the row mention some text, case-insensitively?
        ///
        /// - Parameter query: The text, lowercased.
        /// - Returns: `true` if its type, context, target or initiating signing ID contains it.
        func mentions(_ query: String) -> Bool {
            [type, context, target, message.process.signing_id ?? ""]
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
                       type: CommandLineEvents.shortName(name),
                       symbol: eventStringToImage(from: name), kind: Self.kind(of: name),
                       context: Self.stored(message.context), target: Self.stored(message.target_path),
                       finding: matched.first,
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
    /// The class each event is, by its `ES_EVENT_TYPE_NOTIFY_` name, colored as the catalog colors it.
    private static let groups: [String: EventCatalog.Group] = Dictionary(
        EventCatalog.groups.flatMap { group in group.events.map { ($0.name, group) } },
        uniquingKeysWith: { first, _ in first })

    /// - Parameter name: An `ES_EVENT_TYPE_NOTIFY_` name.
    /// - Returns: Its kind, or Other for one the catalog doesn't group.
    private static func kind(of name: String) -> Kind {
        groups[name].map { Kind(title: $0.title, color: $0.tint) } ?? Kind(title: "Other", color: .gray)
    }

    // MARK: Details
    /// A stored string, without the placeholder an event without one is stored with.
    ///
    /// - Parameter value: The stored value.
    /// - Returns: The value, or "" for none.
    private static func stored(_ value: String?) -> String {
        value == "Not supported" ? "" : value ?? ""
    }
}
