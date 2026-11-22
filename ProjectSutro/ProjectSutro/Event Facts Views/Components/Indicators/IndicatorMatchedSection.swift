//
//  IndicatorMatchedSection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/22/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Why an event matched
/// Why an event matched an indicator, as its hit says (``IndicatorHit/matched``): what the event had, and the
/// event's type. The Indicators popover lists what it had (``IndicatorMatchedSection``), and marks the lines of the
/// predicate it passed (``PredicateLayout/passedLines(by:eventType:)``).
struct IndicatorMatch {
    /// The key paths the predicate's comparisons read, each with the value the event had.
    let fields: [IndicatorMatchedField]
    /// The event's type, such as `ES_EVENT_TYPE_NOTIFY_EXEC`.
    let eventType: String?

    /// - Parameter message: An event on the main queue's context.
    /// - Returns: Why it matched each indicator, by the indicator's identity. Only a hit the Security Extension made
    ///   says, so an event matched as it's shown has none, nor does a rule that compares only the event's type.
    static func matches(of message: ESMessage) -> [UUID: IndicatorMatch] {
        guard !message.isDeleted, let hits = message.storedIndicators else { return [:] }
        let eventType = message.es_event_type
        return Dictionary(hits.compactMap { hit in
            hit.matched.map { (hit.id, IndicatorMatch(fields: $0, eventType: eventType)) }
        }) { first, _ in first }
    }
}


// MARK: - Matched section
/// What an event had that made it match, on an indicator's card in the Indicators popover: under Matched, each key
/// path with the event's value in a box as wide as the value, both selectable. A value a hit cut short says so in
/// its help.
struct IndicatorMatchedSection: View {
    let fields: [IndicatorMatchedField]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            Text("Matched")
                .font(.system(size: 13, weight: .semibold))
                .frame(minHeight: 24)
                .help("What this event had that the indicator matched.")
            VStack(alignment: .leading, spacing: 8) {
                ForEach(fields, id: \.self) { field in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(field.field).foregroundStyle(.secondary)
                        Text(field.value.text)
                            .lineLimit(4)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(IndicatorPredicateSection.panel,
                                        in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                            .help(field.value.isCut ? "The value's first 256 characters." : field.value.text)
                    }
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityElement(children: .combine)
                }
            }
        }
    }
}
