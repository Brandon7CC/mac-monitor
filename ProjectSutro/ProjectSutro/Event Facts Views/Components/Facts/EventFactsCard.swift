//
//  EventFactsCard.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/10/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Facts box
/// Facts in a box as wide as Event Facts, one below another: ``FactRow``s, mostly.
struct FactsBox<Content: View>: View {
    /// The facts.
    @ViewBuilder let content: () -> Content

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, content: content)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}


// MARK: - Event facts card
/// One event's facts in Event Facts' Metadata tab: its label, what the event says, and its Details box. That box has
/// the audit tokens of the process that made the event and of the process it acted on when it has one, and an exec's
/// environment, code signing flags and file descriptors.
///
/// Every event's view is this card around its own facts, so the label and the Details box are written once:
/// ```swift
/// if let event = esSystemEvent.event.mount {
///     EventFactsCard(message: esSystemEvent) {
///         FactsBox { FactRow(name: "Mount point", value: event.statfs.f_mntonname) }
///     }
/// }
/// ```
struct EventFactsCard<Facts: View>: View {
    /// The event.
    let message: ESMessage
    /// The process the event acted on, whose audit tokens the Details box adds, or `nil`.
    var target: ESProcess?
    /// The label's color for a type it doesn't color itself: Open Directory's are orange.
    var labelTint: Color?
    /// What the event says: ``FactsBox``es, and anything else it shows above its Details box.
    @ViewBuilder let facts: () -> Facts

    var body: some View {
        VStack(alignment: .leading) {
            SystemEventTypeLabel(message: message, tint: labelTint)
                .font(.title2)
            facts()
            /// A new event starts its environment table unfiltered and collapsed.
            EventDetailsBox(details: EventDetails(message: message, target: target))
                .id(message.objectID)
        }
    }
}
