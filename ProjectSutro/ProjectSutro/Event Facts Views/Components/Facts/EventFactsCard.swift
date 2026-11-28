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


// MARK: - Facts scroll
/// An Event Facts tab's facts, one below another, scrolling as a whole. A scroll view, not a list: a list holds them in
/// one table cell, and a control updating inside that cell never finished updating the window.
struct FactsScroll<Content: View>: View {
    /// The facts.
    @ViewBuilder let content: () -> Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, content: content)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}


// MARK: - Event facts card
/// One event's facts in Event Facts' Metadata tab: its label, then what the event says.
///
/// Every event's view is this card around its own facts, so the label is written once:
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
    /// The label's color for a type it doesn't color itself: Open Directory's are orange.
    var labelTint: Color?
    /// What the event says: ``FactsBox``es, mostly.
    @ViewBuilder let facts: () -> Facts

    var body: some View {
        VStack(alignment: .leading) {
            SystemEventTypeLabel(message: message, tint: labelTint)
                .font(.title2)
            facts()
        }
    }
}
