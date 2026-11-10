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
/// One event's facts in Event Facts' Metadata tab: its label, what the event says, and its context items. Those are
/// the audit tokens of the process that made the event, the audit token of the process it acted on when it has one,
/// and any button the event adds.
///
/// Every event's view is this card around its own facts, so the label, the context items and the sheets are written
/// once:
/// ```swift
/// if let event = esSystemEvent.event.mount {
///     EventFactsCard(message: esSystemEvent) {
///         FactsBox { FactRow(name: "Mount point", value: event.statfs.f_mntonname) }
///     }
/// }
/// ```
struct EventFactsCard<Facts: View, Context: View>: View {
    /// The audit tokens a sheet shows.
    private enum Tokens: String, Identifiable {
        case process, target
        var id: String { rawValue }
    }

    /// The event.
    let message: ESMessage
    /// The audit token of the process the event acted on, which adds a Target audit tokens button, or `nil`.
    var targetAuditToken: String?
    /// The label's color for a type it doesn't color itself: Open Directory's are orange.
    var labelTint: Color?
    /// What the event says: ``FactsBox``es, and anything else it shows above its context items.
    @ViewBuilder let facts: () -> Facts
    /// The event's own context buttons, after the audit tokens'.
    @ViewBuilder let context: () -> Context
    /// The audit tokens shown in a sheet, if any are.
    @State private var shown: Tokens?

    /// - Parameters:
    ///   - message: The event.
    ///   - targetAuditToken: The audit token of the process the event acted on, or `nil` without one.
    ///   - labelTint: The label's color for a type it doesn't color itself, or `nil`.
    ///   - facts: What the event says.
    ///   - context: The event's own context buttons.
    init(message: ESMessage, targetAuditToken: String? = nil, labelTint: Color? = nil,
         @ViewBuilder facts: @escaping () -> Facts, @ViewBuilder context: @escaping () -> Context) {
        self.message = message
        self.targetAuditToken = targetAuditToken
        self.labelTint = labelTint
        self.facts = facts
        self.context = context
    }

    var body: some View {
        VStack(alignment: .leading) {
            SystemEventTypeLabel(message: message, tint: labelTint)
                .font(.title2)
            facts()
            Divider()
            Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") { shown = .process }
                    if targetAuditToken != nil {
                        Button("**Target audit tokens**") { shown = .target }
                    }
                    context()
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }.sheet(item: $shown) { tokens in
            switch tokens {
            case .process: AuditTokenView(process: message.process)
            case .target: AuditTokenView(audit_token: targetAuditToken ?? "")
            }
            Button("**Dismiss**") { shown = nil }.padding(.bottom)
        }
    }
}

extension EventFactsCard where Context == EmptyView {
    /// A card whose only context items are audit tokens.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - targetAuditToken: The audit token of the process the event acted on, or `nil` without one.
    ///   - labelTint: The label's color for a type it doesn't color itself, or `nil`.
    ///   - facts: What the event says.
    init(message: ESMessage, targetAuditToken: String? = nil, labelTint: Color? = nil,
         @ViewBuilder facts: @escaping () -> Facts) {
        self.init(message: message, targetAuditToken: targetAuditToken, labelTint: labelTint, facts: facts) {
            EmptyView()
        }
    }
}
