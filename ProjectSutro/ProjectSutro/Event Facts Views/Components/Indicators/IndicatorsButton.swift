//
//  IndicatorsButton.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Toolbar button
/// The indicators an event matched, and those the events around it did (``RelatedIndicators``), behind a button at
/// the trailing edge of Event Facts' toolbar: the top indicator's symbol, in its color, how many the event matched,
/// and how many more the events around it did, as `+2`. The button toggles the Indicators popover
/// (``IndicatorsPopover``), High first, then by name. Only an event with one of either has the button.
struct IndicatorsButton: ViewModifier {
    let message: ESMessage
    @ObservedObject private var store = IndicatorStore.shared
    /// Is the popover showing?
    @State private var isShown = false
    /// The indicators the events around the event matched.
    @State private var related = RelatedIndicators()

    /// The event's facts, with the button in their toolbar when the event, or one around it, matched an indicator.
    ///
    /// - Parameter content: The event's facts.
    /// - Returns: The facts, with the button.
    func body(content: Content) -> some View {
        let indicators = Indicator.bySeverity(store.marks(for: message).indicators)
        let isEmpty = indicators.isEmpty && related.isEmpty
        content
            .toolbar {
                if let top = indicators.first ?? related.top {
                    /// At the window's trailing edge.
                    Spacer()
                    button(top: top, indicators: indicators)
                }
            }
            /// The button goes with the last of them, so the popover doesn't open by itself when one comes back.
            .onChange(of: isEmpty) { none in if none { isShown = false } }
            /// Looked up for each event, when the indicators change, and again as the popover opens, since a
            /// process still running goes on making events.
            .task(id: "\(message.objectID)|\(store.revision)|\(isShown)") {
                related = RelatedIndicators(around: message, matcher: store.matcher)
            }
    }

    /// - Parameters:
    ///   - top: The indicator listed first: the event's own, else the first around it.
    ///   - indicators: Every indicator the event matched, in order.
    /// - Returns: The button, with its popover.
    private func button(top: Indicator, indicators: [Indicator]) -> some View {
        Button {
            isShown.toggle()
        } label: {
            /// The same space at both ends of the capsule macOS 26 and later draw around it. The count keeps its own
            /// width: a monospaced 1 leaves a gap after it, which reads as more padding at the trailing end.
            HStack(spacing: 5) {
                IndicatorSymbol(indicator: top).opacity(indicators.isEmpty ? 0.6 : 1)
                if !indicators.isEmpty {
                    Text(indicators.count, format: .number).fontWeight(.semibold)
                }
                if !related.isEmpty {
                    Text("+\(related.count)").foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 4)
        }
        .help(help(top: top, indicators: indicators))
        .accessibilityLabel("Indicators this event and the events around it matched")
        .accessibilityValue((indicators + related.correlated.map(\.indicator) + related.group.map(\.indicator))
            .map(\.name).joined(separator: ", "))
        /// Below the button, its arrow on the button's bottom edge pointing up at it.
        .popover(isPresented: $isShown, arrowEdge: .bottom) {
            IndicatorsPopover(indicators: indicators, related: related) { isShown = false }
        }
    }

    /// - Parameters:
    ///   - top: The indicator listed first.
    ///   - indicators: Every indicator the event matched, in order.
    /// - Returns: What the button's numbers count.
    private func help(top: Indicator, indicators: [Indicator]) -> String {
        let own = indicators.isEmpty ? "This event matched no indicator"
            : indicators.count == 1 ? "Indicator this event matched: \(top.name)"
            : "\(indicators.count) indicators this event matched, \(top.name) first"
        guard !related.isEmpty else { return own }
        return own + ". Its correlated events and groups matched \(related.count)."
    }
}
