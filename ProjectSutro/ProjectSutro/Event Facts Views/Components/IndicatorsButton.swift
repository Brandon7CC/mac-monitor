//
//  IndicatorsButton.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Toolbar button
/// The indicators an event matched, behind a button at the trailing edge of Event Facts' toolbar: the top indicator's
/// symbol, in its color, and how many it matched. The button toggles the Indicators popover (``IndicatorsPopover``),
/// High first, then by name. Only an event that matched one has the button.
struct IndicatorsButton: ViewModifier {
    let message: ESMessage
    @ObservedObject private var store = IndicatorStore.shared
    /// Is the popover showing?
    @State private var isShown = false

    /// The event's facts, with the button in their toolbar when the event matched an indicator.
    ///
    /// - Parameter content: The event's facts.
    /// - Returns: The facts, with the button.
    func body(content: Content) -> some View {
        let indicators = Indicator.bySeverity(store.marks(for: message).indicators)
        content
            .toolbar {
                if let top = indicators.first {
                    /// At the window's trailing edge.
                    Spacer()
                    button(top: top, indicators: indicators)
                }
            }
            /// The button goes with the last of them, so the popover doesn't open by itself when one comes back.
            .onChange(of: indicators.isEmpty) { none in if none { isShown = false } }
    }

    /// - Parameters:
    ///   - top: The indicator listed first.
    ///   - indicators: Every indicator the event matched, in order.
    /// - Returns: The button, with its popover.
    private func button(top: Indicator, indicators: [Indicator]) -> some View {
        Button {
            isShown.toggle()
        } label: {
            /// The same space at both ends of the capsule macOS 26 and later draw around it. The count keeps its own
            /// width: a monospaced 1 leaves a gap after it, which reads as more padding at the trailing end.
            HStack(spacing: 5) {
                IndicatorSymbol(indicator: top)
                Text(indicators.count, format: .number).fontWeight(.semibold)
            }
            .padding(.horizontal, 4)
        }
        .help(indicators.count == 1 ? "Indicator this event matched: \(top.name)"
              : "\(indicators.count) indicators this event matched, \(top.name) first")
        .accessibilityLabel("Indicators this event matched")
        .accessibilityValue(indicators.map(\.name).joined(separator: ", "))
        /// Below the button, its arrow on the button's bottom edge pointing up at it.
        .popover(isPresented: $isShown, arrowEdge: .bottom) {
            IndicatorsPopover(indicators: indicators) { isShown = false }
        }
    }
}
