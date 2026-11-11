//
//  EventIndicatorMatcher.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - The indicators an event matched
/// The indicators each event matched, with the same answer as its record (``ESMessage/recordedIndicators(with:)``):
/// the Security Extension's verdicts when the event has them (``ESMessage/storedIndicators``), else the indicators
/// that are on, matched now (``IndicatorMatcher``), as for an Open Trace or an event from an older Security Extension.
/// So the event tables' dots, Correlation, Groups, the Indicators popover, a search that names `indicators`, the
/// JSON tab and an export agree.
///
/// A verdict's indicator is shown as the list has it now, on or off. One the list no longer has, such as one deleted
/// since, is shown from the verdict: its name, tactic, technique and severity, with a plain symbol. An indicator the
/// Security Extension refused is never in its verdicts. Not thread-safe: use one per queue, on the events' context's
/// queue.
public final class EventIndicatorMatcher {
    /// Matches events with no verdicts.
    private let matcher: IndicatorMatcher
    /// Every indicator in the list, on or off, by identity, with its place.
    private let listed: [UUID: (index: Int, indicator: Indicator)]

    /// Every indicator in the list, on or off, in its order: the order summaries list what events matched.
    public let order: [Indicator]

    /// - Parameter indicators: The indicators, in the order their cards show.
    public init(_ indicators: [Indicator]) {
        order = indicators
        matcher = IndicatorMatcher(indicators)
        listed = Dictionary(indicators.enumerated().map { ($1.id, ($0, $1)) }) { first, _ in first }
    }

    /// - Parameter message: The event.
    /// - Returns: The indicators it matched, in the list's order, then those the list no longer has, in the verdicts'.
    public func matches(_ message: ESMessage) -> [Indicator] {
        guard let hits = message.storedIndicators else { return matcher.matches(message) }
        return hits.map { hit in listed[hit.id] ?? (Int.max, Indicator(verdict: hit)) }
            .enumerated().sorted { ($0.element.index, $0.offset) < ($1.element.index, $1.offset) }
            .map(\.element.indicator)
    }
}


extension Indicator {
    /// The indicator a verdict names, for one the list no longer has: its name, tactic, technique and severity, with
    /// a plain gray symbol, shown where it is and marking the tables with a dot.
    ///
    /// - Parameter hit: The verdict.
    init(verdict hit: IndicatorHit) {
        self.init(id: hit.id, name: hit.name, description: "", symbol: "exclamationmark.magnifyingglass", color: .gray,
                  predicate: "",
                  tactic: Tactic.allCases.first { $0.identifier == hit.tactic_id },
                  technique: hit.technique.flatMap { Self.isTechnique($0) ? $0 : nil }, severity: hit.severity)
    }
}
