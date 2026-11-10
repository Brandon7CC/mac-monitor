//
//  IndicatorAlert.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Notifications to post
/// A notification the coalescer decided to post (``IndicatorAlertCoalescer``): an indicator's first notice, a summary
/// of its later matches, or the overflow summary of matches no notice of their own could take.
public enum IndicatorAlert: Hashable, Sendable {
    /// An indicator matched while idle: the notice for its event.
    case first(IndicatorAlertEvent)
    /// An indicator's matches gathered in a window, which replace its notice.
    case summary(IndicatorAlertSummary)
    /// Matches no notice could take, across indicators.
    case overflow(IndicatorAlertOverflow)

    /// The matches it stands for: one for a notice, every one gathered for a summary.
    public var count: Int {
        switch self {
        case .first: 1
        case .summary(let summary): summary.count
        case .overflow(let overflow): overflow.count
        }
    }
}


/// An indicator's matches gathered while its notice's window was open, or while a High waited for a token.
public struct IndicatorAlertSummary: Hashable, Sendable {
    /// The matches.
    public var count: Int
    /// The earliest one's time.
    public var since: Date
    /// The latest one, which a click opens.
    public var latest: IndicatorAlertEvent
    /// The distinct processes they came from, up to the limit (``IndicatorAlertLimits/distinctProcesses``).
    public var processes: Set<String>
    /// Did more distinct processes match than are counted?
    public var hasMoreProcesses = false

    /// - Parameter event: The first match.
    init(_ event: IndicatorAlertEvent) {
        (count, since, latest, processes) = (1, event.time, event, [event.processKey])
    }

    /// Gather another match.
    ///
    /// - Parameters:
    ///   - event: The match.
    ///   - limit: The most distinct processes counted.
    mutating func add(_ event: IndicatorAlertEvent, limit: Int) {
        count += 1
        since = min(since, event.time)
        if event.time >= latest.time { latest = event }
        guard !processes.contains(event.processKey) else { return }
        if processes.count < limit { processes.insert(event.processKey) } else { hasMoreProcesses = true }
    }
}


/// The overflow summary: matches across indicators that no notice of their own could take, because their tokens ran
/// out or their events were old.
public struct IndicatorAlertOverflow: Hashable, Sendable {
    /// One indicator's matches in it.
    public struct Entry: Hashable, Sendable {
        /// The indicator.
        public let indicator: IndicatorAlertEvent.Match
        /// Its matches.
        public var count: Int
        /// Its latest match.
        public var latest: IndicatorAlertEvent
    }

    /// Every indicator's matches, those with the fewest first, then by name, so a lone rare match isn't hidden
    /// behind a common one.
    public let entries: [Entry]

    /// - Parameter entries: The indicators' matches, in any order.
    init(_ entries: [Entry]) {
        self.entries = entries.sorted { first, second in
            first.count != second.count ? first.count < second.count
                : first.indicator.name.localizedStandardCompare(second.indicator.name) == .orderedAscending
        }
    }

    /// The matches.
    public var count: Int { entries.reduce(0) { $0 + $1.count } }
}
