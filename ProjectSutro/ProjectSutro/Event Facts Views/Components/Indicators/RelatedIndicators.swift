//
//  RelatedIndicators.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/10/26.
//

import CoreData
import SutroESFramework


// MARK: - Related indicators
/// The indicators the events around an event matched, which the Indicators popover lists under the event's own: an
/// indicator is stamped on the event that shows it, so an exec whose process then loads code from memory carries
/// none for that itself.
///
/// - **Correlated:** those matched by the events an exec's process went on to make, which the Correlation tab lists.
/// - **Group:** those matched by the other execs in the event's process group and session, which the Groups tab
///   lists.
///
/// Made on the main thread, the view context's queue: it fetches the correlated events and both groups.
struct RelatedIndicators {
    /// An indicator, and how many of the related events matched it.
    struct Entry: Identifiable {
        let indicator: Indicator
        let events: Int
        var id: UUID { indicator.id }
    }

    /// Those an exec's correlated events matched, High first, then by name.
    private(set) var correlated: [Entry] = []
    /// Those the other execs of the event's process group and session matched, in the same order.
    private(set) var group: [Entry] = []

    /// Did no event around it match one?
    var isEmpty: Bool { correlated.isEmpty && group.isEmpty }
    /// How many indicators the events around it matched, each once.
    var count: Int { Set(correlated.map(\.id)).union(group.map(\.id)).count }
    /// The one listed first: the first correlated, else the first of the groups.
    var top: Indicator? { (correlated.first ?? group.first)?.indicator }

    /// None, for an event not looked at yet.
    init() {}

    /// - Parameters:
    ///   - message: The event Event Facts shows, on the main queue's context.
    ///   - matcher: The indicators to look for, read from each event's stored verdicts first (``IndicatorStore``).
    init(around message: ESMessage, matcher: EventIndicatorMatcher) {
        guard !message.isDeleted, message.es_event_type != nil else { return }
        if message.event.exec != nil { correlated = Self.tally(message.correlated_array, matcher) }
        let store = CoreDataController.shared
        var seen: Set<NSManagedObjectID> = [message.objectID]
        let execs = (store.getProcGroup(message: message) + store.getProcSessionGroup(message: message))
            .filter { seen.insert($0.objectID).inserted }
        group = Self.tally(execs, matcher)
    }

    /// - Parameters:
    ///   - events: Events.
    ///   - matcher: The indicators to look for.
    /// - Returns: Each indicator one of them matched, with how many did, High first, then by name.
    private static func tally(_ events: [ESMessage], _ matcher: EventIndicatorMatcher) -> [Entry] {
        var counts: [UUID: Int] = [:], indicators: [UUID: Indicator] = [:]
        for event in events {
            for indicator in matcher.matches(event) {
                counts[indicator.id, default: 0] += 1
                indicators[indicator.id] = indicator
            }
        }
        return Indicator.bySeverity(Array(indicators.values)).map { Entry(indicator: $0, events: counts[$0.id] ?? 1) }
    }
}
