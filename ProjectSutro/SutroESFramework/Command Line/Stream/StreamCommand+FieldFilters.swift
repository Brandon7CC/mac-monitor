//
//  StreamCommand+FieldFilters.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Field filters
/// What `macmonitor stream` says about the field filters a stream asked for (``StreamInvocation/fieldFilters``), and
/// which gaps they make that aren't losses.
extension StreamCommand {
    /// The event types whose gaps aren't losses: those of the filters the Security Extension says it applied.
    ///
    /// - Parameter echoed: ``StreamStarted/fieldFilters``: `nil` from a Security Extension older than 3.0.1, whose gaps
    ///   are all real. Names this build doesn't know are ignored.
    /// - Returns: `es_event_type_t` raw values, for ``StreamDropMeter/fieldFilteredTypes``.
    static func fieldFilteredTypes(echoed: [String]?) -> Set<Int> {
        Set(filters(named: echoed ?? []).map { Int($0.event.rawValue) })
    }

    /// Warnings for filters asked for that a Security Extension older than 3.0.1 can't apply, on the events it streams.
    ///
    /// - Parameters:
    ///   - asked: The filters the stream asked for.
    ///   - events: ``StreamStarted/events``.
    /// - Returns: One line per filter, such as "macmonitor: this Security Extension streams every close. Open Mac
    ///   Monitor to finish updating."
    static func unappliedFieldFilters(asked: Set<FieldFilter>, events: [String]) -> [String] {
        let subscribed = Set(events)
        return FieldFilter.allCases
            .filter { asked.contains($0) && subscribed.contains(eventTypeToString(from: $0.event)) }
            .map { "macmonitor: this Security Extension streams every \($0.eventName). Open Mac Monitor to finish "
                + "updating." }
    }

    /// What the banner adds for the filters the Security Extension applied.
    ///
    /// - Parameter echoed: ``StreamStarted/fieldFilters``.
    /// - Returns: Such as ", only modified closes (--every close shows every close)", or "" for none.
    static func keeping(echoed: [String]?) -> String {
        filters(named: echoed ?? []).map { filter in
            ", \(filter.streamPhrase) (--every \(filter.eventName) shows every \(filter.eventName))"
        }.joined()
    }

    /// What the closing line adds for the messages field filters left out.
    ///
    /// - Parameter counts: ``StreamSummary/fieldFiltered``, by `ES_EVENT_TYPE_*` name.
    /// - Returns: Such as ", left out 5210 unmodified closes", or "" for none.
    static func leftOut(_ counts: [String: Int]?) -> String {
        (counts ?? [:]).filter { $0.value > 0 }.sorted { $0.key < $1.key }.map { name, count in
            let filter = FieldFilter.allCases.first { eventTypeToString(from: $0.event) == name }
            let noun = filter?.leftOutNoun ?? "\(CommandLineEvents.shortName(name)) event"
            return ", left out \(String.counted(count, noun))"
        }.joined()
    }

    /// The filters named, in ``FieldFilter/allCases`` order.
    ///
    /// - Parameter names: ``FieldFilter`` wire names. Unknown ones are ignored.
    /// - Returns: The filters.
    private static func filters(named names: [String]) -> [FieldFilter] {
        let named = Set(names)
        return FieldFilter.allCases.filter { named.contains($0.rawValue) }
    }
}


private extension FieldFilter {
    /// Its event's short name, such as "close".
    var eventName: String {
        CommandLineEvents.shortName(eventTypeToString(from: event))
    }
}
