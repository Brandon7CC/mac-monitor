//
//  StreamPlan.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Stream plan
/// A validated ``StreamOptions``: the stream a `macmonitor` session may start.
///
/// The Security Extension builds one from every stream request, and only ever subscribes to its events, so a stream
/// can only ever hold NOTIFY events Mac Monitor models (`supportedEvents`), never an AUTH event, which a capture
/// session never answers. `macmonitor` checks the same rules first, for friendlier errors.
public struct StreamPlan: Equatable {
    /// The most event names a request may carry, duplicates included.
    public static let maximumEvents: Int = 256
    
    /// The events to subscribe to, each once, in the order they were named.
    public let events: [es_event_type_t]
    /// Apply the saved mute set, and follow its changes?
    public let appliesSavedMutes: Bool
    /// The field filters to apply, only those on subscribed events, or `nil` for a 3.0.0 request that named none.
    public let fieldFilters: Set<FieldFilter>?
}


extension StreamPlan {
    /// Validate a request's options.
    ///
    /// No events means the defaults: with the close a field filter keeps modified-only, or, for a 3.0.0 request
    /// (no ``StreamOptions/fieldFilters``), without the events that are default only with a filter.
    ///
    /// - Parameter options: The options.
    /// - Throws: ``XPCRequestError/invalid(_:)`` for more than ``maximumEvents`` event or filter names, a name that
    ///   isn't a NOTIFY event Mac Monitor models on this Mac, or two filters on one event.
    ///   ``XPCRequestError/unsupported(_:)`` for a field filter this build doesn't know.
    public init(_ options: StreamOptions) throws(XPCRequestError) {
        guard options.events.count <= Self.maximumEvents else {
            throw .invalid("""
                The request names \(options.events.count) events. A stream can name at most \(Self.maximumEvents).
                """)
        }
        let events = options.events.isEmpty
            ? (options.fieldFilters == nil ? defaultEventSubscriptionsWithoutFieldFilters : defaultEventSubscriptions)
            : try Self.events(named: options.events)
        var filters: Set<FieldFilter>?
        if let names = options.fieldFilters { filters = try Self.fieldFilters(named: names, over: events) }
        self.init(events: events, appliesSavedMutes: options.appliesSavedMutes, fieldFilters: filters)
    }
    
    /// The events a request names.
    ///
    /// - Parameter names: `ES_EVENT_TYPE_NOTIFY_*` names.
    /// - Returns: The events, each once, in the order first named.
    /// - Throws: ``XPCRequestError/invalid(_:)`` for a name that isn't a NOTIFY event Mac Monitor models on this Mac.
    private static func events(named names: [String]) throws(XPCRequestError) -> [es_event_type_t] {
        let supported = supportedEventsByName()
        var events: [es_event_type_t] = [], seen = Set<UInt32>()
        for name in names {
            guard let event = supported[name] else {
                throw .invalid("\(name) isn't an event macmonitor can stream on this Mac.")
            }
            if seen.insert(event.rawValue).inserted { events.append(event) }
        }
        return events
    }
    
    /// The field filters a request names, on the events it streams.
    ///
    /// - Parameters:
    ///   - names: ``FieldFilter`` wire names.
    ///   - events: The events the stream subscribes to.
    /// - Returns: The filters whose event is among `events`.
    /// - Throws: ``XPCRequestError/invalid(_:)`` for more than ``maximumEvents`` names or two filters on one event,
    ///   ``XPCRequestError/unsupported(_:)`` for a name this build doesn't know: a newer `macmonitor`.
    static func fieldFilters(named names: [String],
                             over events: [es_event_type_t]) throws(XPCRequestError) -> Set<FieldFilter> {
        guard names.count <= maximumEvents else {
            throw .invalid("""
                The request names \(names.count) field filters. A stream can name at most \(maximumEvents).
                """)
        }
        var filters = Set<FieldFilter>(), filtered = Set<UInt32>()
        for name in names {
            guard let filter = FieldFilter(rawValue: name) else {
                throw .unsupported("""
                    \(name) isn't a field filter this Security Extension knows. Open Mac Monitor to finish updating.
                    """)
            }
            guard filters.insert(filter).inserted else { continue }
            guard filtered.insert(filter.event.rawValue).inserted else {
                throw .invalid("The request names two field filters on \(eventTypeToString(from: filter.event)).")
            }
        }
        let subscribed = Set(events.map(\.rawValue))
        return filters.filter { subscribed.contains($0.event.rawValue) }
    }
    
    /// Every event a stream may subscribe to, by its `ES_EVENT_TYPE_NOTIFY_*` name: the NOTIFY events Mac Monitor
    /// models on this Mac.
    ///
    /// - Returns: The events by name.
    static func supportedEventsByName() -> [String: es_event_type_t] {
        Dictionary(supportedEvents.map { (eventTypeToString(from: $0), $0) }, uniquingKeysWith: { first, _ in first })
    }
}
