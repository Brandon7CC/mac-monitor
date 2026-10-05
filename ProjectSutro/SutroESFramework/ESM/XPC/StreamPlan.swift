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
    
    /// Validate a request's options.
    ///
    /// - Parameter options: The options.
    /// - Throws: ``XPCRequestError/invalid(_:)`` for more than ``maximumEvents`` names, or a name that isn't a
    ///   NOTIFY event Mac Monitor models on this Mac.
    public init(_ options: StreamOptions) throws {
        guard options.events.count <= Self.maximumEvents else {
            throw XPCRequestError.invalid("""
                The request names \(options.events.count) events. A stream can name at most \(Self.maximumEvents).
                """)
        }
        guard !options.events.isEmpty else {
            self.init(events: defaultEventSubscriptions, appliesSavedMutes: options.appliesSavedMutes)
            return
        }
        let supported = Self.supportedEventsByName()
        var events: [es_event_type_t] = [], seen = Set<UInt32>()
        for name in options.events {
            guard let event = supported[name] else {
                throw XPCRequestError.invalid("\(name) isn't an event macmonitor can stream on this Mac.")
            }
            if seen.insert(event.rawValue).inserted { events.append(event) }
        }
        self.init(events: events, appliesSavedMutes: options.appliesSavedMutes)
    }
    
    /// - Parameters:
    ///   - events: The events to subscribe to.
    ///   - appliesSavedMutes: Apply the saved mute set?
    init(events: [es_event_type_t], appliesSavedMutes: Bool) {
        self.events = events
        self.appliesSavedMutes = appliesSavedMutes
    }
    
    /// The events' `ES_EVENT_TYPE_NOTIFY_*` names, in order.
    public var eventNames: [String] {
        events.map { eventTypeToString(from: $0) }
    }
    
    /// Every event a stream may subscribe to, by its `ES_EVENT_TYPE_NOTIFY_*` name: the NOTIFY events Mac Monitor
    /// models on this Mac.
    ///
    /// - Returns: The events by name.
    static func supportedEventsByName() -> [String: es_event_type_t] {
        Dictionary(supportedEvents.map { (eventTypeToString(from: $0), $0) }, uniquingKeysWith: { first, _ in first })
    }
}
