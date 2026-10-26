//
//  CommandLineEvents.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Event names
/// The events `macmonitor` can stream, by the names people type: `exec`, or `ES_EVENT_TYPE_NOTIFY_EXEC`.
///
/// A short name is the `ES_EVENT_TYPE_NOTIFY_*` name without its prefix, in lowercase, as eslogger names events.
public enum CommandLineEvents {
    /// The prefix every streamable event's full name has.
    static let notifyPrefix = "ES_EVENT_TYPE_NOTIFY_"
    
    /// An event's short name.
    ///
    /// - Parameter fullName: An `ES_EVENT_TYPE_*` name.
    /// - Returns: `exec` for `ES_EVENT_TYPE_NOTIFY_EXEC`. A name without the NOTIFY prefix comes back lowercased.
    public static func shortName(_ fullName: String) -> String {
        String(fullName.dropFirst(fullName.hasPrefix(notifyPrefix) ? notifyPrefix.count : 0)).lowercased()
    }
    
    /// The event a name stands for, if `macmonitor` can stream it on this Mac.
    ///
    /// - Parameter name: A short name in any case, or a full `ES_EVENT_TYPE_NOTIFY_*` name.
    /// - Returns: The event, or `nil` for an AUTH event, one Mac Monitor doesn't model, or a name that isn't one.
    public static func event(named name: String) -> es_event_type_t? {
        let full = name.hasPrefix(notifyPrefix) ? name : notifyPrefix + name.uppercased()
        return StreamPlan.supportedEventsByName()[full]
    }
    
    /// The NOTIFY event a name stands for, whether or not `macmonitor` streams it: a mute may name any event Mac
    /// Monitor knows.
    ///
    /// - Parameter name: A short name in any case, or a full `ES_EVENT_TYPE_NOTIFY_*` name.
    /// - Returns: The event, or `nil` for an AUTH event or a name Mac Monitor doesn't know.
    public static func notifyEvent(named name: String) -> es_event_type_t? {
        let event = eventStringToType(from: name.hasPrefix(notifyPrefix) ? name : notifyPrefix + name.uppercased())
        return event == ES_EVENT_TYPE_LAST ? nil : event
    }
    
    /// Every event `macmonitor` can stream on this Mac, by short name, with whether a stream with no events named
    /// includes it.
    ///
    /// - Returns: The events, sorted by short name.
    public static func catalog() -> [(name: String, fullName: String, isDefault: Bool)] {
        let defaults = Set(defaultEventSubscriptions.map(\.rawValue))
        return supportedEvents.map { event in
            let fullName = eventTypeToString(from: event)
            return (shortName(fullName), fullName, defaults.contains(event.rawValue))
        }.sorted { $0.name < $1.name }
    }
}
