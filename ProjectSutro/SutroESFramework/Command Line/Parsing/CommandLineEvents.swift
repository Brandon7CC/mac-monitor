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
/// A short name is the `ES_EVENT_TYPE_NOTIFY_*` name without its prefix, in lowercase, as eslogger names events
/// (``EventNames``). Mac Monitor's own events have one name for both.
public enum CommandLineEvents {
    /// An event's short name (``EventNames/shortName(_:)``).
    ///
    /// - Parameter fullName: An `ES_EVENT_TYPE_*` name, or a Mac Monitor event's.
    /// - Returns: `exec` for `ES_EVENT_TYPE_NOTIFY_EXEC`. A name without the NOTIFY prefix comes back lowercased.
    public static func shortName(_ fullName: String) -> String {
        EventNames.shortName(fullName)
    }
    
    /// The event a name stands for, if `macmonitor` can stream it on this Mac.
    ///
    /// - Parameter name: A short name in any case, or a full name.
    /// - Returns: The event, or `nil` for an AUTH event, one Mac Monitor doesn't model, or a name that isn't one.
    public static func event(named name: String) -> es_event_type_t? {
        StreamPlan.supportedEventsByName()[EventNames.fullName(name)]
    }
    
    /// The NOTIFY event, or Mac Monitor event, a name stands for, whether or not `macmonitor` streams it: a mute may
    /// name any event Mac Monitor knows.
    ///
    /// - Parameter name: A short name in any case, or a full name.
    /// - Returns: The event, or `nil` for an AUTH event or a name Mac Monitor doesn't know.
    public static func notifyEvent(named name: String) -> es_event_type_t? {
        let event = eventStringToType(from: EventNames.fullName(name))
        return event == ES_EVENT_TYPE_LAST ? nil : event
    }
    
    /// Every event `macmonitor` can stream on this Mac, by short name, with whether a stream with no events named
    /// includes it. The network flow events never are.
    ///
    /// - Returns: The events, sorted by short name.
    public static func catalog() -> [(name: String, fullName: String, isDefault: Bool)] {
        let defaults = Set(defaultEventSubscriptions.map(\.rawValue))
        return StreamPlan.streamableEvents.map { event in
            let fullName = eventTypeToString(from: event)
            return (shortName(fullName), fullName, defaults.contains(event.rawValue))
        }.sorted { $0.name < $1.name }
    }
}


// MARK: - Field filters
extension CommandLineParser {
    /// What `--every` takes: each event that has a field filter, by short name, then `all`.
    static let everyChoices = FieldFilter.filteredEvents.map {
        CommandLineEvents.shortName(eventTypeToString(from: $0))
    } + ["all"]
    
    /// Turn off an event's field filters, or every one, for `--every`.
    ///
    /// - Parameters:
    ///   - value: An event's name, or `all`.
    ///   - invocation: The stream.
    /// - Throws: ``CommandLineUsageError`` for anything but an event that has a field filter, or `all`.
    static func every(_ value: String, in invocation: inout StreamInvocation) throws {
        guard value != "all" else {
            invocation.fieldFilters = []
            return
        }
        guard let event = CommandLineEvents.event(named: value), !FieldFilter.offered(for: event).isEmpty else {
            throw CommandLineUsageError("--every takes \(everyChoices.dropLast().joined(separator: ", ")) or "
                                        + "\(everyChoices.last ?? "all"), not '\(value)'.", command: "stream")
        }
        invocation.fieldFilters = invocation.fieldFilters.filter { $0.event != event }
    }
}
