//
//  StreamFilter+Relations.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/23/26.
//

import Foundation


// MARK: - Related events
/// The events a search predicate's `SUBQUERY` goes through, related to the event being searched.
///
/// `SUBQUERY(process_group, $e, $e.es_event_type == "ES_EVENT_TYPE_NOTIFY_CREATE").@count > 0` matches an event whose
/// process group created a file. Inside a `SUBQUERY`, `$e.path` is the related event's and a plain key path the
/// searched event's, so `$e.process.pid == process.pid` joins the two, and `$e.mach_time > mach_time` puts the related
/// event after. Not `global_seq_num`: each Endpoint Security client numbers its own events. `events` relates every
/// event to every other, for events nothing else relates. An event is never related to itself.
public enum PredicateRelation: String, CaseIterable {
    /// Every event recorded, or in the trace.
    case events
    /// The events of the processes in the event's process group.
    case processGroup = "process_group"
    /// The events of the processes in the event's session.
    case sessionGroup = "session_group"
    /// The events of the process the event created, its `EXEC` target or `FORK` child, as Correlation shows them.
    case correlated
    /// The other events of the event's process.
    case processEvents = "process_events"

    /// What it relates, for the predicate editor.
    public var summary: String {
        switch self {
        case .events: return "Every other event"
        case .processGroup: return "Events in the same process group"
        case .sessionGroup: return "Events in the same session"
        case .correlated: return "Events of the process it created (EXEC or FORK)"
        case .processEvents: return "Other events of the same process"
        }
    }

    /// Every relation's name, for errors: "events, process_group, …".
    static var names: String { allCases.map(\.rawValue).joined(separator: ", ") }

    /// Which events a related event is among, by its own process.
    ///
    /// - Parameter record: A related event's record.
    /// - Returns: Its group, or `nil` if it has none.
    func group(ofRelated record: NSDictionary) -> AnyHashable? {
        switch self {
        case .events: return ""
        case .processGroup: return Self.hashable(record, "process.group_id")
        case .sessionGroup: return Self.hashable(record, "process.session_id")
        case .correlated, .processEvents: return Self.hashable(record, "process.audit_token_string")
        }
    }

    /// Which events relate to a searched event.
    ///
    /// - Parameter record: The searched event's record.
    /// - Returns: The group its related events are among, or `nil` if it has none.
    func group(ofSearched record: NSDictionary) -> AnyHashable? {
        switch self {
        case .events: return ""
        case .processGroup:
            return Self.hashable(record, "event.exec.target.group_id") ?? Self.hashable(record, "process.group_id")
        case .sessionGroup:
            return Self.hashable(record, "event.exec.target.session_id") ?? Self.hashable(record, "process.session_id")
        case .correlated:
            return Self.hashable(record, "event.exec.target.audit_token_string")
                ?? Self.hashable(record, "event.fork.child.audit_token_string")
        case .processEvents: return Self.hashable(record, "process.audit_token_string")
        }
    }

    /// - Parameters:
    ///   - record: A record.
    ///   - keyPath: A key path to a string or a number.
    /// - Returns: The value, or `nil` if it's anything else.
    private static func hashable(_ record: NSDictionary, _ keyPath: String) -> AnyHashable? {
        hashable(record.value(forKeyPath: keyPath))
    }

    /// - Parameter value: A value.
    /// - Returns: The value if it's a string or a number, to group or look events up by, else `nil`.
    static func hashable(_ value: Any?) -> AnyHashable? {
        switch value {
        case let string as NSString: return string
        case let number as NSNumber: return number
        default: return nil
        }
    }
}
