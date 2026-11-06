//
//  FieldFilter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Field filters
/// A condition on one event's own fields that a capture lane checks before it builds the event. A message that fails
/// it is left out: counted (``CaptureSession/fieldFilteredMessages``), never serialized. It still advanced Endpoint
/// Security's `seq_num` and `global_seq_num`, so its gap is not a loss.
///
/// The raw value is the wire name: its event's `ES_EVENT_TYPE_*` name, a period, the field. It travels beside event
/// names in ``SensorProtocol/eventSubscriptions(reply:)`` and in ``StreamOptions/fieldFilters``. It never names an event
/// (`eventStringToType(from:)` reads it as `ES_EVENT_TYPE_LAST`), so a Security Extension older than 3.0.1 refuses it.
/// An event has at most one filter on at a time.
public enum FieldFilter: String, CaseIterable, Sendable {
    /// Only closes of modified files: `es_event_close_t.modified`.
    case modifiedCloses = "ES_EVENT_TYPE_NOTIFY_CLOSE.modified"

    /// The event whose messages the filter checks.
    public var event: es_event_type_t {
        switch self {
        case .modifiedCloses: return ES_EVENT_TYPE_NOTIFY_CLOSE
        }
    }

    /// What Settings calls it, beside its event.
    public var title: String {
        switch self {
        case .modifiedCloses: return "Only modified files"
        }
    }

    /// What Settings says it does.
    public var help: String {
        switch self {
        case .modifiedCloses:
            return "Records a close only if the file was modified (es_event_close_t.modified). A file changed only "
                + "through a writable mapping closes unmodified; mmap events show such mappings. Uncheck to record "
                + "every close."
        }
    }

    /// What `macmonitor`'s banner says the stream keeps, such as "only modified closes".
    public var streamPhrase: String {
        switch self {
        case .modifiedCloses: return "only modified closes"
        }
    }

    /// What one message it left out is, singular, for `macmonitor`'s closing line: "unmodified close".
    public var leftOutNoun: String {
        switch self {
        case .modifiedCloses: return "unmodified close"
        }
    }

    /// Does a message of ``event`` pass? Reads only ``event``'s union member, never its `target`.
    ///
    /// - Parameter message: A message of ``event``: call it for no other. Only read during the call.
    /// - Returns: `true` to build the event, `false` to leave it out.
    @inline(__always)
    func admits(_ message: UnsafePointer<es_message_t>) -> Bool {
        switch self {
        case .modifiedCloses: return message.pointee.event.close.modified
        }
    }

    /// The filters an event offers.
    ///
    /// - Parameter event: An event type.
    /// - Returns: Its filters, in ``allCases`` order: none for most events.
    public static func offered(for event: es_event_type_t) -> [FieldFilter] {
        allCases.filter { $0.event == event }
    }

    /// The events that offer a filter, each once, in ``allCases`` order (`macmonitor stream --every`).
    public static var filteredEvents: [es_event_type_t] {
        var seen = Set<UInt32>()
        return allCases.map(\.event).filter { seen.insert($0.rawValue).inserted }
    }

    /// Each filter by its event's raw value, for a capture lane to look up per message. Build it off the hot path.
    ///
    /// - Parameter filters: The filters on: at most one per event.
    /// - Returns: An entry for every raw value up to the largest filtered one, `nil` where no filter is on. Empty for
    ///   no filters.
    static func table(_ filters: Set<FieldFilter>) -> ContiguousArray<FieldFilter?> {
        let size = filters.map { Int($0.event.rawValue) + 1 }.max() ?? 0
        var table = ContiguousArray<FieldFilter?>(repeating: nil, count: size)
        for filter in allCases where filters.contains(filter) { table[Int(filter.event.rawValue)] = filter }
        return table
    }
}
